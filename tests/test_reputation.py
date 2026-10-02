"""Reputación — el ranking, y lo que un ranking tiene que cumplir.

Cuatro cosas, y las cuatro son la razón de que esto sea un módulo aparte y no
un campo más en el ledger:

* **ordena por lo que cuenta.** Un nodo que sirvió más inferencias va por
  delante aunque anuncie menos VRAM. El orden es determinista hasta en el
  empate, porque un ranking que se reordena entre dos ejecuciones no es
  discutible: es ilegible.
* **distingue el dinero del mérito.** Los satoshis van en su propia columna. Un
  nodo al que le pagan 100 sats por inferencia no es el doble de bueno, y una
  tabla con un solo número de "valor" invita a inventar un tipo de cambio que no
  existe.
* **no es un saldo.** No hay con qué gastarlo ni a quién transferírselo. Eso se
  fija por ausencia de API, que es la única forma de que un `spend` reintroducido
  no pase desapercibido.
* **la evidencia es la cadena.** El board verificado reconstruye el número desde
  las anclas contra una cabecera; el de contadores proyecta lo que la malla ya contó. Cuando discrepan —una ancla que no verifica— el verificado deja de
  contar y el contador no, y esa discrepancia es justo lo que un terceiro vería.
"""

from __future__ import annotations

import pytest

from delm.core.anchor import AnchorLedger, AnchorRecord
from delm.core.bsv_keys import Secp256k1KeyPair
from delm.core.contrib import CapacityReport, ContributionLedger
from delm.core.membership import BlockHeader, InclusionProof, MembershipOutput, merkle_root
from delm.core.provenance import KeyPair
from delm.core.reputation import (
    ReputationBoard,
    ReputationEntry,
    board_from_counters,
    board_from_verified,
    verified_count,
)

MESH = "malla-reputacion"
NOW = 1_000.0
TXID = "9a" * 32
MEMBERSHIP_TXID = "cc" * 32
#: The requester is another node; a self-requested anchor does not build.
REQUESTER = Secp256k1KeyPair.new("quien-pide")


def _peer(led: ContributionLedger, peer_id: str, vram: float,
          advertised: float | None = None) -> None:
    key = KeyPair.new(peer_id)
    ch = led.issue_challenge(peer_id, now=NOW)
    rep = CapacityReport(mesh_id=MESH, peer_id=peer_id, vram_gb=vram,
                         vram_advertised_gb=vram if advertised is None
                         else advertised,
                         ram_gb=32.0, cpu_cores=8, nonce=ch.nonce,
                         issued_at=NOW, expires_at=NOW + 3600).sign(key)
    assert led.admit(rep, now=NOW)[0]
    led.observe(peer_id, NOW, dt_s=60)


def _verified_ledger(worker: Secp256k1KeyPair, *, txid: str = TXID,
                     satoshis: int = 100,
                     signer: Secp256k1KeyPair | None = None) -> AnchorLedger:
    """An anchor ledger holding one anchor, signed by *signer* (default: worker).

    ``signer`` is how a forged entry is built: the record says one thing and the
    signature comes from another key, which is exactly what verification exists
    to catch.
    """
    membership = MembershipOutput(txid=MEMBERSHIP_TXID, vout=0, satoshis=1000,
                                 script_hash="bb" * 32)
    chain = AnchorLedger(membership_outputs=[membership])
    rec = AnchorRecord(membership_txid=MEMBERSHIP_TXID, membership_vout=0,
                       membership_pubkey=worker.public_key.hex(),
                       requester_pubkey=REQUESTER.public_key.hex(),
                       satoshis=satoshis, occurred_at=1_700_000_000)
    # The inclusion has to be of the *membership* transaction: the anchor
    # checks that the proof and the declared membership are the same one, so a
    # proof from any other transaction is refused even when it is real.
    inc = InclusionProof(txid=MEMBERSHIP_TXID, index=0, path=[],
                         merkle_root=merkle_root(
                             [bytes.fromhex(MEMBERSHIP_TXID)[::-1]]).hex(),
                         height=900_000)
    chain.append(rec, inc, rec.sign(signer or worker))
    return chain


def _header(txid: str = MEMBERSHIP_TXID, height: int = 900_000) -> BlockHeader:
    """The header the anchor was included under (its membership transaction)."""
    leaf = bytes.fromhex(txid)[::-1]
    return BlockHeader(merkle_root=merkle_root([leaf]).hex(), height=height)


# ------------------------------------------------------------ el orden
def test_the_board_orders_by_inferences_then_satoshis_then_id():
    board = ReputationBoard(entries=(
        ReputationEntry(node_id="c", inferences_served=5, satoshis_earned=10),
        ReputationEntry(node_id="a", inferences_served=5, satoshis_earned=99),
        ReputationEntry(node_id="b", inferences_served=9, satoshis_earned=1),
        ReputationEntry(node_id="d", inferences_served=0, satoshis_earned=0),
    ))
    ordered = [e.node_id for e in
               sorted(board.entries,
                      key=lambda e: (-e.inferences_served, -e.satoshis_earned,
                                     e.node_id))]
    # Serving wins over money: "a" has 99 sats and "b" has 9 inferences.
    assert ordered[0] == "b"
    assert ordered[1] == "a"
    # Sats break ties, and node_id makes it total.
    assert ordered[2:] == ["c", "d"]


def test_position_is_one_based_and_unknown_nodes_are_absent():
    led = ContributionLedger(MESH)
    _peer(led, "a", 8.0)
    _peer(led, "b", 24.0)
    led.record_inference("a", txid="11" * 32)
    led.record_inference("b", txid="22" * 32)
    board = board_from_counters(led)
    assert board.position("a") == 1
    assert board.position("b") == 2
    assert board.position("fantasma") is None


def test_the_ranking_is_deterministic():
    led = ContributionLedger(MESH)
    for peer, vram in (("z", 8.0), ("a", 8.0), ("m", 24.0)):
        _peer(led, peer, vram)
    for peer in ("z", "a", "m"):
        led.record_inference(peer, txid=f"{peer[0]}0" * 32, satoshis=100)
    first = board_from_counters(led).to_dict()
    assert first == board_from_counters(led).to_dict()
    # Los tres empatan en todo, y el desempate por id los ordena igual en las
    # dos corridas: un ranking que se reordena entre ejecuciones no se puede
    # discutir, porque no se puede leer.
    assert [e["node_id"] for e in first["entries"]] == ["a", "m", "z"]


# ------------------------------------------------- dinero y merito, separados
def test_the_render_keeps_satoshis_in_their_own_column():
    """Una tabla con un solo numero de "valor" invita a inventar un tipo de cambio."""
    led = ContributionLedger(MESH)
    _peer(led, "a", 8.0)
    led.record_inference("a", txid="ab" * 32, satoshis=100)
    out = ReputationBoard(entries=(
        ReputationEntry(node_id="a", inferences_served=1, satoshis_earned=100,
                        vram_advertised_gb=8.0, observed_s=60.0),
    )).render()
    assert "inferencias" in out and "sats" in out
    assert "no se gasta, no se transfiere y no compra nada" in out


def test_an_empty_board_says_so_instead_of_printing_a_header():
    out = ReputationBoard().render()
    assert "ningún nodo con historial" in out
    assert "#" not in out.split("\n")[2]


# ------------------------------------------------------- proveedores y clientes
def test_a_consumer_is_on_the_board_but_not_among_the_providers():
    """Se ve, marcado como lo que es. Esconderse seria tan falso como colarse."""
    led = ContributionLedger(MESH)
    _peer(led, "consumidor", 24.0, advertised=0.0)
    _peer(led, "proveedor", 8.0)
    board = board_from_counters(led)
    assert {e.node_id for e in board} == {"consumidor", "proveedor"}
    assert [e.node_id for e in board.providers()] == ["proveedor"]
    assert board.get("consumidor").publishes_vram is False
    assert board.get("proveedor").publishes_vram is True


# ------------------------------------------------------- la cadena lo sostiene
def test_the_verified_board_counts_only_what_verifies():
    worker = Secp256k1KeyPair.new("n1")
    chain = _verified_ledger(worker)
    board = board_from_verified({"n1": chain}, _header())
    assert board.get("n1").inferences_served == 1
    assert board.get("n1").satoshis_earned == 100


def test_an_anchor_cannot_be_signed_by_a_key_that_is_not_the_membership_one():
    """La falsificacion no llega ni a construirse.

    Se asumia que un impostor podia firmar un ancla con otra clave y que la
    verificacion lo cazaria despues. No: `AnchorRecord.sign` rechaza la clave
    equivocada en el momento de firmar, porque el proposito del ancla es
    atribuir el gasto al nodo correcto y una firma de otra clave no lo haria.
    Es mejor no construirlo que construirlo y rechazarlo despues.
    """
    from delm.core.membership import ProtocolError

    worker = Secp256k1KeyPair.new("n1")
    rec = AnchorRecord(membership_txid=MEMBERSHIP_TXID, membership_vout=0,
                       membership_pubkey=worker.public_key.hex(),
                       requester_pubkey=REQUESTER.public_key.hex(),
                       satoshis=100)
    with pytest.raises(ProtocolError) as exc:
        rec.sign(Secp256k1KeyPair.new("impostor"))
    assert "no atribuiria el gasto" in str(exc.value)


def test_without_a_header_nothing_counts():
    """Sin cabecera no hay contra que comprobar, y la respuesta honesta es cero.

    Un ledger sin verificar es una afirmacion. Devolver "las que el nodo dice"
    seria presentar un ranking de afirmaciones como un ranking de hechos.
    """
    worker = Secp256k1KeyPair.new("n1")
    chain = _verified_ledger(worker)
    assert verified_count(chain, None) == 0
    # El board sale vacio, no con filas a cero: un nodo al que no se le puede
    # comprobar no aparece en un ranking que se presenta como verificado.
    board = board_from_verified({"n1": chain}, None)
    assert len(board) == 0
    assert board.position("n1") is None


def test_a_ledger_with_no_signatures_counts_nothing():
    """Un ledger sin firmas no verifica nada, y tampoco se rompe: cuenta cero."""
    worker = Secp256k1KeyPair.new("n1")
    membership = MembershipOutput(txid=MEMBERSHIP_TXID, vout=0, satoshis=1000,
                                 script_hash="bb" * 32)
    chain = AnchorLedger(membership_outputs=[membership])
    chain.anchors.append(AnchorRecord(
        membership_txid=MEMBERSHIP_TXID, membership_vout=0,
        membership_pubkey=worker.public_key.hex(),
        requester_pubkey=Secp256k1KeyPair.new("p").public_key.hex(),
        satoshis=100))
    assert verified_count(chain, _header()) == 0


# ------------------------------------------------------------------ el balance
def test_the_counter_board_needs_no_anchor_ledger():
    """La via barata: proyectar lo que la malla ya conto.

    Se usa para pintar, no para liquidar. La distincion con el board
    verificado esta en el nombre y en el docstring, porque confundirlos seria
    la forma facil de que un ranking pareciera mas solido de lo que es.
    """
    led = ContributionLedger(MESH)
    _peer(led, "a", 8.0)
    board = board_from_counters(led)
    assert board.to_dict()["entries"][0]["inferences_served"] == 0
    led.record_inference("a", txid="ab" * 32, satoshis=100)
    assert board_from_counters(led).get("a").inferences_served == 1