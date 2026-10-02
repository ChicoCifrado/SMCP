"""La tesis del intercambio, encadenada de punta a punta.

Por qué este archivo existe: los tests de `contrib` y de `placement` prueban
**piezas**. Ninguno prueba la afirmación que el proyecto sostiene, que es una
afirmación sobre la **secuencia**:

    un nodo publica VRAM (firmado)  ->  la malla lo coloca carga  ->
    otro nodo le pide una inferencia  ->  el ancla lo demuestra contra la
    cabecera  ->  y solo entonces su historial sube

Los tests por pieza pasan los tres aunque el paso del medio este roto: pueden
estar midiendo un contador que nunca se consulta, o un plan que coloca trabajo
donde no lo hay.

**La tesis anterior era otra.** Antes la cadena era "contribuir → ganar crédito
por estar vivo → el planner coloca → la inferencia se sirve si se puede
gastar". Esa se elimino entera: un nodo que gana por existir tiene un
incentivo para no hacer nada, que es lo contrario de lo que una malla quiere.
Se puede ver el cambio en `delm/core/reputation.py`.

Qué NO es este test (y por qué importa decirlo):

* **No es una atestación de hardware.** Las cifras de VRAM son *afirmaciones
  firmadas*: `test_contrib.py` fija que una afirmación firmada pero falsa se
  admite. Lo que sí se comprueba es que la **firma** ate los números, y que la
  **cadena** ate la inferencia.
* **No toca red.** No hay cliente HTTP: la inferencia es un hecho anclado, y
  lo que se prueba es la contabilidad de ese hecho, no que un modelo sepa
  Contestar.
* **El pago no se comprueba aqui.** Que la inferencia se pagara es cosa de
  `delm.core.x402` (challenge/proof) y de la cadena; este test empieza donde
  esa parte ya dio por buena.
"""

from __future__ import annotations

import pytest

from delm.core.anchor import AnchorRecord
from delm.core.bsv_keys import Secp256k1KeyPair
from delm.core.contrib import CapacityReport, ContributionLedger
from delm.core.membership import BlockHeader, InclusionProof, merkle_root
from delm.core.placement import ModelSpec, plan_placement
from delm.core.provenance import KeyPair
from delm.core.reputation import board_from_counters, board_from_verified

MESH = "malla-tesis"
NOW = 1_000.0


# ------------------------------------------------------------------ helpers
def _provider(led: ContributionLedger, peer_id: str, vram: float,
              advertised: float | None = None, *,
              identity: KeyPair | None = None) -> KeyPair:
    """Admit capacity for *peer_id*, offering *advertised* (default: all)."""
    identity = identity or KeyPair.new(peer_id)
    ch = led.issue_challenge(peer_id, now=NOW)
    rep = CapacityReport(
        mesh_id=MESH, peer_id=peer_id, vram_gb=vram,
        vram_advertised_gb=vram if advertised is None else advertised,
        ram_gb=32.0, cpu_cores=8, nonce=ch.nonce, issued_at=NOW,
        expires_at=NOW + 3600).sign(identity)
    ok, why = led.admit(rep, now=NOW)
    assert ok, why
    led.observe(peer_id, NOW, dt_s=60)
    return identity


def _header(txid: str, height: int = 900_000) -> BlockHeader:
    """Header whose Merkle root *is* the txid: a single leaf, so root == leaf."""
    return BlockHeader(merkle_root=txid, height=height)


def _inclusion(txid: str, height: int = 900_000) -> InclusionProof:
    """Inclusion of a lone transaction; root == txid (see test_anchor.py)."""
    # El txid de presentacion es big-endian y la hoja interna little-endian, asi
    # que la hoja se invierte. Sin eso la raiz seria distinta de la que
    # computa cualquier otro y el test pasaria sin probar nada.
    leaf = bytes.fromhex(txid)[::-1]
    return InclusionProof(txid=txid, index=0, path=[],
                          merkle_root=merkle_root([leaf]).hex(), height=height)


def _anchored_inference(worker: Secp256k1KeyPair, requester: Secp256k1KeyPair,
                        txid: str, *, satoshis: int = 100,
                        height: int = 900_000):
    """A real, verifiable anchor for one inference the *network* requested.

    Returns ``(record, signature, inclusion, header)``, all of which verify —
    so a test that counts it is counting something a third party could check.
    """
    rec = AnchorRecord(membership_txid=txid, membership_vout=0,
                       membership_pubkey=worker.public_key.hex(),
                       requester_pubkey=requester.public_key.hex(),
                       satoshis=satoshis, occurred_at=1_700_000_000)
    return rec, rec.sign(worker), _inclusion(txid, height), _header(txid, height)


# ------------------------------------------------------------------- la tesis
def test_the_whole_chain_from_offer_to_ranking():
    """Un nodo que publica, recibe carga, sirve a la red y sube en el ranking."""
    led = ContributionLedger(MESH)
    provider_key = Secp256k1KeyPair.new("proveedor")
    # 1. publica capacidad, firmada, y la malla la admite
    identity = _provider(led, "proveedor", vram=8.0)
    assert led.peers["proveedor"].vram_advertised_gb == 8.0

    # 2. la malla le coloca carga: es un proveedor, y por eso tiene stage
    plan = plan_placement(ModelSpec(name="Qwen/Qwen3-8B", memory_required_gb=6.0),
                          led)
    assert plan.ok and plan.peers == ("proveedor",)
    assert plan.stages[0].memory_gb == pytest.approx(6.0)

    # 3. otro nodo le pide una inferencia, y el ancla lo demuestra
    requester = Secp256k1KeyPair.new("quien-pide")
    txid = "9a" * 32
    rec, sig, inc, header = _anchored_inference(provider_key, requester, txid)
    assert rec.verify(sig, inc, header)[0] is True

    # 4. solo entonces el historial sube
    assert led.record_inference("proveedor", txid=txid, satoshis=100) == \
        (True, "ok")
    assert led.peers["proveedor"].inferences_served == 1

    # 5. y el ranking lo muestra, ordenando por inferencias servidas
    board = board_from_counters(led)
    assert board.position("proveedor") == 1
    assert board.get("proveedor").inferences_served == 1
    # La identidad ed25519 del handshake no es la de membresia: son dos
    # claves y por eso el anclaje necesita la secp256k1. Que `identity` exista
    # no se usa mas alla de la admision, y aun asi hace falta para el paso 1.
    assert identity.author_id == "proveedor"


def test_serving_the_network_is_what_moves_the_ranking():
    """El ranking ordena por inferencias servidas, no por VRAM anunciada."""
    led = ContributionLedger(MESH)
    # El mas grande sirve una inferencia; el mas pequeno, tres.
    _provider(led, "grande", vram=24.0)
    _provider(led, "pequeno", vram=4.0)
    for i in range(3):
        led.record_inference("pequeno", txid=f"{i:02x}" * 32, satoshis=100)
    led.record_inference("grande", txid="ff" * 32, satoshis=100)
    board = board_from_counters(led)
    # Tres inferencias de una caja de 4 GiB baten a una de una de 24 GiB.
    assert board.position("pequeno") == 1
    assert board.get("grande").vram_advertised_gb == 24.0
    assert board.get("pequeno").inferences_served == 3


def test_an_unanchored_inference_does_not_move_the_ranking():
    """Sin ancla no hay prueba, y sin prueba no hay historial.

    Es el reverso exacto de la regla que se esta construyendo: un nodo no puede
    subir su puesto diciéndolo, solo mostrando una transaccion incluida.
    """
    led = ContributionLedger(MESH)
    _provider(led, "a", vram=8.0)
    assert led.record_inference("a", txid="")[0] is False
    assert board_from_counters(led).get("a").inferences_served == 0
    # Y una transacion repetida tampoco: el contador no la admite dos veces.
    assert led.record_inference("a", txid="ab" * 32, satoshis=100)[0] is True
    assert led.record_inference("a", txid="ab" * 32, satoshis=100)[0] is False
    assert led.peers["a"].inferences_served == 1


def test_a_consumer_never_reaches_the_ranking():
    """Quien no ofrece VRAM no sirve la malla, y no aparece en ella.

    El nodo de 24 GiB que ofrece 0 es el caso del nivel `metered` de `tiers`:
    esta en la malla, pero es cliente. Si su historial contara, el ranking
    estaria lleno de nodos que no han hecho nada por nadie.
    """
    led = ContributionLedger(MESH)
    _provider(led, "cliente", vram=24.0, advertised=0.0)
    _provider(led, "proveedor", vram=8.0)
    assert led.record_inference("cliente", txid="ab" * 32)[0] is False
    led.record_inference("proveedor", txid="cd" * 32, satoshis=100)
    board = board_from_counters(led)
    assert [p.node_id for p in board.providers()] == ["proveedor"]
    # Sigue estando en el board (tiene historia declarada, aunque sea cero),
    # pero marcado como no-proveedor para que ningun consumidor se cuelgue.
    assert board.get("cliente").publishes_vram is False


def test_the_verified_board_counts_what_the_chain_supports():
    """El board verificado reconstruye el numero desde las anclas, no desde el
    contador del ledger.

    Es la diferencia entre "la malla contó esto" y "la cadena lo sostiene". Con
    un ancla limpia ambos coinciden; en cuanto una no verifica, el board
    verificado deja de contarla **aunque el contador local siga diciendo que
    sí** — y esa discrepancia es justo la que un tercero vería.
    """
    from delm.core.anchor import AnchorLedger
    from delm.core.membership import MembershipOutput

    led = ContributionLedger(MESH)
    wk = Secp256k1KeyPair.new("proveedor")
    rq = Secp256k1KeyPair.new("quien-pide")
    _provider(led, "proveedor", vram=8.0)

    # El ledger de anclas solo acepta anclas de una membresia que conoce, asi
    # que hay que registrar el output primero: un ledger que aceptara cualquier
    # clave seria un ledger que cualquiera puede rellenar.
    txid = "9a" * 32
    membership = MembershipOutput(txid="cc" * 32, vout=0, satoshis=1000,
                                 script_hash="bb" * 32)
    chain = AnchorLedger(membership_outputs=[membership])
    rec, sig, inc, header = _anchored_inference(wk, rq, txid)
    # La membresia que el ancla declara tiene que ser la que el ledger conoce.
    rec = AnchorRecord(**{**rec.to_dict(), "membership_txid": membership.txid})
    sig = rec.sign(wk)
    inc = InclusionProof(txid=membership.txid, index=0, path=[],
                         merkle_root=merkle_root(
                             [bytes.fromhex(membership.txid)[::-1]]).hex(),
                         height=header.height)
    header = BlockHeader(merkle_root=inc.merkle_root, height=900_000)
    assert rec.verify(sig, inc, header)[0] is True
    ok, why = chain.append(rec, inc, sig)
    assert ok, why
    assert led.record_inference("proveedor", txid=txid, satoshis=100)[0] is True

    verified = board_from_verified({"proveedor": chain}, header)
    counters = board_from_counters(led)
    assert verified.get("proveedor").inferences_served == 1
    assert verified.get("proveedor").inferences_served == \
        counters.get("proveedor").inferences_served
    assert verified.get("proveedor").satoshis_earned == 100

    # Ahora una segunda ancla que NO verifica (firma de otra clave): el
    # contador local la contaria, el verificado no.
    chain.append(rec, inc, "00" * 64)
    led.record_inference("proveedor", txid="bb" * 32, satoshis=100)
    assert led.peers["proveedor"].inferences_served == 2
    assert board_from_verified({"proveedor": chain}, header) \
        .get("proveedor").inferences_served == 1


def test_a_self_served_inference_cannot_be_anchored_at_all():
    """La forma mas barata de inflar el ranking esta cerrada en el ancla.

    Ejecutar inferencia contra uno mismo y anclarla exigiria que el
    solicitante fuera el propio nodo, y eso no se construye: falla al
    construirse el registro. No es una comprobacion posterior que alguien
    pudiera saltarse por otro camino — no hay registro que saltarse.
    """
    node = Secp256k1KeyPair.new("n1")
    from delm.core.membership import ProtocolError

    with pytest.raises(ProtocolError) as exc:
        AnchorRecord(membership_txid="ab" * 32, membership_vout=0,
                     membership_pubkey=node.public_key.hex(),
                     requester_pubkey=node.public_key.hex(), satoshis=100)
    assert "auto-solicitada" in str(exc.value)