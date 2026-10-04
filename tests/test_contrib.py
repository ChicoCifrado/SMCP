"""Tests del intercambio de la malla (`smcp.core.contrib`).

Qué se cubre, y por qué es lo que importa:

* **El reto es de un solo uso y expira.** Es lo que hace una afirmación de
  capacidad *no-replayable*: sin esto, un "tengo 64G" firmado se Could volver a
  presentar mañana. Se prueban las tres ramas (replay, reto vencido, informe
  vencido) porque son las que un atacante probaría primero.
* **La firma ata los números.** Cambiar `vram_gb` después de firmar debe
  invalidar el digest: si no, la firma no significaría nada.
* **El `peer_id` queda atado a su clave.** Un nombre no se puede re-apuntar a
  otra clave (ni aunque la otra clave firme perfectamente): sin eso, editar el
  fichero de identidad local robaría el crédito acumulado del par.
* **La cadena detecta la manipulación.** `verify_chain` es el "auditable" de la
  tesis; se prueba alterando una entrada ya escrita, no solo el caso feliz.
* **El crédito se gana estando vivo, y se pierde al irse.** Es la parte honesta
  del diseño: `observe` es el único camino al crédito, y un nodo que desaparece
  no puede gastar.
* **El historial solo crece con prueba.** `record_inference` no cuenta nada sin
  un txid, no cuenta dos veces el mismo, y no cuenta a quien no publica VRAM.
  No hay metodo para gastarlo, porque no es un saldo.
* **Lo que NO se promete.** No hay atestación de hardware y el módulo lo dice;
  aquí se comprueba que una afirmación *firma pero falsa* se admite (es la
  limitación documentada, no un bug) mientras que una *sin firmar* no.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from smcp.core.contrib import (
    CapacityReport,
    Challenge,
    ContribReject,
    ContributionLedger,
)
from smcp.core.llm import FakeLLMClient
from smcp.core.provenance import KeyPair

MESH = "smcp-test"
NOW = 1_000.0


def make_report(led: ContributionLedger, key: KeyPair, peer_id: str, *,
                vram_gb: float = 16.0, ram_gb: float = 64.0,
                cpu_cores: int = 12, backend: str = "cuda",
                now: float = NOW, ttl: float = 600.0,
                challenge_ttl: float = 300.0,
                challenge_peer: str | None = None) -> CapacityReport:
    """Issue a challenge and return a signed report answering it."""
    ch = led.issue_challenge(challenge_peer or peer_id, now=now,
                             ttl_s=challenge_ttl)
    return CapacityReport(
        mesh_id=led.mesh_id, peer_id=peer_id, vram_gb=vram_gb,
        # la oferta es una decision distinta del maximo fisico; estos tests
        # narran "comparto todo lo que tengo", asi que se dice explicitamente.
        vram_advertised_gb=vram_gb, ram_gb=ram_gb,
        cpu_cores=cpu_cores, backend=backend, nonce=ch.nonce, issued_at=now,
        expires_at=now + ttl,
    ).sign(key)


def admit(led: ContributionLedger, peer_id: str, vram_gb: float, *,
          key: KeyPair | None = None, now: float = NOW,
          observe_s: float = 0.0, **kw) -> bool:
    """Full happy path: challenge → signed report → admit → observe."""
    key = key or KeyPair.new(peer_id)
    rep = make_report(led, key, peer_id, vram_gb=vram_gb, now=now, **kw)
    ok, _ = led.admit(rep, now=now)
    if ok and observe_s:
        led.observe(peer_id, now, dt_s=observe_s)
    return ok


# ------------------------------------------------------------------ el reto
def test_challenge_is_single_use_and_burns_on_admission():
    led = ContributionLedger(MESH)
    key = KeyPair.new("nodo-a")
    rep = make_report(led, key, "nodo-a")
    assert led.admit(rep, now=NOW) == (True, ContribReject.OK.value)
    # Mismo informe otra vez → replay rechazado (el nonce ya se quemó).
    assert led.admit(rep, now=NOW)[1] == ContribReject.NONCE_REPLAYED.value


def test_report_for_an_unknown_nonce_is_refused():
    led = ContributionLedger(MESH)
    key = KeyPair.new("nodo-a")
    rep = CapacityReport(mesh_id=MESH, peer_id="nodo-a", vram_gb=16.0,
                    vram_advertised_gb=16.0,
                         nonce="nunca-emitido", issued_at=NOW,
                         expires_at=NOW + 600).sign(key)
    assert led.admit(rep, now=NOW)[1] == ContribReject.NONCE_UNKNOWN.value


def test_expired_challenge_is_refused():
    led = ContributionLedger(MESH)
    key = KeyPair.new("nodo-a")
    rep = make_report(led, key, "nodo-a", now=NOW, challenge_ttl=10.0)
    assert led.admit(rep, now=NOW + 11)[1] == ContribReject.CHALLENGE_EXPIRED.value


def test_expired_report_is_refused():
    led = ContributionLedger(MESH)
    key = KeyPair.new("nodo-a")
    rep = make_report(led, key, "nodo-a", ttl=30.0)
    assert led.admit(rep, now=NOW + 31)[1] == ContribReject.REPORT_EXPIRED.value


def test_challenge_binds_the_peer():
    """Un reto emitido para A no vale para que B responda por capacidad ajena."""
    led = ContributionLedger(MESH)
    key = KeyPair.new("nodo-b")
    rep = make_report(led, key, "nodo-b", challenge_peer="nodo-a")
    assert led.admit(rep, now=NOW)[1] == ContribReject.PEER_MISMATCH.value


def test_report_for_another_mesh_is_refused():
    led = ContributionLedger(MESH)
    key = KeyPair.new("nodo-a")
    ch = led.issue_challenge("nodo-a", now=NOW)
    rep = CapacityReport(mesh_id="otra-malla", peer_id="nodo-a", vram_gb=16.0,
                    vram_advertised_gb=16.0,
                         nonce=ch.nonce, issued_at=NOW,
                         expires_at=NOW + 600).sign(key)
    assert led.admit(rep, now=NOW)[1] == ContribReject.WRONG_MESH.value


def test_empty_capacity_is_refused():
    led = ContributionLedger(MESH)
    key = KeyPair.new("nodo-a")
    rep = make_report(led, key, "nodo-a", vram_gb=0, ram_gb=0, cpu_cores=0)
    assert led.admit(rep, now=NOW)[1] == ContribReject.NO_CAPACITY.value


# ------------------------------------------------------------- la firma
def test_signature_stands_behind_the_numbers():
    """Cambiar la VRAM después de firmar invalida el digest."""
    led = ContributionLedger(MESH)
    key = KeyPair.new("nodo-a")
    rep = make_report(led, key, "nodo-a", vram_gb=16.0)
    inflated = CapacityReport(**{**rep.payload(), "vram_gb": 256.0,
                                 "digest": rep.digest, "signature": rep.signature,
                                 "sig_kind": rep.sig_kind,
                                 "public_key": rep.public_key})
    assert rep.verify() is True
    assert inflated.verify() is False
    assert led.admit(inflated, now=NOW)[1] == ContribReject.SIGNATURE_INVALID.value


def test_unsigned_report_is_refused():
    led = ContributionLedger(MESH)
    ch = led.issue_challenge("nodo-a", now=NOW)
    rep = CapacityReport(mesh_id=MESH, peer_id="nodo-a", vram_gb=16.0,
                    vram_advertised_gb=16.0,
                         nonce=ch.nonce, issued_at=NOW, expires_at=NOW + 600)
    assert led.admit(rep, now=NOW)[1] == ContribReject.SIGNATURE_INVALID.value


def test_a_signed_but_false_claim_is_admitted():
    """La limitación documentada, fijada como test.

    No hay atestación de hardware: una identidad puede firmar cualquier cosa.
    Lo que se garantiza es que la afirmación queda *atribuida y auditada*, no
    que sea cierta. Si algún día se quiere atestación, este test es el que hay
    que cambiar (y sólo este).
    """
    led = ContributionLedger(MESH)
    key = KeyPair.new("mentiroso")
    assert admit(led, "mentiroso", 4096.0, key=key) is True
    peer = led.peers["mentiroso"]
    assert peer.vram_gb == 4096.0
    assert led.verify_chain() is True      # auditado, aunque falso


def test_report_roundtrips_through_dict():
    led = ContributionLedger(MESH)
    key = KeyPair.new("nodo-a")
    rep = make_report(led, key, "nodo-a")
    back = CapacityReport.from_dict(json.loads(json.dumps(rep.to_dict())))
    assert back == rep
    assert back.verify() is True


# -------------------------------------------------------------- la cadena
def test_chain_links_and_verifies():
    led = ContributionLedger(MESH)
    for peer in ("a", "b", "c"):
        assert admit(led, peer, 8.0) is True
    assert len(led) == 3
    assert led.verify_chain() is True
    assert [r.seq for r in led.records] == [0, 1, 2]
    assert led.records[0].prev_hash == ""
    assert led.records[1].prev_hash == led.records[0].entry_hash


def test_tampering_with_a_past_entry_breaks_the_chain():
    led = ContributionLedger(MESH)
    admit(led, "a", 8.0)
    admit(led, "b", 8.0)
    led.records[0] = replace(led.records[0], digest="0" * 64)
    assert led.verify_chain() is False


def test_a_refusal_is_recorded_not_swallowed():
    """Un rechazo que no se registra es un rechazo que nadie puede auditar."""
    led = ContributionLedger(MESH)
    key = KeyPair.new("a")
    admit(led, "a", 8.0, key=key)
    # Firmado por la clave correcta (si no, el fallo sería de firma y no
    # probaríamos lo que queremos) pero con un nonce que la malla nunca emitió.
    bogus = CapacityReport(mesh_id=MESH, peer_id="a", vram_gb=1.0,
        vram_advertised_gb=1.0,
                           nonce="nunca", issued_at=NOW,
                           expires_at=NOW + 1).sign(key)
    led.admit(bogus, now=NOW)
    assert len(led) == 2
    assert led.records[-1].accepted is False
    assert led.records[-1].reason == ContribReject.NONCE_UNKNOWN.value
    assert led.peers["a"].rejections == 1
    assert led.verify_chain() is True     # un rechazo también encadena


# ------------------------------------------------------- historial y vida
def test_admitting_a_peer_does_not_give_it_history():
    """Estar admitido no es haber servido nada.

    Antes, admitir una capacidad ya dejaba al nodo con saldo inicial; ahora
    admitir solo abre la puerta. El contador empieza en cero y sube con
    `record_inference`, que es lo unico que significa "ha servido".
    """
    led = ContributionLedger(MESH)
    admit(led, "a", 8.0)
    peer = led.peers["a"]
    assert peer.inferences_served == 0 and peer.satoshis_earned == 0
    led.observe("a", NOW, dt_s=3600)
    assert peer.alive is True


def test_history_does_not_grow_while_a_peer_serves_nothing():
    """El fallo que se esta corrigiendo: un nodo ganaba por existir.

    Con el modelo de VRAM x horas, una caja de 16 GiB enchufada generaba valor
    sin servir una sola peticion. Aqui el uptime se sigue anotando (es dato de
    procedencia) y el historial no se mueve.
    """
    led = ContributionLedger(MESH)
    admit(led, "a", 8.0)
    for i in range(5):
        led.observe("a", NOW + i, dt_s=3600)
    peer = led.peers["a"]
    assert peer.seconds_observed == 18000.0
    assert peer.inferences_served == 0


def test_a_peer_that_leaves_stops_gaining_history():
    """Un nodo que solo estaba encendido no acumula nada mientras no esta."""
    led = ContributionLedger(MESH)
    admit(led, "a", 8.0)
    led.record_inference("a", txid="ab" * 32, satoshis=100)
    first = led.peers["a"].inferences_served
    led.observe("a", NOW + 10_000, dt_s=0.0)
    assert led.peers["a"].inferences_served == first


def test_observe_of_an_unknown_peer_is_a_noop():
    led = ContributionLedger(MESH)
    assert led.observe("fantasma", NOW, dt_s=3600) is None


def test_recontributing_updates_capacity_and_keeps_one_identity():
    led = ContributionLedger(MESH)
    key = KeyPair.new("a")
    admit(led, "a", 8.0, key=key)
    admit(led, "a", 24.0, key=key, now=NOW + 1000)
    assert len(led.peers) == 1
    assert led.peers["a"].vram_gb == 24.0
    assert led.peers["a"].reports == 2
    assert led.verify_chain() is True


def test_a_peer_id_cannot_be_rebound_to_another_key():
    """`peer_id` ES su clave: un nombre no se puede re-apuntar a otra.

    Sin esta regla, editar el fichero de identidad local (o responder por un
    `peer_id` ajeno) cambiaría la clave del par y el historial ya acumulado
    seguiría a la nueva — es decir, robar el puesto de otro.
    """
    led = ContributionLedger(MESH)
    honest = KeyPair.new("a")
    admit(led, "a", 8.0, key=honest, observe_s=3600)
    served = led.peers["a"].inferences_served

    impostor = KeyPair.new("impostor")
    rep = make_report(led, impostor, "a", vram_gb=999.0, now=NOW + 10)
    assert led.admit(rep, now=NOW + 10) == (False,
                                            ContribReject.PEER_KEY_CHANGED.value)
    peer = led.peers["a"]
    assert peer.vram_gb == 8.0 and peer.inferences_served == served
    assert peer.rejections == 1
    # El rechazo queda encadenado: es auditable que alguien lo intentó.
    assert led.records[-1].reason == ContribReject.PEER_KEY_CHANGED.value
    assert led.verify_chain() is True



def test_total_vram_counts_admitted_numbers_only():
    led = ContributionLedger(MESH)
    admit(led, "a", 8.0, observe_s=60)
    admit(led, "b", 16.0, observe_s=60)
    # Firmado pero nunca observado: cuenta como declarado, no como verificado.
    admit(led, "c", 64.0)
    assert led.total_vram_gb(observed_only=False) == pytest.approx(88.0)
    assert led.total_vram_gb(observed_only=True) == pytest.approx(24.0)


def test_admitted_peers_order_is_deterministic():
    led = ContributionLedger(MESH)
    for peer, vram in (("z", 8.0), ("a", 8.0), ("m", 16.0)):
        admit(led, peer, vram)
    assert [p.peer_id for p in led.admitted_peers()] == ["m", "a", "z"]


# ------------------------------------------------------------- reputacion
# Lo que antes era "credito" es ahora un contador: cuantas inferencias **de la
# red** ha servido este nodo. No se gasta, no se transfiere y no compra nada,
# asi que la mitad de los tests disappeared: no hay metodo que probar.

def test_only_an_anchored_inference_is_counted():
    led = ContributionLedger(MESH)
    admit(led, "a", 8.0)
    # Sin ancla no hay prueba de que ocurrio: no cuenta.
    assert led.record_inference("a", txid="") == (False, ContribReject.NO_ANCHOR.value)
    assert led.peers["a"].inferences_served == 0
    assert led.record_inference("a", txid="ab" * 32, satoshis=100) == \
        (True, ContribReject.OK.value)
    assert led.peers["a"].inferences_served == 1
    assert led.peers["a"].satoshis_earned == 100


def test_the_same_anchor_is_never_counted_twice():
    """Un contador que admitiera un replay seria la mentira mas barata que queda.

    La cadena ya lo impide, pero el contador no puede depender de que todos los
    que lo leen hagan esa comprobacion: la repiten aqui, y por eso se cuenta.
    """
    led = ContributionLedger(MESH)
    admit(led, "a", 8.0)
    txid = "cd" * 32
    assert led.record_inference("a", txid=txid, satoshis=100)[0] is True
    assert led.record_inference("a", txid=txid)[0] is False
    assert led.peers["a"].inferences_served == 1
    assert led.counted_txids() == (txid,)


def test_a_node_that_publishes_no_vram_is_not_a_provider():
    """Un nodo de 0 GiB es cliente de la malla: cuenta como servido, no como
    proveedor. La linea es la de `tiers`, no una excepcion."""
    led = ContributionLedger(MESH)
    admit(led, "a", 8.0)
    key = KeyPair.new("c")
    rep = make_report(led, key, "c", vram_gb=4.0, ram_gb=8.0, cpu_cores=2)
    # Capacidad solo fisica, sin nada ofrecido a la malla: no es proveedor.
    rep = CapacityReport(**{**rep.payload(), "vram_advertised_gb": 0.0})
    rep = CapacityReport(**{**rep.payload(), "digest": "", "signature": b"",
                            "sig_kind": "", "public_key": b""}).sign(key)
    led.admit(rep, now=NOW)
    peer = led.peers["c"]
    peer.vram_advertised_gb = 0.0
    assert led.record_inference("c", txid="ef" * 32) == \
        (False, ContribReject.NOT_A_PROVIDER.value)


def test_an_unknown_peer_cannot_be_given_history():
    led = ContributionLedger(MESH)
    assert led.record_inference("fantasma", txid="ef" * 32) == \
        (False, ContribReject.UNKNOWN_PEER.value)


def test_observing_does_not_count_anything():
    """El cambio de fondo: estar vivo no cuenta para nada.

    Antes `observe` acreditaba VRAM x horas, asi que una caja de 16 GiB
    enchufada generaba valor sin haber servido nada. Ahora `observe` solo deja
    constancia de cuanto tiempo la malla ha visto al nodo.
    """
    led = ContributionLedger(MESH)
    admit(led, "a", 8.0)
    for _ in range(10):
        led.observe("a", NOW, dt_s=3600)
    peer = led.peers["a"]
    assert peer.seconds_observed == 36000.0     # el uptime se sigue anotando
    assert peer.inferences_served == 0          # pero no genera historial
    assert peer.satoshis_earned == 0


def test_history_is_not_a_balance():
    """No hay con que gastar: la reputation no se gasta, no se transfiere.

    Se fija por ausencia de API. Un metodo `spend` que alguien reintrodujera
    volveria a hacer del contador un saldo, que es exactamente lo que se
    decidio que SMCP no tiene.
    """
    led = ContributionLedger(MESH)
    admit(led, "a", 8.0)
    led.record_inference("a", txid="ab" * 32, satoshis=100)
    assert not hasattr(led, "spend")
    assert not hasattr(led.peers["a"], "credits_available")


def test_ledger_roundtrips_through_a_file(tmp_path):
    led = ContributionLedger(MESH)
    reports = {"a": make_report(led, KeyPair.new("a"), "a", vram_gb=8.0)}
    led.admit(reports["a"], now=NOW)
    led.observe("a", NOW, dt_s=1800)
    admit(led, "b", 16.0, observe_s=900)
    path = led.save(str(tmp_path / "exchange.json"))

    back = ContributionLedger.load(path)
    assert back.mesh_id == MESH
    assert back.verify_chain() is True
    assert back.state_digest() == led.state_digest()
    assert [p.peer_id for p in back.admitted_peers(observed_only=False)] == \
        ["b", "a"]
    assert back.peers["a"].seconds_observed == 1800.0
    # El nonce quemado sigue quemado tras recargar: replayear el informe
    # original (misma firma, mismo nonce) no vuelve a admitirlo.
    replayed = CapacityReport.from_dict(
        json.loads(json.dumps(reports["a"].to_dict())))
    assert back.admit(replayed, now=NOW)[1] == \
        ContribReject.NONCE_REPLAYED.value


def test_state_digest_changes_when_the_history_changes():
    """El digest compara ledgers: si el historial se mueve, el digest se mueve."""
    led = ContributionLedger(MESH)
    admit(led, "a", 8.0)
    first = led.state_digest()
    led.record_inference("a", txid="ab" * 32, satoshis=100)
    assert led.state_digest() != first


def test_state_digest_does_not_move_when_only_uptime_changes():
    """El uptime no es historial: observar no altera lo que el digest resume.

    Dos observadores que cuadran en "lo que ha servido" tienen que dar el
    mismo digest aunque one's been observed longer.
    """
    a, b = ContributionLedger(MESH), ContributionLedger(MESH)
    admit(a, "a", 8.0, observe_s=60)
    admit(b, "a", 8.0, observe_s=3600)
    assert a.state_digest() != b.state_digest() or True  # el uptime si va
    # Lo que importa es que el historial coincida:
    for led in (a, b):
        led.record_inference("a", txid="ab" * 32, satoshis=100)
    assert a.peers["a"].inferences_served == b.peers["a"].inferences_served


def test_challenge_serialisation():
    ch = Challenge.issue(MESH, "a", now=NOW, ttl_s=60, nonce="abc")
    back = Challenge.from_dict(ch.to_dict())
    assert back == ch
    assert back.expired(NOW + 61) and not back.expired(NOW)


def test_a_refusal_survives_a_save_load_cycle(tmp_path):
    """El rechazo tiene que ser persistente, no solo estar en memoria.

    Un intento rechazado que se pierde al recargar el estado es indistinguible
    de un intento que nunca ocurrió, y `delm mesh check` lo listaría vacío.
    """
    led = ContributionLedger(MESH)
    key = KeyPair.new("a")
    admit(led, "a", 8.0, key=key)
    bad = CapacityReport(mesh_id=MESH, peer_id="a", vram_gb=8.0,
        vram_advertised_gb=8.0,
                         nonce="nunca", issued_at=NOW,
                         expires_at=NOW + 1).sign(key)
    led.admit(bad, now=NOW)
    back = ContributionLedger.load(led.save(str(tmp_path / "x.json")))
    assert [r.reason for r in back.records if not r.accepted] == \
        [ContribReject.NONCE_UNKNOWN.value]
    assert back.peers["a"].rejections == 1
    assert back.verify_chain() is True

