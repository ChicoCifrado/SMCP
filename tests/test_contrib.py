"""Tests del intercambio de la malla (`delm.core.contrib`).

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
* **La inferencia se paga.** `MeteredLLMClient` con `FakeLLMClient`: sirve si hay
  crédito y se niega con `PermissionError` si no — el "a cambio" del intercambio,
  verificado de punta a punta contra el cliente real del proyecto.
* **Lo que NO se promete.** No hay atestación de hardware y el módulo lo dice;
  aquí se comprueba que una afirmación *firma pero falsa* se admite (es la
  limitación documentada, no un bug) mientras que una *sin firmar* no.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from delm.core.contrib import (
    CapacityReport,
    Challenge,
    ContribReject,
    ContributionLedger,
    ExchangePolicy,
    MeteredLLMClient,
)
from delm.core.llm import FakeLLMClient
from delm.core.provenance import KeyPair

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
          observe_s: float = 0.0, policy: ExchangePolicy | None = None,
          **kw) -> bool:
    """Full happy path: challenge → signed report → admit → observe."""
    key = key or KeyPair.new(peer_id)
    rep = make_report(led, key, peer_id, vram_gb=vram_gb, now=now, **kw)
    ok, _ = led.admit(rep, now=now)
    if ok and observe_s:
        led.observe(peer_id, now, dt_s=observe_s, policy=policy or ExchangePolicy())
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


# --------------------------------------------------------- crédito y vida
def test_credit_only_accrues_through_observe():
    led = ContributionLedger(MESH)
    policy = ExchangePolicy(credits_per_gib_hour=1.0, baseline_credits=0.0)
    admit(led, "a", 8.0, policy=policy)
    assert led.peers["a"].credits == 0.0     # admitir no es ganar crédito
    led.observe("a", NOW, dt_s=3600, policy=policy)
    assert led.peers["a"].credits == pytest.approx(8.0)
    assert led.peers["a"].alive is True


def test_credit_is_proportional_to_contributed_vram():
    led = ContributionLedger(MESH)
    policy = ExchangePolicy(credits_per_gib_hour=1.0, baseline_credits=0.0)
    admit(led, "chico", 4.0, policy=policy)
    admit(led, "grande", 16.0, policy=policy)
    led.observe("chico", NOW, dt_s=3600, policy=policy)
    led.observe("grande", NOW, dt_s=3600, policy=policy)
    assert led.peers["grande"].credits == 4 * led.peers["chico"].credits


def test_a_peer_that_leaves_stops_earning():
    led = ContributionLedger(MESH)
    policy = ExchangePolicy(credits_per_gib_hour=1.0)
    admit(led, "a", 8.0, policy=policy)
    led.observe("a", NOW, dt_s=3600, policy=policy)
    first = led.peers["a"].credits
    # Sin `observe` no hay acreditación: el reloj del mesh es la única fuente.
    led.observe("a", NOW + 10_000, dt_s=0.0, policy=policy)
    assert led.peers["a"].credits == first


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
    `peer_id` ajeno) cambiaría la clave del par y los créditos ya ganados
   seguirían a la nueva — es decir, robar el crédito de otro.
    """
    led = ContributionLedger(MESH)
    honest = KeyPair.new("a")
    admit(led, "a", 8.0, key=honest, policy=ExchangePolicy(), observe_s=3600)
    earned = led.peers["a"].credits

    impostor = KeyPair.new("impostor")
    rep = make_report(led, impostor, "a", vram_gb=999.0, now=NOW + 10)
    assert led.admit(rep, now=NOW + 10) == (False,
                                            ContribReject.PEER_KEY_CHANGED.value)
    peer = led.peers["a"]
    assert peer.vram_gb == 8.0 and peer.credits == earned
    assert peer.rejections == 1
    # El rechazo queda encadenado: es auditable que alguien lo intentó.
    assert led.records[-1].reason == ContribReject.PEER_KEY_CHANGED.value
    assert led.verify_chain() is True



def test_total_vram_counts_admitted_numbers_only():
    led = ContributionLedger(MESH)
    policy = ExchangePolicy()
    admit(led, "a", 8.0, policy=policy, observe_s=60)
    admit(led, "b", 16.0, policy=policy, observe_s=60)
    # Firmado pero nunca observado: cuenta como declarado, no como verificado.
    admit(led, "c", 64.0, policy=policy)
    assert led.total_vram_gb(observed_only=False) == pytest.approx(88.0)
    assert led.total_vram_gb(observed_only=True) == pytest.approx(24.0)


def test_admitted_peers_order_is_deterministic():
    led = ContributionLedger(MESH)
    for peer, vram in (("z", 8.0), ("a", 8.0), ("m", 16.0)):
        admit(led, peer, vram)
    assert [p.peer_id for p in led.admitted_peers()] == ["m", "a", "z"]


# ------------------------------------------------------------------ gasto
def test_spend_debits_and_refuses_when_short():
    led = ContributionLedger(MESH)
    policy = ExchangePolicy(baseline_credits=0.0)
    admit(led, "a", 8.0, policy=policy)
    led.observe("a", NOW, dt_s=3600, policy=policy)   # 8 créditos
    assert led.spend("a", 5.0, policy=policy) == (True, ContribReject.OK.value)
    assert led.peers["a"].credits_available == pytest.approx(3.0)
    assert led.spend("a", 5.0, policy=policy)[1] == \
        ContribReject.INSUFFICIENT_CREDIT.value
    # Un rechazo no descuenta (y nunca deja el saldo en negativo).
    assert led.peers["a"].credits_available == pytest.approx(3.0)


def test_spend_by_an_unknown_or_dead_peer_is_refused():
    led = ContributionLedger(MESH)
    policy = ExchangePolicy()
    admit(led, "a", 8.0, policy=policy)
    assert led.spend("fantasma", 1.0, policy=policy)[1] == \
        ContribReject.UNKNOWN_PEER.value
    # Admitido pero nunca observado: sin `observe` no hay acceso.
    assert led.spend("a", 1.0, policy=policy)[1] == \
        ContribReject.PEER_NOT_OBSERVED.value


def test_request_cost_has_a_floor_and_scales_with_tokens():
    policy = ExchangePolicy(credits_per_request=0.5, credits_per_ktoken=0.01)
    assert policy.request_cost() == pytest.approx(0.5)
    assert policy.request_cost(tokens_in=1000, tokens_out=2000) == \
        pytest.approx(0.5 + 0.03)
    # Tokens negativos no restan crédito.
    assert policy.request_cost(tokens_in=-10_000) == pytest.approx(0.5)


def test_entitlement_is_baseline_plus_earned():
    policy = ExchangePolicy(baseline_credits=1.5)
    led = ContributionLedger(MESH)
    admit(led, "a", 8.0, policy=policy)
    led.observe("a", NOW, dt_s=3600, policy=policy)
    assert policy.entitlement(led.peers["a"]) == pytest.approx(1.5 + 8.0)


# ------------------------------------------------- inferencia que se paga
@pytest.mark.asyncio
async def test_metered_client_serves_when_credited_and_refuses_when_not():
    led = ContributionLedger(MESH)
    policy = ExchangePolicy(baseline_credits=0.0)
    admit(led, "a", 8.0, policy=policy)
    led.observe("a", NOW, dt_s=3600, policy=policy)     # 8 créditos
    client = MeteredLLMClient(FakeLLMClient(), led, "a", policy)
    await client.complete("hola")
    assert client.served == 1
    assert led.peers["a"].credits_spent == pytest.approx(policy.request_cost())
    # Agotado el crédito: la inferencia se niega, no se sirve gratis.
    with pytest.raises(PermissionError) as exc:
        for _ in range(200):
            await client.complete("hola")
    assert client.refused > 0
    assert "sin crédito" in str(exc.value)
    assert led.peers["a"].credits_available == pytest.approx(0.0, abs=1e-9)


@pytest.mark.asyncio
async def test_metered_client_wraps_any_backend_without_changing_its_contract():
    led = ContributionLedger(MESH)
    policy = ExchangePolicy()
    admit(led, "a", 8.0, policy=policy)
    led.observe("a", NOW, dt_s=3600, policy=policy)
    inner = FakeLLMClient()
    client = MeteredLLMClient(inner, led, "a", policy)
    out = await client.complete("¿qué es SMCP?")
    assert isinstance(out, str) and out
    stats = client.stats()
    assert stats["served"] == 1 and stats["refused"] == 0
    assert stats["log"][0]["ok"] is True
    assert stats["entitlement"] > 0


# --------------------------------------------------------- persistencia
def test_ledger_roundtrips_through_a_file(tmp_path):
    led = ContributionLedger(MESH)
    policy = ExchangePolicy()
    reports = {"a": make_report(led, KeyPair.new("a"), "a", vram_gb=8.0)}
    led.admit(reports["a"], now=NOW)
    led.observe("a", NOW, dt_s=1800, policy=policy)
    admit(led, "b", 16.0, policy=policy, observe_s=900)
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


def test_state_digest_changes_when_balances_change():
    led = ContributionLedger(MESH)
    policy = ExchangePolicy(baseline_credits=0.0)
    admit(led, "a", 8.0, policy=policy)
    first = led.state_digest()
    led.observe("a", NOW, dt_s=3600, policy=policy)
    assert led.state_digest() != first


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



# ==================================================================
# El cobro va antes, pero `served` solo cuenta lo servido (P2)
# ==================================================================
# `MeteredLLMClient` debita el credito ANTES del `await`: es lo que impide
# que un par sin credito gaste GPU ajena. El coste de ese orden es que un
# endpoint caido tambien se cobra. Estos tests fijan la otra mitad — que el
# fallo quede REGISTRADO como fallo, no como inferencia servida.
#
# El caso end-to-end contra un endpoint real vive en
# `tests/test_meshllm_thesis.py` (opt-in, `slow`). Aqui va la version
# offline, con un doble que falla, para que CI lo vea siempre.


class _FailingInner:
    """Un backend que falla, como lo haria un endpoint caido."""

    async def complete(self, *a, **k):
        raise RuntimeError("endpoint caido")


class _ExplodingInner:
    """Falla ruidosamente si alguien lo llama: aqui no debe llamarse nunca."""

    async def complete(self, *a, **k):
        raise AssertionError("el modelo no debe llamarse sin credito")


def _credited(peer: str, *, vram: float = 8.0, observe_s: float = 1800.0,
              policy: ExchangePolicy | None = None) -> tuple:
    """Ledger con un par admitido, observado y con credito. -> (led, pol, id)."""
    led = ContributionLedger(MESH)
    key = KeyPair.new(peer)
    pol = policy or ExchangePolicy(credits_per_gib_hour=10.0,
                                   baseline_credits=0.0)
    assert admit(led, peer, vram, key=key, now=NOW, observe_s=observe_s,
                 policy=pol), "el par debe admitirse y ganar credito"
    assert led.peers[peer].credits_available > 0.0
    return led, pol, peer


@pytest.mark.asyncio
async def test_served_is_not_incremented_when_inference_fails():
    """Un endpoint caido no puede contar como inferencia servida.

    Antes de P2: `served += 1` ocurria ANTES del `await`, asi que un 404 o
    un timeout contaba como servicio y el log decia `ok: True` de una
    inferencia que nunca existio. El credito, ademas, ya estaba debitado.
    """
    led, pol, peer = _credited("p2-falla")
    client = MeteredLLMClient(_FailingInner(), led, peer, pol)

    with pytest.raises(RuntimeError):
        await client.complete("hola", tokens_in=100, tokens_out=100)

    assert client.served == 0, "un fallo de inferencia no es un servicio"
    assert client.failed == 1
    # el log se corrige: la entrada paso de cobro-aceptado a fallo
    assert client.log[-1]["ok"] is False
    assert "inference_failed" in client.log[-1]["reason"]
    # y el credito se cobro igualmente: el orden es deliberado
    assert led.peers[peer].credits_spent > 0.0


@pytest.mark.asyncio
async def test_refused_and_failed_are_distinct_outcomes():
    """Rechazado por credito != cobrado y fallo de inferencia.

    Un par sin credito nunca llega al modelo (`failed` no se toca); uno con
    credito cuyo endpoint cae si lo hace. Confundirlos haria parecer que se
    intento servir algo que se rechazo de entrada.
    """
    # (a) sin credito -> refused, failed == 0, el modelo no se toca
    led = ContributionLedger(MESH)
    key = KeyPair.new("p2-sin-credito")
    strict = ExchangePolicy(baseline_credits=0.0, credits_per_gib_hour=0.0)
    assert admit(led, "n1", 8.0, key=key, now=NOW, observe_s=0.0,
                 policy=strict)
    assert led.peers["n1"].credits_available == 0.0
    without = MeteredLLMClient(_ExplodingInner(), led, "n1", strict)
    with pytest.raises(PermissionError):
        await without.complete("x", tokens_in=1000, tokens_out=1000)
    assert without.refused == 1
    assert without.served == 0 and without.failed == 0

    # (b) con credito, endpoint caido -> failed, refused == 0
    led2, pol2, peer2 = _credited("p2-con-credito")
    failing = MeteredLLMClient(_FailingInner(), led2, peer2, pol2)
    with pytest.raises(RuntimeError):
        await failing.complete("x", tokens_in=100, tokens_out=100)
    assert failing.failed == 1
    assert failing.refused == 0 and failing.served == 0


@pytest.mark.asyncio
async def test_successful_inference_still_counts_and_does_not_touch_failed():
    """El camino feliz no cambia: `served` sube, `failed` no se toca."""
    led, pol, peer = _credited("p2-feliz")
    client = MeteredLLMClient(FakeLLMClient(), led, peer, pol)
    out = await client.complete("hola", tokens_in=10, tokens_out=10)
    assert isinstance(out, str)
    assert client.served == 1
    assert client.failed == 0 and client.refused == 0
    assert client.log[-1]["ok"] is True


@pytest.mark.asyncio
async def test_stats_exposes_the_three_outcomes():
    """`stats()` distingue servida / rechazada / fallida.

    `served + failed` es lo que se cobro de verdad (el cobro va antes);
    `served` es lo que se recibio. La diferencia es responsabilidad del
    endpoint, y tiene que ser visible sin abrir el log a mano.
    """
    led, pol, peer = _credited("p2-stats")
    client = MeteredLLMClient(FakeLLMClient(), led, peer, pol)
    await client.complete("hola", tokens_in=10, tokens_out=10)
    st = client.stats()
    assert st["served"] == 1
    assert st["failed"] == 0 and st["refused"] == 0
    assert "failed" in st
