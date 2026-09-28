"""La tesis del intercambio, encadenada de punta a punta (P2).

Por qué este archivo existe: hay 32 tests de `contrib` y 22 de `placement`, y
todos prueban **piezas**. Ninguno prueba la afirmación que el proyecto
sostiene, que es una afirmación sobre la **secuencia**:

    contribuir capacidad  ->  ganar crédito por estar vivo  ->  que el
    planner coloque el modelo ahí  ->  que la inferencia se sirva solo si ese
    crédito se puede gastar.

Esa cadena es lo que distingue "tengo 32 tests verdes" de "el intercambio
funciona". Los tests por pieza pasan los tres aunque el cuarto paso este roto:
pueden estar midiendo un ledger que nunca se consulta, o un planner que
devuelve un plan que nadie usa para cobrar.

Qué NO es este test (y por qué importa decirlo):

* **No es una atestación de hardware.** Las cifras de VRAM son *afirmaciones
  firmadas*. El propio módulo lo dice y `test_contrib.py` lo cubre: una
  afirmación firmada pero falsa se admite. Este test no intenta cerrar esa
  laguna porque no es un bug, es el límite documentado del diseño. Lo que
  sí comprueba es que la **firma** ate los números a lo largo de toda la
  cadena: si alguien manipula la capacidad *después* de admitirla, el
  planner debe dejar de ver esa capacidad.
* **No prueba que exista un nodo real.** `FakeLLMClient` es un doble
  determinista. Lo que se prueba es la *mediación* (que el crédito decide si
  la inferencia se sirve), no la capacidad del modelo.
* **No toca red.** `test_meshllm_wiring.py` cubre el cliente contra un
  endpoint real y se skipea si no lo hay. Este es su complemento offline: la
  economía del intercambio sin depender de que haya una malla encendida.
"""

from __future__ import annotations

import asyncio

import pytest

from delm.core.contrib import (
    ContributionLedger,
    ExchangePolicy,
    MeteredLLMClient,
)
from delm.core.llm import FakeLLMClient
from delm.core.placement import ModelSpec, plan_placement
from delm.core.provenance import KeyPair

MESH = "smcp-thesis"
NOW = 1_000.0


# --------------------------------------------------------------- helpers
#: Politica estricta: sin `baseline_credits`. El default (1.0) es una
#: bienvenida para que la malla sea usable antes de acumular, pero para probar
#: que **la observacion** es lo que abre el grifo, el baseline la enmascara.
STRICT = ExchangePolicy(baseline_credits=0.0)


def admit_and_earn(led: ContributionLedger, peer_id: str, vram_gb: float, *,
                   observe_s: float, key: KeyPair | None = None,
                   now: float = NOW, policy: ExchangePolicy | None = None,
                   ) -> KeyPair:
    """La vía completa de un par: reto → informe firmado → admitir → observar.

    Devuelve la `KeyPair` para que el test pueda alterar la afirmación DESPUÉS
    (que es la mitad atacar del test de manipulación).
    """
    key = key or KeyPair.new(peer_id)
    policy = policy or ExchangePolicy()
    ch = led.issue_challenge(peer_id, now=now, ttl_s=300.0)
    from delm.core.contrib import CapacityReport

    rep = CapacityReport(
        mesh_id=led.mesh_id, peer_id=peer_id, vram_gb=vram_gb, ram_gb=64.0,
        cpu_cores=12, backend="cuda", nonce=ch.nonce, issued_at=now,
        expires_at=now + 600.0,
    ).sign(key)
    ok, reason = led.admit(rep, now=now)
    assert ok, f"admit debería aceptar un informe firmado: {reason}"
    # El crédito SOLO se gana por `observe`; sin esto el par está admitido
    # pero no ha ganado nada, que es el caso que el planner debe rechazar.
    led.observe(peer_id, now, dt_s=observe_s, policy=policy)
    return key


def spec(gb: float, **kw) -> ModelSpec:
    return ModelSpec(name="Qwen/Qwen3-32B", memory_required_gb=gb,
                     n_layers=64, quant="Q4_K_M", fit_level="good",
                     estimated_tps=12.0, **kw)


# ------------------------------------------------------- la tesis, completa
def test_contribute_earn_place_and_pay_is_one_chain():
    """Un par contribuye, gana crédito, recibe el plan, y paga la inferencia.

    Este es el test que justifica el diseño. Los otros comprueban que cada
    pieza funciona; este comprueba que **encajan**.
    """
    led = ContributionLedger(MESH)
    policy = STRICT
    # 2 pares de 8G, los dos observados 60s: nobody contributes and nobody
    # is idle, porque el crédito se gana con `observe`.
    admit_and_earn(led, "n1", 8.0, observe_s=1800.0, policy=policy)
    admit_and_earn(led, "n2", 8.0, observe_s=1800.0, policy=policy)

    # (1) El planner SI coloca: 12G deben repartirse entre los dos 8G.
    plan = plan_placement(spec(12.0), led, policy=policy)
    assert plan.ok, f"con 16G admitidos y crédito, el plan debe ser OK: {plan.reason}"
    assert len(plan.stages) == 2, "12G no caben en un solo nodo de 8G: debe repartir"
    assert {s.peer_id for s in plan.stages} == {"n1", "n2"}

    # (2) La inferencia se SIRVE, y se cobra. Esto es lo que conecta el plan
    # con el gasto: el mismo ledger que colocó el modelo es el que debita.
    metered = MeteredLLMClient(FakeLLMClient(), led, peer_id="n1",
                               policy=policy)
    before = led.peers["n1"].credits_available
    out = asyncio.run(metered.complete("verifica este contexto compartido"))
    assert out, "con crédito debe servir la inferencia"
    after = led.peers["n1"].credits_available
    assert after < before, "servir debe debitar crédito del par que se sirvió"
    assert abs((before - after) - policy.request_cost()) < 1e-6, (
        "el débito debe ser exactamente el coste de la petición")


def test_credit_is_the_thing_that_unlocks_the_plan_not_the_claim():
    """La tesis, contraprueba: la **afirmación** sola no da plan.

    Un par admite y firma 64G, pero nunca se observa. Su capacidad es real
    en el ledger (`admitted_peers` lo ve) y aun así el planner debe negarse:
    el intercambio es "a cambio" de presencia, no de marketing. Esto separa
    las dos mitades del diseño y prueba que `require_credit` significa algo.
    """
    led = ContributionLedger(MESH)
    policy = STRICT
    # Admitido, firmado, 64G — pero `observe_s=0`: jamás visto.
    admit_and_earn(led, "ghost", 64.0, observe_s=0.0, policy=policy)

    # La capacidad está admitida…
    assert any(p.peer_id == "ghost" for p in led.admitted_peers(observed_only=False))
    # …pero no observada, así que no hay plan: el planner exige presencia.
    plan = plan_placement(spec(8.0), led, policy=policy)
    assert not plan.ok, (
        "un par que nunca se observó no puede dar garantias de capacidad: "
        "el plan debe rechazarse aunque la capacidad esté admitida")
    assert plan.reason, "un rechazo debe nombrar su motivo"


def test_manipulating_capacity_after_admission_changes_the_plan():
    """La mitad atacar: alterar los números después de que se admitieron.

    La firma ata los números *en el informe*. Si un par pudiera reescribir su
    capacidad en el ledger local después de admitirla, se llevaría el plan
    entero. Este test comprueba que la manipulación no cambia lo que el planner
    ve: el ledger guarda lo que se firmó, no lo que se le dice después.
    """
    led = ContributionLedger(MESH)
    policy = STRICT
    key = admit_and_earn(led, "n1", 8.0, observe_s=1800.0, policy=policy)

    plan_ok = plan_placement(spec(8.0), led, policy=policy)
    assert plan_ok.ok, "8G de un par de 8G caben justo"

    # Intento: reescribir la capacidad del par a 64G en el ledger, sin
    # volver a pasar por `admit` (que exigiría un reto nuevo firmado).
    led.peers["n1"].vram_gb = 64.0

    plan_after = plan_placement(spec(8.0), led, policy=policy)
    # El planner sigue viendo 8G (el valor firmado), así que un modelo de 32G
    # NO debe caber — si "cupiera", la manipulación habría funcionado.
    plan_big = plan_placement(spec(32.0), led, policy=policy)
    assert not plan_big.ok, (
        "tras manipular la capacidad, un modelo de 32G no debe planearse: "
        "el planner debe seguir viendo la capacidad firmada (8G), no la "
        "escrita (64G)")


# --------------------------------------------- la inferencia sin crédito
def test_inference_is_refused_without_credit_even_with_capacity():
    """Capacidad sin crédito no compra inferencia.

    El reverso de la tesis: si `MeteredLLMClient` sirviera sin crédito, el
    "a cambio" sería decorativo. Un par que contribuye capacidad pero nunca se
    observa tiene el derecho a no ser servido, aunque su capacidad esté
    admitida.
    """
    led = ContributionLedger(MESH)
    policy = STRICT
    # Capacidad admitida, crédito NO ganado (observe_s=0).
    admit_and_earn(led, "n1", 32.0, observe_s=0.0, policy=policy)

    metered = MeteredLLMClient(FakeLLMClient(), led, peer_id="n1",
                               policy=policy)
    with pytest.raises(PermissionError):
        asyncio.run(metered.complete("pide sin crédito"))
    assert metered.refused == 1, (
        "el rechazo debe contabilizarse en el cliente (quien cobra), "
        "no tragarse en silencio")


def test_the_exchange_is_ordered_observe_then_spend():
    """Un par que gana crédito tras observar puede gastar; el orden importa.

    Prueba la asimetría temporal: el mismo par, el mismo plan, pero el gasto
    solo es posible DESPUÉS de `observe`. Antes de observar, se niega (test
    anterior); después, se sirve. Es la misma instancia, no dos escenarios.
    """
    led = ContributionLedger(MESH)
    policy = STRICT
    key = KeyPair.new("n1")
    metered = MeteredLLMClient(FakeLLMClient(), led, peer_id="n1",
                               policy=policy)

    # Antes de observar: se niega.
    admit_and_earn(led, "n1", 8.0, observe_s=0.0, policy=policy, key=key)
    with pytest.raises(PermissionError):
        asyncio.run(metered.complete("antes de observar"))

    # Tras observar: se sirve. Mismo par, mismo ledger.
    led.observe("n1", NOW + 1800.0, dt_s=1800.0, policy=policy)
    out = asyncio.run(metered.complete("después de observar"))
    assert out, "tras observar y ganar crédito, la inferencia debe servirse"
