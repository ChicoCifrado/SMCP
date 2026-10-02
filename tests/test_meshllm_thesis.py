"""La tesis del intercambio, contra un endpoint REAL (P2, opt-in).

Por qué este archivo y `test_exchange_thesis.py` son distintos:

- `test_exchange_thesis.py` prueba la cadena **offline**, con un doble
  determinista (`FakeLLMClient`). Es la que corre en CI.
- Este prueba que la misma cadena funciona contra **un LLM de verdad**, y
  sobre todo que la **mediación** del crédito se sostiene cuando hay una
  llamada de red de por medio.

Eso último es lo que los tests offline no pueden ver. Que
`MeteredLLMClient` cobre el crédito y luego delegue es correcto en un doble;
en la realidad hay un `await` a un endpoint ajeno, un timeout, una
respuesta vacía, y el crédito ya está debitado. **Si el cobro ocurre antes
de que la inferencia funcione, el sistema cobra por nada.** Estos tests lo
comprueban contra hardware.

``slow`` y opt-in: se skipea si no hay endpoint. Sin CI hard-dependency.

Run manual::

    MESH_LLM_URL=http://127.0.0.1:8888/v1 \
      python -m pytest tests/test_meshllm_thesis.py -m slow -v

Los tests que NO necesitan inferencia (los de crédito insuficiente) corren
igualmente con endpoint: la mediación se decide antes de llamar al modelo.
"""
from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request

import pytest

from delm.core.contrib import (
    CapacityReport,
    ContributionLedger,
    ExchangePolicy,
    MeteredLLMClient,
)
from delm.core.llm import OpenAICompatibleClient
from delm.core.placement import ModelSpec, plan_placement
from delm.core.provenance import KeyPair

MESH_URL = os.environ.get("MESH_LLM_URL", "http://127.0.0.1:8888/v1")
PROBE_TIMEOUT = float(os.environ.get("MESH_PROBE_TIMEOUT", "10.0"))
#: Un modelo con razonamiento se come el presupuesto de tokens en razonar y
#: devuelve `finish_reason="length"` con la respuesta vacia. Por eso el
#: default es holgado: el objetivo es una cadena, no una frase.
MAX_TOKENS = int(os.environ.get("MESH_MAX_TOKENS", "256"))


# --------------------------------------------------------------- helpers
def _probe(url: str) -> str | None:
    """Primer ``model.id`` de ``{url}/models``, o ``None`` si no hay endpoint."""
    try:
        with urllib.request.urlopen(url + "/models", timeout=PROBE_TIMEOUT) as r:
            data = json.loads(r.read())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, OSError, ValueError):
        return None
    models = data.get("data", [])
    return models[0].get("id") if models else None


def _admit(led: ContributionLedger, peer: str, vram: float, key: KeyPair,
           mesh: str, now: float, *, seconds: float = 1800.0,
           policy: ExchangePolicy | None = None) -> float:
    """Report firmado + observado -> devuelve el credito disponible.

    Mismo camino que en producción: `issue_challenge` (nonce de la malla) →
    `report` firmado por el par → `admit`. Saltarse el reto haría que el
    test no midiera nada real.

    El credito lo acumula `observe(peer, now, dt_s=...)` — el intervalo que
    el observador avala, no un reloj que corre por su cuenta.
    """
    ch = led.issue_challenge(peer, now=now)
    rep = CapacityReport(
        mesh_id=mesh, peer_id=peer, vram_gb=vram,
        vram_advertised_gb=vram, ram_gb=vram * 2,
        cpu_cores=8, backend="cuda", nonce=ch.nonce,
        issued_at=now, expires_at=now + 3600.0,
    ).sign(key)
    ok, why = led.admit(rep, now=now)
    assert ok, f"el report firmado debe admitirse: {why}"
    pol = policy if policy is not None else ExchangePolicy()
    led.observe(peer, now=now + seconds, dt_s=seconds, policy=pol)
    return led.peers[peer].credits_available


# --------------------------------------------------------------- la tesis
@pytest.mark.slow
def test_credit_gates_a_real_inference_end_to_end():
    """La cadena completa contra un endpoint real:_place, cobrar, inferir.

    Es el test que `test_exchange_thesis.py` no puede hacer. Cada paso es el
    de producción: report firmado -> observe -> plan -> cliente metered ->
    endpoint de verdad.
    """
    model = _probe(MESH_URL)
    if model is None:
        pytest.skip(f"no hay endpoint en {MESH_URL} (opt-in; usa MESH_LLM_URL)")

    mesh = "smcp-p2-real"
    now = 1000.0
    led = ContributionLedger(mesh)
    key = KeyPair.new("nodo-real")
    policy = ExchangePolicy(credits_per_gib_hour=10.0, baseline_credits=0.0,
                            require_alive_to_spend=True)

    # 1. capacidad firmada + observada -> credito
    credit = _admit(led, "n1", 8.0, key, mesh, now)
    assert credit > 0.0, f"un par observado debe ganar credito (got {credit})"

    # 2. el planner coloca el modelo (8G declarados, modelo pequeno)
    spec = ModelSpec(name=model, memory_required_gb=2.0)
    plan = plan_placement(spec, led, policy=policy)
    assert plan.ok, f"el plan deberia entrar: {plan.notes}"
    assert plan.total_vram_gb == pytest.approx(8.0)

    # 3. la inferencia real, mediada por el credito
    # api_key vacio a proposito: un endpoint local rechaza el header
    # Authorization (401); el cliente lo strip-ea en el wire.
    inner = OpenAICompatibleClient(model=model, base_url=MESH_URL, api_key="")
    metered = MeteredLLMClient(inner, led, "n1", policy=policy)
    out = asyncio.run(metered.complete("Di OK.", tokens_in=100,
                                       tokens_out=MAX_TOKENS,
                                       max_tokens=MAX_TOKENS))

    assert isinstance(out, str) and out.strip(), (
        f"la inferencia real devolvio vacio: {out!r}")
    assert metered.served == 1 and metered.refused == 0
    # el credito se debito de verdad
    assert led.peers["n1"].credits_available < credit
    assert metered.log[-1]["ok"] is True


@pytest.mark.slow
def test_insufficient_credit_refuses_BEFORE_any_network_call():
    """Sin credito, NO se llama al endpoint — y no se cobra por nada.

    Este es el test que mas importa del archivo. El orden correcto es
    cobrar-despuues, no despues: si el `MeteredLLMClient` llamara al modelo y
    luego comprobara el saldo, un par sin credito consumiria GPU ajena gratis.

    Con `max_tokens` enorme y un endpoint lento, un error aqui se
    manifestaria como timeout, no como assertion: por eso el probe exige
    endpoint real, para que la ausencia de inferencia sea concluyente.
    """
    model = _probe(MESH_URL)
    if model is None:
        pytest.skip(f"no hay endpoint en {MESH_URL}")

    mesh = "smcp-p2-refuse"
    led = ContributionLedger(mesh)
    key = KeyPair.new("nodo-sin-credito")
    # Politica sin baseline: observar da credito, pero lo forzamos a 0 para
    # que la admision no baste y el gasto falle.
    policy = ExchangePolicy(baseline_credits=0.0, credits_per_gib_hour=0.0,
                            require_alive_to_spend=True)
    _admit(led, "n1", 8.0, key, mesh, 1000.0, seconds=0.0)
    assert led.peers["n1"].credits_available == 0.0, (
        "esta_POLITICA no debe dar credito: el test depende de saldo 0")

    # Un cliente que EXPLOTA si alguien lo llama: si el mediador cobrase
    # despues, este test colgaria/fallaria aqui en vez de por el saldo.
    class ExplodingInner:
        async def complete(self, *a, **k):
            raise AssertionError(
                "se llamo al modelo SIN credito: el cobro va antes de la "
                "inferencia, no despues")

    metered = MeteredLLMClient(ExplodingInner(), led, "n1", policy=policy)
    with pytest.raises(PermissionError, match="sin cr[eé]dito"):
        asyncio.run(metered.complete("Di OK.", tokens_in=1000, tokens_out=1000))

    assert metered.served == 0 and metered.refused == 1
    # `failed` NO se toca: el rechazo fue por credito, no por inferencia. Son
    # dos cosas distintas y confundirlas haria parecer que se intento servir.
    assert metered.failed == 0
    # y el log lo registra como rechazo, con su motivo
    assert metered.log[-1]["ok"] is False
    assert metered.log[-1]["reason"]


@pytest.mark.slow
def test_credit_debit_survives_a_real_endpoint_failure():
    """Si el endpoint real falla, el cobro queda registrado como fallo.

    Aqui el fallo es de **red de verdad**: mismo host y puerto que el
    endpoint que funciona, pero un path que no existe. La inferencia falla
    con un 404 real, no simulado.

    Lo que se fija es la asimetria del diseno: `MeteredLLMClient` debita
    ANTES de llamar al modelo (por eso un par sin credito no puede gastar
    GPU ajena — ver el test anterior). El coste de esa choice es que un
    intento fallido tambien se cobra. Lo aceptable es que **quede
    registrado**: nada de esto puede parecerse a una inferencia servida.
    """
    model = _probe(MESH_URL)
    if model is None:
        pytest.skip(f"no hay endpoint en {MESH_URL}")

    mesh = "smcp-p2-fallo"
    led = ContributionLedger(mesh)
    key = KeyPair.new("nodo-fallo")
    policy = ExchangePolicy(credits_per_gib_hour=10.0, baseline_credits=50.0)
    _admit(led, "n1", 8.0, key, mesh, 1000.0, policy=policy)
    before = led.peers["n1"].credits_available
    assert before > 0.0

    # Mismo host y puerto reales, ruta que el servidor no sirve -> 404 de verdad
    broken = MESH_URL.rstrip("/") + "/ruta-que-no-existe/v1"
    inner = OpenAICompatibleClient(model=model, base_url=broken, api_key="")
    metered = MeteredLLMClient(inner, led, "n1", policy=policy)

    with pytest.raises(Exception):
        asyncio.run(metered.complete("Di OK.", tokens_in=100,
                                     tokens_out=MAX_TOKENS,
                                     max_tokens=MAX_TOKENS))

    # no se sirvio: el fallo no se confunde con una inferencia servida
    assert metered.served == 0
    assert metered.failed == 1, "el fallo se cuenta aparte de lo servido"
    # el log se corrige a posteriori: la entrada paso de `ok: True` (cobro
    # aceptado) a `ok: False` con el motivo real del fallo
    assert metered.log[-1]["ok"] is False
    assert "inference_failed" in metered.log[-1]["reason"]
    # el debit se aplico de verdad: el cobro va antes del await, por diseño
    assert led.peers["n1"].credits_available < before
    # y el saldo nunca queda negativo ni se corrompe
    assert led.peers["n1"].credits_available >= 0.0
    # `served + failed` es lo que se cobró de verdad; `served` es lo que se
    # recibió. La diferencia es la responsabilidad del endpoint.
    stats = metered.stats()
    assert stats["served"] == 0 and stats["failed"] == 1
    assert stats["refused"] == 0
