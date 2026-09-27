"""Tests del reparto de modelo entre nodos (`delm.core.placement`).

La tesis del proyecto dice: *un modelo más grande que una sola caja, corriendo
sobre varias*. Eso se sostiene o se cae aquí, así que los tests cubren las
cuatro cosas que la harían falsa:

* **No se reparte sobre capacidad no admitida.** Un nodo que no firmó no cuenta,
  por mucha VRAM que tenga en el announce; y sin.slice crédito, tampoco (el
  "a cambio" del intercambio tiene que ser real, no decorativo).
* **El reparto es determinista.** Mismo ledger → mismo plan byte a byte. Sin
  esto, un plan no se puede loguear ni comparar entre observadores, que es
  justo para lo que existe.
* **LosStage suman exactamente lo pedido** y el rango de capas cubre
  ``[0, n-1]`` sin huecos ni solapes: un reparto que "casi" suma es un reparto
  que no se puede ejecutar.
* **Cada stage cabe en su nodo** (con la reserva que se le pida) y el rechazo
  explica *qué falta*, porque el operador tiene que poder arreglarlo.

Y el límite explícito: `n_layers=0` (lo que ocurre con llmfit, que no publica
capas) → plan por cuota de memoria y el mapeo capa→stage lo decide el executor.
Eso se prueba para que nadie lo lea como un bug.
"""

from __future__ import annotations

import json

import pytest

from delm.core.contrib import CapacityReport, ContributionLedger, ExchangePolicy
from delm.core.placement import (
    DEFAULT_MESH_ENDPOINT,
    ModelSpec,
    PlanReject,
    Stage,
    plan_from_dict,
    plan_json,
    plan_placement,
)
from delm.core.provenance import KeyPair

MESH = "smcp-test"
NOW = 1_000.0
POLICY = ExchangePolicy(credits_per_gib_hour=1.0, baseline_credits=1.0)


def mesh(*peers: tuple[str, float], observe_s: float = 3600.0,
         mesh_id: str = MESH) -> ContributionLedger:
    """A ledger with *peers* (id, vram_gb) admitted and observed."""
    led = ContributionLedger(mesh_id)
    for peer_id, vram in peers:
        key = KeyPair.new(peer_id)
        ch = led.issue_challenge(peer_id, now=NOW)
        rep = CapacityReport(mesh_id=mesh_id, peer_id=peer_id, vram_gb=vram,
                             ram_gb=32.0, cpu_cores=8, backend="cuda",
                             nonce=ch.nonce, issued_at=NOW,
                             expires_at=NOW + 3600).sign(key)
        assert led.admit(rep, now=NOW)[0]
        led.observe(peer_id, NOW, dt_s=observe_s, policy=POLICY)
    return led


def spec(gb: float, **kw) -> ModelSpec:
    return ModelSpec(name=kw.pop("name", "Qwen/Qwen3-32B"),
                     memory_required_gb=gb, **kw)


# --------------------------------------------------------------- el rechazo
def test_no_peers_means_no_plan():
    plan = plan_placement(spec(10.0), ContributionLedger(MESH), policy=POLICY)
    assert plan.ok is False
    assert plan.reason == PlanReject.NO_ADMITTED_PEERS.value
    assert "contribute" in " ".join(plan.notes)
    assert plan.stages == ()


def test_admitted_but_unobserved_nodes_are_distinguished():
    """La diferencia importa: el arreglo es distinto en cada caso."""
    led = mesh(("a", 16.0), observe_s=0.0)     # admitido, nunca observado
    led.peers["a"].last_seen = 0.0
    led.peers["a"].seconds_observed = 0.0
    plan = plan_placement(spec(8.0), led, policy=POLICY, observed_only=True)
    assert plan.reason == PlanReject.PEER_NOT_OBSERVED.value


def test_an_unobserved_node_never_gets_a_stage():
    """Un nodo que la malla no está viendo no puede servir inferencia.

    `ExchangePolicy.require_alive_to_spend` es lo que lo impide: sin `observe`
    no hay crédito, y sin crédito no hay stage — ni siquiera con VRAM de sobra.
    ``require_credit=False`` es la válvula de diagnóstico y sí lo salta a
    propósito, así que también se fija aquí ese contrato.
    """
    led = mesh(("a", 16.0), observe_s=0.0)
    led.peers["a"].last_seen = 0.0
    strict = plan_placement(spec(8.0), led, policy=POLICY, observed_only=False)
    assert strict.ok is False
    assert strict.reason == PlanReject.INSUFFICIENT_CREDIT.value
    # Diagnóstico: la válvula de escape, que es lo que la hace honesta.
    diagnostic = plan_placement(spec(8.0), led, policy=POLICY,
                                observed_only=False, require_credit=False)
    assert diagnostic.ok is True
    assert diagnostic.node_count == 1



def test_not_enough_mesh_vram_says_how_much_is_missing():
    led = mesh(("a", 16.0))
    plan = plan_placement(spec(40.0), led, policy=POLICY)
    assert plan.ok is False
    assert plan.reason == PlanReject.INSUFFICIENT_MESH_VRAM.value
    assert "faltan 24.0G" in " ".join(plan.notes)


def test_a_spec_without_memory_is_refused_not_guessed():
    led = mesh(("a", 64.0))
    plan = plan_placement(spec(0.0), led, policy=POLICY)
    assert plan.reason == PlanReject.SPEC_MISSING_MEMORY.value


def test_reserve_can_make_every_node_unusable():
    led = mesh(("a", 8.0))
    plan = plan_placement(spec(4.0), led, policy=POLICY, reserve_gb=8.0)
    assert plan.reason == PlanReject.PEER_TOO_SMALL.value


def test_uncredited_nodes_are_excluded_from_the_mesh():
    """La parte honesta del intercambio: VRAM sin crédito no se usa."""
    led = ContributionLedger(MESH)
    key = KeyPair.new("a")
    ch = led.issue_challenge("a", now=NOW)
    rep = CapacityReport(mesh_id=MESH, peer_id="a", vram_gb=64.0, ram_gb=32.0,
                         cpu_cores=8, nonce=ch.nonce, issued_at=NOW,
                         expires_at=NOW + 3600).sign(key)
    led.admit(rep, now=NOW)
    led.observe("a", NOW, dt_s=0.0)        # observado, pero 0 créditos ganados
    strict = ExchangePolicy(baseline_credits=0.0)
    plan = plan_placement(spec(8.0), led, policy=strict, require_credit=True)
    assert plan.reason == PlanReject.INSUFFICIENT_CREDIT.value
    assert "a" in plan.detail["blocked"]
    # Diagnóstico: con --no-credit el mismo nodo sí entra.
    diag = plan_placement(spec(8.0), led, policy=strict, require_credit=False)
    assert diag.ok is True and diag.node_count == 1


# ------------------------------------------------------------------ el plan
def test_single_node_plan_when_it_fits():
    led = mesh(("a", 16.0), ("b", 24.0))
    plan = plan_placement(spec(14.0), led, policy=POLICY)
    assert plan.ok is True
    assert plan.single_node is True
    assert plan.node_count == 1
    # El nodo más grande es el primero: menos fragmentación.
    assert plan.peers == ("b",)
    assert plan.stages[0].memory_gb == pytest.approx(14.0)
    assert plan.stages[0].utilization == pytest.approx(14.0 / 24.0, abs=1e-3)
    assert "cabe entero en b" in " ".join(plan.notes)


def test_multi_node_split_is_proportional_to_verified_vram():
    led = mesh(("a", 8.0), ("b", 16.0), ("c", 24.0))
    plan = plan_placement(spec(40.0), led, policy=POLICY, reserve_gb=1.0)
    assert plan.ok is True
    assert plan.node_count == 3
    assert plan.peers == ("c", "b", "a")           # mayor VRAM primero
    usable = {"a": 7.0, "b": 15.0, "c": 23.0}
    total = sum(usable.values())
    for s in plan.stages:
        assert s.memory_gb == pytest.approx(40.0 * usable[s.peer_id] / total,
                                            abs=1e-3)
        assert s.memory_gb < s.peer_vram_gb     # ningún nodo se desborda


def test_stages_sum_exactly_to_the_requirement():
    led = mesh(("a", 8.0), ("b", 16.0), ("c", 24.0), ("d", 7.0))
    plan = plan_placement(spec(53.0), led, policy=POLICY)
    assert sum(s.memory_gb for s in plan.stages) == pytest.approx(53.0, abs=1e-6)
    # También con 1e-9 de ruido: la suma tiene que seguir cuadrando.
    plan2 = plan_placement(spec(53.37), led, policy=POLICY)
    assert sum(s.memory_gb for s in plan2.stages) == pytest.approx(53.37,
                                                                   abs=1e-6)


def test_layer_ranges_tile_the_model_when_the_count_is_known():
    led = mesh(("a", 8.0), ("b", 16.0), ("c", 24.0))
    plan = plan_placement(spec(40.0, n_layers=64), led, policy=POLICY)
    ranges = [(s.first_layer, s.last_layer) for s in plan.stages]
    assert ranges[0][0] == 0
    assert ranges[-1][1] == 63
    for (_, prev_end), (nxt_start, _) in zip(ranges, ranges[1:]):
        assert nxt_start == prev_end + 1        # sin huecos ni solapes
    assert all(s.first_layer is not None for s in plan.stages)


def test_without_layer_count_the_plan_is_by_memory():
    """Lo que ocurre siempre con llmfit: no publica nº de capas."""
    led = mesh(("a", 16.0), ("b", 24.0))
    plan = plan_placement(spec(30.0), led, policy=POLICY)
    assert all(s.first_layer is None and s.last_layer is None
               for s in plan.stages)
    assert "no publica nº de capas" in " ".join(plan.notes)


def test_a_one_layer_model_still_gets_a_valid_range():
    led = mesh(("a", 8.0), ("b", 16.0))
    plan = plan_placement(spec(20.0, n_layers=1), led, policy=POLICY)
    ranges = [(s.first_layer, s.last_layer) for s in plan.stages]
    assert ranges[-1][1] == 0
    assert all(r[1] is not None for r in ranges)


def test_credits_are_charged_per_stage_and_proportional():
    led = mesh(("a", 8.0), ("b", 16.0), ("c", 24.0))
    plan = plan_placement(spec(40.0), led, policy=POLICY)
    total = sum(s.credits_cost for s in plan.stages)
    assert total == pytest.approx(POLICY.request_cost(), abs=1e-6)
    # El nodo que más aporta es el que más paga: la proporción es la misma.
    biggest = max(plan.stages, key=lambda s: s.memory_gb)
    assert biggest.credits_cost > min(s.credits_cost for s in plan.stages)


def test_charged_false_costs_nothing():
    led = mesh(("a", 8.0), ("b", 16.0))
    plan = plan_placement(spec(20.0), led, policy=POLICY, charged=False)
    assert all(s.credits_cost == 0.0 for s in plan.stages)


# ------------------------------------------------------------ determinismo
def test_the_same_ledger_gives_a_byte_identical_plan():
    led = mesh(("a", 8.0), ("b", 16.0), ("c", 24.0))
    s = spec(40.0, n_layers=64)
    first = plan_json(plan_placement(s, led, policy=POLICY, reserve_gb=1.0))
    second = plan_json(plan_placement(s, led, policy=POLICY, reserve_gb=1.0))
    assert first == second


def test_plan_roundtrips_for_audit_replay():
    led = mesh(("a", 8.0), ("b", 16.0), ("c", 24.0))
    plan = plan_placement(spec(40.0, n_layers=64), led, policy=POLICY)
    back = plan_from_dict(json.loads(plan_json(plan)))
    assert back.to_dict() == plan.to_dict()
    assert back.render() == plan.render()


def test_render_is_deterministic_and_shows_the_verdict():
    led = mesh(("a", 8.0), ("b", 16.0))
    plan = plan_placement(spec(20.0, n_layers=32), led, policy=POLICY)
    text = plan.render()
    assert text == plan.render()
    assert "plan OK" in text
    assert "0-" in text and "21-31" in text   # los rangos de capas se pintan
    assert DEFAULT_MESH_ENDPOINT in text

    bad = plan_placement(spec(400.0), led, policy=POLICY)
    assert "rechazado" in bad.render()
    assert "insufficient_mesh_vram" in bad.render()
    assert "plan OK" not in bad.render()


# ----------------------------------------------------------------- la unión
def test_spec_is_built_from_a_fit_row():
    """El puente llmfit→placement: la memoria de UNA caja es la que hay que cubrir."""
    from delm.core.llmfit import FitRow

    row = FitRow.from_payload({
        "name": "Qwen/Qwen3-32B-GGUF", "params_b": 32.0,
        "memory_required_gb": 19.5, "best_quant": "Q4_K_M",
        "fit_level": "marginal", "estimated_tps": 28.4, "runtime": "llama.cpp",
    })
    s = ModelSpec.from_fit_row(row)
    assert s.name == "Qwen/Qwen3-32B-GGUF"
    assert s.memory_required_gb == 19.5
    assert s.quant == "Q4_K_M"
    assert s.fit_level == "marginal"
    assert s.estimated_tps == 28.4
    # from_dict/to_dict no pierden nada (el plan se loguea y se relee).
    assert ModelSpec.from_dict(json.loads(json.dumps(s.to_dict()))) == s


def test_spec_serialisation_survives_json():
    s = ModelSpec(name="m", memory_required_gb=3.5, n_layers=7, quant="Q4_K_M",
                  fit_level="good", estimated_tps=12.0, endpoint_hint="http://x")
    assert ModelSpec.from_dict(json.loads(json.dumps(s.to_dict()))) == s


def test_endpoint_hint_from_the_model_wins_over_the_default():
    led = mesh(("a", 16.0))
    plan = plan_placement(spec(8.0, endpoint_hint="http://10.0.0.5:9337/v1"), led,
                          policy=POLICY)
    assert plan.endpoint == "http://10.0.0.5:9337/v1"
    # ... y un --endpoint explícito gana sobre el hint del modelo.
    plan2 = plan_placement(spec(8.0, endpoint_hint="http://10.0.0.5:9337/v1"),
                           led, policy=POLICY, endpoint="http://127.0.0.1:1/v1")
    assert plan2.endpoint == "http://127.0.0.1:1/v1"


def test_stage_utilization_of_a_zero_vram_peer_is_one():
    assert Stage(peer_id="x", memory_gb=1.0, peer_vram_gb=0.0).utilization == 1.0
