"""Tests de la métrica HCI (Headroom-Closed Index).

Cubre:
- Benchmark.hci: normalización 0-100 (frontier->0, perfect->100, clamp).
- Benchmark.closed_by: puntos cerrados por una mejora.
- BenchFamily.hci: media ponderada de la familia.
- HCIMeter.measure / improve: medir un config y una mejora RSI.
- RSIImprovement: vista JSON (summary) y closed.
- DeterministicScorer: scorer puro (para demo sin modelo).
- SMCP_FAMILY: la familia por defecto de SMCP.
"""
from __future__ import annotations

import pytest

from delm.core.hci import (
    Benchmark,
    BenchFamily,
    DeterministicScorer,
    HCIMeter,
    RSIImprovement,
    SMCP_FAMILY,
)


# ------------------------------------------------------------------ Benchmark
def test_benchmark_frontier_is_zero_hci():
    b = Benchmark(id="x", frontier=0.30, perfect=1.00)
    assert b.hci(0.30) == 0.0


def test_benchmark_perfect_is_100_hci():
    b = Benchmark(id="x", frontier=0.30, perfect=1.00)
    assert b.hci(1.00) == 100.0


def test_benchmark_interpolates_linearly():
    b = Benchmark(id="x", frontier=0.30, perfect=1.00)
    # 0.65 = mitad del hueco (0.30..1.00) -> 50
    assert b.hci(0.65) == pytest.approx(50.0)


def test_benchmark_clamps_below_frontier():
    b = Benchmark(id="x", frontier=0.30, perfect=1.00)
    assert b.hci(0.10) == 0.0  # por debajo de la frontera -> 0


def test_benchmark_clamps_above_perfect():
    b = Benchmark(id="x", frontier=0.30, perfect=1.00)
    assert b.hci(1.20) == 100.0  # por encima del tope -> 100


def test_benchmark_rejects_invalid_frontier():
    with pytest.raises(ValueError):
        Benchmark(id="bad", frontier=0.9, perfect=0.5)  # perfect < frontier


def test_benchmark_closed_by_measures_improvement():
    b = Benchmark(id="x", frontier=0.30, perfect=1.00)
    # mejora de 0.30 -> 0.65 cierra 50 puntos
    assert b.closed_by(0.30, 0.65) == pytest.approx(50.0)
    # una regresión cierra < 0
    assert b.closed_by(0.65, 0.30) == pytest.approx(-50.0)


# ------------------------------------------------------------------ BenchFamily
def test_family_hci_is_weighted_mean():
    fam = BenchFamily(id="f", benchmarks=(
        Benchmark(id="a", frontier=0.0, perfect=1.0),
        Benchmark(id="b", frontier=0.0, perfect=1.0),
    ))
    # a=0.5 (->50), b=1.0 (->100) -> media 75
    assert fam.hci({"a": 0.5, "b": 1.0}) == pytest.approx(75.0)


def test_family_hci_uniform_weights_default():
    fam = BenchFamily(id="f", benchmarks=(
        Benchmark(id="a", frontier=0.0, perfect=1.0),
        Benchmark(id="b", frontier=0.0, perfect=1.0),
    ))
    # sin pesos -> uniforme: a=1.0 (->100), b=1.0 (->100) -> 100
    assert fam.hci({"a": 1.0, "b": 1.0}) == pytest.approx(100.0)


def test_family_hci_missing_score_uses_frontier():
    fam = BenchFamily(id="f", benchmarks=(
        Benchmark(id="a", frontier=0.30, perfect=1.0),
        Benchmark(id="b", frontier=0.50, perfect=1.0),
    ))
    # falta "b" -> se usa su frontier (->0 para b)
    h = fam.hci({"a": 1.0})
    # a=1.0 -> 100; b faltante -> 0. media = 50
    assert h == pytest.approx(50.0)


def test_family_rejects_weight_mismatch():
    with pytest.raises(ValueError):
        BenchFamily(id="bad", benchmarks=(
            Benchmark(id="a", frontier=0.0, perfect=1.0),
        ), weights=(0.5, 0.5))  # 2 pesos, 1 benchmark


# ------------------------------------------------------------------ HCIMeter
def test_meter_measure_returns_family_hci():
    meter = HCIMeter(SMCP_FAMILY)
    # swe=0.30 (->0), qa=1.0 (->100) -> media 50
    h = meter.measure({"swe-style": 0.30, "multi-doc-qa": 1.0})
    assert h == pytest.approx(50.0)


def test_meter_improve_returns_rsiimprovement():
    scorer = DeterministicScorer(lambda c: {
        "swe-style": c.get("swe", 0.30),
        "multi-doc-qa": c.get("qa", 0.55),
    })
    meter = HCIMeter(SMCP_FAMILY, scorer)
    imp = meter.improve(
        before={"swe": 0.30, "qa": 0.55},
        after={"swe": 0.60, "qa": 0.80},
    )
    assert isinstance(imp, RSIImprovement)
    # la mejora cierra > 0 puntos
    assert imp.closed > 0.0
    # hci_after > hci_before
    assert imp.hci_after > imp.hci_before


def test_meter_without_scorer_raises_on_score():
    meter = HCIMeter(SMCP_FAMILY)  # sin scorer
    with pytest.raises(ValueError):
        meter.score({"x": 1})


def test_meter_without_scorer_raises_on_improve():
    meter = HCIMeter(SMCP_FAMILY)  # sin scorer
    with pytest.raises(ValueError):
        meter.improve(before={}, after={})


# ------------------------------------------------------------------ RSIImprovement
def test_rsiimprovement_summary_is_json():
    imp = RSIImprovement(
        family_id="f",
        before={"a": 0.5}, after={"a": 1.0},
        hci_before=50.0, hci_after=100.0, closed=50.0,
    )
    s = imp.summary()
    assert s["family"] == "f"
    assert s["closed"] == pytest.approx(50.0)
    assert s["hci_after"] > s["hci_before"]
    # serializable a JSON (str keys, float values)
    import json
    json.dumps(s)


# ------------------------------------------------------------------ DeterministicScorer
def test_deterministic_scorer_is_pure():
    scorer = DeterministicScorer(lambda c: {"x": c.get("k", 0)})
    assert scorer({"k": 0.7}) == {"x": 0.7}
    assert scorer({}) == {"x": 0.0}


# ------------------------------------------------------------------ SMCP_FAMILY
def test_smcp_family_has_two_benchmarks():
    assert len(SMCP_FAMILY.benchmarks) == 2
    ids = {b.id for b in SMCP_FAMILY.benchmarks}
    assert ids == {"swe-style", "multi-doc-qa"}


def test_smcp_family_frontiers_are_valid():
    for b in SMCP_FAMILY.benchmarks:
        assert 0.0 <= b.frontier < b.perfect


# ==================================================================
# Las NO-GARANTIAS del HCI, como tests (P3)
# ==================================================================
# El threat model dice (seccion 2, "Mejoras opt-in") que el HCI es
# instrumentacion autoinformada: el frontier es una constante escrita a
# mano, el Scorer no esta verificado, y el HCI no esta conectado al loop
# RSI. Estas afirmaciones son *codigo*, asi que se comprueban: si alguien
# conecta de verdad el HCI al loop, o ancla el frontier a una suite
# externa, el test falla y obliga a reescribir la no-garantia.


def test_hci_is_not_wired_into_the_rsi_loop():
    """`RSILoop` no debe importar `hci`: la medida no gobierna la retencion.

    El threat model afirma que hoy van por caminos separados. Si este test
    falla, la no-garantia "el HCI no gobierna el gate" queda obsoleta y hay
    que reescribir esa seccion (no solo borrarla: sigue siendo cierto que
    el Scorer no esta verificado).
    """
    import inspect

    from delm.core import rsi

    src = inspect.getsource(rsi)
    assert "hci" not in src.lower(), (
        "RSILoop ya menciona hci: la no-garantia 'el HCI no esta conectado al "
        "loop RSI' del threat model hay que actualizarla."
    )


def test_hci_normalizes_against_a_hardcoded_frontier():
    """El HCI es aritmetica contra una constante del repo, no una medida.

    Con el mismo `frontier`, el HCI es una funcion pura de los scores. Este
    test no juzga si el numero es *correcto* (no se puede saber sin una suite
    externa) sino que fija lo que el HCI **si** es: una transformacion
    determinista de numeros que el propio repo declara como orientativos.
    """
    b = SMCP_FAMILY.benchmarks[0]
    # el mismo score -> el mismo HCI, siempre
    assert b.hci(0.5) == b.hci(0.5)
    # y mover el frontier mueve el HCI: la escala la define el repo
    shifted = Benchmark(id=b.id, frontier=b.frontier + 0.2, perfect=b.perfect)
    assert shifted.hci(0.5) < b.hci(0.5), (
        "el HCI depende del frontier declarado: no es una medicion externa"
    )


def test_a_scorer_can_lie_and_the_hci_will_not_notice():
    """El `Scorer` no esta verificado: un scorer mentiroso produce un HCI valido.

    Este es el punto central de la no-garantia. Un `Scorer` que devuelve
    0.99 sin ejecutar nada produce un HCI de 100 igual que uno "honesto" con
    esos mismos numeros: la formula es identica y lo unico que cambia es la
    entrada, que no lleva ninguna firma. El `RSIImprovement` resultante queda
    *auditable* (se puede firmar y encadenar) pero no *veraz*.
    """
    # un scorer que NO ejecuta nada y se inventa el mismo 0.99 para cualquier
    # config: da igual que "mejore" el parametro, el score no se mueve
    liar = DeterministicScorer(lambda c: {"swe-style": 0.99, "multi-doc-qa": 0.99})
    meter = HCIMeter(SMCP_FAMILY, liar)

    imp = meter.improve({}, {"max_burst": 8})

    # el HCI sale casi perfecto (98.17: el `before` vacio cae a la frontera)...
    assert imp.hci_after == pytest.approx(98.1746, abs=0.001)
    # ...y no hay nada en el resultado que delate de donde salio
    summary = imp.summary()
    assert set(summary) == {
        "family", "hci_before", "hci_after", "closed", "before", "after"}
    # el summary no registra de donde salieron los scores: no hay scorer_id,
    # ni timestamp, ni digest que ate la medida a una ejecucion concreta
    assert "scorer" not in summary
    assert "digest" not in summary
    assert "timestamp" not in summary

    # lo que se firma al retener una regla RSI es la REGLA, no su efecto
    # medido: aqui la "mejora" no mueve el HCI y aun asi el numero es
    # presentable, sin ninguna marca de que el scorer no haya ejecutado nada
    assert imp.closed == 0.0
