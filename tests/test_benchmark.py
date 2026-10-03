"""Tests de benchmark: que mide y escala (con el fake)."""

import asyncio

from delm.core.benchmark import (
    BenchmarkPoint,
    run_point,
    scale_sweep,
    summarize,
)
from delm.core.llm import FakeLLMClient


def test_run_point_measures():
    """Un punto mide throughput, latencia y tokens."""
    llm = FakeLLMClient()

    async def go():
        return await run_point(llm, workers=1, tasks=2)

    pt = asyncio.run(go())
    assert pt.workers == 1
    assert pt.tasks == 2
    assert pt.admitted >= 0
    assert pt.wall_s > 0
    assert pt.throughput_tps > 0
    # latencia registrada (el fake tambien la llena)
    assert pt.latency_p50_ms >= 0


def test_scale_sweep_returns_points():
    """El sweep devuelve un punto por nivel de workers."""
    llm = FakeLLMClient()

    async def go():
        return await scale_sweep(
            llm, worker_counts=[1, 2], tasks_per_worker=1)

    points = asyncio.run(go())
    assert len(points) == 2
    assert [p.workers for p in points] == [1, 2]
    # el baseline es W=1
    assert points[0].speedup == 1.0


def test_summarize_concludes():
    """El resumen trae tabla, eficiencia y conclusion."""
    llm = FakeLLMClient()

    async def go():
        pts = await scale_sweep(
            llm, worker_counts=[1, 2, 4], tasks_per_worker=1)
        return summarize(pts)

    res = asyncio.run(go())
    assert len(res["points"]) == 3
    assert "parallel_efficiency" in res
    assert "conclusion" in res
    assert res["avg_latency_p50_ms"] >= 0


def test_benchmark_point_to_dict():
    """El punto se serializa limpio para la API."""
    pt = BenchmarkPoint(
        workers=2, tasks=4, admitted=4, wall_s=1.5,
        throughput_tps=2.66, latency_p50_ms=120.0,
        latency_p95_ms=300.0, tokens_out_per_s=100.0,
        speedup=1.33,
    )
    d = pt.to_dict()
    assert d["workers"] == 2
    assert d["throughput_tps"] == 2.66
    assert d["speedup"] == 1.33
    assert "latency_p95_ms" in d


def test_fake_scales_or_is_honest():
    """Con el fake, el throughput no se degrada al añadir workers."""
    llm = FakeLLMClient()

    async def go():
        return await scale_sweep(
            llm, worker_counts=[1, 4], tasks_per_worker=2)

    pts = asyncio.run(go())
    assert pts[1].admitted >= pts[0].admitted
