"""Tests del benchmark multi-nodo (con el fake)."""

import asyncio

from delm.core.llm import FakeLLMClient
from delm.core.multi_node_bench import (
    MultiNodePoint,
    run_multi_node,
    summarize_multi,
)


def test_run_multi_node_one_llm():
    """Un nodo (un LLM) mide y admite."""

    async def go():
        return await run_multi_node([FakeLLMClient()], tasks_per_node=1)

    pt = asyncio.run(go())
    assert pt.nodes == 1
    assert pt.tasks == 1
    assert pt.admitted >= 0
    assert pt.wall_s > 0


def test_run_multi_node_two_llms():
    """Dos nodos (dos LLMs) admiten mas que uno."""

    async def go():
        return await run_multi_node(
            [FakeLLMClient(), FakeLLMClient()], tasks_per_node=1)

    pt = asyncio.run(go())
    assert pt.nodes == 2
    assert pt.tasks == 2
    assert pt.admitted >= 1


def test_summarize_multi_scaling():
    """El resumen trae tabla, per-node throughput y scaling."""

    async def go():
        pts = await run_multi_node([FakeLLMClient()], tasks_per_node=1)
        return summarize_multi([pts])

    res = asyncio.run(go())
    assert len(res["points"]) == 1
    assert "per_node_throughput" in res
    assert "scaling" in res
    assert res["avg_latency_p50_ms"] >= 0


def test_multi_node_point_to_dict():
    """El punto se serializa limpio."""
    pt = MultiNodePoint(
        nodes=2, tasks=2, admitted=2, wall_s=10.0,
        throughput_tps=0.2, latency_p50_ms=5000.0,
        latency_p95_ms=6000.0, speedup=1.8,
    )
    d = pt.to_dict()
    assert d["nodes"] == 2
    assert d["throughput_tps"] == 0.2
    assert d["speedup"] == 1.8
    assert "latency_p95_ms" in d
