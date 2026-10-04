"""Benchmark multi-nodo real: cada worker con SU propio modelo.

El benchmark.py original usa UN LLM para todos los workers
(un solo endpoint), asi que con un modelo que serializa
peticiones el throughput no escala. Este modulo reparte
los workers entre N endpoints (N modelos), que es la
configuracion real de la malla: cada nodo aporta SU
modelo.

La hipotesis a verificar: con N modelos distintos
(N procesos beellama), el throughput escala ~linealmente
con N y la latencia p50 se mantiene.
"""

from __future__ import annotations

import asyncio
import statistics
import time
from dataclasses import dataclass
from typing import Any

from smcp.core.admission import AdmissionPipeline
from smcp.core.gist import GistKind
from smcp.core.llm import LLMClient
from smcp.core.metrics import MetricsTracker
from smcp.core.pipeline import DelmPipeline, Worker
from smcp.core.provenance import KeyPair
from smcp.core.secure_context import SecureSharedContext, TrustGate, TrustPolicy
from smcp.core.shared_context import SharedContext
from smcp.core.task_queue import Task
from smcp.core.verifier import RuleVerifier


@dataclass
class MultiNodePoint:
    """Una medicion con W nodos, cada uno con su modelo."""
    nodes: int
    tasks: int
    admitted: int
    wall_s: float
    throughput_tps: float
    latency_p50_ms: float
    latency_p95_ms: float
    speedup: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": self.nodes,
            "tasks": self.tasks,
            "admitted": self.admitted,
            "wall_s": round(self.wall_s, 3),
            "throughput_tps": round(self.throughput_tps, 4),
            "latency_p50_ms": round(self.latency_p50_ms, 1),
            "latency_p95_ms": round(self.latency_p95_ms, 1),
            "speedup": round(self.speedup, 3),
        }


async def run_multi_node(
    llms: list[LLMClient],
    *,
    tasks_per_node: int = 1,
    body: str = "State one concrete fact.",
    max_rounds: int = 4,
) -> MultiNodePoint:
    """Ejecuta tasks_per_node tareas por nodo; cada nodo = su LLM.

    Cada worker se construye con SU llama (llms[i % len(llms)]),
    asi N procesos beellama atienden N workers a la vez.
    """
    n = len(llms)
    # contexto seguro: admite gists firmados
    ctx = SecureSharedContext(
        gate=TrustGate(TrustPolicy.REQUIRE_SIGNED),
        injection_threshold=2,
    )
    # admission compartida (verifier + compression)
    verifier = RuleVerifier(min_ngram_words=4)
    # un LLM para comprimir (el primero); el verifier es deterministico
    admission = AdmissionPipeline(
        llm=llms[0], verifier=verifier, max_retries=2)

    pipe = DelmPipeline(llm=llms[0], n_workers=n, secure=True)
    # reusar el ctx seguro del pipeline
    ctx = pipe.ctx
    keys: dict[int, KeyPair] = {}
    for i in range(n):
        if i not in keys:
            keys[i] = KeyPair.new(f"worker-{i}")
        if isinstance(ctx, SecureSharedContext):
            ctx.register_key(f"worker-{i}", keys[i].public_key, keys[i].kind)

    task_list = [
        Task(label=f"t-{i:03d}", body=body, kind="solve", deps=[])
        for i in range(tasks_per_node * n)
    ]
    pipe.queue.enqueue_many(task_list)

    tracker = MetricsTracker()
    workers = [
        Worker(
            i, llms[i % n], ctx, pipe.queue, admission,
            reason=None, yield_between=True,
            author_id=f"worker-{i}", key=keys[i], metrics=tracker,
        )
        for i in range(n)
    ]
    t0 = time.perf_counter()
    await asyncio.gather(*(w.run() for w in workers))
    wall = time.perf_counter() - t0

    lats = sorted(r.latency_ms for r in tracker.records())
    p50 = statistics.median(lats) if lats else 0.0
    p95 = lats[int(len(lats) * 0.95)] if lats else 0.0
    return MultiNodePoint(
        nodes=n,
        tasks=len(task_list),
        admitted=len(ctx),
        wall_s=wall,
        throughput_tps=(len(ctx) / wall if wall > 0 else 0.0),
        latency_p50_ms=p50,
        latency_p95_ms=p95,
    )


async def multi_node_sweep(
    llm_pools: list[list[LLMClient]],
    *,
    tasks_per_node: int = 1,
    body: str = "State one concrete fact.",
) -> list[MultiNodePoint]:
    """Barre pools de LLMs: [1 modelo], [2 modelos], ...

    Cada pool es una lista de LLMClient (uno por nodo). El
    primer punto (1 nodo) es el baseline; la speedup de los
    demas es throughput(baseline).
    """
    points: list[MultiNodePoint] = []
    baseline: float | None = None
    for pool in llm_pools:
        pt = await run_multi_node(
            pool, tasks_per_node=tasks_per_node, body=body)
        if baseline is None and pt.throughput_tps > 0:
            baseline = pt.throughput_tps
        pt.speedup = (
            pt.throughput_tps / baseline
            if baseline and baseline > 0 else 1.0
        )
        points.append(pt)
    return points


def summarize_multi(points: list[MultiNodePoint]) -> dict[str, Any]:
    """Tabla: throughput vs nodos y si escala."""
    if not points:
        return {"points": []}
    rows = [p.to_dict() for p in points]
    eff = [
        round(p.throughput_tps / p.nodes, 3)
        for p in points if p.nodes > 0
    ]
    avg_p50 = statistics.median(
        [p.latency_p50_ms for p in points if p.latency_p50_ms > 0]
    ) or 0.0
    # speedup real vs ideal (N nodos)
    ideal = [p.nodes for p in points]
    speedups = [p.speedup for p in points]
    scaling = _scaling(ideal, speedups)
    return {
        "points": rows,
        "per_node_throughput": eff,
        "avg_latency_p50_ms": round(avg_p50, 1),
        "scaling": scaling,
    }


def _scaling(ideal: list[int], speedups: list[float]) -> str:
    if not speedups:
        return "sin datos"
    last_n = ideal[-1] if ideal else 1
    last_s = speedups[-1] if speedups else 1.0
    if last_s >= last_n * 0.8:
        return f"escala ~lineal: {last_s:.2f}x con {last_n} nodos (data-parallel funciona)"
    if last_s >= last_n * 0.4:
        return f"escala sublineal: {last_s:.2f}x con {last_n} nodos (hay contencion)"
    return f"no escala: {last_s:.2f}x con {last_n} nodos (cuello de botella compartido)"
