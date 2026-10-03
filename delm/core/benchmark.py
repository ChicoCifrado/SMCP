"""Benchmark de la malla: throughput vs nodos, latencia por inferencia.

Responde a la pregunta de data-parallel: si N nodos tienen el
mismo modelo completo, ¿escala el throughput linealmente? ¿Se
degrada la latencia de una sola inferencia por compartir el
contexto C y la cola T?

Diseno:
  * Un ``BenchmarkHarness`` ejecuta K tareas con W workers
    (W = nodos) contra un LLMClient, midiendo:
      - throughput: tareas admitidas por segundo (wall clock)
      - latencia: p50 / p95 de latency_ms por inferencia
      - saturacion: tokens_out por segundo agregados
  * ``scale_sweep`` barre W en [1, 2, 4, ...] y devuelve una
    tabla: para cada W, throughput, latencia p50/p95, y la
    pendiente (speedup respecto a W=1).
  * Todo contra el cliente real o el fake — el harness no
    sabe (ni le importa) cual es; mide lo que tarda.

La hipotesis a verificar: con el modelo completo en cada
nodo, el throughput escala ~linealmente con W (data
parallel) y la latencia p50 se mantiene (el contexto
compartido no serializa la inferencia).
"""

from __future__ import annotations

import asyncio
import statistics
import time
from dataclasses import dataclass, field
from typing import Any

from delm.core.llm import LLMClient
from delm.core.metrics import MetricsTracker, TaskMetrics
from delm.core.pipeline import DelmPipeline
from delm.core.task_queue import Task


@dataclass
class BenchmarkPoint:
    """Una medicion para un numero dado de workers (nodos)."""
    workers: int
    tasks: int
    admitted: int
    wall_s: float
    throughput_tps: float
    latency_p50_ms: float
    latency_p95_ms: float
    tokens_out_per_s: float
    speedup: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "workers": self.workers,
            "tasks": self.tasks,
            "admitted": self.admitted,
            "wall_s": round(self.wall_s, 3),
            "throughput_tps": round(self.throughput_tps, 3),
            "latency_p50_ms": round(self.latency_p50_ms, 1),
            "latency_p95_ms": round(self.latency_p95_ms, 1),
            "tokens_out_per_s": round(self.tokens_out_per_s, 1),
            "speedup": round(self.speedup, 3),
        }


def _latencies(tracker: MetricsTracker) -> list[float]:
    return sorted(r.latency_ms for r in tracker.records())


async def run_point(
    llm: LLMClient,
    *,
    workers: int,
    tasks: int,
    body: str = "State one concrete fact.",
    max_rounds: int = 4,
) -> BenchmarkPoint:
    """Ejecuta ``tasks`` tareas con ``workers`` nodos y mide."""
    tracker = MetricsTracker()
    pipe = DelmPipeline(llm=llm, n_workers=workers, metrics=tracker)
    task_list = [
        Task(label=f"t-{i:03d}", body=body, kind="solve", deps=[])
        for i in range(tasks)
    ]
    t0 = time.perf_counter()
    outcome = await pipe.run(
        task_list, max_rounds=max_rounds,
        yield_between=True,
    )
    wall = time.perf_counter() - t0
    lats = _latencies(tracker)
    p50 = statistics.median(lats) if lats else 0.0
    p95 = (lats[int(len(lats) * 0.95)] if lats else 0.0)
    tokens_out = sum(r.tokens_out for r in tracker.records())
    tps = outcome.admitted_gists / wall if wall > 0 else 0.0
    return BenchmarkPoint(
        workers=workers,
        tasks=tasks,
        admitted=outcome.admitted_gists,
        wall_s=wall,
        throughput_tps=tps,
        latency_p50_ms=p50,
        latency_p95_ms=p95,
        tokens_out_per_s=(tokens_out / wall if wall > 0 else 0.0),
    )


async def scale_sweep(
    llm: LLMClient,
    *,
    worker_counts: list[int] | None = None,
    tasks_per_worker: int = 2,
    body: str = "State one concrete fact.",
) -> list[BenchmarkPoint]:
    """Barre W workers y devuelve la tabla de puntos.

    Cada punto usa ``tasks_per_worker * W`` tareas, asi la carga
    por nodo es constante y el throughput es comparable entre
    niveles de paralelismo.
    """
    counts = worker_counts or [1, 2, 4]
    points: list[BenchmarkPoint] = []
    baseline: float | None = None
    for w in counts:
        tasks = tasks_per_worker * w
        pt = await run_point(llm, workers=w, tasks=tasks, body=body)
        if baseline is None and pt.throughput_tps > 0:
            baseline = pt.throughput_tps
        pt.speedup = (
            pt.throughput_tps / baseline
            if baseline and baseline > 0 else 1.0
        )
        points.append(pt)
    return points


def summarize(points: list[BenchmarkPoint]) -> dict[str, Any]:
    """Tabla resumen: escala lineal vs real, y latencia."""
    if not points:
        return {"points": []}
    rows = [p.to_dict() for p in points]
    # pendiente del throughput respecto a workers (speedup ideal = W)
    ideal = [p.workers for p in points]
    actual = [p.throughput_tps for p in points]
    efficiency = (
        [a / i for a, i in zip(actual, ideal)]
        if ideal and all(i > 0 for i in ideal) else []
    )
    avg_lat_p50 = statistics.median(
        [p.latency_p50_ms for p in points if p.latency_p50_ms > 0]
    ) or 0.0
    return {
        "points": rows,
        "parallel_efficiency": [round(e, 3) for e in efficiency],
        "avg_latency_p50_ms": round(avg_lat_p50, 1),
        "conclusion": _conclude(points, efficiency),
    }


def _conclude(points: list[BenchmarkPoint], efficiency: list[float]) -> str:
    """Una frase: ¿escala lineal, sublineal o degrada?"""
    if not efficiency:
        return "sin datos suficientes"
    avg_eff = statistics.mean(efficiency)
    if avg_eff >= 0.8:
        return "escala ~lineal: data-parallel funciona, el contexto no serializa"
    if avg_eff >= 0.4:
        return "escala sublineal: hay contencion (contexto o cliente compartido)"
    return "no escala: el cuello de botella es compartido (modelo o red)"
