"""Cost / latency tracker for the DeLM pipeline (observability layer).

Fills the "no hay metricas de coste por tarea ni de latencia acumulada"
gap. Deterministic, dependency-free, synchronous — safe to unit-test and
replay, same discipline as the rest of the framework.

Usage from a Worker:

    tracker = MetricsTracker()
    ...
    with tracker.timed(label=task.label, worker_id=wid, model="gemini-3-flash",
                       tokens_in=tin, tokens_out=tout) as m:
        result = await llm.complete(...)
        m.admitted = True        # mutate the in-flight record
        m.attempts = attempts

    agg = tracker.aggregate()    # JSON-serializable dict (dump to the ledger)

Exception policy: if the block inside :meth:`timed` raises, the record is
still written, with ``admitted=False`` and ``error`` set, and the exception
is re-raised — a crashed task must not look admitted in the aggregates.

Notes:

* Prices in :data:`DEFAULT_PRICING` are *orientative* 2026 defaults and
  change frequently; pass your own table to ``MetricsTracker(pricing=...)``
  for real accounting. Unknown models price at 0.0 (never raises).
* Recording is append-only under asyncio (GIL-sufficient). If workers ever
  run on real threads, guard :meth:`record` with a lock.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ModelPricing:
    """USD per 1M tokens, OpenAI-style pricing table."""
    per_1m_input_usd: float
    per_1m_output_usd: float


# Sensible defaults for common OpenAI-compatible models (2026, orientative);
# override by passing your own pricing dict to MetricsTracker.
DEFAULT_PRICING: dict[str, ModelPricing] = {
    "gemini-3-flash":        ModelPricing(0.10, 0.40),
    "gpt-4o-mini":           ModelPricing(0.15, 0.60),
    "gpt-4o":                ModelPricing(2.50, 10.00),
    "claude-sonnet-4":       ModelPricing(3.00, 15.00),
    "fake":                  ModelPricing(0.0, 0.0),
}


@dataclass
class TaskMetrics:
    """One recorded task execution (mutable while in-flight via `timed`)."""
    label: str
    worker_id: str = ""
    model: str = ""
    attempts: int = 1
    admitted: bool = True
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    error: str | None = None


def _pct(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * q
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    if lo == hi:
        return sorted_vals[lo]
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


@dataclass
class MetricsTracker:
    """Records per-task metrics and aggregates them."""
    pricing: dict[str, ModelPricing] = field(
        default_factory=lambda: dict(DEFAULT_PRICING))
    _records: list[TaskMetrics] = field(default_factory=list)

    # ---------------------------------------------------------- pricing
    def price(self, model: str, tokens_in: int, tokens_out: int) -> float:
        """USD cost for a completion. Unknown model -> 0.0 (never raises)."""
        p = self.pricing.get(model)
        if p is None:
            return 0.0
        return (tokens_in * p.per_1m_input_usd
                + tokens_out * p.per_1m_output_usd) / 1_000_000

    # ---------------------------------------------------------- record
    def record(self, m: TaskMetrics) -> None:
        self._records.append(m)

    @contextmanager
    def timed(self, label: str, worker_id: str = "", model: str = "",
              tokens_in: int = 0, tokens_out: int = 0,
              attempts: int = 1):
        """Context manager: times the block and records on exit.

        The yielded TaskMetrics can be mutated inside the block so the
        caller can set ``admitted`` / ``attempts`` / token counts measured
        *after* the call. If the block raises, the record is still written
        with ``admitted=False`` and ``error`` set, and the exception is
        re-raised.
        """
        m = TaskMetrics(label=label, worker_id=worker_id, model=model,
                        attempts=attempts,
                        tokens_in=tokens_in, tokens_out=tokens_out)
        start = time.perf_counter()
        try:
            yield m
        except Exception as exc:
            m.admitted = False
            m.error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            m.latency_ms = (time.perf_counter() - start) * 1000.0
            m.cost_usd = self.price(model, tokens_in=m.tokens_in,
                                    tokens_out=m.tokens_out)
            self.record(m)

    # ---------------------------------------------------------- read
    def records(self) -> list[TaskMetrics]:
        return list(self._records)

    def aggregate(self) -> dict:
        """Aggregate view: totals, latency percentiles, admit rate.

        Returns a JSON-serializable dict with per-worker AND per-model
        breakdowns (so cost attribution survives workers sharing models).
        Latency aggregates include failed/crashed tasks; filter
        :meth:`records` first if only successful latencies matter.
        """
        rs = self._records
        n = len(rs)
        lat = sorted(r.latency_ms for r in rs)
        done = [r for r in rs if r.admitted]
        cost = sum(r.cost_usd for r in rs)

        def _bucket(attr: str) -> dict[str, dict]:
            out: dict[str, dict] = {}
            for r in rs:
                w = out.setdefault(getattr(r, attr) or "-", {
                    "tasks": 0, "admitted": 0, "cost_usd": 0.0,
                    "tokens_in": 0, "tokens_out": 0})
                w["tasks"] += 1
                w["admitted"] += int(r.admitted)
                w["cost_usd"] += r.cost_usd
                w["tokens_in"] += r.tokens_in
                w["tokens_out"] += r.tokens_out
            return out

        by_worker = _bucket("worker_id")
        by_model = _bucket("model")
        return {
            "tasks": n,
            "admitted": len(done),
            "admit_rate": (len(done) / n) if n else 0.0,
            "total_cost_usd": round(cost, 6),
            "total_tokens_in": sum(r.tokens_in for r in rs),
            "total_tokens_out": sum(r.tokens_out for r in rs),
            "total_retries": sum(max(0, r.attempts - 1) for r in rs),
            "failed": sum(1 for r in rs if not r.admitted),
            "latency_ms": {
                "avg": round(sum(lat) / n, 2) if n else 0.0,
                "p50": round(_pct(lat, 0.50), 2),
                "p95": round(_pct(lat, 0.95), 2),
                "max": round(lat[-1], 2) if n else 0.0,
            },
            "by_worker": by_worker,
            "by_model": by_model,
        }


__all__ = ["ModelPricing", "TaskMetrics", "MetricsTracker", "DEFAULT_PRICING"]
