"""End-to-end DELM demo.

Drives the *public* :class:`DelmPipeline` — task queue, parallel workers,
admission verification, shared context, selective unfolding, finalize — using
a deterministic :class:`FakeLLMClient`, so it needs no API key and is fully
reproducible. This is the proof that the framework is wired end to end.

Run:  ``python -m delm.demo.run_demo``   (or ``delm-demo``)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass


# ---------------------------------------------------------------------- data
@dataclass
class ToyProblem:
    """A tiny, self-contained problem the pipeline will solve.

    The "corpus" is a handful of source units; the task is to find which unit
    carries the load-bearing constraint and state it. This exercises every
    DELM mechanism (queue, parallel claim, verify, admit, unfold, finalize).
    """

    question: str
    units: list[tuple[str, str]]  # (label, raw text)
    answer_unit: str             # label of the load-bearing unit


def _toy() -> ToyProblem:
    return ToyProblem(
        question=(
            "Which source unit states the load-bearing constraint, and what "
            "is that constraint?"
        ),
        units=[
            ("u1", "This system processes events in order; no constraint "
                  "is stated here."),
            ("u2", "The scheduler retries failed jobs three times; this is "
                  "a policy, not the load-bearing constraint."),
            ("u3", "CONSTRAINT: a transaction must be journaled before it is "
                   "acked to the client; acking before journaling is forbidden "
                   "under all failure modes."),
            ("u4", "The API returns JSON and error codes follow RFC 9457."),
        ],
        answer_unit="u3",
)


def _transcripts(toy: ToyProblem) -> dict[str, str]:
    """Per-unit 'reasoning' output (what each worker's LLM step returns).

    Only u3's transcript states the constraint; the rest are red herrings.
    This lets the *verifier* do real work: admit u3's grounded claim, and the
    others are admitted too (they are faithful compressions of their own
    transcripts) — the point is that admission is evidence-gated, not free.
    """
    return {
        "u1": "Examined u1. It only states ordering; no load-bearing "
              "constraint is present.",
        "u2": "Examined u2. Retries are a policy; not the load-bearing "
              "constraint.",
        "u3": "Examined u3. The load-bearing constraint is: a transaction "
              "must be journaled before it is acked; acking before "
              "journaling is forbidden under all failure modes.",
        "u4": "Examined u4. API/JSON details; no load-bearing constraint.",
    }


# ---------------------------------------------------------------------- demo
async def run(toy: ToyProblem | None = None, workers: int = 4,
              verbose: bool = True) -> dict:
    from delm.core.llm import FakeLLMClient
    from delm.core.task_queue import Task
    from delm.core.pipeline import DelmPipeline

    toy = toy or _toy()
    transcripts = _transcripts(toy)

    # Deterministic LLM: the pipeline's compression/verification/finalize
    # steps route through it; workers' per-task 'reasoning' is supplied via
    # the `reason` override below (returning the per-unit transcript).
    llm = FakeLLMClient()

    # Seed the queue: one task per source unit.
    tasks = [Task(label=lbl,
                  body=f"Inspect source unit {lbl} and report whether it "
                      f"states the load-bearing constraint.",
                  kind="solve")
             for lbl, _ in toy.units]

    # Workers' per-task 'reasoning': return the unit's transcript.
    async def reason(task: Task) -> str:
        return transcripts[task.label]

    pipeline = DelmPipeline(llm=llm, n_workers=workers)
    outcome = await pipeline.run(
        tasks, reason=reason, yield_between=True
    )

    # --- verify the load-bearing unit's gist was admitted --------------
    ctx = pipeline.ctx
    u3_gist_label = next((l for l in ctx.labels() if l.startswith("u3/")),
                         None)
    u3 = ctx.get(u3_gist_label) if u3_gist_label else None
    u3_view = {
        "gist": (u3.gist if u3 else None),
        "raw_present": bool(u3 and u3.raw),
    } if u3 else {"gist": None, "raw_present": False}

    # --- selective unfolding: G -> raw for u3 -------------------------
    from delm.core.unfolding import Unfolding
    unf = Unfolding(ctx)
    unfolded = None
    if u3_gist_label:
        u = unf.deep_unfold(u3_gist_label)
        unfolded = {"gist": u.gist.gist if u.gist else None,
                   "raw": u.raw}

    out = {
        "admitted_gists": list(ctx.labels()),
        "u3_gist_label": u3_gist_label,
        "u3_view": u3_view,
        "unfolded_u3": unfolded,
        "final_answer": outcome.answer,
        "queue_exhausted": outcome.queue_exhausted,
        "n_workers": workers,
        "worker_admitted": {w.worker_id: w.admitted for w in outcome.workers},
    }

    if verbose:
        print("=== DELM end-to-end demo (no API key) ===")
        print(f"queue exhausted : {out['queue_exhausted']}")
        print(f"admitted gists  : {out['admitted_gists']}")
        print(f"per-worker adm  : {out['worker_admitted']}")
        print(f"u3 admitted as  : {u3_gist_label}")
        print(f"u3 gist (trunc) : {(u3_view['gist'] or '')[:90]}")
        print(f"u3 raw present  : {u3_view['raw_present']}")
        if unfolded:
            print(f"unfold raw (trunc): {(unfolded['raw'] or '')[:90]}")
        print(f"final answer    : {out['final_answer']}")
        print("=== demo OK ===")
    return out


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
