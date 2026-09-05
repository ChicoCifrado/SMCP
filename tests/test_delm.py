"""Unit + end-to-end tests for the DELM framework.

Every test is deterministic (no network, no API key) and locks in one
mechanism from the paper: task queue, parallel claim, admission
verification, shared context, selective unfolding, and the full pipeline.
"""
from __future__ import annotations

import asyncio

import pytest

from delm.core.gist import Gist, GistKind, RefTag, Summary
from delm.core.shared_context import SharedContext
from delm.core.task_queue import Task, TaskQueue
from delm.core.admission import AdmissionPipeline
from delm.core.verifier import RuleVerifier, VerifyResult
from delm.core.unfolding import Unfolding
from delm.core.llm import FakeLLMClient
from delm.core.pipeline import DelmPipeline
from delm.demo.run_demo import run as demo_run
from tests.conftest import toy_units


# ------------------------------------------------------------- task queue
def test_queue_eligibility_and_deps():
    q = TaskQueue()
    q.enqueue(Task(label="a", body="A", deps=[]))
    q.enqueue(Task(label="b", body="B", deps=["a"]))
    assert q.eligible_labels() == ["a"]
    q.claim("a")
    q.complete("a")
    # b becomes eligible only after a completes
    assert q.eligible_labels() == ["b"]
    q.claim("b")
    q.complete("b")
    assert q.is_empty()


def test_queue_rejects_unmet_dep_claim():
    q = TaskQueue()
    q.enqueue(Task(label="a", body="A", deps=[]))
    q.enqueue(Task(label="b", body="B", deps=["a"]))
    with pytest.raises(ValueError):
        q.claim("b")  # a not done -> b not eligible
    q.claim("a")
    q.complete("a")
    q.claim("b")  # now eligible
    q.complete("b")


def test_queue_rejects_double_claim():
    q = TaskQueue()
    q.enqueue(Task(label="a", body="A", deps=[]))
    q.claim("a")
    q.complete("a")
    with pytest.raises(ValueError):
        q.claim("a")  # already DONE


def test_queue_cycle_detection():
    q = TaskQueue()
    q.enqueue(Task(label="a", body="A", deps=["b"]))
    q.enqueue(Task(label="b", body="B", deps=["a"]))
    assert q.cycle_check()  # non-empty -> a cycle exists


# ------------------------------------------------------------ shared context
def test_shared_context_snapshot_and_admit():
    ctx = SharedContext()
    g1 = Gist(label="g1", gist="one", kind=GistKind.FACT)
    g2 = Gist(label="g2", gist="two", kind=GistKind.FACT)
    ctx.admit(g1)
    snap1 = ctx.snapshot()
    ctx.admit(g2)
    snap2 = ctx.snapshot()
    assert len(snap1) == 1
    assert len(snap2) == 2
    assert [g.label for g in snap2] == ["g1", "g2"]
    assert ctx.get("g2").gist == "two"
    assert "one" in ctx.render()


def test_shared_context_readme_render():
    ctx = SharedContext()
    ctx.admit(Gist(label="x", gist="hello", kind=GistKind.FACT))
    assert "[x] hello" in ctx.render()


# ------------------------------------------------------- admission: source
def test_source_admission_grounded_accepted():
    """A Summary whose RefTags are verbatim in the raw unit is admitted."""
    llm = FakeLLMClient()
    verifier = RuleVerifier()
    ctx = SharedContext()
    raw = ("CONSTRAINT: a transaction must be journaled before it is acked; "
          "acking before journaling is forbidden under all failure modes.")
    summary = Summary(
        claims=[{
            "claim": "a transaction must be journaled before it is acked",
            "ref": RefTag(head="a transaction must be journaled",
                           tail="under all failure modes."),
        }],
        raw_unit=raw,
    )
    adm = AdmissionPipeline(llm=llm, verifier=verifier)

    async def go():
        # Directly verify the source path (admission.admit_source uses the
        # LLM to build the summary; here we verify the gate on a known-good
        # Summary to lock the acceptance behavior).
        return await verifier.verify("source",
                                     {"raw": raw, "summary": summary})

    res = asyncio.run(go())
    assert res.ok is True


def test_source_admission_ungrounded_rejected():
    """A Summary whose RefTag is NOT in the raw unit is rejected."""
    verifier = RuleVerifier()
    raw = "CONSTRAINT: a transaction must be journaled before it is acked."
    summary = Summary(
        claims=[{
            "claim": "a totally different claim",
            "ref": RefTag(head="this text is not in the raw unit at all",
                           tail="nor is this tail"),
        }],
        raw_unit=raw,
    )

    async def go():
        return await verifier.verify("source",
                                     {"raw": raw, "summary": summary})

    res = asyncio.run(go())
    assert res.ok is False
    assert res.reasons  # has a reason


# ------------------------------------------------- admission: trajectory
def test_trajectory_admission_faithful_accepted():
    """A gist that is a faithful (n-gram) subset of the trajectory passes."""
    verifier = RuleVerifier(min_ngram_words=3)
    result = ("The load-bearing constraint is that a transaction must be "
              "journaled before it is acked to the client.")
    # A contiguous prefix ending mid-sentence: every gist 3-gram appears in
    # result, so it is a faithful (n-gram) subset.
    gist = ("The load-bearing constraint is that a transaction")

    async def go():
        return await verifier.verify("trajectory",
                                     {"result": result, "gist": gist})

    res = asyncio.run(go())
    assert res.ok is True


def test_trajectory_admission_unfaithful_rejected():
    """A gist that invents claims not in the trajectory is rejected."""
    verifier = RuleVerifier(min_ngram_words=3)
    result = "The load-bearing constraint is that a transaction must be " \
             "journaled before it is acked."
    gist = "The constraint is that the moon is made of cheese and the " \
           "sun is a green dragon."

    async def go():
        return await verifier.verify("trajectory",
                                     {"result": result, "gist": gist})

    res = asyncio.run(go())
    assert res.ok is False


# ------------------------------------------------------------ unfolding
def test_unfolding_g_to_s_to_raw():
    ctx = SharedContext()
    raw = "RAW-UNIT-TEXT"
    summary = Summary(claims=[{"claim": "c",
                               "ref": RefTag(head="RAW", tail="TEXT")}],
                      raw_unit=raw)
    g = Gist(label="u3", gist="gist-of-u3", kind=GistKind.SOURCE,
             summary=summary, raw=raw)
    ctx.admit(g)
    unf = Unfolding(ctx)
    u = unf.deep_unfold("u3")
    assert u.gist is not None
    assert u.summary is not None
    assert u.raw == raw


def test_unfolding_neighbors():
    ctx = SharedContext()
    for lbl in ("u11", "u12", "u13"):
        ctx.admit(Gist(label=lbl, gist=f"g-{lbl}", kind=GistKind.SOURCE,
                       raw=f"raw-{lbl}"))
    unf = Unfolding(ctx)
    u = unf.deep_unfold("u12")
    assert set(u.neighbors) == {"u11", "u13"}


# ------------------------------------------------------------ full pipeline
def test_end_to_end_pipeline_runs():
    """The public DelmPipeline drives queue -> workers -> admit -> finalize."""
    from delm.core.llm import FakeLLMClient
    from delm.core.task_queue import Task

    toy = {lbl: txt for lbl, txt in toy_units()}

    async def reason(task: Task) -> str:
        return toy[task.label]

    async def go():
        pipe = DelmPipeline(llm=FakeLLMClient(), n_workers=4)
        tasks = [Task(label=lbl, body=f"inspect {lbl}", kind="solve")
                 for lbl in toy]
        return await pipe.run(tasks, reason=reason, yield_between=True)

    out = asyncio.run(go())
    assert out.queue_exhausted is True
    assert out.admitted_gists >= 1
    assert out.answer  # finalizer produced an answer
    # Parallelism: with 4 workers and yield_between, claims are distributed.
    admitted_by_worker = [w.admitted for w in out.workers]
    assert sum(admitted_by_worker) >= 1
    assert max(admitted_by_worker) <= 4  # no single worker hoarded all tasks


def test_demo_end_to_end():
    """Run the bundled demo and assert the load-bearing unit was admitted."""
    out = asyncio.run(demo_run())
    assert out["queue_exhausted"] is True
    assert out["u3_gist_label"] is not None
    assert out["u3_view"]["raw_present"] is True
    assert out["final_answer"]
    # u3's gist carries the load-bearing constraint text.
    assert "journaled" in out["u3_view"]["gist"]
