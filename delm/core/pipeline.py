"""Parallel workers and the DELM pipeline (Algorithm 1).

This is the decentralized half of the design. There is *no* central
orchestrator merging results; instead:

  * N workers run concurrently. Each is a :class:`Worker` that, in a loop:
      1. claims the next eligible task from the :class:`TaskQueue`;
      2. reads the current :class:`SharedContext` (a lock-free snapshot);
      3. does local reasoning (an :class:`LLMClient` call);
      4. routes the result through the :class:`AdmissionPipeline` so only a
         verified gist lands in the shared context;
      5. repeats until the queue is exhausted.
  * When the queue empties, the *last* worker to finish decides whether more
    subtasks are needed (``generate_more``); if so it enqueues them and the
    loop continues, otherwise it ``finalize``s the answer from the shared
    context.

The only synchronization is the atomic admission into the shared context and
the queue's eligibility check — exactly the paper's "concurrent admission
with disciplined reads and writes" (§A.4).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from delm.core.admission import AdmissionOutcome, AdmissionPipeline
from delm.core.gist import Gist, GistKind
from delm.core.ledger import TrustGate, TrustPolicy
from delm.core.expansion import ExpansionPolicy, ExpansionState
from delm.core.llm import LLMClient
from delm.core.metrics import MetricsTracker
from delm.core.provenance import KeyPair
from delm.core.secure_context import SecureSharedContext
from delm.core.shared_context import SharedContext
from delm.core.task_queue import Task, TaskQueue, TaskState


@dataclass
class WorkerResult:
    worker_id: int
    solved: int = 0
    failed: int = 0
    admitted: int = 0
    notes: list[str] = field(default_factory=list)


class Worker:
    """One decentralized agent.

    ``reason`` is the per-task inference step; by default it asks the
    :class:`LLMClient` and routes the answer through admission. Subclasses or
    the ``reason`` override can implement task-specific logic (e.g. a
    SWE-bench implementer that edits a repo and runs tests).
    """

    def __init__(self, worker_id: int, llm: LLMClient,
                 ctx: SharedContext, queue: TaskQueue,
                 admission: AdmissionPipeline,
                 reason: Callable[[Task], Awaitable[str]] | None = None,
                 yield_between: bool = False,
                 author_id: str | None = None,
                 key: "KeyPair | None" = None,
                 metrics: MetricsTracker | None = None):
        self.id = worker_id
        self.llm = llm
        self.ctx = ctx
        self.queue = queue
        self.admission = admission
        self._reason = reason
        # When True, yield to the event loop after each claim so concurrent
        # workers interleave. With a real (network) LLM this is implicit —
        # the await inside reason() already blocks; we make it explicit so a
        # deterministic fake client still spreads claims across workers.
        self.yield_between = yield_between
        # Provenance identity: the author_id this worker admits as, and the
        # key it signs with. A worker is *its* author; the secure context
        # verifies the signature against the registered public key.
        self.author_id = author_id or f"worker-{worker_id}"
        self.key = key
        # Optional per-pipeline cost/latency tracker (shared across workers).
        self.metrics = metrics
        self.result = WorkerResult(worker_id=worker_id)

    # ------------------------------------------------------------- reason
    async def _default_reason(self, task: Task) -> str:
        prompt = (
            f"[ROLE:SOLVER]\n"
            f"task {task.label} ({task.kind}): {task.body}\n"
            f"shared context so far:\n{self.ctx.render()}\n"
            "Solve the task. Be concise; state the concrete finding or the "
            "minimal change and its evidence."
        )
        return await self.llm.complete(prompt)

    async def reason(self, task: Task) -> str:
        return await (self._reason or self._default_reason)(task)

    # ------------------------------------------------------------- run
    async def run(self) -> WorkerResult:
        while True:
            if self.yield_between:
                await asyncio.sleep(0)  # let peer workers claim / interleave
            eligible = self.queue.eligible_labels()
            if not eligible:
                break
            # First-come claim: workers race on eligibility; the queue's
            # claim() is the single serialization point.
            task = self._claim(eligible)
            if task is None:
                break
            ok = await self._execute(task)
            if ok:
                self.result.admitted += 1
                self.result.solved += 1
            else:
                self.result.failed += 1
        return self.result

    def _claim(self, eligible: list[str]) -> Task | None:
        for label in eligible:
            try:
                return self.queue.claim(label)
            except ValueError:
                continue
        return None

    async def _execute(self, task: Task) -> bool:
        """Reason + admit, recording metrics when a tracker is attached."""
        if self.metrics is None:
            outcome = await self._admit(task, await self.reason(task))
            return outcome.admitted
        with self.metrics.timed(
            label=task.label, worker_id=f"w{self.id}",
            model=getattr(self.llm, "model", ""),
        ) as m:
            outcome = await self._admit(task, await self.reason(task))
            m.admitted = outcome.admitted
            m.attempts = outcome.attempts
        return outcome.admitted

    async def _admit(self, task: Task, raw: str) -> AdmissionOutcome:
        """Route a worker's raw result through the admission gate.

        The worker signs the gist under its own ``author_id``/``key`` so the
        secure context can verify provenance (who admitted what).
        """
        label = f"{task.label}/w{self.id}"
        kind = GistKind.FACT if task.kind == "solve" else GistKind.REASONING
        outcome = await self.admission.admit_trajectory(
            self.ctx, label, raw, kind=kind,
            author_id=self.author_id, key=self.key,
        )
        self.result.notes.append(
            f"{label}: admitted={outcome.admitted} (attempts={outcome.attempts})"
        )
        # Mark the task done either way (its finding is recorded, or it is a
        # dead end peers can now avoid).
        self.queue.complete(task.label)
        return outcome


@dataclass
class PipelineOutcome:
    answer: str
    admitted_gists: int
    rounds: int
    workers: list[WorkerResult]
    queue_exhausted: bool = True
    metrics: dict = field(default_factory=dict)


class DelmPipeline:
    """The full DELM loop (paper Algorithm 1) over one task set.

    Parameters
    ----------
    llm:
        Model-agnostic client (any :class:`LLMClient`).
    n_workers:
        Number of parallel decentralized agents.
    generate_more:
        Callable invoked by the *last* finishing worker when the queue is
        exhausted. It may return a list of new :class:`Task` to enqueue (the
        "generate more subtasks" step) or ``None`` to finalize.
    """

    def __init__(self, llm: LLMClient, n_workers: int = 4,
                 generate_more: Callable[[SharedContext, TaskQueue],
                                         list[Task] | None] | None = None,
                 secure: bool = True,
                 gate: TrustGate | None = None,
                 injection_threshold: int = 2,
                 metrics: MetricsTracker | None = None,
                 expansion_policy: ExpansionPolicy | None = None,
                 expansion_budget: int = 0):
        self.llm = llm
        self.n_workers = n_workers
        self.generate_more = generate_more
        if secure:
            self.ctx = SecureSharedContext(
                gate=gate or TrustGate(TrustPolicy.REQUIRE_SIGNED),
                injection_threshold=injection_threshold,
            )
        else:
            self.ctx = SharedContext()
        self.queue = TaskQueue()
        # Per-pipeline cost/latency tracker; attached to every worker and
        # dumped into PipelineOutcome.metrics at the end.
        self.metrics = metrics or MetricsTracker()
        # Optional deterministic when-to-expand heuristic. When set, the
        # last-worker step consults it with the real queue state (done /
        # failed / budget) and the generated burst is bounded to n_new.
        # expansion_budget > 0 caps the total tasks spawned this way.
        self.expansion_policy = expansion_policy
        self.expansion_budget = max(0, int(expansion_budget))
        self._expansion_spawned = 0
        self.admission = AdmissionPipeline(
            llm=llm,
            verifier=_default_verifier(llm),
        )
        # Per-worker signing keys (one author identity per worker). Generated
        # lazily in run(); their public keys are registered in the secure
        # context's keyring so admissions can be verified.
        self._keys: dict[int, KeyPair] = {}

    async def run(self, initial_tasks: list[Task],
                  max_rounds: int = 8,
                  reason: Callable[[Task], Awaitable[str]] | None = None,
                  yield_between: bool = False) -> PipelineOutcome:
        # Per-worker identities: one author_id + signing key per worker. The
        # secure context verifies each admission against the registered
        # public key, so a worker cannot admit under someone else's identity.
        for i in range(self.n_workers):
            if i not in self._keys:
                self._keys[i] = KeyPair.new(f"worker-{i}")
            if isinstance(self.ctx, SecureSharedContext):
                self.ctx.register_key(
                    f"worker-{i}",
                    self._keys[i].public_key,
                    self._keys[i].kind,
                )
        self.queue.enqueue_many(initial_tasks)
        workers = [
            Worker(i, self.llm, self.ctx, self.queue, self.admission,
                   reason=reason, yield_between=yield_between,
                   author_id=f"worker-{i}", key=self._keys[i],
                   metrics=self.metrics)
            for i in range(self.n_workers)
        ]
        rounds = 0
        while rounds < max_rounds:
            # All workers race on the shared queue until it is exhausted.
            await asyncio.gather(*(w.run() for w in workers))
            rounds += 1
            # Last-worker step: generate more subtasks or finalize.
            if self.queue.is_empty():
                more = self._maybe_expand(workers)
                if more:
                    self._expansion_spawned += len(more)
                    self.queue.enqueue_many(more)
                    continue
                break
            # If the queue is not empty but nothing is eligible (e.g. a
            # deadlock on unmet deps), break to avoid a spin.
            if not self.queue.eligible_labels():
                break
        answer = await self._finalize()
        return PipelineOutcome(
            answer=answer,
            admitted_gists=len(self.ctx),
            rounds=rounds,
            workers=[w.result for w in workers],
            metrics=self.metrics.aggregate(),
        )

    def _maybe_expand(self, workers: list[Worker]) -> list[Task] | None:
        """Last-worker step: decide (via ExpansionPolicy, if configured)
        whether to generate more subtasks, and bound the burst to n_new.

        Queue-state semantics: ``done`` counts tasks whose admission
        succeeded; ``failed`` counts completed-but-rejected ones (so
        ``done + failed == completed`` and the policy sees real signal).
        """
        if self.expansion_policy is None:
            return (self.generate_more(self.ctx, self.queue)
                    if self.generate_more else None)
        completed = len(self.queue.done_labels())
        failed = sum(w.result.failed for w in workers)
        done = max(0, completed - failed)
        if self.expansion_budget > 0:
            budget_remaining = max(
                0, self.expansion_budget - self._expansion_spawned)
        else:
            budget_remaining = 1 << 30  # unmanaged
        decision = self.expansion_policy.decide(ExpansionState(
            pending=0, running=0, done=done, failed=failed,
            budget_remaining=budget_remaining))
        if not decision.expand or self.generate_more is None:
            return None
        more = self.generate_more(self.ctx, self.queue) or []
        more = more[:decision.n_new]
        return more or None

    async def _finalize(self) -> str:
        prompt = (
            "[ROLE:FINALIZER]\n"
            "Produce the final answer strictly from the verified shared "
            "context below. Do not introduce new claims.\n"
            f"shared context:\n{self.ctx.render()}"
        )
        return await self.llm.complete(prompt)


# --- default verifier wiring -------------------------------------------
from delm.core.verifier import RuleVerifier  # noqa: E402  (local import)


def _default_verifier(llm: LLMClient) -> RuleVerifier:
    """DELM's default admission gate is the deterministic :class:`RuleVerifier`.

    Swap in :class:`LLMVerifier` (or a hybrid) for production; the pipeline
    does not care which implements the gate.
    """
    return RuleVerifier()
