"""Expansion policy — the `generate_more` heuristic (round-2), made concrete.

The pipeline interface has a "generate more subtasks" step, but the
*heuristic of when* was not tuned. This module fills that gap with a small,
deterministic, fully testable policy.

Decision logic (in order):

1. **Queue alive** (pending or running > 0)      -> do not expand.
2. **Nothing learned** (done + failed == 0)      -> do not expand
   (no signal yet; the finalizer should just answer or wait).
3. **Target reached** (only when ``target_progress`` is set): if
   ``done / (done + failed) >= target_progress`` -> do not expand
   (the success ratio already satisfies the caller's goal).
4. **Budget exhausted** (budget_remaining <= 0)  -> finalize.
5. **Failure storm** (fail_ratio >= max_fail_ratio) -> finalize: expanding
   against a task family that mostly fails just burns budget. Terminal by
   design: there is no cooldown/retry — if the caller wants to retry the
   failed tasks instead of expanding, that decision belongs to
   ``generate_more`` itself, not to this policy.
6. Otherwise -> expand by a bounded burst: n_new = min(max_burst,
   budget_remaining).

The policy is pure: it reads an ExpansionState and returns an
ExpansionDecision, so it can be unit-tested and replayed. No randomness,
no LLM in the loop.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExpansionState:
    """What the policy sees. All counters are in *tasks*, not tokens."""
    pending: int
    running: int
    done: int
    failed: int
    budget_remaining: int          # max additional tasks allowed (hard cap)
    target_progress: float | None = None  # opt-in success-ratio goal in (0, 1]


@dataclass(frozen=True)
class ExpansionDecision:
    expand: bool
    n_new: int
    reason: str


class ExpansionPolicy:
    """Deterministic when-to-expand heuristic."""

    def __init__(self, max_burst: int = 4, max_fail_ratio: float = 0.5):
        if max_burst < 1:
            raise ValueError("max_burst must be >= 1")
        if not (0.0 < max_fail_ratio <= 1.0):
            raise ValueError("max_fail_ratio must be in (0, 1]")
        self.max_burst = max_burst
        self.max_fail_ratio = max_fail_ratio

    def decide(self, s: ExpansionState) -> ExpansionDecision:
        if s.pending > 0 or s.running > 0:
            return ExpansionDecision(False, 0, "queue-alive")
        total = s.done + s.failed
        if total == 0:
            return ExpansionDecision(False, 0, "no-signal")
        if s.target_progress is not None:
            if not (0.0 < s.target_progress <= 1.0):
                raise ValueError("target_progress must be in (0, 1] or None")
            progress = s.done / total
            if progress >= s.target_progress:
                return ExpansionDecision(False, 0,
                                         f"target-reached ({progress:.2f})")
        if s.budget_remaining <= 0:
            return ExpansionDecision(False, 0, "budget-exhausted")
        fail_ratio = s.failed / total
        if fail_ratio >= self.max_fail_ratio:
            return ExpansionDecision(False, 0,
                                     f"failure-storm ({fail_ratio:.2f})")
        n = min(self.max_burst, s.budget_remaining)
        return ExpansionDecision(True, n,
                                 f"drained, burst={n} "
                                 f"(fail_ratio={fail_ratio:.2f})")


__all__ = ["ExpansionState", "ExpansionDecision", "ExpansionPolicy"]
