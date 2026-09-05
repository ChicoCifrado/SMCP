"""Selective unfolding (paper §A.2).

Agents read the compact gist layer by default. When a gist is not enough, an
agent *selectively unfolds* a label, in two stages:

  * ``G -> S``  (UNFOLD):        retrieve the reference-grounded Summary.
  * ``S -> raw``(DEEP_UNFOLD):   retrieve the raw source unit.

Unfolding is on-demand and coarse-to-fine: an agent pays for detail only when
it needs it. Unfolded content is *local to the requesting call* — it is NOT
written back into the shared context, so the gist layer stays clean for the
other agents (paper: "prevents detailed intermediate content from polluting
the shared context").

Neighborhood-aware raw retrieval: requesting label ``n`` also returns
``n-1`` and ``n+1`` (off-by-one absorption), mirroring the paper.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from delm.core.gist import Gist, Summary
from delm.core.shared_context import SharedContext
from delm.core.taint import TaintLevel


@dataclass
class Unfolded:
    label: str
    gist: Gist | None = None
    summary: Summary | None = None
    raw: str | None = None
    neighbors: list[str] = None  # type: ignore


class Unfolding:
    """Coarse-to-fine, on-demand retrieval over a :class:`SharedContext`."""

    def __init__(self, ctx: SharedContext) -> None:
        self.ctx = ctx
        # Quarantine hook: label -> effective taint level. If ``ctx`` is a
        # SecureSharedContext (it exposes a ``taint`` registry), the real
        # derived level is used, so a CONFIRMED gist's raw is withheld from
        # deep_unfold. Otherwise (a plain SharedContext) the level is CLEAN
        # and nothing is quarantined.
        taint = getattr(ctx, "taint", None)
        if taint is not None:
            self._taint_level = lambda label: taint.derived_level(label)
        else:
            self._taint_level = lambda label: TaintLevel.CLEAN

    def _quarantined(self, label: str) -> bool:
        return self._taint_level(label) >= TaintLevel.CONFIRMED

    def unfold(self, label: str) -> Unfolded:
        """``G -> S``: return the gist plus its reference-grounded Summary.

        A ``CONFIRMED`` (blocked) label is quarantined: the gist/summary are
        withheld, not just the raw, so a blocked source cannot be read back
        through the unfold path.
        """
        if self._quarantined(label):
            return Unfolded(label=label)
        g = self.ctx.get(label)
        if g is None:
            return Unfolded(label=label)
        return Unfolded(label=label, gist=g, summary=g.summary)

    def deep_unfold(self, label: str, with_neighbors: bool = True) -> Unfolded:
        """``S -> raw``: return the raw unit (and optional neighbors).

        A ``CONFIRMED`` label is quarantined: the raw (the most dangerous
        injection vector) is withheld.
        """
        if self._quarantined(label):
            return Unfolded(label=label)
        u = self.unfold(label)
        if u.gist is None:
            return u
        u.raw = u.gist.raw
        if with_neighbors:
            u.neighbors = self._neighbors(label)
        return u

    def _neighbors(self, label: str) -> list[str]:
        """Labels of the raw units adjacent to ``label`` (n-1, n+1)."""
        out: list[str] = []
        # Gist labels in this framework are stable strings; neighbors are
        # resolved by prefix convention (e.g. "u12" -> "u11", "u13").
        import re
        m = re.match(r"^(.*?)(\d+)$", label)
        if not m:
            return out
        prefix, num = m.group(1), int(m.group(2))
        for cand in (prefix + str(num - 1), prefix + str(num + 1)):
            if self.ctx.get(cand) is not None:
                out.append(cand)
        return out

    def batch(self, labels: list[str], deep: bool = False) -> list[Unfolded]:
        """Unfold several labels in one call (e.g. an agent's per-step request)."""
        return [self.deep_unfold(l) if deep else self.unfold(l) for l in labels]
