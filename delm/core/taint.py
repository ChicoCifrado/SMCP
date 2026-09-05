"""Taint model — provenance-based quarantine of untrusted content.

A *taint* marks a **source label** as untrusted. The key idea: taint is
attached to the *source* (the unit an agent read), not to the gist that
happens to summarize it. Any gist *derived from* a tainted source inherits
the taint (transitive closure), so a single poisoned source cannot spread
untrusted content through the shared context under many labels.

Levels
------
* ``CLEAN``      — no taint.
* ``SUSPICIOUS`` — a heuristic (or low-confidence signal) flagged the source;
  it is *quarantined*: still visible to agents, but rendered with an explicit
  "untrusted data" frame so the model treats it as data, not instructions.
* ``CONFIRMED``  — an operator or a high-confidence detector confirmed the
  source is adversarial; it is *blocked*: removed from the agent-visible
  render (the strongest quarantine).

The registry is deliberately small and synchronous so it can be unit-tested
and replayed. It is owned by the secure context (see
:mod:`delm.core.secure_context`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict


class TaintLevel(IntEnum):
    """Quarantine level of a source label."""
    CLEAN = 0
    SUSPICIOUS = 1   # quarantined: visible, framed as untrusted data
    CONFIRMED = 2   # blocked: removed from the agent-visible render


@dataclass
class TaintSource:
    """A tainted source label and why it is tainted.

    ``derived_from`` records the *immediate* untrusted parent (the source
    this one was derived from), enabling transitive closure: a gist derived
    from a poisoned source is itself tainted, and so on.
    """
    label: str
    level: TaintLevel
    reason: str = ""
    derived_from: str | None = None


@dataclass
class TaintRegistry:
    """Maps source labels to their quarantine level and reason.

    Monotonic by default: a label can be *escalated* (CLEAN -> SUSPICIOUS ->
    CONFIRMED) but not silently de-escalated, so a quarantine is sticky. An
    explicit :meth:`clear` is available for operator action.

    Transitive closure: :meth:`derived_level` returns the *effective* level
    of a label, walking ``derived_from`` up to the root and taking the
    maximum. A gist derived from a CONFIRMED source is effectively CONFIRMED
    even if its own label was only flagged SUSPICIOUS at admission time.
    """
    _levels: Dict[str, TaintLevel] = field(default_factory=dict)
    _reasons: Dict[str, str] = field(default_factory=dict)
    _derived: Dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------- write
    def flag(self, label: str, level: TaintLevel, reason: str = "",
             derived_from: str | None = None) -> None:
        """Set ``label`` to ``level`` (escalation only by default)."""
        if derived_from is not None:
            self._derived[label] = derived_from
        cur = self._levels.get(label, TaintLevel.CLEAN)
        if level > cur:
            self._levels[label] = level
            self._reasons[label] = reason or self._reasons.get(label, "")

    def flag_source(self, src: TaintSource) -> None:
        """Convenience: flag from a :class:`TaintSource`."""
        self.flag(src.label, src.level, src.reason, src.derived_from)

    def link(self, label: str, parent: str) -> None:
        """Record that ``label`` is derived from ``parent`` (transitive closure).

        Independent of any taint level: a clean gist derived from a poisoned
        one must still inherit the quarantine.
        """
        self._derived[label] = parent

    def escalate(self, label: str, level: TaintLevel, reason: str = "",
                 derived_from: str | None = None) -> None:
        """Alias for :meth:`flag`; only ever raises the level."""
        self.flag(label, level, reason, derived_from)

    def clear(self, label: str) -> None:
        """Operator action: remove any taint on ``label``."""
        self._levels.pop(label, None)
        self._reasons.pop(label, None)
        self._derived.pop(label, None)

    # ------------------------------------------------------------- read
    def level(self, label: str) -> TaintLevel:
        """Direct level of ``label`` (no transitive closure)."""
        return self._levels.get(label, TaintLevel.CLEAN)

    def reason(self, label: str) -> str:
        return self._reasons.get(label, "")

    def is_tainted(self, label: str) -> bool:
        return self._levels.get(label, TaintLevel.CLEAN) > TaintLevel.CLEAN

    def derived_level(self, label: str, _depth: int = 0) -> TaintLevel:
        """Effective level of ``label``, walking ``derived_from`` to the root.

        Returns the *maximum* level along the derivation chain, so a gist
        derived from a CONFIRMED source is effectively CONFIRMED.
        """
        if _depth > 64:  # cycle guard
            return self._levels.get(label, TaintLevel.CLEAN)
        direct = self._levels.get(label, TaintLevel.CLEAN)
        parent = self._derived.get(label)
        if parent is None:
            return direct
        return max(direct, self.derived_level(parent, _depth + 1))

    def quarantined(self) -> set[str]:
        """Labels at SUSPICIOUS or above (visible but framed)."""
        return {l for l, v in self._levels.items()
                if v >= TaintLevel.SUSPICIOUS}

    def blocked(self) -> set[str]:
        """Labels at CONFIRMED (removed from the agent-visible render)."""
        return {l for l, v in self._levels.items()
                if v >= TaintLevel.CONFIRMED}

    def sources(self) -> list[TaintSource]:
        """All tainted labels as :class:`TaintSource` (for audit)."""
        return [TaintSource(l, v, self._reasons.get(l, ""),
                            self._derived.get(l))
                for l, v in self._levels.items()]

    def all(self) -> Dict[str, TaintLevel]:
        return dict(self._levels)

    def __contains__(self, label: str) -> bool:
        return self.is_tainted(label)

    def __bool__(self) -> bool:
        return bool(self._levels)


__all__ = ["TaintLevel", "TaintSource", "TaintRegistry"]
