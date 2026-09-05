"""Gist, Summary, RefTag — the data model of the shared context.

DELM stores, per source unit, a three-level hierarchy (paper §A.1):

    raw source unit  u_i  --(compress)-->  Summary S_i  --(compress)-->  Gist G_i

Only the compact Gist is admitted into the visible shared context C.
The Summary (a reference-grounded evidence map) and the raw unit live in
backing stores (``L`` and ``R``) and are reachable only via selective
unfolding (see :mod:`delm.core.unfolding`).

A Gist carries a ``RefTag``: the first/last N words of the supporting span,
copied verbatim, used by the verifier to check that a claim is actually
grounded in the raw text (paper §A.3, "admission-time verification").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class GistKind(str, Enum):
    """What kind of progress a gist records.

    Mirrors the note types the SWE-bench reference implementation uses for
    its shared blackboard (``SharedLessons``); the long-context pipeline uses
    ``SOURCE``/``REASONING``.
    """

    SOURCE = "SOURCE"            # a long source unit (doc/chunk)
    REASONING = "REASONING"     # a completed reasoning trajectory
    FACT = "FACT"               # a verified finding / constraint
    FAIL = "FAIL"               # a falsified hypothesis / dead end
    PATCH_SUMMARY = "PATCH_SUMMARY"  # a candidate fix with evidence
    CLAIM = "CLAIM"             # short-lived "I'm working on X" (TTL'd)


@dataclass
class RefTag:
    """Verbatim head/tail of the span that supports a claim.

    ``head`` is the first ``n_words`` words of the supporting span, ``tail``
    the last ``n_words``. The verifier requires both to appear, in order and
    verbatim, in the raw source unit — a cheap, strong grounding check.
    """

    head: str
    tail: str
    n_words: int = 5

    def as_tuple(self) -> tuple[str, str]:
        return (self.head, self.tail)


@dataclass
class Summary:
    """Reference-grounded evidence map for one source unit (the S_i layer).

    ``bullets`` is a list of dicts, each with:
      * ``claim``: a single atomic claim (str)
      * ``ref``: a :class:`RefTag` pointing at the supporting span

    This is the "localization" layer: it tells an agent *where* in the raw
    text a fact lives without exposing the whole text.
    """

    claims: list[dict[str, Any]] = field(default_factory=list)
    raw_unit: str = ""

    def to_text(self) -> str:
        lines = []
        for b in self.claims:
            ref: RefTag = b["ref"]
            lines.append(f"- {b['claim']}  [ref: {ref.head!r} ... {ref.tail!r}]")
        return "\n".join(lines) if lines else ""


@dataclass
class Gist:
    """The compact, admitted entry of the shared context (the G_i layer).

    Only ``Gist`` objects are visible to all agents by default. ``gist`` is
    a short, highly compact one-paragraph view of the source unit's relevance
    to the task; ``kind`` classifies the progress; ``refs`` are the RefTags
    used at admission time.
    """

    label: str                      # stable id, e.g. "u1", "t3/patch"
    gist: str                       # the compact view (what agents read)
    kind: GistKind = GistKind.SOURCE
    refs: list[RefTag] = field(default_factory=list)
    # Backing pointers — *not* part of the visible gist, only used to
    # resolve selective unfolding (G -> S -> raw).
    summary: Summary | None = None
    raw: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    # Provenance (set at admission time, see :mod:`delm.core.provenance`):
    #   * ``author_id``  — which agent admitted this gist
    #   * ``digest``     — canonical SHA-256 of the gist content
    #   * ``signature`` — the agent's signature over the digest
    #   * ``sig_kind``  — "ed25519" or "hmac"
    # These are *not* part of the visible gist text; they are metadata the
    # trust gate and ledger use to verify provenance.
    author_id: str = ""
    digest: str = ""
    signature: bytes = b""
    sig_kind: str = ""

    def to_prompt(self) -> str:
        """Render the gist as it appears in an agent's shared-context view."""
        return f"[{self.label}] {self.gist}"

    def __str__(self) -> str:
        return self.to_prompt()
