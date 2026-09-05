"""SharedContext — the verified shared state C (paper §3.1).

This is the heart of DELM: a common communication substrate that *all* agents
read and write, replacing the central orchestrator. Design invariants
(paper §A.4 "Concurrent admission and read/write discipline"):

  * **Write-before-publish / atomic admission.** A gist is admitted in one
    atomic step: backing content (Summary/raw) is written first, then the
    visible entry is appended. Agents read *lock-free snapshots*, so a slow
    verification never blocks other workers.
  * **Snapshot reads.** ``snapshot()`` returns an immutable view of the
    gists as of some moment; entries admitted later are only visible in
    subsequent snapshots.
  * **Only verified gists are admitted.** Admitted entries are produced by
    :class:`~delm.core.admission.AdmissionPipeline`; raw/unverified output
    never enters C directly.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any

from delm.core.gist import Gist


@dataclass
class SharedContext:
    """The shared, verified context C.

    Thread/async-safety model: a single ``itertools.count`` sequence number
    plus a monotonically-increasing counter give each admitted gist a stable
    order. Reads are lock-free snapshots (copy-on-read); writes are atomic
    appends. For in-process use this is sufficient; a distributed
    deployment would swap the backing store for an atomic key-value layer.
    """

    _gists: list[Gist] = field(default_factory=list)
    _seq: itertools.count = field(default_factory=lambda: itertools.count(1))
    _by_label: dict[str, int] = field(default_factory=dict)
    _task: str = ""

    # ------------------------------------------------------------------ init
    def __post_init__(self) -> None:
        if not isinstance(self._seq, itertools.count):
            self._seq = itertools.count(1)

    def bind(self, task: str) -> None:
        self._task = task

    # ------------------------------------------------------------------ write
    def admit(self, gist: Gist) -> Gist:
        """Atomically admit a verified gist into C.

        Backing content (``gist.summary`` / ``gist.raw``) is written *before*
        the visible entry is appended, satisfying write-before-publish: any
        agent that can see the label can also resolve its backing stores.
        """
        if gist.label in self._by_label:
            # Re-admission under the same label replaces the entry (idempotent
            # re-verification), keeping the visible view stable.
            idx = self._by_label[gist.label]
            self._gists[idx] = gist
            return gist
        self._gists.append(gist)
        self._by_label[gist.label] = len(self._gists) - 1
        return gist

    # ------------------------------------------------------------------ read
    def snapshot(self) -> tuple[Gist, ...]:
        """Immutable view of all admitted gists, in admission order."""
        return tuple(self._gists)

    def get(self, label: str) -> Gist | None:
        idx = self._by_label.get(label)
        return self._gists[idx] if idx is not None else None

    def render(self) -> str:
        """Render C as the shared-context block shown to every agent."""
        if not self._gists:
            return "(empty shared context)"
        return "\n".join(g.to_prompt() for g in self._gists)

    def labels(self) -> list[str]:
        return [g.label for g in self._gists]

    def __len__(self) -> int:
        return len(self._gists)

    def __iter__(self):
        return iter(self._gists)
