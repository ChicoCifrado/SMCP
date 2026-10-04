"""TaskQueue — the dependency-aware task queue T (paper §3.1, §A.4).

T stores pending subtasks. Agents *claim* tasks asynchronously; a task with
``[deps: a, b]`` becomes eligible only after ``a`` and ``b`` complete. When
the queue empties, the most recently completed agent may call
``generate_more`` to append fresh subtasks (or return ``[DONE]`` to stop).

Eligibility is computed on-demand from completion state, so no central
scheduler is needed: any worker can ask "what is eligible right now?".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TaskState(str, Enum):
    PENDING = "pending"
    ELIGIBLE = "eligible"
    RUNNING = "running"
    DONE = "done"


@dataclass
class Task:
    """One subtask in the queue.

    ``deps`` are labels of upstream tasks; ``body`` is the instruction given
    to the claiming agent. ``kind`` lets the orchestrator route it to the
    right worker (e.g. ``"solve"`` vs ``"summarize"``).
    """

    label: str
    body: str
    kind: str = "generic"
    deps: list[str] = field(default_factory=list)
    state: TaskState = TaskState.PENDING
    result: Any = None
    error: str | None = None

    def eligible(self, done: set[str]) -> bool:
        return all(d in done for d in self.deps)


@dataclass
class TaskQueue:
    """Dependency-aware queue of :class:`Task`."""

    _tasks: dict[str, Task] = field(default_factory=dict)
    _order: list[str] = field(default_factory=list)
    _done: set[str] = field(default_factory=set)

    # ------------------------------------------------------------ enqueue
    def enqueue(self, task: Task) -> Task:
        if task.label in self._tasks:
            raise ValueError(f"duplicate task label {task.label!r}")
        self._tasks[task.label] = task
        self._order.append(task.label)
        return task

    def enqueue_many(self, tasks: list[Task]) -> None:
        for t in tasks:
            self.enqueue(t)

    # ------------------------------------------------------------ claim
    def eligible_labels(self) -> list[str]:
        """Labels of tasks whose deps are all done (ready to claim)."""
        out = [
            lbl
            for lbl in self._order
            if (t := self._tasks[lbl]).state in (TaskState.PENDING, TaskState.ELIGIBLE)
            and t.eligible(self._done)
        ]
        return out

    def claim(self, label: str) -> Task:
        """Mark a task running. Caller must have checked ``eligible_labels``.

        Idempotent-safe: a task already RUNNING/DONE cannot be re-claimed, so
        two workers racing on the same label only ever claim it once. This is
        the queue's single serialization point.
        """
        t = self._tasks[label]
        if t.state not in (TaskState.PENDING, TaskState.ELIGIBLE):
            raise ValueError(f"task {label!r} already {t.state.value}")
        if not t.eligible(self._done):
            raise ValueError(f"task {label!r} not eligible (unmet deps {t.deps})")
        t.state = TaskState.RUNNING
        return t

    # ------------------------------------------------------------ complete
    def complete(self, label: str, result: Any = None, error: str | None = None) -> Task:
        t = self._tasks[label]
        t.state = TaskState.DONE
        t.result = result
        t.error = error
        self._done.add(label)
        return t

    def failed(self, label: str, error: str) -> Task:
        t = self._tasks[label]
        t.state = TaskState.DONE
        t.error = error
        self._done.add(label)
        return t

    # ------------------------------------------------------------ inspect
    def is_empty(self) -> bool:
        return all(t.state == TaskState.DONE for t in self._tasks.values())

    def pending_count(self) -> int:
        return sum(1 for t in self._tasks.values() if t.state != TaskState.DONE)

    def get(self, label: str) -> Task:
        return self._tasks[label]

    def all_labels(self) -> list[str]:
        return list(self._order)

    def done_labels(self) -> set[str]:
        return set(self._done)

    def cycle_check(self) -> list[str]:
        """Return labels involved in a dependency cycle (should be empty)."""
        # Simple DFS cycle detection over the deps graph.
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {lbl: WHITE for lbl in self._order}
        cycle: list[str] = []

        def visit(node: str) -> bool:
            color[node] = GRAY
            for d in self._tasks[node].deps:
                if d not in color:
                    continue
                if color[d] == GRAY:
                    cycle.append(d)
                    return True
                if color[d] == WHITE and visit(d):
                    return True
            color[node] = BLACK
            return False

        for lbl in self._order:
            if color[lbl] == WHITE:
                visit(lbl)
        return cycle
