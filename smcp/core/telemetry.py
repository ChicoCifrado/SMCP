"""Turning a stream of utilisation samples into one dispatchable number.

This is the part of NVIDIA PAIR that is worth copying almost verbatim, because
it encodes two mistakes that are easy to make and hard to notice.

**The first: a node that stops reporting is not idle.** When telemetry goes
stale, its pressure becomes :data:`UNKNOWN_GPU_PRESSURE` — which is ``1``, not
``0``. Zero would mean "nothing running, send it everything", and a peer that
crashed, was suspended, or was deliberately silent would immediately become
the most attractive node in the mesh. The same reasoning already applies to
:class:`~smcp.core.timechain.Timechain`: evidence that something *was* proved is
not the same as evidence it is still true, and unproven is not idle.

**The second: the last sample is not the state.** A single 100% spike would
make a healthy node look saturated, so utilisation is smoothed with an EWMA
before it is banded. And the bands have asymmetric hysteresis — rising at
40/70/85 but falling at 35/65/80 — so a node hovering on a boundary does not
flip bands every few seconds and make routing oscillate between it and its
peers. A ranking that flickers is a ranking that keeps recomputing for no
reason and sends work back and forth.

What PAIR does *not* do is any of this over verified data: these samples are
self-reported by design (see :mod:`smcp.core.capability`). The signing in this
module makes a wrong reading attributable, not impossible.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Sequence

#: Freshness window. Beyond this a sample is not evidence of current pressure.
TELEMETRY_FRESHNESS_S = 10.0

#: EWMA smoothing factor. 0.35 reacts within a few ticks while still ignoring
#: a lone spike.
EWMA_ALPHA = 0.35

#: Pressure band boundaries, ascending. Utilisation at or above a boundary
#: steps up into that band.
BANDS_UP = (40, 70, 85)

#: Boundaries at which a band steps *down*. Strictly below BANDS_UP, so a value
#: sitting exactly on a boundary is stable instead of oscillating.
BANDS_DOWN = (0, 35, 65, 80)

MAX_PRESSURE = 3

#: Pressure attributed to a node whose telemetry is missing or stale.
#:
#: Deliberately **not zero**. Zero is a claim — "this node is idle" — and a
#: node that is not reporting cannot make that claim. One is "unknown, so treat
#: it as ordinary", which keeps the mesh from dumping work on a peer that went
#: silent, while still preferring a node that says it is idle (band 0).
UNKNOWN_GPU_PRESSURE = 1


def pressure_band(utilization: float) -> int:
    """Band a utilisation value with no memory of the previous band."""
    for i, edge in enumerate(BANDS_UP):
        if utilization < edge:
            return i
    return MAX_PRESSURE


def pressure_with_hysteresis(utilization: float, previous: int) -> int:
    """Band a utilisation value while resisting oscillation.

    Steps up as soon as a rising edge is crossed, but only steps down once
    utilisation has fallen below the *lower* edge. A value oscillating around
    40 therefore settles instead of alternating between bands 0 and 1.
    """
    if previous < 0 or previous > MAX_PRESSURE:
        return pressure_band(utilization)
    p = previous
    while p < MAX_PRESSURE and utilization >= BANDS_UP[p]:
        p += 1
    while p > 0 and utilization < BANDS_DOWN[p]:
        p -= 1
    return p


@dataclass
class GpuTelemetry:
    """Per-node smoothing state. One instance per node in the mesh."""

    node_id: str
    ewma: float = 0.0
    pressure: int = 0
    has_ewma: bool = False
    received_at: float = 0.0
    age_at_receipt: float = 0.0
    samples: int = 0

    def pressure_at(self, now: float) -> int:
        """This node's pressure *now*, honouring freshness.

        The sample carries its own age (measured where it was produced, so a
        slow gossip hop cannot launder a stale reading into a fresh one), and
        that age keeps growing with wall clock until it exceeds the window.
        """
        if not self.has_ewma:
            return UNKNOWN_GPU_PRESSURE
        if self.age_at_receipt + max(0.0, now - self.received_at) > \
                TELEMETRY_FRESHNESS_S:
            return UNKNOWN_GPU_PRESSURE
        return self.pressure


@dataclass
class TelemetryView:
    """The mesh's current read on every node, and its canonical form.

    ``to_view()`` is the part that matters for SMCP: it is a deterministic
    serialisation of the whole mesh's belief, so its digest is a single hash
    that can be chained into the ledger and, eventually, published as a BSV
    ``OP_RETURN``. That makes the ranking itself attestable — you can prove
    later what the mesh thought the load was, without publishing any node's
    capacity.
    """

    #: node_id -> state
    nodes: dict[str, GpuTelemetry] = field(default_factory=dict)
    generation: int = 0

    # -- ingestion ----------------------------------------------------------
    def observe(self, node_id: str, utilization_percent: Optional[int], *,
                observed_at: float, now: Optional[float] = None) -> int:
        """Fold one sample in and return this node's pressure afterwards.

        ``utilization_percent=None`` means the node is reporting but cannot
        read its own utilisation (an old driver, or a shared GPU). It is
        recorded as unknown rather than zero, for the reason above.
        """
        now = time.time() if now is None else now
        age = max(0.0, now - observed_at)
        # A sample that arrives older than the freshness window is not evidence
        # of anything; record the node as present but unreadable. A node that
        # reports no utilisation is the same case: present, but it cannot make
        # a claim, so it must not inherit an idle band.
        util: Optional[int] = utilization_percent
        if age > TELEMETRY_FRESHNESS_S or util is None:
            util = None
        st = self.nodes.get(node_id) or GpuTelemetry(node_id=node_id)

        before = st.pressure_at(now)
        st.received_at = now
        st.age_at_receipt = min(age, TELEMETRY_FRESHNESS_S + 1.0)
        st.samples += 1
        if util is not None:
            value = float(util)
            if not st.has_ewma:
                st.ewma = value
                st.pressure = pressure_band(value)
            else:
                st.ewma = EWMA_ALPHA * value + (1 - EWMA_ALPHA) * st.ewma
                st.pressure = pressure_with_hysteresis(st.ewma, st.pressure)
            st.has_ewma = True
        self.nodes[node_id] = st
        after = st.pressure_at(now)
        if before != after:
            self.generation += 1
        return after

    # -- read ---------------------------------------------------------------
    def pressure_of(self, node_id: str, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        st = self.nodes.get(node_id)
        return st.pressure_at(now) if st else UNKNOWN_GPU_PRESSURE

    def is_fresh(self, node_id: str, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        st = self.nodes.get(node_id)
        if st is None or not st.has_ewma:
            return False
        return st.age_at_receipt + max(0.0, now - st.received_at) <= \
            TELEMETRY_FRESHNESS_S

    def nodes_claiming_idle(self) -> tuple[str, ...]:
        """Nodes that have affirmatively reported band 0."""
        now = time.time()
        return tuple(sorted(
            nid for nid, st in self.nodes.items()
            if st.has_ewma and st.pressure_at(now) == 0))

    def nodes_silent(self) -> tuple[str, ...]:
        """Nodes present in the view whose telemetry has gone stale."""
        now = time.time()
        return tuple(sorted(nid for nid in self.nodes
                            if not self.is_fresh(nid, now)))

    # -- ranking ------------------------------------------------------------
    def rank(self, pending: dict[str, int] | None = None,
             now: Optional[float] = None) -> list[str]:
        """Order nodes by load: pending work plus GPU pressure, then pressure,
        then id.

        The tie-break on id is not cosmetic — it makes the order a pure
        function of its inputs, so two observers that saw the same telemetry
        compute the same ranking and therefore the same digest.
        """
        now = time.time() if now is None else now
        pending = pending or {}

        def key(nid: str) -> tuple[int, int, str]:
            return (pending.get(nid, 0) + self.pressure_of(nid, now),
                    self.pressure_of(nid, now),
                    nid)

        return sorted(self.nodes, key=key)

    # -- canonical form -----------------------------------------------------
    def to_view(self, now: Optional[float] = None) -> dict[str, Any]:
        """A deterministic snapshot of the whole view.

        Only *derived* state goes in: pressures, never the raw utilisation
        samples. That is deliberate — the ranking is what the mesh decided, and
        it is safe to publish; the raw telemetry is the node's own business.
        """
        now = time.time() if now is None else now
        return {
            "v": 1,
            "generation": self.generation,
            "nodes": [
                {
                    "node_id": nid,
                    "pressure": self.pressure_of(nid, now),
                    "fresh": self.is_fresh(nid, now),
                    "samples": st.samples,
                }
                for nid, st in sorted(self.nodes.items())
            ],
        }

    def view_digest(self, now: Optional[float] = None) -> str:
        import hashlib

        blob = json.dumps(self.to_view(now), sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()


@dataclass
class UtilizationSample:
    """One node's reading of its own GPU utilisation at a moment."""

    node_id: str
    utilization_percent: Optional[int]
    observed_at: float
    #: Wall clock on the *producing* node. Only meaningful as a freshness hint
    #: when its clock is roughly right; it is never treated as an ordering
    #: authority, which is what the anchored ledger is for.
    source_clock: float = 0.0

    def age(self, now: float) -> float:
        return max(0.0, now - self.observed_at)


def sample_from_gpus(gpus: Iterable[Any], *, node_id: str, now: float
                     ) -> UtilizationSample:
    """Reduce a node's GPUs to one utilisation figure.

    The maximum, not the mean or the sum: the scheduler acts on how saturated
    the *bottleneck* is, and averaging a saturated GPU with an idle one hides
    exactly the node that cannot accept more work.
    """
    best: Optional[int] = None
    for g in gpus:
        u = getattr(g, "utilization_percent", None)
        if u is None:
            continue
        best = int(u) if best is None else max(best, int(u))
    return UtilizationSample(node_id=node_id, utilization_percent=best,
                             observed_at=now, source_clock=time.time())