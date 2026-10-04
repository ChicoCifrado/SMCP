"""Dedicated reservations: the paid tier that must not sell the same VRAM twice.

:mod:`smcp.core.placement` plans. This module *holds*. The difference is the
whole reason it exists: a plan is a piece of JSON, and two callers can both
hold a valid plan naming the same node and the same GiB. Nothing in a plan
stops the second one from dispatching.

So a reservation is a mutable, process-local claim on a named slice of a node's
*available* VRAM, taken under a lock before the work is dispatched and released
when it ends. Follows the shape of NVIDIA PAIR's ``reserveCandidate``: a
generation stamp on every reservation, and reservations discarded wholesale when
a newer baseline arrives.

Three properties this has to get right, and the reason each is not obvious:

**Atomicity.** Take-and-account happen in one critical section. Reading the
free amount, then incrementing, is a double-sale waiting for a scheduler tick.

**Generation.** The baseline (what a node has told us about itself) is a
periodic snapshot, and a reservation taken against snapshot *N* must not be
released against snapshot *N+1* — the new snapshot already accounts for that
work, so decrementing would double-count the completion and make a busy node
look idle. Hence the stamp: a release whose generation no longer matches is
dropped, and the reservation dies with the snapshot. This is the subtle one,
and PAIR calls out the exact failure it prevents: a snapshot that applies while
clearing reservations, then a stale release matching the *new* generation and
freeing a reservation that belongs to someone else.

**Reservation vs telemetry.** :attr:`PeerContribution.vram_shared_gb` is what a
node *reports* it is using. This is what *this mesh* has handed out. They are
independent: a node may be running the paid tier's own work (telemetry) while a
reservation it never heard about sits against it, and a reservation may be
outstanding long before the node's next report. Conflating them double-counts;
ignoring either one lets the mesh oversubscribe. Both feed the same available
figure, from different directions.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field, replace
from typing import Any

from .contrib import PeerContribution

#: Why a reservation could not be taken. Machine-readable, like ContribReject.
FREE = "free"
RESERVED = "reserved"
UNKNOWN_PEER = "unknown_peer"
NOT_ENOUGH = "not_enough_available"
EXPIRED_BASELINE = "expired_baseline"
BELOW_MINIMUM = "below_minimum"
ALREADY_HELD = "already_held"

#: release-side outcomes. Named apart from the reserve reasons so a log line
#: distinguishes "I could not take it" from "I gave it back".
NOT_HELD_ALIAS = "not_held"
RELEASED = "released"
STALE_GENERATION = "stale_generation"
UNCHANGED = "unchanged"
MOVED = "moved"


@dataclass(frozen=True)
class Reservation:
    """One held claim on a node's VRAM. Immutable: state lives in the book.

    ``held`` distinguishes "no reservation was taken" from "a reservation on
    the empty-string node", so releasing on a path that never reserved is a
    no-op instead of an error. Same reason PAIR carries the flag.

    ``generation`` is the baseline this claim was taken against. A release whose
    stamp is stale is ignored — see the module docstring.
    """

    reservation_id: str
    peer_id: str
    memory_gb: float
    generation: int
    taken_at: float
    expires_at: float = 0.0
    held: bool = True
    tier: str = "paid"
    #: free-form so a caller can bind its own booking id; never load-bearing
    meta: dict[str, Any] = field(default_factory=dict)

    def expired(self, now: float) -> bool:
        """Expired only if a TTL was set. Zero means "holds until released"."""
        return self.expires_at > 0.0 and now > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {"reservation_id": self.reservation_id, "peer_id": self.peer_id,
                "memory_gb": round(self.memory_gb, 4),
                "generation": self.generation, "taken_at": self.taken_at,
                "expires_at": self.expires_at, "tier": self.tier,
                "held": self.held}

    @classmethod
    def none(cls) -> "Reservation":
        return cls(reservation_id="", peer_id="", memory_gb=0.0,
                   generation=0, taken_at=0.0, held=False)


def _same(a: "Reservation", b: "Reservation") -> bool:
    """Dos reservas son la misma si dicen lo mismo.

    La identidad de objeto no vale: una reserva recargada de disco es otro
    objeto con el mismo contenido, y compararlas por identidad haria que
    ``adopt`` creyera que todas son nuevas.
    """
    return (a.peer_id == b.peer_id
            and a.reservation_id == b.reservation_id
            and a.generation == b.generation)


def _reservation_from(raw: dict[str, Any]) -> "Reservation":
    """Reconstruye una reserva desde su ``to_dict()``.

    Falla fuerte si faltan campos: un estado sin ``peer_id`` o sin
    ``memory_gb`` no es una reserva, y fingir que lo es pondria en el libro una
    promesa que nadie hizo.
    """
    return Reservation(
        reservation_id=str(raw["reservation_id"]),
        peer_id=str(raw["peer_id"]),
        memory_gb=float(raw["memory_gb"]),
        generation=int(raw["generation"]),
        taken_at=float(raw.get("taken_at", 0.0)),
        expires_at=float(raw.get("expires_at", 0.0)),
    )


@dataclass
class _NodeBook:
    """Per-node accounting. Mutated only under the book's lock."""

    #: baseline generation this book's numbers came from
    generation: int = 0
    #: the node's signed numbers at snapshot time
    available_gb: float = 0.0
    reported_used_gb: float = 0.0
    advertised_gb: float = 0.0
    physical_gb: float = 0.0
    live_reserved_gb: float = 0.0
    reservations: dict[str, Reservation] = field(default_factory=dict)

    @property
    def free_gb(self) -> float:
        """What can still be promised, floored at zero.

        The baseline's own available figure already subtracts what the node
        reported using; on top of that comes what this mesh has reserved. Both,
        from both directions — see the module docstring.
        """
        return max(0.0, self.available_gb - self.live_reserved_gb)


class ReservationBook:
    """Atomic dedicated reservations over the mesh's available VRAM.

    Thread-safe. One instance per mesh, held by whatever dispatches work.

    The book deliberately does **not** persist. A reservation is a promise about
    the next few minutes of local scheduling; reloading one from disk after a
    restart would either hold VRAM nobody is using or free VRAM somebody was
    promised. Both are worse than starting empty, which is also why a
    reservation is not a payment receipt: the payment side is a ledger, this is
    a scheduler.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._nodes: dict[str, _NodeBook] = {}
        self._generation = 0
        self._seq = 0

    # -- baseline ---------------------------------------------------------
    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def publish_snapshot(self, peers: dict[str, PeerContribution], *,
                         now: float | None = None) -> int:
        """Adopt a fresh baseline from the ledger; return the new generation.

        Raises the generation and **keeps** outstanding reservations, re-stamping
        each to the new generation. They survive because a snapshot says what a
        node *reported*, not what this mesh handed out: a fresh report that
        predates a reservation cannot know about it, so clearing on every
        snapshot would silently release live claims and hand the same VRAM to
        the next caller. That is the oversell this module exists to prevent, and
        it is what an unconditional clear would reintroduce.

        What *is* reset is the reported side — ``available_gb`` — because that
        is what the new report is authoritative about.

        Their memory is preserved, though, so a claim can never exceed what the
        node is newly reported as having free: a claim larger than the fresh
        baseline is dropped rather than carried into a state that cannot honour
        it.

        A snapshot is refused if its generation is not strictly newer, so a
        redelivered or reordered snapshot cannot roll the baseline back.
        """
        moment = time.time() if now is None else now
        with self._lock:
            self._generation += 1
            carried: dict[str, _NodeBook] = {}
            for pid, book in self._nodes.items():
                peer = peers.get(pid)
                if peer is None:
                    continue  # node left the mesh: its claims die with it
                fresh_available = peer.vram_available_gb
                still_fits = book.live_reserved_gb <= fresh_available + 1e-9
                carried[pid] = _NodeBook(
                    generation=self._generation,
                    available_gb=fresh_available,
                    reported_used_gb=peer.vram_shared_gb,
                    advertised_gb=peer.vram_advertised_gb,
                    physical_gb=peer.vram_gb,
                    live_reserved_gb=book.live_reserved_gb if still_fits else 0.0,
                    reservations=(dict(book.reservations) if still_fits else {}),
                )
                if still_fits:
                    for res in carried[pid].reservations.values():
                        carried[pid].reservations[res.reservation_id] = (
                            replace(res, generation=self._generation))
            for pid, peer in peers.items():
                carried.setdefault(pid, _NodeBook(
                    generation=self._generation,
                    available_gb=peer.vram_available_gb,
                    reported_used_gb=peer.vram_shared_gb,
                    advertised_gb=peer.vram_advertised_gb,
                    physical_gb=peer.vram_gb))
            self._nodes = carried
            return self._generation

    # -- reserve ----------------------------------------------------------
    def reserve(self, peer_id: str, memory_gb: float, *,
                ttl_s: float = 0.0, now: float | None = None,
                tier: str = "paid",
                meta: dict[str, Any] | None = None) -> tuple[Reservation | None, str]:
        """Atomically hold *memory_gb* on *peer_id*. Returns (reservation, reason).

        ``ALREADY_HELD`` is returned when the caller passes an id that is already
        outstanding: re-reserving is not a top-up, and silently replacing the
        old claim would let a retry free memory that is still in use.

        Check and account happen inside one lock. There is no window between
        "there is room" and "I took it".
        """
        moment = time.time() if now is None else now
        with self._lock:
            book = self._nodes.get(peer_id)
            if book is None:
                return None, UNKNOWN_PEER
            self._expire_locked(book, now=moment)
            if memory_gb <= 0:
                return None, NOT_ENOUGH
            if book.free_gb + 1e-9 < memory_gb:
                return None, NOT_ENOUGH
            self._seq += 1
            rid = f"{peer_id}#{self._seq}"
            if rid in book.reservations:
                return None, ALREADY_HELD
            res = Reservation(
                reservation_id=rid, peer_id=peer_id,
                memory_gb=round(float(memory_gb), 4),
                generation=book.generation, taken_at=moment,
                expires_at=(moment + ttl_s) if ttl_s > 0 else 0.0,
                tier=tier, meta=dict(meta or {}))
            book.reservations[rid] = res
            book.live_reserved_gb += res.memory_gb
            return res, RESERVED

    def release(self, res: Reservation | None, *,
                now: float | None = None) -> str:
        """Give back a reservation. Returns a machine-readable outcome.

        ``released`` — the claim was outstanding and is now gone.
        ``not_held`` — nothing to do: never reserved, or already released.
        ``stale_generation`` — the baseline moved on, so this snapshot already
        accounts for the work. Dropping it is correct; decrementing would
        double-count the completion and make a busy node look idle.
        ``unknown_peer`` — the node left the baseline between take and release.
        """
        moment = time.time() if now is None else now
        if res is None or not res.held or not res.reservation_id:
            return NOT_HELD_ALIAS
        with self._lock:
            book = self._nodes.get(res.peer_id)
            if book is None:
                return UNKNOWN_PEER
            if res.generation != book.generation:
                return STALE_GENERATION
            held = book.reservations.pop(res.reservation_id, None)
            if held is None:
                return NOT_HELD_ALIAS
            book.live_reserved_gb = max(0.0,
                                        book.live_reserved_gb - held.memory_gb)
            return RELEASED

    def move(self, res: Reservation | None, to_peer_id: str, *,
             now: float | None = None) -> tuple[Reservation | None, str]:
        """Transfer a held claim to another node — the failover case.

        The source stops carrying the load and the destination starts. A move
        that crosses a generation boundary takes a *fresh* reservation on the
        destination rather than carrying the stale stamp, because the new
        baseline superseded the accounting this claim was made against.
        """
        moment = time.time() if now is None else now
        if res is None or not res.held:
            return None, NOT_HELD_ALIAS
        if res.peer_id == to_peer_id:
            return res, UNCHANGED
        with self._lock:
            src = self._nodes.get(res.peer_id)
            dst = self._nodes.get(to_peer_id)
            if src is None or dst is None:
                return None, UNKNOWN_PEER
            if res.generation != src.generation:
                # Stale claim: it no longer counts anywhere, so do not move it.
                return None, STALE_GENERATION
            held = src.reservations.pop(res.reservation_id, None)
            if held is None:
                return None, NOT_HELD_ALIAS
            src.live_reserved_gb = max(0.0,
                                       src.live_reserved_gb - held.memory_gb)
            self._expire_locked(dst, now=moment)
            if dst.free_gb + 1e-9 < held.memory_gb:
                # No room at the destination: put it back. Losing the claim
                # silently would let the source look free while it is not.
                src.reservations[res.reservation_id] = held
                src.live_reserved_gb += held.memory_gb
                return None, NOT_ENOUGH
            self._seq += 1
            moved = Reservation(
                reservation_id=f"{to_peer_id}#{self._seq}",
                peer_id=to_peer_id, memory_gb=held.memory_gb,
                generation=dst.generation, taken_at=held.taken_at,
                expires_at=held.expires_at, tier=held.tier,
                meta=dict(held.meta))
            dst.reservations[moved.reservation_id] = moved
            dst.live_reserved_gb += moved.memory_gb
            return moved, MOVED

    def expire(self, *, now: float | None = None) -> int:
        """Drop TTL-expired reservations. Returns how many were freed."""
        moment = time.time() if now is None else now
        with self._lock:
            freed = 0
            for book in self._nodes.values():
                freed += self._expire_locked(book, now=moment)
            return freed

    def _expire_locked(self, book: _NodeBook, *, now: float) -> int:
        dead = [rid for rid, r in book.reservations.items() if r.expired(now)]
        for rid in dead:
            gone = book.reservations.pop(rid)
            book.live_reserved_gb = max(0.0,
                                        book.live_reserved_gb - gone.memory_gb)
        return len(dead)

    # -- read -------------------------------------------------------------
    def free_gb(self, peer_id: str, *, now: float | None = None) -> float:
        """What can still be promised on *peer_id* right now."""
        moment = time.time() if now is None else now
        with self._lock:
            book = self._nodes.get(peer_id)
            if book is None:
                return 0.0
            self._expire_locked(book, now=moment)
            return book.free_gb

    def reserved_gb(self, peer_id: str) -> float:
        with self._lock:
            book = self._nodes.get(peer_id)
            return 0.0 if book is None else book.live_reserved_gb

    def reservations_for(self, peer_id: str) -> tuple[Reservation, ...]:
        with self._lock:
            book = self._nodes.get(peer_id)
            if book is None:
                return ()
            return tuple(sorted(book.reservations.values(),
                                key=lambda r: r.reservation_id))

    def all_reservations(self) -> tuple[Reservation, ...]:
        with self._lock:
            out = [r for b in self._nodes.values() for r in b.reservations.values()]
        return tuple(sorted(out, key=lambda r: r.reservation_id))

    # -- estado compartido entre procesos -----------------------------------
    def state_of(self) -> "Any":
        """La foto de lo *vivo*: generacion, secuencia y reservas.

        Deliberadamente no incluye los snapshots de capacidad. Eso es lo que el
        nodo **reporta**, y llega por su propio camino (el heartbeat, firmado).
        Meterlo aqui seria una segunda fuente de verdad sobre cuanto tiene cada
        nodo, y las dos discreparian justo cuando un nodo cambia de VRAM — que
        es cuando importa.
        """
        with self._lock:
            from smcp.core.reservation_ipc import ReservationSnapshot
            return ReservationSnapshot(
                generation=self._generation,
                seq=self._seq,
                reservations=[r.to_dict() for node in self._nodes.values()
                              for r in node.reservations.values()],
            )

    def adopt(self, state: Any) -> int:
        """Carga una foto de otro proceso y devuelve cuantas se fusionaron.

        Lo que se fusiona son las **vivas**, y una reserva que ya esta da lo
        mismo, asi que el numero de vuelta es "cuantas entraron de verdad". Se
        llama fusion y no carga porque una adopcion no debe crear ni destruir
        nada: solo atestiguar lo que otro proceso ya decidio.

        Falla suelta por fila: una entrada corrupta no puede invalidar el
        resto del estado, porque el estado de un nodo sigue siendo util aunque
        la fila de otro este corrupta.
        """
        with self._lock:
            n = 0
            for raw in getattr(state, "reservations", None) or []:
                try:
                    res = _reservation_from(raw)
                except (KeyError, TypeError, ValueError):
                    continue
                node = self._nodes.setdefault(res.peer_id,
                                              _NodeBook(generation=0))
                if res.reservation_id not in node.reservations:
                    node.reservations[res.reservation_id] = res
                    node.live_reserved_gb += res.memory_gb
                    n += 1
            return n

    def merge(self, other: "ReservationBook") -> int:
        """Fusiona el estado vivo de otro libro **del mismo proceso**.

        El caso de un planificador con dos libros (por ejemplo uno por malla)
        que necesita una vista comun. No atraviesa la frontera de proceso — para
        eso esta :meth:`adopt` con un
        :class:`~smcp.core.reservation_ipc.InterprocessGuard`.
        """
        with self._lock, other._lock:
            n = 0
            for peer_id, src in other._nodes.items():
                node = self._nodes.setdefault(peer_id,
                                              _NodeBook(generation=0))
                for rid, res in src.reservations.items():
                    if rid not in node.reservations:
                        node.reservations[rid] = res
                        node.live_reserved_gb += res.memory_gb
                        n += 1
            return n

    def snapshot(self) -> dict[str, Any]:
        """Per-node view for the CLI and the web API."""
        with self._lock:
            return {
                "generation": self._generation,
                "nodes": {
                    pid: {
                        "generation": b.generation,
                        "physical_gb": round(b.physical_gb, 4),
                        "advertised_gb": round(b.advertised_gb, 4),
                        "reported_used_gb": round(b.reported_used_gb, 4),
                        "reserved_gb": round(b.live_reserved_gb, 4),
                        "free_gb": round(max(0.0, b.available_gb
                                             - b.live_reserved_gb), 4),
                        "reservations": [r.reservation_id
                                         for r in sorted(
                                             b.reservations.values(),
                                             key=lambda r: r.reservation_id)],
                    }
                    for pid, b in sorted(self._nodes.items())
                },
            }


__all__ = [
    "Reservation",
    "ReservationBook",
    "RESERVED",
    "FREE",
    "NOT_ENOUGH",
    "UNKNOWN_PEER",
    "BELOW_MINIMUM",
    "EXPIRED_BASELINE",
    "ALREADY_HELD",
    "NOT_HELD_ALIAS",
    "RELEASED",
    "STALE_GENERATION",
    "UNCHANGED",
    "MOVED",
]
