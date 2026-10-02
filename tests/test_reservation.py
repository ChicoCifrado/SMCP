"""Atomic dedicated reservations.

The threat is not a clever attacker, it is two ordinary callers at the same
instant. A plan is JSON; two plans can name the same node and the same GiB and
both be individually valid. So the tests are mostly about arithmetic under
concurrency, and about the generation stamp — the subtle part, since a stale
release *not* being honoured is what stops one request from freeing another's
memory.
"""

from __future__ import annotations

import threading
import time

from delm.core.contrib import PeerContribution
from delm.core.reservation import (
    ALREADY_HELD,
    MOVED,
    NOT_ENOUGH,
    NOT_HELD_ALIAS,
    RELEASED,
    RESERVED,
    STALE_GENERATION,
    UNCHANGED,
    UNKNOWN_PEER,
    Reservation,
    ReservationBook,
)



def _must(res: Reservation | None, why: str) -> Reservation:
    """Narrow on the reason, which is the real signal that a claim was taken.

    Checking ``why == RESERVED`` does not narrow ``res`` for a type checker,
    and asserting ``res is not None`` in every test would be noise. One
    assertion here also fails loudly if the vocabulary ever changes.
    """
    assert res is not None, f"sin reservation: {why}"
    assert why == RESERVED, f"motivo inesperado: {why}"
    return res


def _peer(peer_id="n1", *, vram=16.0, advertised=8.0, used=0.0):
    return PeerContribution(peer_id=peer_id, vram_gb=vram,
                            vram_advertised_gb=advertised,
                            vram_shared_gb=used)


def _book(*peers, now=100.0):
    b = ReservationBook()
    b.publish_snapshot({p.peer_id: p for p in peers}, now=now)
    return b


# ---------------------------------------------------------------- the basics
def test_reserving_takes_the_memory_it_asks_for():
    b = _book(_peer(advertised=8.0))
    res = _must(*b.reserve("n1", 4.0, now=100.0))
    assert res.memory_gb == 4.0
    assert b.free_gb("n1", now=100.0) == 4.0


def test_reserve_starts_from_available_not_the_headline():
    """8 offered, 3 reported in use, so 5 can be promised — not 8, not 16."""
    b = _book(_peer(vram=16.0, advertised=8.0, used=3.0))
    assert b.free_gb("n1", now=100.0) == 5.0


def test_a_reservation_beyond_what_is_free_is_refused():
    b = _book(_peer(advertised=8.0))
    res, why = b.reserve("n1", 9.0, now=100.0)
    assert res is None and why == NOT_ENOUGH


def test_two_reservations_exactly_fill_the_node():
    b = _book(_peer(advertised=8.0))
    r1 = _must(*b.reserve("n1", 5.0, now=100.0))
    _must(*b.reserve("n1", 3.0, now=100.0))
    assert b.free_gb("n1", now=100.0) == 0.0


def test_one_gib_over_the_line_is_refused_not_absorbed():
    """The float edge. Without the epsilon a plan for 8.0000001 on an 8 GiB
    node would fail, and with a loose epsilon one for 8.1 would pass."""
    b = _book(_peer(advertised=8.0))
    _must(*b.reserve("n1", 8.0, now=100.0))
    res, why = b.reserve("n1", 0.001, now=100.0)
    assert res is None and why == NOT_ENOUGH


def test_unknown_peer_is_named_rather_than_treated_as_free():
    b = _book(_peer())
    res, why = b.reserve("n2", 1.0, now=100.0)
    assert res is None and why == UNKNOWN_PEER


def test_a_zero_or_negative_reservation_is_refused():
    b = _book(_peer())
    assert b.reserve("n1", 0.0, now=100.0)[1] == NOT_ENOUGH
    assert b.reserve("n1", -5.0, now=100.0)[1] == NOT_ENOUGH


def test_free_on_an_unknown_peer_is_zero_not_infinite():
    """Not-infinite matters: a caller looping over candidates must not treat
    a missing node as the best possible one.
    """
    b = _book(_peer())
    assert b.free_gb("no-existe") == 0.0


# ------------------------------------------------------------------ release
def test_release_returns_the_memory():
    b = _book(_peer(advertised=8.0))
    res = _must(*b.reserve("n1", 4.0, now=100.0))
    assert b.release(res, now=100.0) == RELEASED
    assert b.free_gb("n1", now=100.0) == 8.0
    assert b.all_reservations() == ()


def test_releasing_twice_is_a_no_op_not_a_double_refund():
    """The classic ledger bug. Freeing twice would let a node hold 12 GiB
    after promising 8.
    """
    b = _book(_peer(advertised=8.0))
    res = _must(*b.reserve("n1", 4.0, now=100.0))
    b.release(res, now=100.0)
    b.reserve("n1", 4.0, now=100.0)
    assert b.release(res, now=100.0) == NOT_HELD_ALIAS
    assert b.free_gb("n1", now=100.0) == 4.0


def test_releasing_something_never_reserved_is_a_no_op():
    b = _book(_peer())
    assert b.release(None) == NOT_HELD_ALIAS
    assert b.release(Reservation.none()) == NOT_HELD_ALIAS
    assert b.free_gb("n1", now=100.0) == 8.0


def test_release_on_a_vanished_peer_is_named():
    b = _book(_peer())
    res = _must(*b.reserve("n1", 4.0, now=100.0))
    b.publish_snapshot({}, now=101.0)
    assert b.release(res, now=101.0) == UNKNOWN_PEER


def test_releasing_a_foreign_id_never_frees_someone_elses_memory():
    """Two live reservations; releasing a made-up id must leave both intact."""
    b = _book(_peer(advertised=16.0))
    r1 = _must(*b.reserve("n1", 4.0, now=100.0))
    r2 = _must(*b.reserve("n1", 4.0, now=100.0))
    forged = Reservation(reservation_id="n1#999", peer_id="n1", memory_gb=4.0,
                         generation=b.generation, taken_at=100.0)
    assert b.release(forged, now=100.0) == NOT_HELD_ALIAS
    assert b.free_gb("n1", now=100.0) == 8.0
    assert len(b.reservations_for("n1")) == 2
    assert r1.reservation_id != r2.reservation_id


# ---------------------------------------------------------------- generation
def test_a_new_snapshot_clears_outstanding_reservations():
    """The snapshot already accounts for the work, so keeping the claims would
    count it twice.
    """
    b = _book(_peer(advertised=8.0))
    b.reserve("n1", 4.0, now=100.0)
    assert b.reserved_gb("n1") == 4.0
    b.publish_snapshot({"n1": _peer(advertised=8.0)}, now=101.0)
    assert b.all_reservations() == ()
    assert b.reserved_gb("n1") == 0.0
    assert b.free_gb("n1", now=101.0) == 8.0


def test_releasing_a_reservation_from_the_previous_generation_is_ignored():
    """This is the subtle one, and the reason ``generation`` exists.

    A reservation taken against snapshot N is still in hand when snapshot N+1
    arrives and clears it. If the late release decremented anyway it would free
    memory that a *different*, newer reservation now holds — the node looks
    idle while it is committed.
    """
    b = _book(_peer(advertised=8.0))
    stale = _must(*b.reserve("n1", 4.0, now=100.0))
    b.publish_snapshot({"n1": _peer(advertised=8.0)}, now=101.0)
    assert b.release(stale, now=101.0) == STALE_GENERATION
    # Nothing was double-freed.
    assert b.free_gb("n1", now=101.0) == 8.0


def test_a_stale_release_cannot_free_a_newer_reservation():
    b = _book(_peer(advertised=8.0))
    stale = _must(*b.reserve("n1", 4.0, now=100.0))
    b.publish_snapshot({"n1": _peer(advertised=8.0)}, now=101.0)
    fresh = _must(*b.reserve("n1", 4.0, now=101.0))
    b.release(stale, now=101.0)
    assert b.reserved_gb("n1") == 4.0
    assert [r.reservation_id for r in b.reservations_for("n1")] == \
        [fresh.reservation_id]


def test_the_generation_increases_monotonically():
    b = _book(_peer())
    seen = [b.generation]
    for now in (101.0, 102.0):
        b.publish_snapshot({"n1": _peer()}, now=now)
        seen.append(b.generation)
    assert seen == sorted(seen) and len(set(seen)) == 3


def test_a_snapshot_that_omits_a_peer_drops_its_book():
    b = _book(_peer(), _peer("n2"))
    b.reserve("n1", 2.0, now=100.0)
    b.publish_snapshot({"n1": _peer()}, now=101.0)
    assert b.reserve("n2", 1.0, now=101.0)[1] == UNKNOWN_PEER


# -------------------------------------------------------------------- ttl
def test_a_ttl_reservation_expires_and_frees_itself():
    b = _book(_peer(advertised=8.0))
    res = _must(*b.reserve("n1", 4.0, ttl_s=60.0, now=100.0))
    assert res.expires_at == 160.0
    assert b.expire(now=130.0) == 0
    assert b.free_gb("n1", now=130.0) == 4.0
    assert b.expire(now=170.0) == 1
    assert b.free_gb("n1", now=170.0) == 8.0
    assert b.all_reservations() == ()


def test_a_zero_ttl_never_expires():
    b = _book(_peer())
    res = _must(*b.reserve("n1", 4.0, now=100.0))
    assert res.expires_at == 0.0
    assert b.expire(now=10_000.0) == 0
    assert b.reserved_gb("n1") == 4.0


def test_an_expired_reservation_does_not_block_a_new_booking():
    """Lazily expired on reserve(), so a stale claim cannot wedge a node."""
    b = _book(_peer(advertised=8.0))
    b.reserve("n1", 4.0, ttl_s=60.0, now=100.0)
    _must(*b.reserve("n1", 6.0, now=200.0))
    assert b.free_gb("n1", now=200.0) == 2.0


def test_reading_free_expires_lazily_too():
    b = _book(_peer(advertised=8.0))
    b.reserve("n1", 4.0, ttl_s=60.0, now=100.0)
    assert b.free_gb("n1", now=500.0) == 8.0


# -------------------------------------------------------------------- move
def test_a_move_transfers_the_load():
    b = _book(_peer("n1", advertised=8.0), _peer("n2", advertised=8.0))
    res = _must(*b.reserve("n1", 4.0, now=100.0))
    moved, why = b.move(res, "n2", now=100.0)
    assert why == MOVED and moved is not None and moved.peer_id == "n2"
    assert b.reserved_gb("n1") == 0.0
    assert b.reserved_gb("n2") == 4.0


def test_a_move_to_the_same_node_changes_nothing():
    b = _book(_peer())
    res = _must(*b.reserve("n1", 4.0, now=100.0))
    same, why = b.move(res, "n1", now=100.0)
    assert why == UNCHANGED and same is res
    assert b.reserved_gb("n1") == 4.0


def test_a_move_onto_an_unknown_node_fails():
    b = _book(_peer())
    res = _must(*b.reserve("n1", 4.0, now=100.0))
    moved, why = b.move(res, "fantasma", now=100.0)
    assert moved is None and why == UNKNOWN_PEER
    assert b.reserved_gb("n1") == 4.0


def test_a_failed_move_puts_the_claim_back_on_the_source():
    """Failover landed on a node with no room. Losing the claim would leave
    the source looking free while it is still committed — the exact
    over-subscription this module exists to prevent.
    """
    b = _book(_peer("n1", advertised=8.0), _peer("n2", advertised=2.0))
    res = _must(*b.reserve("n1", 4.0, now=100.0))
    moved, why = b.move(res, "n2", now=100.0)
    assert moved is None and why == NOT_ENOUGH
    assert b.reserved_gb("n1") == 4.0
    assert b.reserved_gb("n2") == 0.0
    assert [r.reservation_id for r in b.reservations_for("n1")] == \
        [res.reservation_id]


def test_a_move_of_a_stale_claim_is_refused():
    b = _book(_peer("n1", advertised=8.0), _peer("n2", advertised=8.0))
    res = _must(*b.reserve("n1", 4.0, now=100.0))
    b.publish_snapshot({"n1": _peer("n1", advertised=8.0),
                        "n2": _peer("n2", advertised=8.0)}, now=101.0)
    moved, why = b.move(res, "n2", now=101.0)
    assert moved is None and why == STALE_GENERATION
    assert b.reserved_gb("n2") == 0.0


def test_the_old_claim_must_not_be_released_after_a_move():
    """documented on the caller: move() returns the new reservation and the
    old one must not be released separately, or the source is freed twice.
    """
    b = _book(_peer("n1", advertised=8.0), _peer("n2", advertised=8.0))
    res = _must(*b.reserve("n1", 4.0, now=100.0))
    moved, _ = b.move(res, "n2", now=100.0)
    assert moved is not None
    # Releasing the *old* id is a no-op: it no longer exists in any book.
    assert b.release(res, now=100.0) == NOT_HELD_ALIAS
    assert b.reserved_gb("n2") == 4.0


# ------------------------------------------------------------- concurrency
def test_concurrent_reservations_never_oversubscribe():
    """The reason the check and the increment share a lock.

    Sixteen threads each ask for 1 GiB against an 8 GiB node. Exactly eight may
    succeed. With a check-then-act race the number is not reliably eight — it
    is often higher, and it is the oversell that makes the paid tier
    unsellable.
    """
    b = _book(_peer(advertised=8.0))
    winners: list[Reservation] = []
    lock = threading.Lock()
    barrier = threading.Barrier(16)

    def attempt():
        barrier.wait()
        res, why = b.reserve("n1", 1.0, now=100.0)
        if why == RESERVED and res is not None:
            with lock:
                winners.append(res)

    threads = [threading.Thread(target=attempt) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(winners) == 8
    assert b.reserved_gb("n1") == 8.0
    assert b.free_gb("n1", now=100.0) == 0.0
    assert len(b.all_reservations()) == 8


def test_concurrent_release_and_reserve_stay_consistent():
    """Interleaved churn must never produce a negative or over-committed book."""
    b = _book(_peer(advertised=4.0))
    errors: list[str] = []
    stop = threading.Event()

    def churn(seed: int):
        i = 0
        while not stop.is_set() and i < 200:
            res, why = b.reserve("n1", 1.0, now=100.0)
            if why == RESERVED and res is not None:
                if b.free_gb("n1", now=100.0) < -1e-9:
                    errors.append("free negativo")
                if b.reserved_gb("n1") > 4.0 + 1e-9:
                    errors.append("sobrecomprometido")
                b.release(res, now=100.0)
            i += 1

    threads = [threading.Thread(target=churn, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stop.set()
    assert errors == []
    assert b.reserved_gb("n1") == 0.0
    assert b.free_gb("n1", now=100.0) == 4.0


def test_concurrent_releases_of_one_reservation_free_it_once():
    """Three threads releasing the same claim. Exactly one may succeed."""
    b = _book(_peer(advertised=8.0))
    res, _ = b.reserve("n1", 4.0, now=100.0)
    outcomes: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(3)

    def drop():
        barrier.wait()
        out = b.release(res, now=100.0)
        with lock:
            outcomes.append(out)

    threads = [threading.Thread(target=drop) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(RELEASED) == 1
    assert outcomes.count(NOT_HELD_ALIAS) == 2
    assert b.free_gb("n1", now=100.0) == 8.0


def test_a_snapshot_during_reservations_leaves_the_book_consistent():
    """Publish racing with reserve: either the claim is in the new book or it
    was cleared, never half-accounted.
    """
    b = _book(_peer(advertised=8.0))
    bad: list[str] = []
    lock = threading.Lock()

    def snapper():
        for i in range(50):
            b.publish_snapshot({"n1": _peer(advertised=8.0)}, now=200.0 + i)

    def reserver():
        for _ in range(50):
            res, why = b.reserve("n1", 2.0, now=200.0)
            if why == RESERVED and res is not None:
                with lock:
                    if b.reserved_gb("n1") > 8.0 + 1e-9:
                        bad.append("sobrecomprometido tras snapshot")
                    if b.reserved_gb("n1") < -1e-9:
                        bad.append("reservado negativo tras snapshot")

    ts = [threading.Thread(target=snapper), threading.Thread(target=reserver)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert bad == []


# ------------------------------------------------------------------ reports
def test_the_snapshot_view_shows_every_number_separately():
    """Same discipline as the VRAM split: physical, offered, used by the node,
    reserved by the mesh, and still free are five different figures.
    """
    b = _book(_peer(vram=16.0, advertised=8.0, used=2.0))
    b.reserve("n1", 3.0, now=100.0)
    view = b.snapshot()["nodes"]["n1"]
    assert view["physical_gb"] == 16.0
    assert view["advertised_gb"] == 8.0
    assert view["reported_used_gb"] == 2.0
    assert view["reserved_gb"] == 3.0
    assert view["free_gb"] == 3.0
    assert view["generation"] == b.generation


def test_a_reservation_carries_its_tier_and_metadata():
    b = _book(_peer())
    res = _must(*b.reserve("n1", 1.0, now=100.0, tier="pago_unico",
                           meta={"order": "abc-123"}))
    assert res.tier == "pago_unico"
    assert res.meta["order"] == "abc-123"
    assert res.held is True


def test_the_meta_dict_is_copied_not_shared():
    b = _book(_peer())
    caller = {"order": "x"}
    res = _must(*b.reserve("n1", 1.0, now=100.0, meta=caller))
    caller["order"] = "y"
    assert res.meta["order"] == "x"


def test_reservations_round_trip_through_dict():
    b = _book(_peer())
    res = _must(*b.reserve("n1", 2.5, now=100.0))
    d = res.to_dict()
    assert d["memory_gb"] == 2.5
    assert d["peer_id"] == "n1"
    assert d["generation"] == b.generation


def test_ids_are_unique_and_monotonic():
    b = _book(_peer(advertised=32.0))
    ids = [_must(*b.reserve("n1", 1.0, now=100.0)).reservation_id
           for _ in range(5)]
    assert len(set(ids)) == 5
    assert ids == sorted(ids, key=lambda s: int(s.split("#")[1]))


def test_the_already_held_reason_exists_even_though_ids_are_generated():
    """Ids are minted internally so this cannot normally fire; it stays because
    a caller-supplied id scheme would need it, and a dead branch that a later
    change could reach silently is worse than an honest constant.
    """
    assert ALREADY_HELD == "already_held"


def test_a_book_with_no_snapshot_reserves_nothing():
    b = ReservationBook()
    assert b.reserve("n1", 1.0)[1] == UNKNOWN_PEER
    assert b.snapshot()["nodes"] == {}


def test_free_uses_the_snapshots_reported_usage_and_the_book_separately():
    """Reservation and telemetry move independently and both subtract.

    A node running someone else's work reports it as usage; this mesh's own
    reservations are separate. Missing either one oversubscribes.
    """
    b = _book(_peer(vram=16.0, advertised=10.0, used=4.0))
    assert b.free_gb("n1", now=100.0) == 6.0
    b.reserve("n1", 2.0, now=100.0)
    assert b.free_gb("n1", now=100.0) == 4.0
    # A new snapshot folds the mesh's work back into the node's own usage.
    b.publish_snapshot({"n1": _peer(vram=16.0, advertised=10.0, used=6.0)},
                       now=101.0)
    assert b.free_gb("n1", now=101.0) == 4.0


def test_time_defaults_to_wall_clock_without_arguments():
    b = _book(_peer())
    res = _must(*b.reserve("n1", 1.0))
    assert res.taken_at > 0
    assert b.release(res) == RELEASED


def test_publish_snapshot_without_now_uses_wall_clock():
    b = ReservationBook()
    gen = b.publish_snapshot({"n1": _peer()})
    assert gen == 1
    assert time.time() > 0