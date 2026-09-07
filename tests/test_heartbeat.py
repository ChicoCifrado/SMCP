"""Tests de ``delm.core.heartbeat`` — heartbeat y detección de caída.

Cubre:
* registro y beat — ``last_heartbeat``/``last_seen`` se actualizan.
* frescura — ``is_fresh`` dentro de ``ttl_secs``.
* caída — ``mark_down``/``sweep`` marcan ``down`` y devuelven los nuevos.
* revirtir — un beat revierte el estado ``down``.
"""
from __future__ import annotations

from delm.core.heartbeat import HeartbeatTracker


# ---------------------------------------------------------------------------
# registro y beat
# ---------------------------------------------------------------------------
def test_register_sets_timestamps():
    t = HeartbeatTracker(ttl_secs=30)
    t.register("p1", now=10)
    hb = t.peers["p1"]
    assert hb.last_heartbeat == 10
    assert hb.last_seen == 10


def test_beat_updates_and_revives():
    t = HeartbeatTracker(ttl_secs=30)
    t.register("p1", now=10)
    t.mark_down("p1", now=100)
    assert t.is_down("p1") is True
    t.beat("p1", now=110)
    assert t.is_down("p1") is False
    assert t.peers["p1"].last_heartbeat == 110


def test_beat_unknown_peer_registers():
    t = HeartbeatTracker(ttl_secs=30)
    t.beat("new", now=5)
    assert "new" in t.peers
    assert t.peers["new"].last_heartbeat == 5


# ---------------------------------------------------------------------------
# frescura
# ---------------------------------------------------------------------------
def test_is_fresh_within_ttl():
    t = HeartbeatTracker(ttl_secs=30)
    t.register("p1", now=10)
    assert t.is_fresh("p1", now=39) is True   # 39-10=29 <= 30
    assert t.is_fresh("p1", now=41) is False  # 41-10=31 > 30


def test_is_fresh_unknown_peer():
    t = HeartbeatTracker(ttl_secs=30)
    assert t.is_fresh("ghost", now=10) is False


# ---------------------------------------------------------------------------
# caída
# ---------------------------------------------------------------------------
def test_mark_down_returns_newly_down():
    t = HeartbeatTracker(ttl_secs=30)
    t.register("p1", now=10)
    assert t.mark_down("p1", now=100) is True   # primer down
    assert t.mark_down("p1", now=110) is False  # ya estaba down


def test_mark_down_unknown_peer():
    t = HeartbeatTracker(ttl_secs=30)
    assert t.mark_down("ghost", now=10) is False


def test_sweep_marks_stale_peers_down():
    t = HeartbeatTracker(ttl_secs=30)
    t.register("p1", now=10)
    t.register("p2", now=10)
    # p2 da un beat reciente, p1 no
    t.beat("p2", now=100)
    newly = t.sweep(now=100)
    assert newly == ["p1"]
    assert t.is_down("p1") is True
    assert t.is_down("p2") is False


def test_sweep_idempotent():
    t = HeartbeatTracker(ttl_secs=30)
    t.register("p1", now=10)
    t.sweep(now=100)
    # segundo barrido: p1 ya estaba down, no vuelve a reportar
    assert t.sweep(now=100) == []


# ---------------------------------------------------------------------------
# retiro
# ---------------------------------------------------------------------------
def test_remove_peer():
    t = HeartbeatTracker(ttl_secs=30)
    t.register("p1", now=10)
    t.remove("p1")
    assert "p1" not in t.peers
    assert t.is_down("p1") is False  # desconocido -> no down
