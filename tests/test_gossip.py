"""Tests de ``delm.core.gossip`` — propagación transitoria de estado de pares.

Cubre:
* floor de versión — ingest y re-difusión respetan ``version_floor``.
* regla path-rich — ``addr`` solo avanza si el anuncio es al menos tan
  path-rich como el existente.
* re-difusión — solo pares no-stale y por encima del floor.
* cambio significativo — detección de cambios que disparan re-difusión.
"""
from __future__ import annotations

import pytest

from delm.core.gossip import (
    GossipTable,
    PeerAnnouncement,
    PeerInfo,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _ann(pid: str, ver=(1, 0), caps=("c1",), addr=("a1",),
          lat=None, ts=None, mesh="m1") -> PeerAnnouncement:
    return PeerAnnouncement(
        peer_id=pid, version=ver, capabilities=caps, addr=addr,
        latency_ms=lat, first_joined_mesh_ts=ts, mesh_id=mesh,
    )


# ---------------------------------------------------------------------------
# floor de versión
# ---------------------------------------------------------------------------
def test_version_floor_accepts_at_or_above():
    t = GossipTable(version_floor=(1, 0))
    assert t.version_allowed((1, 0)) is True
    assert t.version_allowed((2, 5)) is True
    assert t.version_allowed((0, 9)) is False


def test_ingest_direct_rejects_below_floor():
    t = GossipTable(version_floor=(1, 0))
    assert t.ingest_direct(_ann("p1", ver=(0, 5)), now=10) == "version_below_floor"
    assert "p1" not in t.peers


def test_ingest_direct_accepts_above_floor():
    t = GossipTable(version_floor=(1, 0))
    assert t.ingest_direct(_ann("p1", ver=(1, 2)), now=10) == "accepted"
    assert "p1" in t.peers


def test_rebroadcast_respects_floor():
    t = GossipTable(version_floor=(1, 0))
    t.ingest_direct(_ann("ok", ver=(1, 0)), now=10)
    t.ingest_direct(_ann("low", ver=(0, 9)), now=10)  # rechazado
    rb = t.collect_rebroadcasts(now=100, stale_cutoff=0)
    assert [a.peer_id for a in rb] == ["ok"]


# ---------------------------------------------------------------------------
# regla path-rich
# ---------------------------------------------------------------------------
def test_transitive_addr_advances_when_richer():
    t = GossipTable(version_floor=(1, 0))
    t.ingest_direct(_ann("p1", ver=(1, 0), addr=("a1",)), now=10)
    # transitorio con addr más rico (2 vs 1) -> avanza
    t.ingest_transitive(_ann("p1", ver=(1, 0), addr=("a1", "a2")),
                        bridge="b1", now=20)
    assert t.peers["p1"].addr == ("a1", "a2")


def test_transitive_addr_not_overwritten_when_weaker():
    t = GossipTable(version_floor=(1, 0))
    t.ingest_direct(_ann("p1", ver=(1, 0), addr=("a1", "a2")), now=10)
    # transitorio con addr menos rico (1 vs 2) -> no sobreescribe
    t.ingest_transitive(_ann("p1", ver=(1, 0), addr=("a1",)),
                        bridge="b1", now=20)
    assert t.peers["p1"].addr == ("a1", "a2")


def test_transitive_new_peer_created():
    t = GossipTable(version_floor=(1, 0))
    res = t.ingest_transitive(_ann("p9", ver=(1, 0), addr=("a1",)),
                             bridge="b1", now=20)
    assert res == "accepted"
    assert "p9" in t.peers
    assert t.peers["p9"].direct is False


def test_transitive_rejects_below_floor():
    t = GossipTable(version_floor=(1, 0))
    res = t.ingest_transitive(_ann("p9", ver=(0, 1), addr=("a1",)),
                             bridge="b1", now=20)
    assert res == "version_below_floor"
    assert "p9" not in t.peers


# ---------------------------------------------------------------------------
# re-difusión y cambio significativo
# ---------------------------------------------------------------------------
def test_rebroadcast_excludes_stale():
    t = GossipTable(version_floor=(1, 0))
    t.ingest_direct(_ann("p1", ver=(1, 0)), now=10)
    # stale_cutoff=100 -> p1 (last_seen=10) es stale
    rb = t.collect_rebroadcasts(now=200, stale_cutoff=100)
    assert rb == []


def test_meaningful_changed_on_version():
    a = PeerInfo(peer_id="p", version=(1, 0), capabilities=("c",),
                addr=("a",), latency_ms=5, last_seen=0, last_mentioned=0)
    b = PeerInfo(peer_id="p", version=(1, 1), capabilities=("c",),
                addr=("a",), latency_ms=5, last_seen=0, last_mentioned=0)
    assert GossipTable.meaningful_changed(a, b) is True


def test_meaningful_changed_false_when_same():
    a = PeerInfo(peer_id="p", version=(1, 0), capabilities=("c",),
                addr=("a",), latency_ms=5, last_seen=0, last_mentioned=0)
    b = PeerInfo(peer_id="p", version=(1, 0), capabilities=("c",),
                addr=("a",), latency_ms=5, last_seen=0, last_mentioned=0)
    assert GossipTable.meaningful_changed(a, b) is False


def test_meaningful_changed_on_capabilities():
    a = PeerInfo(peer_id="p", version=(1, 0), capabilities=("c1",),
                addr=("a",), latency_ms=5, last_seen=0, last_mentioned=0)
    b = PeerInfo(peer_id="p", version=(1, 0), capabilities=("c1", "c2"),
                addr=("a",), latency_ms=5, last_seen=0, last_mentioned=0)
    assert GossipTable.meaningful_changed(a, b) is True


# ---------------------------------------------------------------------------
# retiro
# ---------------------------------------------------------------------------
def test_remove_peer():
    t = GossipTable(version_floor=(1, 0))
    t.ingest_direct(_ann("p1", ver=(1, 0)), now=10)
    assert t.remove_peer("p1") is True
    assert t.get("p1") is None
    assert t.remove_peer("p1") is False
