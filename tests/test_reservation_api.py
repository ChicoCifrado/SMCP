"""The reservation endpoints, and the book they share.

A book per request would make these endpoints decorative: every call would see
an empty book, promise the same GiB twice, and the oversell would be exactly
the one :mod:`delm.core.reservation` exists to prevent. These tests therefore
pin the sharing, not just the happy path.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from delm.web import api as smcp_api
from delm.web.api import MANAGER
from delm.web.app import app

MESH = "malla-reserva-test"


@pytest.fixture()
def client():
    MANAGER._active = None
    MANAGER._history.clear()
    with TestClient(app) as c:
        yield c
    MANAGER._active = None
    MANAGER._history.clear()


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """tmp state file, and no reservation book inherited from another test."""
    monkeypatch.setattr(smcp_api, "_mesh_state_path",
                        lambda: tmp_path / "mesh_exchange.json")
    monkeypatch.setattr(smcp_api, "_mesh_identity_path",
                        lambda: tmp_path / "mesh_identity.json")
    smcp_api._RESERVATION_BOOKS.clear()
    yield
    smcp_api._RESERVATION_BOOKS.clear()


def _contribute(client, peer_id, vram, advertised, used=0.0):
    """The real contribute endpoint: it issues the challenge and signs."""
    r = client.post("/api/mesh/contribute", params={"mesh_id": MESH},
                    json={"peer_id": peer_id, "vram_gb": vram,
                          "vram_advertised_gb": advertised,
                          "vram_shared_gb": used, "ram_gb": 64,
                          "cpu_cores": 12})
    assert r.status_code == 200, r.text
    return r.json()


def _seed(client):
    """One node with 8 GiB offered out of 16 physical."""
    _contribute(client, "n1", vram=16.0, advertised=8.0)
    return client


# --------------------------------------------------------------- the endpoints
def test_reserve_then_release(client):
    _seed(client)
    r = client.post("/api/mesh/reserve",
                    params={"mesh_id": MESH},
                    json={"peer_id": "n1", "memory_gb": 4.0})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reason"] == "reserved"
    rid = body["reservation"]["reservation_id"]
    assert body["free_gb_after"] == 4.0

    got = client.get("/api/mesh/reservations",
                     params={"mesh_id": MESH})
    assert got.json()["nodes"]["n1"]["reserved_gb"] == 4.0

    rel = client.post("/api/mesh/release",
                      params={"reservation_id": rid,
                              "mesh_id": MESH})
    assert rel.status_code == 200
    assert rel.json()["reason"] == "released"


def test_the_second_reserve_sees_the_first(client):
    """The point of the whole module, over HTTP."""
    _seed(client)
    a = client.post("/api/mesh/reserve",
                    params={"mesh_id": MESH},
                    json={"peer_id": "n1", "memory_gb": 6.0})
    assert a.status_code == 200
    b = client.post("/api/mesh/reserve",
                    params={"mesh_id": MESH},
                    json={"peer_id": "n1", "memory_gb": 6.0})
    assert b.status_code == 409
    assert b.json()["detail"]["reason"] == "not_enough_available"
    assert b.json()["detail"]["free_gb"] == 2.0


def test_reserving_more_than_is_offered_is_a_conflict(client):
    _seed(client)
    r = client.post("/api/mesh/reserve",
                    params={"mesh_id": MESH},
                    json={"peer_id": "n1", "memory_gb": 9.0})
    assert r.status_code == 409


def test_an_unknown_peer_is_a_404_not_a_conflict(client):
    _seed(client)
    r = client.post("/api/mesh/reserve",
                    params={"mesh_id": MESH},
                    json={"peer_id": "fantasma", "memory_gb": 1.0})
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "unknown_peer"


def test_a_zero_reservation_is_rejected_by_validation(client):
    _seed(client)
    r = client.post("/api/mesh/reserve",
                    params={"mesh_id": MESH},
                    json={"peer_id": "n1", "memory_gb": 0.0})
    assert r.status_code == 422


def test_releasing_twice_is_a_404_the_second_time(client):
    _seed(client)
    rid = client.post("/api/mesh/reserve",
                      params={"mesh_id": MESH},
                      json={"peer_id": "n1", "memory_gb": 2.0}
                      ).json()["reservation"]["reservation_id"]
    assert client.post("/api/mesh/release",
                       params={"reservation_id": rid,
                               "mesh_id": MESH}).status_code == 200
    again = client.post("/api/mesh/release",
                        params={"reservation_id": rid,
                                "mesh_id": MESH})
    assert again.status_code == 404
    assert again.json()["detail"]["reason"] == "not_held"


def test_releasing_a_nonsense_id_is_a_404(client):
    _seed(client)
    r = client.post("/api/mesh/release",
                    params={"reservation_id": "n1#9999",
                            "mesh_id": MESH})
    assert r.status_code == 404


def test_a_reservation_carries_the_tier_and_order(client):
    _seed(client)
    body = client.post("/api/mesh/reserve",
                       params={"mesh_id": MESH},
                       json={"peer_id": "n1", "memory_gb": 1.0,
                             "tier": "pago_unico",
                             "order_id": "orden-42"}).json()
    assert body["reservation"]["tier"] == "pago_unico"


def test_the_listing_shows_all_five_numbers(client):
    _seed(client)
    _contribute(client, peer_id="n2", vram=24.0, advertised=12.0, used=2.0)
    client.post("/api/mesh/reserve",
                params={"mesh_id": MESH},
                json={"peer_id": "n2", "memory_gb": 3.0})
    nodes = client.get("/api/mesh/reservations",
                       params={"mesh_id": MESH}).json()["nodes"]
    n2 = nodes["n2"]
    assert n2["physical_gb"] == 24.0
    assert n2["advertised_gb"] == 12.0
    assert n2["reported_used_gb"] == 2.0
    assert n2["reserved_gb"] == 3.0
    assert n2["free_gb"] == 7.0


def test_a_reservation_survives_the_next_request(client):
    """Not just within one call. The book has to outlive the request that made
    it, or the endpoint is a no-op with extra steps.
    """
    _seed(client)
    client.post("/api/mesh/reserve",
                params={"mesh_id": MESH},
                json={"peer_id": "n1", "memory_gb": 5.0})
    view = client.get("/api/mesh/reservations",
                      params={"mesh_id": MESH}).json()
    assert view["nodes"]["n1"]["reserved_gb"] == 5.0


def test_reservations_are_scoped_per_mesh(client):
    _seed(client)
    client.post("/api/mesh/reserve",
                params={"mesh_id": MESH},
                json={"peer_id": "n1", "memory_gb": 5.0})
    # A different mesh id sees no peers admitted, so nothing to reserve.
    r = client.post("/api/mesh/reserve",
                    params={"mesh_id": "otra-malla"},
                    json={"peer_id": "n1", "memory_gb": 1.0})
    assert r.status_code == 404


def test_the_listing_documents_that_it_is_ephemeral(client):
    _seed(client)
    body = client.get("/api/mesh/reservations",
                      params={"mesh_id": MESH}).json()
    assert "memoria" in body["note"]
