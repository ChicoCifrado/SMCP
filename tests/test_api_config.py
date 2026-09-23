"""API tests — config, probe, health."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api_server import app
from smcp_api import MANAGER


@pytest.fixture()
def client():
    MANAGER._active = None
    MANAGER._history.clear()
    with TestClient(app) as c:
        yield c
    MANAGER._active = None
    MANAGER._history.clear()


def test_get_config_masks_key(client: TestClient):
    r = client.get("/api/config")
    assert r.status_code == 200
    j = r.json()
    assert "api_key" not in j  # never expose raw key
    assert j["api_key_set"] in (True, False)
    assert "has_model" in j
    assert "base_url" in j


def test_health(client: TestClient):
    r = client.get("/api/health")
    assert r.status_code == 200
    j = r.json()
    assert j["api"] is True
    assert "model" in j
    assert j["model"]["configured"] in (True, False)


def test_probe(client: TestClient):
    r = client.post("/api/config/probe", json={"check_completion": False})
    assert r.status_code == 200
    j = r.json()
    assert "reachable" in j
    assert "base_url" in j
    # without a live endpoint, reachable may be False — but no exception
    if not j["reachable"]:
        assert j.get("error")
