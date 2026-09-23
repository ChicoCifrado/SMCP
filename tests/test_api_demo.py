"""API tests — in-process demos."""
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


def test_demo_pipeline(client: TestClient):
    r = client.post("/api/demo/pipeline")
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert j["demo"] == "pipeline"
    assert "secs" in j
    data = j["data"]
    assert "final_answer" in data
    assert "admitted_gists" in data


def test_demo_security(client: TestClient):
    r = client.post("/api/demo/security")
    assert r.status_code == 200
    j = r.json()
    assert j["demo"] == "security"
    assert j["ok"] is True
    assert j["data"]["ok"] is True


def test_demo_taint(client: TestClient):
    r = client.post("/api/demo/taint")
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert "stdout" in j["data"]


def test_demo_rsi(client: TestClient):
    r = client.post("/api/demo/rsi")
    assert r.status_code == 200
    j = r.json()
    assert j["demo"] == "rsi"
    assert j["ok"] is True


def test_demo_multihost_rejected(client: TestClient):
    r = client.post("/api/demo/multihost")
    assert r.status_code == 400
    assert "subprocess" in r.json()["detail"] or "/api/run" in r.json()["detail"]


def test_demo_unknown_404(client: TestClient):
    r = client.post("/api/demo/nope")
    assert r.status_code == 404


def test_subprocess_status_functions(client: TestClient):
    r = client.get("/api/status")
    assert r.status_code == 200
    j = r.json()
    assert j["core_modules"] >= 1
    assert j["test_files"] >= 1
    assert len(j["demos"]) >= 4
    r2 = client.get("/api/functions")
    assert r2.status_code == 200
    ids = [f["id"] for f in r2.json()]
    assert "demo" in ids
    assert "tests" in ids
