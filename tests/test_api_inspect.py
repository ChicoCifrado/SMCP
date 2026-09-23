"""API tests — context, ledger, metrics, unfold, verifier."""
from __future__ import annotations

import time

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


@pytest.fixture()
def finished_run(client: TestClient):
    r = client.post("/api/runs", json={
        "tasks": [{"label": "t-001", "body": "Inspect the load-bearing constraint", "kind": "solve"}],
        "n_workers": 1,
        "max_rounds": 4,
        "backend": "fake",
    })
    assert r.status_code == 200
    rid = r.json()["id"]
    for _ in range(50):
        st = client.get(f"/api/runs/{rid}").json()
        if st["status"] in ("done", "error", "cancelled"):
            break
        time.sleep(0.1)
    assert st["status"] == "done", st
    return rid


def test_context_list(client: TestClient, finished_run: str):
    r = client.get("/api/context")
    assert r.status_code == 200
    j = r.json()
    assert j["run"]["id"] == finished_run
    assert "gists" in j
    assert "render" in j
    assert j["size"] == len(j["gists"])


def test_context_label_and_unfold(client: TestClient, finished_run: str):
    j = client.get("/api/context").json()
    if not j["gists"]:
        pytest.skip("pipeline admitted no gists for fake run")
    label = j["gists"][0]["label"]
    one = client.get(f"/api/context/{label}")
    assert one.status_code == 200
    assert one.json()["gist"]["label"] == label

    uf = client.post("/api/unfold", json={"label": label, "deep": True})
    assert uf.status_code == 200
    assert "unfolded" in uf.json()


def test_context_missing_404(client: TestClient, finished_run: str):
    r = client.get("/api/context/nope-not-there")
    assert r.status_code == 404


def test_ledger_chain(client: TestClient, finished_run: str):
    r = client.get("/api/ledger")
    assert r.status_code == 200
    j = r.json()
    assert j["run"]["id"] == finished_run
    assert j["chain_ok"] is True
    assert isinstance(j["entries"], list)
    assert j["count"] == len(j["entries"])


def test_metrics(client: TestClient, finished_run: str):
    r = client.get("/api/metrics")
    assert r.status_code == 200
    j = r.json()
    assert "aggregate" in j
    assert "records" in j


def test_verifier_trajectory(client: TestClient):
    r = client.post("/api/verifier/check", json={
        "kind": "trajectory",
        "result": "transaction must be journaled before ack",
        "gist": "journal-before-ack constraint",
    })
    assert r.status_code == 200
    j = r.json()
    assert "ok" in j
    assert "reasons" in j
    assert isinstance(j["bullet_report"], list)


def test_verifier_invalid_kind(client: TestClient):
    r = client.post("/api/verifier/check", json={"kind": "bogus"})
    assert r.status_code == 422
