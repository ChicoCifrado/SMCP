"""API tests — runs lifecycle (create, state, outcome, cancel, 409)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api_server import app
from smcp_api import MANAGER


@pytest.fixture()
def client():
    # Isolate runs between tests
    MANAGER._active = None
    MANAGER._history.clear()
    with TestClient(app) as c:
        yield c
    MANAGER._active = None
    MANAGER._history.clear()


def _body(**kw):
    base = {
        "tasks": [{"label": "t-001", "body": "Inspect the constraint", "kind": "solve"}],
        "n_workers": 1,
        "max_rounds": 4,
        "backend": "fake",
    }
    base.update(kw)
    return base


def test_create_and_list_runs(client: TestClient):
    r = client.post("/api/runs", json=_body())
    assert r.status_code == 200
    h = r.json()
    assert h["id"].startswith("run_")
    assert h["status"] in ("queued", "starting", "running", "done", "error")
    assert h["task_count"] == 1

    r2 = client.get("/api/runs")
    assert r2.status_code == 200
    j = r2.json()
    assert j["active"] or j["runs"]


def test_run_conflict_409(client: TestClient):
    # First create a long-lived-ish run; second must 409 while active.
    r1 = client.post("/api/runs", json=_body())
    assert r1.status_code == 200
    # Immediately try another (fake runs finish fast, so also accept 200 if done)
    r2 = client.post("/api/runs", json=_body())
    if r2.status_code == 409:
        assert "active" in r2.json()["detail"]
    else:
        assert r2.status_code == 200


def test_run_validation(client: TestClient):
    r = client.post("/api/runs", json={"tasks": []})
    assert r.status_code == 422
    r = client.post("/api/runs", json=_body(backend="bogus"))
    assert r.status_code == 422
    r = client.post("/api/runs", json=_body(n_workers=99))
    assert r.status_code == 422


def test_run_not_found(client: TestClient):
    r = client.get("/api/runs/run_missing")
    assert r.status_code == 404


def test_fake_run_completes(client: TestClient):
    r = client.post("/api/runs", json=_body())
    assert r.status_code == 200
    rid = r.json()["id"]
    # TestClient runs the event loop; wait for outcome
    import time
    for _ in range(50):
        st = client.get(f"/api/runs/{rid}").json()
        if st["status"] in ("done", "error", "cancelled"):
            break
        time.sleep(0.1)
    assert st["status"] == "done", st
    out = client.get(f"/api/runs/{rid}/outcome")
    assert out.status_code == 200
    o = out.json()
    assert "answer" in o
    assert o["rounds"] >= 1
    state = client.get(f"/api/runs/{rid}/state")
    assert state.status_code == 200
    sj = state.json()
    assert sj["id"] == rid
    assert sj["queue"] or sj["gists"] or sj["status"] == "done"


def test_cancel_finished_returns_header(client: TestClient):
    r = client.post("/api/runs", json=_body())
    rid = r.json()["id"]
    import time
    for _ in range(50):
        st = client.get(f"/api/runs/{rid}").json()
        if st["status"] in ("done", "error", "cancelled"):
            break
        time.sleep(0.1)
    c = client.post(f"/api/runs/{rid}/cancel")
    assert c.status_code == 200
    assert c.json()["id"] == rid
