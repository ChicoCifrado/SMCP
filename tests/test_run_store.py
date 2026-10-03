"""Tests de run_store: persistencia de runs en disco."""

import time

import pytest

from delm.core.run_store import RunStore, StoredRun


@pytest.fixture()
def store(tmp_path):
    return RunStore(path=str(tmp_path / "runs.db"))


def _run(rid="run_abc123", gists=None):
    return StoredRun(
        id=rid,
        header={"id": rid, "status": "done", "n_workers": 2},
        outcome={"answer": "Paris", "admitted_gists": 1},
        events=[{"type": "started", "ts": time.time()}],
        gists=gists if gists is not None else [{"label": "t-001/w0"}],
        created_at=time.time(),
        updated_at=time.time(),
    )


def test_save_and_get(store):
    r = _run()
    store.save(r)
    got = store.get("run_abc123")
    assert got is not None
    assert got.id == "run_abc123"
    assert got.header["status"] == "done"
    assert got.outcome["answer"] == "Paris"
    assert got.events[0]["type"] == "started"
    assert got.gists[0]["label"] == "t-001/w0"


def test_get_missing_returns_none(store):
    assert store.get("run_nope") is None


def test_history_ordering(store):
    a = _run(rid="run_a")
    b = _run(rid="run_b")
    store.save(a)
    time.sleep(0.01)
    store.save(b)
    hist = store.history()
    assert [h.id for h in hist] == ["run_b", "run_a"]


def test_save_updates_existing(store):
    r = _run()
    store.save(r)
    r2 = StoredRun(
        id="run_abc123",
        header={"id": "run_abc123", "status": "error"},
        outcome=None,
        events=[],
        gists=[],
        created_at=r.created_at,
        updated_at=time.time(),
    )
    store.save(r2)
    got = store.get("run_abc123")
    assert got.header["status"] == "error"
    assert got.outcome is None


def test_drop(store):
    store.save(_run())
    assert store.drop("run_abc123") is True
    assert store.get("run_abc123") is None
    assert store.drop("run_abc123") is False


def test_clear(store):
    store.save(_run("run_1"))
    store.save(_run("run_2"))
    n = store.clear()
    assert n == 2
    assert store.history() == []


def test_persists_across_instances(tmp_path):
    p = str(tmp_path / "runs.db")
    r = _run()
    RunStore(path=p).save(r)
    got = RunStore(path=p).get("run_abc123")
    assert got is not None
    assert got.outcome["admitted_gists"] == 1


def test_many_gists_survive(store):
    gists = [{"label": f"t-{i}/w0", "digest": f"d{i:04x}"} for i in range(50)]
    r = _run(gists=gists)
    store.save(r)
    got = store.get("run_abc123")
    assert got is not None
    assert len(got.gists) == 50
    assert got.gists[-1]["digest"] == "d0031"
