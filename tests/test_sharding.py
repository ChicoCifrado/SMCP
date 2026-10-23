"""Tests del reparto de expertos MoE (`smcp.core.sharding`).

Cubren las dos estrategias y el selector, sin GPU ni red: el plan es puro
y determinista, igual que `placement`.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import pytest

from smcp.core.contrib import CapacityReport, ContributionLedger
from smcp.core.placement import ModelSpec, plan_placement
from smcp.core.provenance import KeyPair
from smcp.core.sharding import (
    ShardingStrategy,
    plan_tensor_sharding,
    plan_expert_assignment,
    plan_sharding,
    recommend_strategy,
)


PEERS = ["n0", "n1", "n2", "n3"]


# --------------------------------------------------------------- tensor sharding
def test_tensor_sharding_tiles_hidden_out():
    plan = plan_tensor_sharding("m", PEERS, hidden_in=768, hidden_out=768,
                                batch_size=2, seq_len=3)
    assert plan.ok
    assert plan.strategy == ShardingStrategy.TENSOR_SHARDING
    assert plan.n_peers == 4
    # cada peer tiene 2 shards (W_i col, W_o row)
    for pid in PEERS:
        assert len(plan.peer_shards[pid]) == 2
    # tiling: la union de rangos cubre [0, hidden_out) sin huecos
    for matrix in ("W_i", "W_o"):
        axis = "col" if matrix == "W_i" else "row"
        ranges = sorted(s.rng for p in PEERS
                        for s in plan.peer_shards[p]
                        if s.matrix == matrix)
        assert ranges[0].start == 0
        assert ranges[-1].end == 768
        for a, b in zip(ranges, ranges[1:]):
            assert a.end == b.start


def test_tensor_sharding_even_split():
    plan = plan_tensor_sharding("m", ["a", "b"], hidden_in=16, hidden_out=8)
    for pid in ("a", "b"):
        sh = [s for s in plan.peer_shards[pid] if s.matrix == "W_i"][0]
        assert sh.rng.size == 4


def test_tensor_sharding_uneven_absorbs_remainder():
    # 10 / 3 = 3,3,4
    plan = plan_tensor_sharding("m", ["a", "b", "c"], hidden_in=4, hidden_out=10)
    sizes = sorted(s.rng.size for p in ("a", "b", "c")
                   for s in plan.peer_shards[p] if s.matrix == "W_i")
    assert sizes == [3, 3, 4]
    assert sum(sizes) == 10


def test_tensor_sharding_rejects_no_peers():
    plan = plan_tensor_sharding("m", [], hidden_out=8)
    assert plan.ok is False
    assert plan.reason == "no_peers"


def test_tensor_sharding_rejects_missing_hidden_out():
    plan = plan_tensor_sharding("m", ["a"], hidden_out=0)
    assert plan.ok is False
    assert plan.reason == "missing_hidden_out"


def test_tensor_sharding_rejects_hidden_smaller_than_peers():
    plan = plan_tensor_sharding("m", ["a", "b", "c"], hidden_out=2)
    assert plan.ok is False
    assert plan.reason == "hidden_out_smaller_than_peers"


def test_tensor_sharding_comm_bytes():
    plan = plan_tensor_sharding("m", ["a", "b"], hidden_in=4, hidden_out=4,
                                batch_size=2, seq_len=3, bytes_per_elem=4)
    # tokens = 6, input_bytes = 6*4*4 = 96; n=2 -> scatter = 2*96 = 192
    assert plan.scatter_bytes == 2 * 6 * 4 * 4
    assert plan.gather_bytes == plan.scatter_bytes
    assert plan.total_comm_bytes == 2 * plan.scatter_bytes


def test_tensor_sharding_deterministic():
    a = plan_tensor_sharding("m", PEERS, hidden_in=8, hidden_out=16)
    b = plan_tensor_sharding("m", PEERS, hidden_in=8, hidden_out=16)
    assert a.to_dict() == b.to_dict()


def test_tensor_sharding_roundtrip_dict():
    plan = plan_tensor_sharding("m", ["a", "b"], hidden_in=4, hidden_out=8,
                                n_expert=4, n_expert_used=2)
    d = plan.to_dict()
    assert d["n_expert"] == 4
    assert d["n_expert_used"] == 2
    assert "peer_shards" in d


# --------------------------------------------------------------- expert assignment
def test_expert_assignment_covers_all():
    plan = plan_expert_assignment("m", PEERS, n_expert=16, overlap=0)
    assert plan.ok
    union = set()
    for v in plan.peer_experts.values():
        union |= set(v)
    assert union == set(range(16))


def test_expert_assignment_overlap():
    plan = plan_expert_assignment("m", ["a", "b"], n_expert=8, overlap=2)
    assert plan.ok
    # cada peer tiene al menos 2 extra
    for v in plan.peer_experts.values():
        assert len(v) >= 4  # 4 base + 2 overlap (con solape)


def test_expert_assignment_rejects_no_peers():
    plan = plan_expert_assignment("m", [], n_expert=8)
    assert plan.ok is False
    assert plan.reason == "no_peers"


def test_expert_assignment_rejects_missing_n_expert():
    plan = plan_expert_assignment("m", ["a", "b"], n_expert=0)
    assert plan.ok is False
    assert plan.reason == "missing_n_expert"


def test_expert_assignment_min_experts():
    plan = plan_expert_assignment("m", ["a", "b"], n_expert=4,
                                  min_experts_per_node=3)
    # 4 experts / 2 peers = 2 base, < 3 -> rechazo
    assert plan.ok is False
    assert "below_min" in plan.reason


# --------------------------------------------------------------- dispatch
def test_plan_sharding_dispatch():
    p1 = plan_sharding("m", ["a", "b"], strategy=ShardingStrategy.TENSOR_SHARDING,
                       hidden_out=8)
    assert p1.strategy == ShardingStrategy.TENSOR_SHARDING
    p2 = plan_sharding("m", ["a", "b"], strategy=ShardingStrategy.EXPERT_ASSIGNMENT,
                       n_expert=4)
    assert p2.strategy == ShardingStrategy.EXPERT_ASSIGNMENT


def test_plan_sharding_unknown_strategy():
    # passing a raw string not in enum
    plan = plan_sharding("m", ["a"], strategy="foo")  # type: ignore[arg-type]
    assert plan.ok is False


# --------------------------------------------------------------- recommend
def test_recommend_tensor_sharding_fast_big_batch():
    s = recommend_strategy(n_peers=4, batch_size=64, latency_ms=5.0, n_expert=128)
    assert s == ShardingStrategy.TENSOR_SHARDING


def test_recommend_expert_assignment_slow():
    s = recommend_strategy(n_peers=4, batch_size=64, latency_ms=100.0)
    assert s == ShardingStrategy.EXPERT_ASSIGNMENT


def test_recommend_expert_assignment_small_batch():
    s = recommend_strategy(n_peers=4, batch_size=2, latency_ms=5.0)
    assert s == ShardingStrategy.EXPERT_ASSIGNMENT


def test_recommend_expert_assignment_single_peer():
    s = recommend_strategy(n_peers=1, batch_size=64, latency_ms=5.0)
    assert s == ShardingStrategy.EXPERT_ASSIGNMENT


# --------------------------------------------------------------- ModelSpec
def test_modelspec_moe_fields_roundtrip():
    ms = ModelSpec(name="q", memory_required_gb=10.0, n_expert=128,
                   n_expert_used=8, hidden_in=768, hidden_out=768)
    d = ms.to_dict()
    assert d["n_expert"] == 128
    assert d["n_expert_used"] == 8
    ms2 = ModelSpec.from_dict(d)
    assert ms2.n_expert == 128
    assert ms2.hidden_out == 768


def test_modelspec_defaults_backward_compat():
    ms = ModelSpec(name="q", memory_required_gb=10.0)
    assert ms.n_expert == 0
    assert ms.hidden_out == 0


def _probe(url: str) -> str | None:
    try:
        with urllib.request.urlopen(url + "/models", timeout=10.0) as r:
            data = json.loads(r.read())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, OSError, ValueError):
        return None
    models = data.get("data", [])
    return models[0].get("id") if models else None


@pytest.mark.slow
def test_real_endpoint_sharding_plan():
    model_id = _probe(MESH_URL)
    if model_id is None:
        pytest.skip(f"sin endpoint en {MESH_URL}")
    # metadata MoE inventada (el endpoint no la publica); valida el flujo.
    spec = ModelSpec(name=model_id, memory_required_gb=8.0, n_layers=32,
                     n_expert=64, n_expert_used=8, hidden_in=768, hidden_out=768)
    led = ContributionLedger("m")
    for pid, vram in (("n0", 16.0), ("n1", 16.0)):
        key = KeyPair.new(pid)
        from smcp.core.contrib import CapacityReport
        ch = led.issue_challenge(pid, now=1000.0)
        rep = CapacityReport(mesh_id="m", peer_id=pid, vram_gb=vram,
                            vram_advertised_gb=vram, ram_gb=32.0, cpu_cores=8,
                            nonce=ch.nonce, issued_at=1000.0,
                            expires_at=1000.0 + 3600).sign(key)
        assert led.admit(rep, now=1000.0)[0]
        led.observe(pid, 1000.0, dt_s=3600.0)
    plan = plan_placement(spec, led, sharding_strategy=None)
    assert plan.ok
    assert "sharding" in plan.detail
    sh = plan.detail["sharding"]
    assert sh and sh.get("ok") is True
    assert sh.get("n_expert") == 64
    ms = ModelSpec(name="q", memory_required_gb=10.0, n_expert=128,
                   n_expert_used=8, hidden_in=768, hidden_out=768)
    d = ms.to_dict()
    assert d["n_expert"] == 128
    assert d["n_expert_used"] == 8
    ms2 = ModelSpec.from_dict(d)
    assert ms2.n_expert == 128
    assert ms2.hidden_out == 768


# --------------------------------------------------------------- placement integration
def _make_ledger(peers, vram):
    led = ContributionLedger("m")
    for pid in peers:
        key = KeyPair.new(pid)
        ch = led.issue_challenge(pid, now=1000.0)
        rep = CapacityReport(mesh_id="m", peer_id=pid, vram_gb=vram,
                            vram_advertised_gb=vram, ram_gb=32.0, cpu_cores=8,
                            nonce=ch.nonce, issued_at=1000.0,
                            expires_at=1000.0 + 3600).sign(key)
        assert led.admit(rep, now=1000.0)[0]
        led.observe(pid, 1000.0, dt_s=3600.0)
    return led


def test_placement_attaches_sharding_for_moe():
    spec = ModelSpec(name="q", memory_required_gb=8.0, n_layers=4,
                     n_expert=64, n_expert_used=8, hidden_in=768, hidden_out=768)
    led = _make_ledger(["n0", "n1"], 16.0)
    plan = plan_placement(spec, led)
    assert plan.ok
    assert "sharding" in plan.detail
    sh = plan.detail["sharding"]
    assert sh and sh.get("ok") is True
    assert sh.get("n_expert") == 64
    assert any("sharding:" in n for n in plan.notes)


def test_placement_no_sharding_for_dense():
    spec = ModelSpec(name="q", memory_required_gb=8.0, n_layers=4)
    led = _make_ledger(["n0", "n1"], 16.0)
    plan = plan_placement(spec, led)
    assert plan.ok
    assert plan.detail.get("sharding") == {}


# --------------------------------------------------------------- slow (real endpoint)
MESH_URL = os.environ.get("MESH_LLM_URL", "http://127.0.0.1:8888/v1")


def _probe(url: str) -> str | None:
    try:
        with urllib.request.urlopen(url + "/models", timeout=10.0) as r:
            data = json.loads(r.read())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, OSError, ValueError):
        return None
    models = data.get("data", [])
    return models[0].get("id") if models else None


@pytest.mark.slow
def test_real_endpoint_sharding_plan():
    model_id = _probe(MESH_URL)
    if model_id is None:
        pytest.skip(f"sin endpoint en {MESH_URL}")
    spec = ModelSpec(name=model_id, memory_required_gb=8.0, n_layers=32,
                     n_expert=64, n_expert_used=8, hidden_in=768, hidden_out=768)
    led = _make_ledger(["n0", "n1"], 16.0)
    plan = plan_placement(spec, led, sharding_strategy=None)
    assert plan.ok
    assert "sharding" in plan.detail
    sh = plan.detail["sharding"]
    assert sh and sh.get("ok") is True
    assert sh.get("n_expert") == 64