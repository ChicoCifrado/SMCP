"""Property-based tests para admission/verify (capacidad).

Usa random (stdlib) en vez de hypothesis para no añadir dependencias.
Verifica invariantes de capacity_is_intact y capacity_claim_status.
"""
from __future__ import annotations

import random

from smcp.core.contrib import PeerContribution, capacity_is_intact, capacity_claim_status


def _make_peer(rng: random.Random) -> tuple[PeerContribution, str]:
    peer = PeerContribution(
        peer_id=f"peer-{rng.randint(0, 1000)}",
        vram_gb=round(rng.uniform(1.0, 64.0), 4),
        vram_advertised_gb=round(rng.uniform(1.0, 64.0), 4),
        ram_gb=round(rng.uniform(1.0, 128.0), 4),
        cpu_cores=rng.randint(1, 64),
        backend=rng.choice(["cuda", "cpu", ""]),
    )
    # admitir con digest
    mesh_id = "mesh-test"
    peer.admitted_digest = peer.capacity_digest(mesh_id)
    return peer, mesh_id


def test_intact_after_admission():
    rng = random.Random(42)
    for _ in range(200):
        peer, mesh_id = _make_peer(rng)
        assert capacity_is_intact(peer, mesh_id) is True


def test_intact_false_when_field_mutated():
    rng = random.Random(7)
    for _ in range(200):
        peer, mesh_id = _make_peer(rng)
        # mutar un campo
        field = rng.choice(["vram_gb", "vram_advertised_gb", "ram_gb", "cpu_cores", "backend"])
        if field == "vram_gb":
            peer.vram_gb += 1.0
        elif field == "vram_advertised_gb":
            peer.vram_advertised_gb += 1.0
        elif field == "ram_gb":
            peer.ram_gb += 1.0
        elif field == "cpu_cores":
            peer.cpu_cores += 1
        else:
            peer.backend = "mutated"
        assert capacity_is_intact(peer, mesh_id) is False


def test_intact_false_when_no_digest():
    rng = random.Random(99)
    for _ in range(50):
        peer, mesh_id = _make_peer(rng)
        peer.admitted_digest = ""
        assert capacity_is_intact(peer, mesh_id) is False


def test_claim_status_agree():
    rng = random.Random(1)
    for _ in range(100):
        vram = round(rng.uniform(1.0, 64.0), 4)
        peer = PeerContribution(peer_id="p", vram_gb=vram)
        # detected = claim (within 2%)
        status = capacity_claim_status(peer, detected_vram_gb=vram)
        assert status == "agree"


def test_claim_status_exceeds():
    rng = random.Random(2)
    for _ in range(100):
        vram = round(rng.uniform(10.0, 64.0), 4)
        peer = PeerContribution(peer_id="p", vram_gb=vram)
        detected = vram * 0.5  # detected much less
        status = capacity_claim_status(peer, detected_vram_gb=detected)
        assert status == "claim_exceeds_detected"


def test_claim_status_unknown():
    rng = random.Random(3)
    for _ in range(50):
        peer = PeerContribution(peer_id="p", vram_gb=8.0)
        assert capacity_claim_status(peer, detected_vram_gb=None) == "unknown"
        assert capacity_claim_status(peer, detected_vram_gb=0) == "unknown"
        assert capacity_claim_status(peer, detected_vram_gb=-1) == "unknown"


def test_claim_status_detected_only():
    rng = random.Random(4)
    for _ in range(50):
        peer = PeerContribution(peer_id="p", vram_gb=0.0)
        status = capacity_claim_status(peer, detected_vram_gb=8.0)
        assert status == "detected_only"
