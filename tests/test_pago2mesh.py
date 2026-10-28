"""Tests minimos para pago2mesh."""

from smcp.core.provenance import KeyPair
from smcp.core.pago2mesh import Pago2Mesh


def test_pago2mesh_create():
    kp = KeyPair.new("owner")
    p = Pago2Mesh(kp)
    res = p.create("mesh-test", version_floor=(1, 0), timestamp_ms=123)
    assert res.created is True
    assert res.mesh_id == "mesh-test"
    assert res.policy_hash


def test_pago2mesh_sign_payload():
    kp = KeyPair.new("owner")
    p = Pago2Mesh(kp)
    payload = p.build_payload("mesh-test", version_floor=(1, 0), timestamp_ms=123)
    sig = p.sign_payload(payload)
    assert isinstance(sig, (bytes, bytearray))
    assert len(sig) > 0
