"""Tests minimos para pago2mesh."""

from smcp.core.provenance import KeyPair
from smcp.core.pago2mesh import Pago2Mesh, validate_payment_headers


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


def test_validate_payment_headers_ok():
    headers = {
        "x-bsv-beef": "AAAA",
        "x-bsv-sender": "02abc",
        "x-bsv-nonce": "bm9uY2U=",
        "x-bsv-time": "1719500000000",
        "x-bsv-vout": "0",
    }
    assert validate_payment_headers(headers) is True


def test_validate_payment_headers_missing():
    headers = {"x-bsv-beef": "AAAA"}
    assert validate_payment_headers(headers) is False
