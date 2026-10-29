"""Tests minimos para pago2mesh."""

from smcp.core.provenance import KeyPair
from smcp.core.pago2mesh import (
    Pago2Mesh,
    validate_payment_headers,
    parse_beef,
    validate_timestamp,
    validate_payment,
)


def test_parse_beef_ok():
    import base64
    raw = parse_beef(base64.b64encode(b"hello").decode())
    assert raw == b"hello"


def test_parse_beef_invalid():
    try:
        parse_beef("!!!")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_validate_timestamp_ok():
    now = 1000000
    assert validate_timestamp(str(now - 1000), now) is True


def test_validate_timestamp_stale():
    now = 1000000
    assert validate_timestamp(str(now - 40000), now) is False


def test_validate_payment_ok():
    headers = {
        "x-bsv-beef": __import__("base64").b64encode(b"tx").decode(),
        "x-bsv-sender": "02abc",
        "x-bsv-nonce": "bm9uY2U=",
        "x-bsv-time": "1000000",
        "x-bsv-vout": "0",
    }
    now = 1000000
    def internalize(beef, nonce, time, sender, vout):
        return True, False
    ok, reason = validate_payment(headers, now, internalize)
    assert ok is True
    assert reason == "ok"


def test_validate_payment_replay():
    headers = {
        "x-bsv-beef": __import__("base64").b64encode(b"tx").decode(),
        "x-bsv-sender": "02abc",
        "x-bsv-nonce": "bm9uY2U=",
        "x-bsv-time": "1000000",
        "x-bsv-vout": "0",
    }
    now = 1000000
    def internalize(beef, nonce, time, sender, vout):
        return True, True
    ok, reason = validate_payment(headers, now, internalize)
    assert ok is False
    assert reason == "replay"


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
