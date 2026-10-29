"""Tests minimos para join2mesh."""

import base64

from smcp.core.provenance import KeyPair
from smcp.core.join2mesh import (
    Join2Mesh,
    validate_payment_headers,
    parse_beef,
    validate_timestamp,
    validate_payment,
)


def test_parse_beef_ok():
    import base64
    raw = parse_beef(base64.b64encode(b"hello").decode())
    assert raw == b"hello"


def test_validate_timestamp_ok():
    now = 1000000
    assert validate_timestamp(str(now - 1000), now) is True


def test_validate_payment_ok():
    import base64
    headers = {
        "x-bsv-beef": base64.b64encode(b"tx").decode(),
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


def test_join2mesh_handshake():
    kp = KeyPair.new("node-a")
    j = Join2Mesh(kp)
    hs = j.build_handshake("node-a", "mesh-test", timestamp_ms=456)
    assert hs.signature != b""
    assert hs.pub_key_b64


def test_join2mesh_verify_pubkey():
    kp = KeyPair.new("node-a")
    j = Join2Mesh(kp)
    hs = j.build_handshake("node-a", "mesh-test", timestamp_ms=456)
    assert j.verify_pubkey(hs, kp.public_key) is True
    assert j.verify_pubkey(hs, b"wrong") is False


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
