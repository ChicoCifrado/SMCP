"""Tests minimos para join2mesh."""

import base64

from smcp.core.provenance import KeyPair
from smcp.core.join2mesh import Join2Mesh, validate_payment_headers


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
