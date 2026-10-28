"""Tests minimos para join2mesh."""

import base64

from smcp.core.provenance import KeyPair
from smcp.core.join2mesh import Join2Mesh


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
