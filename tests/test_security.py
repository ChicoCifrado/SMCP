"""Tests for the DELM security layer (Capas 1+2).

Covers: canonical digest, ed25519 sign/verify, trust gate, the secure
context's four guarantees (gate / signature / integrity / immutability),
and the append-only hash-chained ledger.
"""
from __future__ import annotations

import pytest

from delm.core.gist import Gist, GistKind
from delm.core.ledger import AdmissionLedger, TrustGate, TrustPolicy
from delm.core.provenance import (
    KeyPair,
    digest_of,
    verify_public,
)
from delm.core.secure_context import SecureSharedContext


# ------------------------------------------------------------------ helpers
def _signed(kp: KeyPair, label: str, text: str,
            kind=GistKind.FACT) -> Gist:
    g = Gist(label=label, gist=text, kind=kind)
    g.author_id = kp.author_id
    g.digest = digest_of(g)
    g.signature = kp.sign(g.digest)
    g.sig_kind = kp.kind
    return g


def _ctx(gate=None, kp: KeyPair | None = None) -> SecureSharedContext:
    c = SecureSharedContext(gate=gate or TrustGate(TrustPolicy.REQUIRE_SIGNED))
    if kp is not None:
        c.register_key(kp.author_id, kp.public_key, kp.kind)
    return c


# ------------------------------------------------------------------ digest
def test_digest_is_stable_and_content_sensitive():
    a = Gist(label="x", gist="hello world")
    b = Gist(label="x", gist="hello world")
    c = Gist(label="x", gist="hello WORLD")
    assert digest_of(a) == digest_of(b)
    assert digest_of(a) != digest_of(c)


def test_digest_ignores_provenance_fields():
    g = Gist(label="x", gist="hello")
    base = digest_of(g)
    g.author_id = "alice"
    g.digest = "deadbeef"
    g.signature = b"\x00\x01"
    g.sig_kind = "ed25519"
    assert digest_of(g) == base  # provenance must not change content digest


# ------------------------------------------------------------------ crypto
def test_ed25519_sign_verify_roundtrip():
    kp = KeyPair.new("alice")
    g = _signed(kp, "u1", "some claim")
    assert verify_public("ed25519", kp.public_key, g.digest, g.signature)


def test_ed25519_rejects_wrong_key():
    a = KeyPair.new("alice")
    b = KeyPair.new("bob")
    g = _signed(a, "u1", "some claim")
    # bob's public key must NOT verify alice's signature
    assert not verify_public("ed25519", b.public_key, g.digest, g.signature)


def test_ed25519_rejects_tampered_digest():
    a = KeyPair.new("alice")
    g = _signed(a, "u1", "some claim")
    # flip one byte of the digest -> verification must fail
    bad = (g.digest[:-1] + ("0" if g.digest[-1] != "0" else "1"))
    assert not verify_public("ed25519", a.public_key, bad, g.signature)


def test_hmac_fallback_sign_verify():
    kp = KeyPair.new("alice", kind="hmac")
    g = _signed(kp, "u1", "some claim")
    assert verify_public("hmac", kp.public_key, g.digest, g.signature)


# ------------------------------------------------------------------ gate
def test_gate_allowlist_only_listed():
    g = TrustGate(TrustPolicy.ALLOWLIST, allowlist={"alice"})
    assert g.permit("alice", True) == (True, "ok")
    assert g.permit("bob", True)[0] is False


def test_gate_denylist_blocks_listed():
    g = TrustGate(TrustPolicy.DENYLIST, denylist={"bob"})
    assert g.permit("bob", True)[0] is False
    assert g.permit("alice", True) == (True, "ok")


def test_gate_require_signed_needs_signature():
    g = TrustGate(TrustPolicy.REQUIRE_SIGNED)
    assert g.permit("alice", True) == (True, "ok")
    assert g.permit("alice", False)[0] is False


# ------------------------------------------------------------------ context
def test_context_admits_signed_gist():
    a = KeyPair.new("alice")
    c = _ctx(kp=a)
    g = _signed(a, "u1", "claim")
    c.admit(g)
    assert c.get("u1") is not None
    assert c.get("u1").digest == g.digest


def test_context_rejects_unsigned_author():
    a = KeyPair.new("alice")
    c = _ctx(kp=a)
    # eve never registered a key
    e = KeyPair.new("eve")
    g = _signed(e, "u9", "injected")
    with pytest.raises(Exception):
        c.admit(g)
    assert c.get("u9") is None


def test_context_rejects_tamper_on_immutable_label():
    a = KeyPair.new("alice")
    c = _ctx(kp=a)
    c.admit(_signed(a, "u1", "original text"))
    # same label, different content -> must be rejected, not overwritten
    g2 = _signed(a, "u1", "TAMPERED text")
    with pytest.raises(Exception):
        c.admit(g2)
    # original survives
    assert c.get("u1").gist == "original text"


def test_context_allows_idempotent_readmit():
    a = KeyPair.new("alice")
    c = _ctx(kp=a)
    g = _signed(a, "u1", "same text")
    c.admit(g)
    g_again = _signed(a, "u1", "same text")
    c.admit(g_again)  # identical digest -> idempotent, must not raise
    assert c.get("u1").gist == "same text"


# ------------------------------------------------------------------ ledger
def test_ledger_hash_chain_verifies():
    c = SecureSharedContext(gate=TrustGate(TrustPolicy.REQUIRE_SIGNED))
    a = KeyPair.new("alice")
    c.register_key("alice", a.public_key, a.kind)
    c.admit(_signed(a, "u1", "a"))
    assert c.ledger.verify_chain()


def test_ledger_tamper_detected():
    c = SecureSharedContext(gate=TrustGate(TrustPolicy.REQUIRE_SIGNED))
    a = KeyPair.new("alice")
    c.register_key("alice", a.public_key, a.kind)
    c.admit(_signed(a, "u1", "a"))
    # mutate an entry -> chain must fail
    c.ledger.entries()[0].reason = "forged"
    assert not c.ledger.verify_chain()


def test_ledger_records_rejections():
    c = SecureSharedContext(gate=TrustGate(TrustPolicy.REQUIRE_SIGNED))
    a = KeyPair.new("alice")
    c.register_key("alice", a.public_key, a.kind)
    e = KeyPair.new("eve")
    try:
        c.admit(_signed(e, "u9", "injected"))
    except Exception:
        pass
    rejected = [e for e in c.ledger.entries() if not e.accepted]
    assert len(rejected) == 1
    assert c.ledger.verify_chain()


# -------------------------------------------------------- pipeline wiring
# These lock in that DelmPipeline *actually* routes through the secure
# context (so the layer can't be silently disabled) and that every admitted
# gist carries a valid signature under its author.
def test_pipeline_uses_secure_context_and_signs():
    import asyncio
    from delm.core.pipeline import DelmPipeline
    from delm.core.llm import FakeLLMClient
    from delm.core.task_queue import Task

    llm = FakeLLMClient()
    pipe = DelmPipeline(llm=llm, n_workers=2)
    assert isinstance(pipe.ctx, SecureSharedContext)
    tasks = [Task(label="t1", body="b", kind="solve"),
             Task(label="t2", body="b", kind="solve")]

    async def reason(t):
        return f"solved {t.label}"

    async def go():
        return await pipe.run(tasks, reason=reason, yield_between=True)

    asyncio.run(go())
    assert len(pipe.ctx) >= 1
    # Every admitted gist must verify under its author's registered key.
    for g in pipe.ctx:
        pub = pipe.ctx.keyring.get(g.author_id)
        assert pub is not None, f"author {g.author_id} not in keyring"
        assert verify_public(pub.kind, pub.public_key, g.digest, g.signature)
    # Ledger must be intact.
    assert pipe.ctx.ledger.verify_chain()


def test_pipeline_rejects_forged_signature():
    import asyncio
    from delm.core.pipeline import DelmPipeline
    from delm.core.llm import FakeLLMClient
    from delm.core.task_queue import Task

    llm = FakeLLMClient()
    pipe = DelmPipeline(llm=llm, n_workers=1)

    async def reason(t):
        return f"solved {t.label}"

    async def go():
        return await pipe.run([Task(label="t1", body="b", kind="solve")],
                              reason=reason, yield_between=True)

    asyncio.run(go())
    # A forged signature (garbage bytes) must be rejected, not admitted.
    from delm.core.gist import Gist
    forged = Gist(label="forged", gist="x", author_id="worker-0")
    forged.digest = "not-a-real-digest"
    forged.signature = b"garbage"
    with pytest.raises(Exception):
        pipe.ctx.admit(forged)
