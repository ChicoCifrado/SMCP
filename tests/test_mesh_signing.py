"""Tests for the four mesh-signing rules.

The spec these pin, in the owner's words:

1. A running node has at most **one** public key listening at a time, and
   guaranteeing that needs idempotency.
2. The public key *signs* the context (it does not encrypt it).
3. The context travels signed at all times.
4. The network trusts only nodes whose context is signed.

Threshold signatures are a later step and do not change these tests: a
threshold attestation would replace the single-key proof checked here with a
combined one, leaving the shape of the rules intact.
"""
import base64

import pytest

from smcp.core.gist import Gist, GistKind
from smcp.core.secure_context import (
    AdmissionDenied,
    KeyRotationDenied,
    SecureSharedContext,
)
from smcp.core.provenance import KeyPair, digest_of


def _key(author: str = "n1") -> KeyPair:
    """A node's key. One per author: the key *is* the identity."""
    return KeyPair.new(author)


def _signed_gist(key: KeyPair, author: str, label: str = "g1",
                 text: str = "un gist") -> Gist:
    g = Gist(label=label, gist=text, kind=GistKind.FACT)
    g.author_id = author
    g.digest = digest_of(g)
    g.signature = key.sign(g.digest)
    g.sig_kind = key.kind
    return g


# ---------------------------------------------------------------------------
# Rule 1: one listening key per node, enforced idempotently
# ---------------------------------------------------------------------------
def test_registering_the_same_key_twice_is_a_no_op():
    """Idempotency: gossip re-delivers announces, and a rebind that changed
    state on each repeat would make the keyring lie about what it has seen."""
    ctx = SecureSharedContext()
    key = _key("n1")
    ctx.register_key("n1", key.public_key, key.kind)
    first = ctx.keyring["n1"]

    ctx.register_key("n1", key.public_key, key.kind)

    assert ctx.keyring["n1"] == first
    assert len(ctx.keyring) == 1


def test_a_second_different_key_is_refused():
    """One listening key at a time. A quiet rebind would let a node that was
    compromised yesterday re-key itself into every peer today."""
    ctx = SecureSharedContext()
    first = _key("n1")
    second = _key("n1-alt")
    ctx.register_key("n1", first.public_key, first.kind)

    with pytest.raises(KeyRotationDenied, match="ya tiene una clave"):
        ctx.register_key("n1", second.public_key, second.kind)

    # The original binding survived the attempt.
    assert ctx.keyring["n1"].public_key == first.public_key


def test_rotation_is_explicit_and_recorded():
    ctx = SecureSharedContext()
    first = _key("n1")
    second = _key("n1-alt")
    ctx.register_key("n1", first.public_key, first.kind)

    ctx.rotate_key("n1", second.public_key, second.kind)

    assert ctx.keyring["n1"].public_key == second.public_key
    # The trail says which author rotated, with fingerprints, not raw keys.
    labels = [e.label for e in ctx.ledger.entries()]
    assert "key-rotation:n1" in labels
    entry = ctx.ledger.by_label("key-rotation:n1")[0]
    assert entry.reason.startswith("rotacion ")
    assert second.public_key.hex() not in entry.reason


def test_key_status_never_exposes_the_key():
    ctx = SecureSharedContext()
    key = _key("n1")
    ctx.register_key("n1", key.public_key, key.kind)

    status = ctx.key_status()

    assert status["n1"]["fingerprint"] == __import__("hashlib").sha256(
        key.public_key).hexdigest()[:16]
    assert key.public_key.hex() not in str(status)


def test_key_anchor_is_immutable():
    """The binding is a trust anchor; mutating it in place would rewrite
    history without leaving a trace."""
    import dataclasses
    ctx = SecureSharedContext()
    key = _key("n1")
    ctx.register_key("n1", key.public_key, key.kind)

    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.keyring["n1"].public_key = b"otro"


# ---------------------------------------------------------------------------
# Rules 2 and 4: signing, and only signed content counts
# ---------------------------------------------------------------------------
def test_signed_content_is_admitted():
    ctx = SecureSharedContext()
    key = _key("n1")
    ctx.register_key("n1", key.public_key, key.kind)
    g = _signed_gist(key, "n1")

    ctx.admit(g)

    assert len(ctx) == 1
    assert ctx.is_attributed(g)


def test_unsigned_content_is_refused_even_when_policy_allows_it():
    """The mesh trusts signed contexts only. An unsigned gist is not weaker
    evidence, it is no evidence.

    The default policy already refuses it; the point of the explicit rule is
    that it still refuses when the policy is relaxed. Otherwise a deployment
    that widened the gate would silently start admitting unsigned content,
    and that is the exact change nobody would review.
    """
    from smcp.core.ledger import TrustGate, TrustPolicy
    # Policy explicitly allows unsigned writers (nobody denylisted, signature
    # not required): only the mesh rule stands between them and C.
    ctx = SecureSharedContext(
        gate=TrustGate(TrustPolicy.DENYLIST), require_signature=False)
    ctx.register_key("n1", _key("n1").public_key, "ed25519")
    g = Gist(label="g1", gist="sin firmar", kind=GistKind.FACT)
    g.author_id = "n1"

    with pytest.raises(AdmissionDenied, match="only trusts signed contexts"):
        ctx.admit(g)

    assert len(ctx) == 0
    # And the refusal is in the audit trail, not silent.
    assert [e for e in ctx.ledger.entries() if not e.accepted], \
        "el rechazo debio quedar en el ledger"


def test_signed_only_drops_everything_unattributable():
    """The view the network trusts."""
    ctx = SecureSharedContext()
    good = _key("n1")
    ctx.register_key("n1", good.public_key, good.kind)
    ctx.admit(_signed_gist(good, "n1", label="real"))

    trusted = ctx.signed_only()

    assert [g.label for g in trusted] == ["real"]
    assert ctx.untrusted_labels() == []


def test_gist_from_an_unknown_author_is_not_attributed():
    """A signature alone proves possession of a key, not that the key belongs
    to the claimed author. Without a prior binding there is no attribution."""
    ctx = SecureSharedContext()
    rogue = _key("nodo-fantasma")
    # Deliberately NOT registered.
    g = _signed_gist(rogue, "nodo-fantasma")

    assert not ctx.is_attributed(g)


def test_signature_stops_counting_after_a_rotation():
    """A rotation is the moment 'who signed this' becomes ambiguous. An old
    signature must not outlive it."""
    ctx = SecureSharedContext()
    old = _key("n1")
    ctx.register_key("n1", old.public_key, old.kind)
    g = _signed_gist(old, "n1")
    ctx.admit(g)
    assert ctx.is_attributed(g)

    ctx.rotate_key("n1", _key("n1-v2").public_key, "ed25519")

    assert not ctx.is_attributed(g)
    assert ctx.untrusted_labels() == ["g1"]


def test_signing_is_not_encryption():
    """Rule 2: the key signs, it does not encrypt. C must stay readable, or
    nothing could render it to an agent."""
    ctx = SecureSharedContext()
    key = _key("n1")
    ctx.register_key("n1", key.public_key, key.kind)
    g = _signed_gist(key, "n1", text="contenido en claro")
    ctx.admit(g)

    rendered = ctx.render()

    assert "contenido en claro" in rendered


def test_content_travels_signed_and_verifies_offline():
    """Rule 3: the context travels signed. A peer holding only the published
    fields must be able to check it without trusting the sender."""
    key = _key("n1")
    g = _signed_gist(key, "n1")

    # The wire form carries exactly what a verifier needs.
    wire = {
        "label": g.label,
        "gist": g.gist,
        "author_id": g.author_id,
        "digest": g.digest,
        "signature": base64.b64encode(g.signature).decode(),
        "sig_kind": g.sig_kind,
    }
    rebuilt = Gist(label=wire["label"], gist=wire["gist"], kind=GistKind.FACT)
    rebuilt.author_id = wire["author_id"]
    rebuilt.signature = base64.b64decode(wire["signature"])

    assert digest_of(rebuilt) == wire["digest"]
    # And the digest verifies against the announced key, standalone.
    from smcp.core.provenance import verify_public
    assert verify_public(wire["sig_kind"], key.public_key,
                         wire["digest"], rebuilt.signature)