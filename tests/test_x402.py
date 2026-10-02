"""Tests for the x402 challenge/proof verifier.

Where these vectors come from: section 13 of the specification says future
revisions *will* include canonical challenge, proof and transaction examples.
It does not include them yet. So nothing here validates interoperability with
another implementation — every vector is derived from the prose and pins
*our* reading of it. When the spec ships real vectors, they belong in this file
next to these, and any disagreement is a bug in one of the two.

The fake settlement layer is deliberately able to lie in specific ways, because
a verifier tested only against a cooperative backend is a verifier that has
only been tested against itself.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest

from delm.core import x402

TXID = "a" * 64
OTHER_TXID = "b" * 64
PAYEE = "76a914" + "11" * 20 + "88ac"
OTHER_SCRIPT = "76a914" + "22" * 20 + "88ac"


class FakeSettlement:
    """A settlement layer whose answers are all under test control."""

    def __init__(
        self,
        *,
        inputs: list[tuple[str, int]] | None = None,
        outputs: list[tuple[str, int]] | None = None,
        txid: str = TXID,
        mempool: bool = True,
        undecodable: bool = False,
        lie_about_spend: bool = False,
        lie_about_inputs: bool = False,
        deny_spend: bool = False,
    ) -> None:
        self._inputs = inputs if inputs is not None else [(TXID, 0)]
        self._outputs = outputs if outputs is not None else [(PAYEE, 50)]
        self._txid = txid
        self._mempool = mempool
        self._undecodable = undecodable
        self._lie_about_spend = lie_about_spend
        self._lie_about_inputs = lie_about_inputs
        #: A backend whose boolean says "not spent" while its input list names
        #: the nonce. The opposite inconsistency from lie_about_spend.
        self._deny_spend = deny_spend

    def inputs_of(self, rawtx_b64: str) -> list[tuple[str, int]]:
        # A backend that lies about the input list while its boolean agrees.
        if self._lie_about_inputs:
            return [("c" * 64, 7)]
        return list(self._inputs)

    def spends_outpoint(self, rawtx_b64: str, txid: str, vout: int) -> bool:
        if self._deny_spend:
            return False
        if self._lie_about_spend:
            return True
        return (txid, vout) in self._inputs

    def payment_outputs(self, rawtx_b64: str) -> list[tuple[str, int]]:
        if self._undecodable:
            raise ValueError("bad rawtx")
        return list(self._outputs)

    def txid_of(self, rawtx_b64: str) -> str:
        if self._undecodable:
            raise ValueError("bad rawtx")
        return self._txid

    def accepted_in_mempool(self, txid: str) -> bool:
        return self._mempool


def make_binding(**kw: Any) -> x402.RequestBinding:
    base: dict[str, Any] = dict(
        method="GET",
        path="/v1/infer",
        query="",
        req_headers_sha256=x402.header_binding_digest({"Host": "api.local"}),
        req_body_sha256=x402.EMPTY_SHA256,
    )
    base.update(kw)
    return x402.RequestBinding(**base)


def make_challenge(**kw: Any) -> x402.Challenge:
    base: dict[str, Any] = dict(
        v=1,
        scheme="bsv-tx-v1",
        domain="api.local",
        amount_sats=50,
        payee_locking_script_hex=PAYEE,
        nonce_utxo=x402.NonceUtxo(TXID, 0, 1, "51"),
        binding=make_binding(),
        expires_at=2_000_000_000,
        require_mempool_accept=True,
    )
    base.update(kw)
    return x402.Challenge(**base)


def make_proof(ch: x402.Challenge, **kw: Any) -> x402.Proof:
    base: dict[str, Any] = dict(
        v=1,
        scheme="bsv-tx-v1",
        challenge_sha256=ch.sha256(),
        request=ch.binding,
        payment_txid=TXID,
        rawtx_b64=base64.b64encode(b"rawtx-bytes").decode(),
    )
    base.update(kw)
    return x402.Proof(**base)


def good_settlement() -> FakeSettlement:
    return FakeSettlement(inputs=[(TXID, 0)], outputs=[(PAYEE, 50)])


# ------------------------------------------------------------------ encoding
def test_canonical_json_is_sorted_and_compact():
    assert x402.canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonical_json_has_no_whitespace():
    assert b" " not in x402.canonical_json({"a": [1, 2], "b": "x"})


def test_challenge_hash_changes_when_any_field_changes():
    """The hash is over the whole object, so no field is outside it."""
    ch = make_challenge()
    for field, value in [
        ("amount_sats", 51),
        ("domain", "otro.local"),
        ("expires_at", 1),
    ]:
        other = make_challenge(**{field: value})
        assert other.sha256() != ch.sha256(), field


def test_canonical_json_roundtrips_unicode():
    ch = make_challenge(domain="nodo-ñ.local")
    assert x402.Challenge.from_dict(json.loads(
        x402.canonical_json(ch.to_dict()).decode("utf-8"))).domain == ch.domain


def test_base64url_is_unpadded_and_roundtrips():
    for payload in [b"", b"a", b"ab", b"abc", b"\x00\xff\xfe", b"x" * 100]:
        enc = x402.b64u_encode(payload)
        assert "=" not in enc
        assert x402.b64u_decode(enc) == payload


def test_base64url_decode_rejects_garbage():
    with pytest.raises(ValueError):
        x402.b64u_decode("!!!not base64!!!")


# ------------------------------------------------------------ header binding
def test_header_binding_lowercases_sorts_and_trims():
    """Steps 2-5 of the spec's canonical header-binding string.

    The name is lowercased and the value trimmed, and the pair is emitted as
    ``name:value\n`` sorted by name.
    """
    d = x402.header_binding_digest({"X-B": " two ", "A": "1"})
    expect = hashlib.sha256(b"a:1\nx-b:two\n").hexdigest()
    assert d == expect


def test_whitespace_in_a_header_name_is_not_trimmed():
    """Only the value is trimmed.

    Trimming the name as well would make ``" X-B"`` and ``"X-B"`` bind to the
    same digest. Those are distinct header names in HTTP, and collapsing them
    here would hand an attacker a free collision.
    """
    assert (x402.header_binding_digest({" X-B ": "v"})
            != x402.header_binding_digest({"X-B ": "v"}))


def test_header_binding_is_order_independent():
    a = x402.header_binding_digest({"A": "1", "B": "2"})
    b = x402.header_binding_digest([("B", "2"), ("A", "1")])
    assert a == b


def test_empty_header_set_hashes_to_the_empty_digest():
    assert x402.header_binding_digest(None) == x402.EMPTY_SHA256
    assert hashlib.sha256(b"").hexdigest() == x402.EMPTY_SHA256


def test_empty_body_digest_matches_the_well_known_value():
    assert x402.body_digest(b"") == x402.EMPTY_SHA256
    assert x402.body_digest(b"x") != x402.EMPTY_SHA256


# ----------------------------------------------------------------- roundtrip
def test_challenge_survives_the_header_roundtrip():
    ch = make_challenge()
    assert x402.Challenge.from_header(ch.to_header()) == ch


def test_proof_survives_the_header_roundtrip():
    ch = make_challenge()
    pr = make_proof(ch)
    assert x402.Proof.from_header(pr.to_header()) == pr


def test_challenge_hash_is_over_canonical_bytes_not_the_header_text():
    """Two byte-different headers must still hash the same.

    Padding and key order in the base64 are transport details; the digest is
    defined over the decoded canonical JSON.
    """
    ch = make_challenge()
    raw = json.loads(x402.b64u_decode(ch.to_header()).decode())
    reordered = x402.b64u_encode(json.dumps(raw).encode())
    assert x402.Challenge.from_header(reordered).sha256() == ch.sha256()


# ------------------------------------------------------------- happy path
def test_a_well_formed_payment_is_accepted():
    v = x402.verify(make_challenge(), make_proof(make_challenge()),
                    good_settlement(), now=1)
    assert v.ok, v.reason
    assert v.settlement == "mempool"
    assert v.paid_sats == 50


def test_verdict_is_truthy_on_success():
    ch = make_challenge()
    assert bool(x402.verify(ch, make_proof(ch), good_settlement(), now=1))


def test_payment_output_may_exceed_the_required_amount():
    v = x402.verify(make_challenge(), make_proof(make_challenge()),
                    FakeSettlement(outputs=[(PAYEE, 999)]), now=1)
    assert v.ok
    assert v.paid_sats == 999


def test_payment_to_another_script_does_not_count():
    v = x402.verify(make_challenge(), make_proof(make_challenge()),
                    FakeSettlement(outputs=[(OTHER_SCRIPT, 10_000)]), now=1)
    assert not v.ok
    assert "payee" in (v.reason or "")


def test_change_sums_across_outputs_to_the_payee():
    v = x402.verify(make_challenge(), make_proof(make_challenge()),
                    FakeSettlement(outputs=[(OTHER_SCRIPT, 10), (PAYEE, 30),
                                            (PAYEE, 25)]), now=1)
    assert v.ok, v.reason
    assert v.paid_sats == 55


def test_verdict_serialises_for_the_web_layer():
    ch = make_challenge()
    d = x402.verify(ch, make_proof(ch), good_settlement(), now=1).to_dict()
    assert d["ok"] is True
    assert d["settlement"] == "mempool"
    assert "header_binding_unverified" in d


# ------------------------------------------------------------------- replay
def test_a_payment_that_does_not_spend_the_nonce_is_refused():
    v = x402.verify(make_challenge(), make_proof(make_challenge()),
                    FakeSettlement(inputs=[(OTHER_TXID, 1)], outputs=[(PAYEE, 50)]),
                    now=1)
    assert not v.ok
    assert "nonce" in (v.reason or "")


def test_a_backend_whose_boolean_alone_claims_the_spend_is_refused():
    """The boolean is not sufficient; the input list must agree.

    ``spends_outpoint`` is one implementation's word for it. If that word were
    enough, replay protection would be exactly as strong as the honesty of
    whatever is wired into :class:`SettlementView` — and the whole point of
    this protocol is that replay protection comes from the settlement layer's
    double-spend rule, not from a service agreeing with itself.

    Here the backend says True while its own input list names a different
    outpoint. Either signal alone would accept a payment that never touched
    the nonce.
    """
    v = x402.verify(make_challenge(), make_proof(make_challenge()),
                    FakeSettlement(inputs=[(OTHER_TXID, 1)],
                                   lie_about_spend=True,
                                   outputs=[(PAYEE, 50)]), now=1)
    assert not v.ok, "el booleano del backend no basta: la lista debe coincidir"
    assert "nonce" in (v.reason or "")


def test_a_backend_whose_input_list_alone_names_the_nonce_is_refused():
    """The list is not sufficient either.

    The mirror image: the boolean says no, but the input list conveniently
    contains the nonce. A backend that disagrees with itself is not a backend
    to trust, and the conjunction catches both directions.
    """
    v = x402.verify(make_challenge(), make_proof(make_challenge()),
                    FakeSettlement(inputs=[(TXID, 0)], lie_about_inputs=True,
                                   outputs=[(PAYEE, 50)]), now=1)
    assert not v.ok, "la lista sola no basta: el booleano debe coincidir"
    assert "nonce" in (v.reason or "")


def test_a_consistent_backend_is_accepted():
    """Both signals agree on a genuine payment: no false rejection."""
    v = x402.verify(make_challenge(), make_proof(make_challenge()),
                    good_settlement(), now=1)
    assert v.ok, v.reason


def test_replay_protection_needs_no_server_side_state():
    """Verifying the same valid payment twice is not an error.

    The spec forbids relying on persistent nonce tracking, so the verifier has
    nothing to remember. Replay is prevented downstream by the nonce being
    spent already. This test states that design property so a future "fix"
    that adds a seen-nonce set is caught.
    """
    ch, pr = make_challenge(), None
    pr = make_proof(ch)
    s = good_settlement()
    assert x402.verify(ch, pr, s, now=1).ok
    assert x402.verify(ch, pr, s, now=1).ok
    assert not hasattr(s, "_seen")
    assert not hasattr(x402, "_SEEN_NONCES")


# ------------------------------------------------------------------ binding
def test_a_proof_for_another_challenge_is_refused():
    ch = make_challenge()
    other = make_challenge(amount_sats=51)
    v = x402.verify(ch, make_proof(other), good_settlement(), now=1)
    assert not v.ok
    assert "challenge_sha256" in (v.reason or "")


def test_a_proof_moved_to_another_path_is_refused():
    ch = make_challenge()
    moved = make_proof(ch, request=ch.binding.__class__(
        **{**ch.binding.to_dict(), "path": "/v1/otro"}))
    v = x402.verify(ch, moved, good_settlement(), now=1)
    assert not v.ok


def test_a_proof_moved_to_another_method_is_refused():
    ch = make_challenge()
    moved = make_proof(ch, request=x402.RequestBinding(
        **{**ch.binding.to_dict(), "method": "POST"}))
    assert not x402.verify(ch, moved, good_settlement(), now=1).ok


def test_a_proof_moved_to_another_body_is_refused():
    ch = make_challenge()
    moved = make_proof(ch, request=x402.RequestBinding(
        **{**ch.binding.to_dict(),
           "req_body_sha256": hashlib.sha256(b"otro").hexdigest()}))
    assert not x402.verify(ch, moved, good_settlement(), now=1).ok


def test_an_inbound_request_that_differs_from_the_challenge_is_refused():
    """Third leg of the three-way check: challenge, proof, and what arrived."""
    ch = make_challenge()
    inbound = x402.RequestBinding(**{**ch.binding.to_dict(), "path": "/otro"})
    v = x402.verify(ch, make_proof(ch), good_settlement(), inbound=inbound,
                    now=1)
    assert not v.ok
    assert "inbound" in (v.reason or "")


def test_matching_inbound_request_is_accepted():
    ch = make_challenge()
    v = x402.verify(ch, make_proof(ch), good_settlement(),
                    inbound=ch.binding, now=1)
    assert v.ok, v.reason


def test_the_method_comparison_is_case_insensitive_but_path_is_not():
    ch = make_challenge()
    lower = make_proof(ch, request=x402.RequestBinding(
        **{**ch.binding.to_dict(), "method": "get"}))
    assert x402.verify(ch, lower, good_settlement(), now=1).ok
    upper_path = make_proof(ch, request=x402.RequestBinding(
        **{**ch.binding.to_dict(), "path": "/V1/infer"}))
    assert not x402.verify(ch, upper_path, good_settlement(), now=1).ok


# --------------------------------------------------------------- expiration
def test_an_expired_challenge_is_refused():
    ch = make_challenge(expires_at=1_000)
    v = x402.verify(ch, make_proof(ch), good_settlement(), now=1_001)
    assert not v.ok
    assert "expired" in (v.reason or "")


def test_the_expiry_boundary_is_strictly_greater_than():
    ch = make_challenge(expires_at=1_000)
    assert x402.verify(ch, make_proof(ch), good_settlement(), now=1_000).ok


# ------------------------------------------------------- settlement states
def test_mempool_acceptance_is_required_when_the_challenge_says_so():
    ch = make_challenge(require_mempool_accept=True)
    v = x402.verify(ch, make_proof(ch),
                    FakeSettlement(mempool=False), now=1)
    assert not v.ok
    assert "mempool" in (v.reason or "")


def test_mempool_is_not_reported_as_confirmed():
    """The single most likely misreading of this protocol.

    ``require_mempool_accept`` means the transaction reached the mempool. The
    verdict must never say "confirmed", because a confirmation race can still
    double-spend it.
    """
    ch = make_challenge(require_mempool_accept=True)
    v = x402.verify(ch, make_proof(ch), good_settlement(), now=1)
    assert v.ok
    assert v.settlement == "mempool"
    assert "confirm" not in v.settlement
    assert v.to_dict()["settlement"] != "confirmed"


def test_without_the_requirement_nothing_is_claimed_about_settlement():
    ch = make_challenge(require_mempool_accept=False)
    v = x402.verify(ch, make_proof(ch), good_settlement(), now=1)
    assert v.ok
    assert v.settlement == "unverified", \
        "no mempool check means no settlement claim"


# ------------------------------------------------------------- shape checks
def test_an_empty_header_binding_is_refused_even_with_a_valid_payment():
    ch = make_challenge(binding=make_binding(
        req_headers_sha256=x402.EMPTY_SHA256))
    v = x402.verify(ch, make_proof(ch), good_settlement(), now=1)
    assert not v.ok
    assert "empty" in (v.reason or "")


def test_a_foreign_domain_is_refused_when_the_authority_is_checked():
    ch = make_challenge(domain="otro.local")
    v = x402.verify(ch, make_proof(ch), good_settlement(),
                    expect_domain="api.local", now=1)
    assert not v.ok
    assert "domain" in (v.reason or "")


def test_the_strong_header_check_rejects_a_wrong_digest():
    ch = make_challenge()
    v = x402.verify(ch, make_proof(ch), good_settlement(), now=1,
                    header_selector=lambda n: True,
                    inbound_headers={"Other": "x"})
    assert not v.ok
    assert "header binding" in (v.reason or "")


def test_the_strong_header_check_accepts_the_real_headers():
    ch = make_challenge()
    v = x402.verify(ch, make_proof(ch), good_settlement(), now=1,
                    header_selector=lambda n: n == "host",
                    inbound_headers={"Host": "api.local"})
    assert v.ok, v.reason
    assert v.header_binding_unverified is False


def test_an_uncheckable_header_binding_is_flagged_rather_than_claimed():
    """Honesty about what was and was not verified."""
    ch = make_challenge()
    v = x402.verify(ch, make_proof(ch), good_settlement(), now=1)
    assert v.ok
    assert v.header_binding_unverified is True
    assert v.to_dict()["header_binding_unverified"] is True


# ------------------------------------------------------------- shape errors
@pytest.mark.parametrize("mutate,fragment", [
    (lambda d: d.pop("amount_sats"), "amount_sats"),
    (lambda d: d.pop("nonce_utxo"), "nonce_utxo"),
    (lambda d: d.pop("payee_locking_script_hex"), "payee_locking_script_hex"),
    (lambda d: d.update(v=99), "version"),
    (lambda d: d.update(scheme="otro"), "scheme"),
    (lambda d: d.update(amount_sats=0), "amount_sats"),
    (lambda d: d.update(amount_sats=-5), "amount_sats"),
    (lambda d: d.update(path="infer"), "path"),
    (lambda d: d.update(nonce_utxo={"txid": TXID, "vout": 0, "satoshis": 0,
                                     "locking_script_hex": "51"}), "satoshis"),
    (lambda d: d.update(nonce_utxo={"txid": TXID, "vout": 0}), "nonce_utxo"),
])
def test_malformed_challenges_are_refused_with_a_reason(mutate, fragment):
    d = make_challenge().to_dict()
    mutate(d)
    v = x402.verify(d, make_proof(make_challenge()), good_settlement(), now=1)
    assert not v.ok, d
    assert fragment in (v.reason or ""), v.reason


def test_an_unsupported_proof_version_is_refused():
    ch = make_challenge()
    v = x402.verify(ch, make_proof(ch, v=2), good_settlement(), now=1)
    assert not v.ok
    assert "proof version" in (v.reason or "")


def test_an_unsupported_proof_scheme_is_refused():
    ch = make_challenge()
    v = x402.verify(ch, make_proof(ch, scheme="lightning"), good_settlement(),
                    now=1)
    assert not v.ok


def test_a_txid_that_does_not_match_the_raw_transaction_is_refused():
    ch = make_challenge()
    v = x402.verify(ch, make_proof(ch, payment_txid=OTHER_TXID),
                    good_settlement(), now=1)
    assert not v.ok
    assert "txid" in (v.reason or "")


def test_an_undecodable_transaction_is_refused_not_raised():
    ch = make_challenge()
    v = x402.verify(ch, make_proof(ch), FakeSettlement(undecodable=True),
                    now=1)
    assert not v.ok


def test_verification_never_raises_on_junk_input():
    """A verifier that throws on hostile input is a DoS, not a check."""
    junk = [
        ({"nope": 1}, make_proof(make_challenge()).to_dict()),
        (make_challenge().to_dict(), {"nope": 1}),
        ({}, {}),
    ]
    for ch_obj, pr_obj in junk:
        v = x402.verify(ch_obj, pr_obj, good_settlement(), now=1)
        assert not v.ok


def test_shape_check_is_reusable_by_an_issuer():
    assert x402.verify_challenge_shape(make_challenge().to_dict()) is None
    bad = make_challenge().to_dict()
    bad["amount_sats"] = -1
    assert x402.verify_challenge_shape(bad) is not None


# -------------------------------------------- x402 is not an identity system
def test_a_paid_request_does_not_confer_membership():
    """The design property that keeps the tiers separate.

    Paying proves funds moved. It must not produce any handle the roster would
    accept, or the price of a resource would become the price of belonging.
    """
    ch = make_challenge()
    v = x402.verify(ch, make_proof(ch), good_settlement(), now=1)
    assert v.ok
    assert v.payer is None, \
        "no payer identity is derived: a wallet is not a node credential"


def test_a_proof_moved_to_another_header_binding_is_refused():
    """The header digest is part of the binding and must be compared.

    Skipping that one field leaves the proof movable across requests that
    differ only in headers — which is precisely the case a header binding
    exists to close.
    """
    ch = make_challenge()
    moved = make_proof(ch, request=x402.RequestBinding(
        **{**ch.binding.to_dict(),
           "req_headers_sha256": hashlib.sha256(b"otro-binding").hexdigest()}))
    v = x402.verify(ch, moved, good_settlement(), now=1)
    assert not v.ok, "el digest de headers forma parte del binding"


def test_a_proof_moved_to_another_query_string_is_refused():
    ch = make_challenge()
    moved = make_proof(ch, request=x402.RequestBinding(
        **{**ch.binding.to_dict(), "query": "model=x"}))
    assert not x402.verify(ch, moved, good_settlement(), now=1).ok


def test_query_and_empty_query_are_distinct():
    """An empty query must not be conflated with any query.

    The spec requires the empty string when no query is present, so a proof
    that adds parameters changes the request it claims to be paying for.
    """
    with_q = make_binding(query="a=1")
    assert with_q.query != make_binding().query
    assert not with_q.matches(make_binding())


def test_a_backend_whose_boolean_denies_a_spend_its_own_list_reports_is_refused():
    """The mirror of the boolean-lies test: this closes the conjunction.

    Here the input list names the nonce but ``spends_outpoint`` returns False.
    Trusting the list alone would accept a payment the backend itself says
    does not touch the nonce — and dropping the boolean is exactly as wrong as
    dropping the list, in the other direction.
    """
    v = x402.verify(make_challenge(), make_proof(make_challenge()),
                    FakeSettlement(inputs=[(TXID, 0)], deny_spend=True,
                                   outputs=[(PAYEE, 50)]), now=1)
    assert not v.ok, "si el backend niega el gasto, el verificador no lo ignora"
    assert "nonce" in (v.reason or "")
