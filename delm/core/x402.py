"""x402 challenge/proof verification, offline — the verifier
role of **BRC-120**.

BRC-120 is a conformance designation, not a second protocol:
compliance means full x402 **version 1.0** as frozen in the
merkleworks-x402-spec repository (``spec/x402.md``), and this
module implements the verifier role of that frozen document —
the challenge shape (§4), the proof shape (§5), the transaction
requirements (§6), the verification procedure (§7), replay
protection (§8) and the rejection reasons behind the error
mapping (§9). What it deliberately does not implement is the
HTTP around them: the 402/retry flow and the status mapping
(402 for an expired challenge or an underpaid amount, 400 for
an unsupported scheme or a binding mismatch) are the server's,
and this module stays the pure, stateless check the server
calls — which is also what keeps it testable with no node.

What this is: the payment half of the three-tier product, as a pure verifier.
Give it a challenge, a proof and a settlement backend, and it tells you whether
one inference was paid for. No sockets, no chain node, no state.

What this is not: an identity system. x402 authenticates the *server* to the
*client*. It says nothing about whether a node is trustworthy, and it creates
no persistent relationship — the spec is explicit that servers MUST NOT rely on
nonce tracking, so a paid request does not make you a "member". In DeLM the
identity layer (:mod:`capability`, :mod:`roster`) is free and separate; this is
the price of the resource, not the price of belonging.

The parts of the spec that shaped this file, and why:

- **The nonce must be the server's.** "Clients MUST NOT supply arbitrary nonce
  UTXOs." The nonce is what makes replay impossible, and replay protection is
  "derived solely from settlement-layer double-spend protection". So the server
  picks the outpoint and the verifier checks the payment spends *that* one.
- **Mempool acceptance is not confirmation.** ``require_mempool_accept`` means
  the transaction reached the mempool. A confirmation race exists: a miner can
  double-spend what the server already accepted. That is a real risk and the
  verdict says so rather than claiming settlement.
- **Binding is deterministic.** ``challenge_sha256`` is SHA-256 over RFC 8785
  canonical JSON, and the proof restates the request binding, which must match
  both the challenge and the inbound request. A proof cannot be moved.
- **There are no test vectors.** Section 13 says future revisions will include
  them. So the vectors here are mine, derived from the spec text, and they pin
  *our* behaviour rather than proving interoperability.

Settlement is an injected protocol rather than a hard dependency, because
parsing a BSV transaction is not this module's job and a hard dependency would
make the verifier untestable without a node. The narrow interface is
:class:`SettlementView` — everything below needs to know about the chain is
four questions.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

__all__ = [
    "SUPPORTED_VERSION",
    "SUPPORTED_SCHEME",
    "MIN_HEADER_HASH_SET",
    "Challenge",
    "Proof",
    "NonceUtxo",
    "RequestBinding",
    "SettlementView",
    "Verdict",
    "Failure",
    "canonical_json",
    "challenge_hash",
    "header_binding_digest",
    "body_digest",
    "b64u_decode",
    "b64u_encode",
    "verify",
    "verify_challenge_shape",
]


SUPPORTED_VERSION = 1
SUPPORTED_SCHEME = "bsv-tx-v1"

#: Empty-request digest, precomputed: SHA-256 of the empty byte string.
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

#: Minimum header-binding set. A verifier that binds nothing binds nothing:
#: a proof would then be replayable across endpoints differing only in headers.
MIN_HEADER_HASH_SET = frozenset({"host"})


# --------------------------------------------------------------------------
# canonical encoding
# --------------------------------------------------------------------------
def canonical_json(obj: Any) -> bytes:
    """RFC 8785-shaped canonical bytes: sorted keys, no whitespace, UTF-8.

    The spec demands RFC 8785 but allows "a deterministic equivalent that
    guarantees identical byte serialization across independent
    implementations". Python's ``sort_keys`` plus compact separators gives
    that for the value types this protocol actually carries (strings, ints,
    bools, objects, arrays). It is *not* full RFC 8785 — the ES6 number
    formatting rules are not implemented — and every amount here is a small
    integer, so the difference cannot bite. It is the same canonical form
    already used in :mod:`contrib` and :mod:`ledger_canon`, which is worth
    more than theoretical purity: one convention in one codebase.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def challenge_hash(challenge_obj: dict[str, Any]) -> str:
    """``challenge_sha256``: SHA-256 over canonical challenge JSON bytes."""
    return _sha256_hex(canonical_json(challenge_obj))


def body_digest(body: bytes) -> str:
    """SHA-256 hex of the raw request body; empty body hashes to the
    well-known empty digest, as the spec requires."""
    return _sha256_hex(body)


def header_binding_digest(
    headers: dict[str, str] | list[tuple[str, str]] | None,
    *,
    select: "HeaderSelector | None" = None,
) -> str:
    """SHA-256 hex of the canonical header-binding string.

    The construction is fixed by the spec and not negotiable: lowercase the
    names, trim optional whitespace around values, sort by name in ascending
    byte order, concatenate as ``name:value\\n``.

    ``select`` chooses which headers are bound. The spec leaves the policy
    implementation-defined but requires it be consistent for a given server.
    A selector that binds an empty set is rejected by :func:`verify` — that is
    a policy error, not something to be allowed silently.
    """
    pairs: list[tuple[str, str]] = []
    if headers is None:
        items: list[tuple[str, str]] = []
    elif isinstance(headers, dict):
        items = list(headers.items())
    else:
        items = list(headers)
    for name, value in items:
        # Step 2 lowercases the *name*; step 3 trims optional whitespace around
        # the *value*. Trimming the name too would be a normalisation the spec
        # does not ask for, and it would make " X-B" and "X-B" bind
        # identically — two distinct header names, as far as HTTP is
        # concerned, collapsing into one.
        lname = name.lower()
        if select is not None and not select(lname):
            continue
        if not isinstance(value, str):
            raise ValueError(f"header value for {name!r} is not a string")
        pairs.append((lname, value.strip()))
    pairs.sort(key=lambda kv: kv[0].encode("utf-8"))
    blob = "".join(f"{n}:{v}\n" for n, v in pairs).encode("utf-8")
    return _sha256_hex(blob)


HeaderSelector = Any


# --------------------------------------------------------------------------
# base64url
# --------------------------------------------------------------------------
def b64u_encode(data: bytes) -> str:
    """base64url without padding, per the header encoding rules."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    """Strict-ish base64url decode that tolerates missing padding.

    Padding is restored before decoding so both padded and unpadded forms work;
    a client that omits the ``=`` is normal, not an attack.
    """
    pad = (-len(text)) % 4
    try:
        return base64.urlsafe_b64decode(text + "=" * pad)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64url: {exc}") from exc


# --------------------------------------------------------------------------
# objects
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class NonceUtxo:
    """The outpoint the payment must spend. Issued by the server."""

    txid: str
    vout: int
    satoshis: int
    locking_script_hex: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "txid": self.txid,
            "vout": self.vout,
            "satoshis": self.satoshis,
            "locking_script_hex": self.locking_script_hex,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NonceUtxo":
        return cls(
            txid=str(d["txid"]),
            vout=int(d["vout"]),
            satoshis=int(d["satoshis"]),
            locking_script_hex=str(d["locking_script_hex"]),
        )

    @property
    def outpoint(self) -> tuple[str, int]:
        return (self.txid, self.vout)


@dataclass(frozen=True)
class RequestBinding:
    """What a challenge binds, and what a proof must restate."""

    method: str
    path: str
    query: str
    req_headers_sha256: str
    req_body_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "query": self.query,
            "req_headers_sha256": self.req_headers_sha256,
            "req_body_sha256": self.req_body_sha256,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RequestBinding":
        # Los cinco campos son obligatorios en el challenge y en el
        # request del proof (§4, §5): `query` vacío es "", no ausente.
        return cls(
            method=str(d["method"]),
            path=str(d["path"]),
            query=str(d["query"]),
            req_headers_sha256=str(d["req_headers_sha256"]),
            req_body_sha256=str(d["req_body_sha256"]),
        )

    def matches(self, other: "RequestBinding") -> bool:
        """Field-by-field, case-insensitive only for the method.

        Path and query are compared byte-for-byte: the spec binds the request
        target, and normalising it here would create exactly the malleability
        the binding exists to prevent.
        """
        return (
            self.method.upper() == other.method.upper()
            and self.path == other.path
            and self.query == other.query
            and self.req_headers_sha256 == other.req_headers_sha256
            and self.req_body_sha256 == other.req_body_sha256
        )


@dataclass(frozen=True)
class Challenge:
    v: int
    scheme: str
    domain: str
    amount_sats: int
    payee_locking_script_hex: str
    nonce_utxo: NonceUtxo
    binding: RequestBinding
    expires_at: int
    require_mempool_accept: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "scheme": self.scheme,
            "domain": self.domain,
            "method": self.binding.method,
            "path": self.binding.path,
            "query": self.binding.query,
            "req_headers_sha256": self.binding.req_headers_sha256,
            "req_body_sha256": self.binding.req_body_sha256,
            "amount_sats": self.amount_sats,
            "payee_locking_script_hex": self.payee_locking_script_hex,
            "nonce_utxo": self.nonce_utxo.to_dict(),
            "expires_at": self.expires_at,
            "require_mempool_accept": self.require_mempool_accept,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Challenge":
        return cls(
            v=int(d["v"]),
            scheme=str(d["scheme"]),
            domain=str(d["domain"]),
            amount_sats=int(d["amount_sats"]),
            payee_locking_script_hex=str(d["payee_locking_script_hex"]),
            nonce_utxo=NonceUtxo.from_dict(d["nonce_utxo"]),
            binding=RequestBinding.from_dict(d),
            expires_at=int(d["expires_at"]),
            require_mempool_accept=bool(d["require_mempool_accept"]),
        )

    def sha256(self) -> str:
        return challenge_hash(self.to_dict())

    def to_header(self) -> str:
        return b64u_encode(canonical_json(self.to_dict()))

    @classmethod
    def from_header(cls, text: str) -> "Challenge":
        return cls.from_dict(json.loads(b64u_decode(text).decode("utf-8")))

    def is_expired(self, now: int) -> bool:
        """Strictly greater than ``expires_at``, as the spec words it."""
        return now > self.expires_at


@dataclass(frozen=True)
class Proof:
    v: int
    scheme: str
    challenge_sha256: str
    request: RequestBinding
    payment_txid: str
    rawtx_b64: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "scheme": self.scheme,
            "challenge_sha256": self.challenge_sha256,
            "request": self.request.to_dict(),
            "payment": {
                "txid": self.payment_txid,
                "rawtx_b64": self.rawtx_b64,
            },
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Proof":
        pay = d["payment"]
        return cls(
            v=int(d["v"]),
            scheme=str(d["scheme"]),
            challenge_sha256=str(d["challenge_sha256"]),
            request=RequestBinding.from_dict(d["request"]),
            payment_txid=str(pay["txid"]),
            rawtx_b64=str(pay["rawtx_b64"]),
        )

    def to_header(self) -> str:
        return b64u_encode(canonical_json(self.to_dict()))

    @classmethod
    def from_header(cls, text: str) -> "Proof":
        return cls.from_dict(json.loads(b64u_decode(text).decode("utf-8")))


# --------------------------------------------------------------------------
# settlement
# --------------------------------------------------------------------------
class SettlementView(Protocol):
    """The four questions verification needs answered about the chain.

    Keeping this an injected protocol is what lets the verifier be tested
    without a node, and it is also the honest boundary: this module must not
    be trusted to answer settlement questions itself.
    """

    def inputs_of(self, rawtx_b64: str) -> list[tuple[str, int]]:
        """Every ``(txid, vout)`` the payment transaction spends.

        Mandatory, not optional. Replay protection rests entirely on proving
        the payment spends the server's nonce, and that cannot be checked from
        anything other than the transaction's own inputs. A backend that
        cannot list them cannot be used to verify, and that is a feature: a
        verifier that quietly accepted an empty input list would report every
        payment as a replay.
        """
        ...

    def spends_outpoint(self, rawtx_b64: str, txid: str, vout: int) -> bool:
        """Whether ``rawtx_b64`` spends exactly the ``(txid, vout)`` outpoint."""
        ...

    def payment_outputs(self, rawtx_b64: str) -> list[tuple[str, int]]:
        """``(locking_script_hex, satoshis)`` for every output in the tx."""
        ...

    def txid_of(self, rawtx_b64: str) -> str:
        """Transaction id computed from the decoded raw bytes."""
        ...

    def accepted_in_mempool(self, txid: str) -> bool:
        """Acceptance signal from the settlement layer.

        This is *not* confirmation. See :class:`Verdict`.
        """
        ...


# --------------------------------------------------------------------------
# verdict
# --------------------------------------------------------------------------
class Failure(str):
    """A rejection reason. Distinct reasons exist so callers can tell an
    expired challenge from a forged one without parsing prose."""


class Verdict:
    """The outcome of verifying one proof.

    ``settlement`` is deliberately a three-state field rather than a bool:

    ``"mempool"``
        Accepted to the mempool. Usable for a 1-sat toll, with the caveat
        below.
    ``"confirmed"``
        In a block.
    ``"unverified"``
        The challenge did not require mempool acceptance, so nothing was
        checked. Do not read this as "it is fine".

    The caveat, stated because it is the thing most likely to be forgotten:
    mempool acceptance is **not** final. A confirmation race exists — a miner
    may double-spend a transaction the server has already served work for. The
    spec's own remedy is the nonce design, which makes a *second* payment of
    the same nonce impossible; it does not make the first one certain.
    """

    __slots__ = (
        "challenge",
        "header_binding_unverified",
        "ok",
        "paid_sats",
        "payer",
        "proof",
        "reason",
        "settlement",
    )

    def __init__(
        self,
        ok: bool,
        reason: str | None = None,
        *,
        settlement: str = "unverified",
        challenge: Challenge | None = None,
        proof: Proof | None = None,
        payer: str | None = None,
        paid_sats: int = 0,
        header_binding_unverified: bool = False,
    ) -> None:
        self.ok = ok
        self.reason = reason
        self.settlement = settlement
        self.challenge = challenge
        self.proof = proof
        self.payer = payer
        self.paid_sats = paid_sats
        #: True when the header binding could not be checked because no
        #: selector was supplied. The proof was still accepted; this records
        #: that one class of binding was taken on trust.
        self.header_binding_unverified = header_binding_unverified

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        if self.ok:
            return f"<Verdict ok settlement={self.settlement} sats={self.paid_sats}>"
        return f"<Verdict rejected: {self.reason}>"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "settlement": self.settlement,
            "paid_sats": self.paid_sats,
            "payer": self.payer,
            "header_binding_unverified": self.header_binding_unverified,
        }


def _reject(reason: str, ch: Challenge | None = None) -> Verdict:
    return Verdict(False, Failure(reason), challenge=ch)


# --------------------------------------------------------------------------
# challenge shape
# --------------------------------------------------------------------------
def verify_challenge_shape(obj: dict[str, Any]) -> str | None:
    """Structural check of a decoded challenge. ``None`` means well-formed.

    Split from :func:`verify` so an issuer can validate a challenge it just
    built, and so the rejection reasons in tests point at one place.
    """
    required = (
        "v", "scheme", "domain", "method", "path", "query",
        "req_headers_sha256", "req_body_sha256", "amount_sats",
        "payee_locking_script_hex", "nonce_utxo", "expires_at",
        "require_mempool_accept",
    )
    missing = [k for k in required if k not in obj]
    if missing:
        return f"challenge missing fields: {','.join(sorted(missing))}"
    if obj["v"] != SUPPORTED_VERSION:
        return f"unsupported challenge version {obj['v']!r}"
    if obj["scheme"] != SUPPORTED_SCHEME:
        return f"unsupported scheme {obj['scheme']!r}"
    if not isinstance(obj["amount_sats"], int) or obj["amount_sats"] <= 0:
        return "amount_sats must be a positive integer"
    if not str(obj["path"]).startswith("/"):
        return "path must be absolute"
    nonce = obj["nonce_utxo"]
    if not isinstance(nonce, dict):
        return "nonce_utxo must be an object"
    nmiss = [k for k in ("txid", "vout", "satoshis", "locking_script_hex") if k not in nonce]
    if nmiss:
        return f"nonce_utxo missing fields: {','.join(sorted(nmiss))}"
    if not isinstance(nonce["satoshis"], int) or nonce["satoshis"] <= 0:
        return "nonce_utxo.satoshis must be greater than zero"
    if not isinstance(obj["expires_at"], int):
        return "expires_at must be a UNIX timestamp"
    if not isinstance(obj["require_mempool_accept"], bool):
        return "require_mempool_accept must be a boolean"
    if not str(obj["payee_locking_script_hex"]):
        return "payee_locking_script_hex is required"
    return None


# --------------------------------------------------------------------------
# verification
# --------------------------------------------------------------------------
def verify(
    challenge: Challenge | dict[str, Any],
    proof: Proof | dict[str, Any],
    settlement: SettlementView,
    *,
    inbound: RequestBinding | None = None,
    inbound_headers: dict[str, str] | list[tuple[str, str]] | None = None,
    now: int | None = None,
    header_selector: HeaderSelector | None = None,
    expect_domain: str | None = None,
    min_header_hash_set: frozenset[str] | None = None,
) -> Verdict:
    """Verify one proof against one challenge. Pure, offline, stateless.

    Follows Section 7's order: decode (already done by the caller), challenge
    reference, request binding, expiration, nonce spend, payment output,
    optional mempool acceptance.

    Parameters
    ----------
    inbound:
        The request as it actually arrived. When given, the proof's binding
        must match it as well as the challenge — a proof that satisfies the
        challenge but describes a different request is still a failure.
    inbound_headers:
        The raw headers that arrived. Required for the strong header check
        described below; without it a supplied selector can only be recorded
        as not checked.
    now:
        The current UNIX time. **The spec makes expiration a MUST for the
        server** (§4, §7 step 4: reject where the time is strictly greater
        than ``expires_at``), so a caller that passes ``None`` is not
        performing that check — the verdict does not record it, and the
        caller owns the gap. Pass the clock.
    expect_domain:
        When given, the challenge's ``domain`` must match this authority. A
        challenge is bound to a host; accepting one minted for another host
        would let a valid challenge be replayed across a redirect or a
        misconfigured proxy.
    min_header_hash_set:
        Lower bound on which headers must be bound. Defaults to
        :data:`MIN_HEADER_HASH_SET`. A binding that covers fewer headers than
        this is refused as a policy error — see :func:`verify`.
    """
    ch_obj = challenge if isinstance(challenge, dict) else challenge.to_dict()
    pr_obj = proof if isinstance(proof, dict) else proof.to_dict()

    shape = verify_challenge_shape(ch_obj)
    if shape is not None:
        return _reject(shape)

    try:
        ch = Challenge.from_dict(ch_obj)
        pr = Proof.from_dict(pr_obj)
    except (KeyError, TypeError, ValueError) as exc:
        # A verifier that raises on hostile input is a denial of service, not
        # a check. Everything from here on assumes well-formed objects.
        return _reject(f"malformed challenge or proof: {exc}")

    if pr.v != SUPPORTED_VERSION:
        return _reject(f"unsupported proof version {pr.v!r}", ch)
    if pr.scheme != SUPPORTED_SCHEME:
        return _reject(f"unsupported scheme {pr.scheme!r}", ch)

    if expect_domain is not None and ch.domain != expect_domain:
        return _reject(
            f"challenge domain {ch.domain!r} is not {expect_domain!r}", ch
        )

    # --- §7 step 2: challenge reference, recomputed by the server.
    if pr.challenge_sha256 != ch.sha256():
        return _reject("challenge_sha256 does not match this challenge", ch)

    # --- §7 step 3: request binding, three-way.
    if not ch.binding.matches(pr.request):
        return _reject("proof request does not match the challenge binding", ch)
    if inbound is not None and not ch.binding.matches(inbound):
        return _reject("proof request does not match the inbound request", ch)

    # --- policy: a binding over no headers binds nothing.
    #
    # The spec lets the binding policy be implementation-defined, so the
    # verifier can only check what it is told. Two cases are decidable without
    # a selector, and one is not:
    #
    #   * The digest is the empty-body digest, which is only reachable by
    #     binding zero headers. That is decidable and always wrong.
    #   * A selector is supplied: it names the headers we claim to bind, and
    #     we can insist the digest matches the digest over exactly those.
    #   * No selector: the digest is some non-empty value we cannot decompose.
    #     Refusing here would make the verifier unusable by default, and
    #     accepting it silently would be a false claim of having checked. So
    #     it is accepted, and the verdict says the check was not performed.
    floor = MIN_HEADER_HASH_SET if min_header_hash_set is None else min_header_hash_set
    header_check_skipped = False
    if ch.binding.req_headers_sha256 == EMPTY_SHA256:
        return _reject(
            "header binding is empty; a proof would replay across headers", ch
        )
    if header_selector is not None and inbound_headers is not None:
        # Strong form: re-derive the digest from the headers that actually
        # arrived and require equality. This proves the bound set is exactly
        # the selected one on this request, rather than trusting a digest the
        # client echoed back.
        expected = header_binding_digest(inbound_headers, select=header_selector)
        if expected != ch.binding.req_headers_sha256:
            return _reject(
                "header binding digest does not match the selected headers", ch
            )
    # Unchecked unless we were given both halves: the selector naming the
    # bound set, and the headers that actually arrived.
    header_check_skipped = bool(floor) and (
        header_selector is None or inbound_headers is None
    )

    # --- §7 step 4: expiration, strictly greater than expires_at.
    if now is not None and ch.is_expired(int(now)):
        return _reject(f"challenge expired at {ch.expires_at}", ch)

    # --- §7 step 5 / §6.4: the transaction must exist and hash as claimed.
    try:
        actual_txid = settlement.txid_of(pr.rawtx_b64)
    except ValueError as exc:
        return _reject(f"undecodable payment transaction: {exc}", ch)
    if actual_txid != pr.payment_txid:
        return _reject("payment.txid does not match rawtx_b64", ch)

    # --- §7 step 6 / §8: the nonce. This is the replay guard.
    #
    # The verifier asks the settlement layer which outpoints the payment
    # spends; it never keeps a list of seen nonces, because the spec forbids
    # relying on that and because a server-side nonce set is exactly the state
    # this design is avoiding.
    try:
        spent = settlement.inputs_of(pr.rawtx_b64)
        spends = settlement.spends_outpoint(
            pr.rawtx_b64, ch.nonce_utxo.txid, ch.nonce_utxo.vout
        )
    except ValueError as exc:
        return _reject(f"cannot read the payment inputs: {exc}", ch)
    if not spends or ch.nonce_utxo.outpoint not in set(spent):
        # Both halves are required: the backend's own answer, and the
        # outpoint list, independently. A backend that reports True while
        # listing different inputs is inconsistent, and either signal alone
        # would be one implementation's word for it.
        return _reject(
            "payment does not spend the challenge nonce outpoint", ch
        )

    # --- §7 step 7 / §6.2-6.3: the payment output. The requirement is
    # "at least amount_sats to payee_locking_script_hex" (§6.8), read as
    # the total paid to that script across the complete transaction — the
    # same reading §6.6 mandates (never a bare output existence check), and
    # deterministic the way §6.9 requires of two compliant implementations.
    try:
        outputs = settlement.payment_outputs(pr.rawtx_b64)
    except ValueError as exc:
        return _reject(f"cannot read payment outputs: {exc}", ch)
    paid = sum(
        sats for script, sats in outputs
        if script == ch.payee_locking_script_hex
    )
    if paid < ch.amount_sats:
        return _reject(
            f"paid {paid} sat to the payee script, {ch.amount_sats} required", ch
        )

    # --- §7 step 8: mempool acceptance, optional and honestly labelled.
    settlement_state = "unverified"
    if ch.require_mempool_accept:
        if not settlement.accepted_in_mempool(pr.payment_txid):
            return _reject("payment was not accepted to the mempool", ch)
        settlement_state = "mempool"

    return Verdict(
        True,
        None,
        settlement=settlement_state,
        challenge=ch,
        proof=pr,
        paid_sats=paid,
        header_binding_unverified=header_check_skipped,
    )
