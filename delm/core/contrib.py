"""The mesh exchange: verified VRAM in, free inference out.

This module is the *economic* layer of SMCP: the part that makes "share your
VRAM, get free inference" a verifiable protocol instead of a promise. It has
three pieces, all deterministic and in-memory (persistence is opt-in, like
:mod:`delm.core.ledger`):

* :class:`Challenge` / :class:`CapacityReport` — how a node states what it
  contributes. The mesh issues a nonce; the node answers with a report **signed
  by its own key and bound to that nonce**, with an expiry. The signature
  proves *which identity* is behind the claim.
* :class:`ContributionLedger` — the admission point and the audit trail. Every
  report is admitted or refused with a machine reason, and admissions are
  appended to a **hash chain** (:meth:`ContributionLedger.verify_chain`), so
  "who contributed what, and when" is replayable and tamper-evident.
* :class:`ExchangePolicy` — the exchange rate and the meter. Credit accrues
  from *verified* capacity **only while the node is observed alive**
  (:meth:`ContributionLedger.observe`), and inference spends it.

What this does and does not prove
---------------------------------

**Does:** (1) every capacity claim is signed by a known identity and cannot be
replayed — the nonce is single-use, both challenge and report expire, and a
``peer_id`` is permanently bound to the key first seen for it
(:attr:`ContribReject.PEER_KEY_CHANGED`), so a name cannot be re-pointed at a
new key to inherit someone else's credits;
(2) the accounting is auditable — hash-chained, and refusing a claim is
recorded with a reason, not silently dropped; (3) credit accrues only during
*observed* uptime, so a node that disappears stops earning immediately rather
than banking credit it never delivered.

**Does not:** prove the claim is *true*. There is no hardware attestation here
— no TPM, no SGX, no measured boot. A node can lie about its VRAM, exactly as
:mod:`delm.core.requirements` already states for build provenance ("proves the
binary was published by a trusted signer, not that the remote process was not
modified"). What honesty buys is therefore **bounded, not absolute**: a liar can
inflate its own credit, but it inflates it against a ledger anyone can audit,
it cannot mint credit for a peer it does not control, it cannot replay a stale
claim, and it forfeits everything the moment it stops being observed. Slashing
/ staking — the economic answer to a caught liar — is explicitly out of scope
(YAGNI), and this module says so rather than pretending otherwise.

The reason this is worth building anyway: the alternative is a mesh where
capacity is a self-reported string. Here it is a signed, expiring, auditable
claim, and every downstream decision (placement, entitlement) reads only
*admitted* numbers — so the trust model is legible instead of implicit.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from delm.core.provenance import KeyPair, verify_public

__all__ = [
    "ContribReject",
    "Challenge",
    "CapacityReport",
    "ContributionRecord",
    "PeerContribution",
    "ContributionLedger",
    "ExchangePolicy",
    "MeteredLLMClient",
    "capacity_is_intact",
    "capacity_claim_status",
    "default_state_path",
    "default_identity_path",
    "EXCHANGE_FORMAT_VERSION",
]

#: Version of the serialized exchange state (one JSON object).
EXCHANGE_FORMAT_VERSION = 1

#: Floor on what a node may offer to be useful at all. A node with less than
#: this is admitted (the ledger does not judge usefulness) but is never picked
#: by placement, and never earns credit for a stage it cannot hold.
MIN_USABLE_VRAM_GB = 0.5

#: Where the exchange state and this node's signing key live by default. The
#: CLI and the web API must agree on these paths — a mesh whose CLI and whose
#: UI disagreed about the state file would be two different meshes — so the
#: resolution lives here and both surfaces call it.
STATE_RELATIVE = Path("config") / "mesh_exchange.json"
IDENTITY_RELATIVE = Path("config") / "mesh_identity.json"


def _default_path(relative: Path) -> Path:
    """``<repo>/config/<file>`` when that directory exists, else CWD-relative.

    Shares the resolution rule with :func:`delm.web.api._config_path`: prefer
    the layout next to the checkout root (so ``python -m delm`` and
    ``delm-serve-web`` agree on where ``config/`` lives) and fall back to the
    working directory for a standalone deployment.

    The root comes from :func:`delm.web.find_repo_root` rather than from
    walking up from this file: walking up three levels from ``delm/core/``
    lands on ``site-packages/`` in an installed wheel, where there is no
    ``config/`` to find and no checkout to point at.

    That import is **lazy** on purpose: ``delm.web`` pulls in fastapi (an
    optional extra), and this module is core. A top-level import would make
    the whole library require the web extra to read a config path.
    """
    try:
        from delm.web import REPO_ROOT
    except ImportError:  # pragma: no cover - delm[web] no instalado
        REPO_ROOT = None
    if REPO_ROOT is not None:
        beside = REPO_ROOT / relative
        if beside.parent.exists():
            return beside
    return relative



class ContribReject(str, Enum):
    """Machine-readable admission reasons. Same discipline as ``RejectReason``."""

    OK = "ok"
    SIGNATURE_INVALID = "signature_invalid"
    NONCE_UNKNOWN = "nonce_unknown"
    NONCE_REPLAYED = "nonce_replayed"
    CHALLENGE_EXPIRED = "challenge_expired"
    REPORT_EXPIRED = "report_expired"
    WRONG_MESH = "wrong_mesh"
    PEER_MISMATCH = "peer_mismatch"
    PEER_KEY_CHANGED = "peer_key_changed"
    NO_CAPACITY = "no_capacity"
    #: the node offers more VRAM than it claims to physically have. Fail-closed:
    #: the report is refused and the attempt is recorded, so the mesh never
    #: plans against it and the owner finds out from a named reason.
    CAPACITY_OVERSTATED = "capacity_overstated"
    # -- spend side
    UNKNOWN_PEER = "unknown_peer"
    INSUFFICIENT_CREDIT = "insufficient_credit"
    PEER_NOT_OBSERVED = "peer_not_observed"


def _canon(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no whitespace. The digest input."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(obj: Any) -> str:
    return hashlib.sha256(_canon(obj)).hexdigest()


def default_state_path() -> Path:
    """Where the exchange state lives (CLI and web API share this)."""
    return _default_path(STATE_RELATIVE)


def default_identity_path() -> Path:
    """Where this node's signing key lives (CLI and web API share this)."""
    return _default_path(IDENTITY_RELATIVE)


# ----------------------------------------------------------------- challenge
@dataclass(frozen=True)
class Challenge:
    """A single-use nonce the mesh hands a peer before it claims capacity.

    The nonce is what makes a claim non-replayable: a report is only admissible
    against an *outstanding* challenge for that peer, and admitting it burns the
    nonce. In a deployment this object travels over the mesh; here it is passed
    in-process, which is what makes the whole exchange unit-testable.
    """

    mesh_id: str
    peer_id: str
    nonce: str = ""
    issued_at: float = 0.0
    expires_at: float = 0.0

    @classmethod
    def issue(cls, mesh_id: str, peer_id: str, *, now: float,
              ttl_s: float = 300.0, nonce: str | None = None) -> "Challenge":
        return cls(mesh_id=mesh_id, peer_id=peer_id,
                   nonce=nonce or uuid.uuid4().hex,
                   issued_at=now, expires_at=now + ttl_s)

    def expired(self, now: float) -> bool:
        return now > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {"mesh_id": self.mesh_id, "peer_id": self.peer_id,
                "nonce": self.nonce, "issued_at": self.issued_at,
                "expires_at": self.expires_at}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Challenge":
        return cls(mesh_id=str(d.get("mesh_id", "")),
                   peer_id=str(d.get("peer_id", "")),
                   nonce=str(d.get("nonce", "")),
                   issued_at=float(d.get("issued_at", 0.0)),
                   expires_at=float(d.get("expires_at", 0.0)))


def capacity_is_intact(peer: PeerContribution, mesh_id: str) -> bool:
    """Does ``peer``'s capacity still match what was signed at admission?

    True for a peer admitted with a capacity digest and untouched since.
    False when the digest is missing — nothing to check against, which is the
    honest answer for a peer built by hand in a test or loaded from a ledger
    written before this field existed — or when a number was rewritten.
    """
    if not peer.admitted_digest:
        return False
    return peer.capacity_digest(mesh_id) == peer.admitted_digest


# ------------------------------------------------------- detection cross-check
def capacity_claim_status(peer: PeerContribution, *,
                          detected_vram_gb: float | None) -> str:
    """Compare a signed capacity claim against independently detected hardware.

    Returns one of:

    - ``"agree"`` — the node's claim is consistent with what was detected.
    - ``"detected_only"`` — hardware was found and the node reported none, so
      the cross-check has nothing to compare.
    - ``"claim_exceeds_detected"`` — the node claims more than detection found.
      The signed claim is what stays authoritative for planning (it is
      attributable, and detection may be partial: a query timeout, a fallback
      path, unified memory reported as RAM); this function is the flag, not a
      correction.
    - ``"unknown"`` — no detection available.

    The asymmetry is deliberate. Refusing the claim would mean letting a
    detection hiccup eject a real node from the mesh, and detection here is
    exactly as trustworthy as the claim: it comes from the same host, over the
    same unauthenticated channel. Neither number is evidence. What this buys
    is *disagreement detection* — a node whose claim moves around between
    observations is visible, which a single unsigned number could never do.
    """
    if detected_vram_gb is None or detected_vram_gb <= 0:
        return "unknown"
    if peer.vram_gb <= 0:
        return "detected_only"
    if peer.vram_gb > detected_vram_gb * 1.02:
        # 2% tolerance: GiB vs GiB rounding in nvidia-smi vs sysfs is real.
        return "claim_exceeds_detected"
    return "agree"


# ------------------------------------------------------------ capacity report
@dataclass(frozen=True)
class CapacityReport:
    """A signed, expiring claim about one peer's capacity.

    ``digest`` covers every field *except* the signature (same non-self-
    referential rule as :func:`delm.core.provenance.digest_of`), so a peer
    cannot swap the numbers after signing.
    """

    mesh_id: str
    peer_id: str
    #: maximum *physical* VRAM of the host. The node's claim about hardware.
    vram_gb: float = 0.0
    #: what the node *offers* the mesh. Its own policy decision, <= vram_gb.
    #: This is the number routing is allowed to spend.
    vram_advertised_gb: float = 0.0
    #: what the mesh is using right now. Telemetry: changes every heartbeat, so
    #: deliberately outside the signed capacity digest.
    vram_shared_gb: float = 0.0
    ram_gb: float = 0.0
    cpu_cores: int = 0
    backend: str = ""
    nonce: str = ""
    issued_at: float = 0.0
    expires_at: float = 0.0
    digest: str = ""
    signature: bytes = b""
    sig_kind: str = ""
    public_key: bytes = b""

    # -- canonical form ---------------------------------------------------
    def payload(self) -> dict[str, Any]:
        """Exactly the fields the signature covers."""
        return {
            "mesh_id": self.mesh_id,
            "peer_id": self.peer_id,
            "vram_gb": round(float(self.vram_gb), 4),
            "vram_advertised_gb": round(float(self.vram_advertised_gb), 4),
            "ram_gb": round(float(self.ram_gb), 4),
            "cpu_cores": int(self.cpu_cores),
            "backend": self.backend,
            "nonce": self.nonce,
            "issued_at": round(float(self.issued_at), 3),
            "expires_at": round(float(self.expires_at), 3),
        }

    def compute_digest(self) -> str:
        return _digest(self.payload())

    @staticmethod
    def capacity_digest(*, mesh_id: str, peer_id: str, vram_gb: float,
                        vram_advertised_gb: float,
                        ram_gb: float, cpu_cores: int, backend: str) -> str:
        """Digest over **only** the capacity numbers, ignoring the nonce/dates.

        This is the anchor that keeps admitted capacity tied to a signature.
        It deliberately excludes ``nonce``/``issued_at``/``expires_at``: those
        say *when* the claim was made, not how big the node is, and a node
        re-reports with a fresh nonce as often as it likes. Pinning the
        capacity is the point — a node that rewrites its own ``vram_gb`` after
        admission changes this digest, which is exactly what
        :func:`capacity_is_intact` detects.

        Lives here, next to :meth:`payload`, so the admission path and the
        verification path cannot drift apart: both call this one function.
        """
        return _digest({"mesh_id": mesh_id,
                        "peer_id": peer_id,
                        "vram_gb": round(float(vram_gb), 4),
                        "vram_advertised_gb": round(float(vram_advertised_gb), 4),
                        "ram_gb": round(float(ram_gb), 4),
                        "cpu_cores": int(cpu_cores),
                        "backend": backend})

    def sign(self, key: KeyPair) -> "CapacityReport":
        """Sign the canonical digest with *key*; returns a new report."""
        digest = self.compute_digest()
        # payload() is what the signature covers, so it cannot also be what
        # rebuilds the object: vram_shared_gb is telemetry and is deliberately
        # absent from the signed set, yet it must survive signing. Passing
        # payload() alone silently reset it to the field default — a node
        # reporting real mesh usage would claim it had none.
        return CapacityReport(**{**self.payload(),
                                 "vram_shared_gb": self.vram_shared_gb,
                                 "digest": digest,
                                 "signature": key.sign(digest),
                                 "sig_kind": key.kind,
                                 "public_key": key.public_key})

    def verify(self) -> bool:
        """Signature check only — says nothing about the claim being true."""
        if not self.digest or not self.signature or not self.public_key:
            return False
        if self.digest != self.compute_digest():
            return False
        return verify_public(self.sig_kind or "ed25519", self.public_key,
                             self.digest, self.signature)

    def expired(self, now: float) -> bool:
        return now > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        # vram_shared_gb rides along unsigned: it is telemetry, and a caller
        # reading this dict is reading a snapshot, not a commitment.
        return {**self.payload(), "vram_shared_gb": round(self.vram_shared_gb, 4),
                "digest": self.digest,
                "signature": self.signature.hex(), "sig_kind": self.sig_kind,
                "public_key": self.public_key.hex()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CapacityReport":
        def _b(key: str) -> bytes:
            try:
                return bytes.fromhex(str(d.get(key, "") or ""))
            except ValueError:
                return b""

        return cls(mesh_id=str(d.get("mesh_id", "")),
                   peer_id=str(d.get("peer_id", "")),
                   vram_gb=float(d.get("vram_gb", 0.0) or 0.0),
                   vram_advertised_gb=float(d.get("vram_advertised_gb", 0.0) or 0.0),
                   vram_shared_gb=float(d.get("vram_shared_gb", 0.0) or 0.0),
                   ram_gb=float(d.get("ram_gb", 0.0) or 0.0),
                   cpu_cores=int(d.get("cpu_cores", 0) or 0),
                   backend=str(d.get("backend", "")),
                   nonce=str(d.get("nonce", "")),
                   issued_at=float(d.get("issued_at", 0.0) or 0.0),
                   expires_at=float(d.get("expires_at", 0.0) or 0.0),
                   digest=str(d.get("digest", "")),
                   signature=_b("signature"), sig_kind=str(d.get("sig_kind", "")),
                   public_key=_b("public_key"))


# ------------------------------------------------------------------ the chain
@dataclass(frozen=True)
class ContributionRecord:
    """One link of the chain: an admission decision about one report."""

    seq: int
    ts: float
    peer_id: str
    digest: str
    accepted: bool
    reason: str
    prev_hash: str
    entry_hash: str

    def payload(self) -> dict[str, Any]:
        return {"seq": self.seq, "ts": round(float(self.ts), 3),
                "peer_id": self.peer_id, "digest": self.digest,
                "accepted": self.accepted, "reason": self.reason,
                "prev_hash": self.prev_hash}

    def to_dict(self) -> dict[str, Any]:
        return {**self.payload(), "entry_hash": self.entry_hash}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ContributionRecord":
        return cls(seq=int(d.get("seq", 0)), ts=float(d.get("ts", 0.0)),
                   peer_id=str(d.get("peer_id", "")),
                   digest=str(d.get("digest", "")),
                   accepted=bool(d.get("accepted", False)),
                   reason=str(d.get("reason", "")),
                   prev_hash=str(d.get("prev_hash", "")),
                   entry_hash=str(d.get("entry_hash", "")))


@dataclass
class PeerContribution:
    """What the mesh currently believes about one peer, and what it owes it.

    Three VRAM numbers, and using the wrong one is the bug this class exists
    to prevent. ``vram_gb`` is the admitted *physical maximum*, ``vram_advertised_gb``
    is what the node offers (its own decision, anchored to its signature), and
    ``vram_shared_gb`` is what the mesh is using right now (telemetry, not
    signed). Placement reads :attr:`vram_available_gb`, never ``vram_gb``.

    ``seconds_observed``
    is the honest part: it only grows while :meth:`ContributionLedger.observe`
    is called, i.e. while the mesh can see the peer.

    ``admitted_digest`` is the digest of the signed :class:`CapacityReport` the
    numbers came from. It is the anchor that keeps the admitted capacity tied
    to a signature: the fields stay plain attributes for ergonomics (and for
    the ledger's own JSON), but :func:`capacity_is_intact` re-checks them
    against the digest, so rewriting ``vram_gb`` after admission is detectable
    instead of silently believed.
    """

    peer_id: str
    #: admitted physical maximum, straight from the node's signed claim
    vram_gb: float = 0.0
    #: what the node offers the mesh; the only VRAM routing may plan against
    vram_advertised_gb: float = 0.0
    #: what the mesh is using at this instant; telemetry, unsigned
    vram_shared_gb: float = 0.0
    ram_gb: float = 0.0
    cpu_cores: int = 0
    backend: str = ""
    public_key: bytes = b""
    sig_kind: str = ""
    admitted_at: float = 0.0
    last_seen: float = 0.0
    seconds_observed: float = 0.0
    credits: float = 0.0
    credits_spent: float = 0.0
    reports: int = 0
    rejections: int = 0
    #: digest of the signed report these numbers were admitted from
    admitted_digest: str = ""

    def capacity_digest(self, mesh_id: str) -> str:
        """The capacity-only digest for this record, under *mesh_id*."""
        return CapacityReport.capacity_digest(
            mesh_id=mesh_id, peer_id=self.peer_id,
            vram_gb=self.vram_gb,
            vram_advertised_gb=self.vram_advertised_gb,
            ram_gb=self.ram_gb, cpu_cores=self.cpu_cores,
            backend=self.backend)

    @property
    def vram_available_gb(self) -> float:
        """What routing may actually plan against. Never negative.

        ``min(offered, physical) - used``, floored at zero. Two independent
        clamps, and the order matters:

        - ``advertised <= physical``: offering more VRAM than exists is the
          inflation attack. Clamping here means an inflated node is *capped*,
          not rejected — the mesh simply never plans past the smaller number.
          Whether it also deserves suspicion is a different question, answered
          by :func:`capacity_claim_status`.
        - the floor at zero: a node whose mesh usage exceeds what it offered is
          over-committed. Reporting a negative would let
          ``max(0.0, offered - reserve)`` become ``0 - reserve`` and produce
          nonsensical negative usable memory, so the floor lives here where the
          subtraction happens.

        Unsigned telemetry can be wrong or hostile. Clamping is not trust: it
        is the refusal to let a lie in this field propagate into a placement
        that then fails at run time.
        """
        return max(0.0, min(self.vram_advertised_gb, self.vram_gb)
                   - self.vram_shared_gb)

    @property
    def credits_available(self) -> float:
        return max(0.0, self.credits - self.credits_spent)

    @property
    def alive(self) -> bool:
        """Alive means *observed* since admission (last_seen set)."""
        return self.last_seen > 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"peer_id": self.peer_id, "vram_gb": self.vram_gb,
                "vram_advertised_gb": self.vram_advertised_gb,
                "vram_shared_gb": self.vram_shared_gb,
                "ram_gb": self.ram_gb, "cpu_cores": self.cpu_cores,
                "backend": self.backend,
                "public_key": self.public_key.hex(), "sig_kind": self.sig_kind,
                "admitted_at": self.admitted_at, "last_seen": self.last_seen,
                "seconds_observed": self.seconds_observed,
                "credits": self.credits, "credits_spent": self.credits_spent,
                "reports": self.reports, "rejections": self.rejections,
                "credits_available": self.credits_available,
                # El anchor de integridad DEBE viajar con el estado: sin el, un
                # ledger re-escrito en disco (o copiado a otro host) perdería la
                # capacidad admitida al releerla, que es la mitad de lo que
                # `capacity_is_intact` existe para detectar.
                "admitted_digest": self.admitted_digest}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PeerContribution":
        def _b(key: str) -> bytes:
            try:
                return bytes.fromhex(str(d.get(key, "") or ""))
            except ValueError:
                return b""

        return cls(peer_id=str(d.get("peer_id", "")),
                   vram_gb=float(d.get("vram_gb", 0.0) or 0.0),
                   vram_advertised_gb=float(d.get("vram_advertised_gb", 0.0) or 0.0),
                   vram_shared_gb=float(d.get("vram_shared_gb", 0.0) or 0.0),
                   ram_gb=float(d.get("ram_gb", 0.0) or 0.0),
                   cpu_cores=int(d.get("cpu_cores", 0) or 0),
                   backend=str(d.get("backend", "")),
                   public_key=_b("public_key"), sig_kind=str(d.get("sig_kind", "")),
                   admitted_at=float(d.get("admitted_at", 0.0) or 0.0),
                   last_seen=float(d.get("last_seen", 0.0) or 0.0),
                   seconds_observed=float(d.get("seconds_observed", 0.0) or 0.0),
                   credits=float(d.get("credits", 0.0) or 0.0),
                   credits_spent=float(d.get("credits_spent", 0.0) or 0.0),
                   reports=int(d.get("reports", 0) or 0),
                   rejections=int(d.get("rejections", 0) or 0),
                   admitted_digest=str(d.get("admitted_digest", "") or ""))


class ContributionLedger:
    """Admission + hash-chained audit trail + per-peer credit balances.

    Deliberately synchronous and in-memory, like :class:`delm.core.ledger.
    AdmissionLedger`: the mesh can hold several of these (one per view of the
    exchange) and replay them. :meth:`to_dict`/:meth:`from_dict` are the
    persistence seam the CLI and the web share.
    """

    def __init__(self, mesh_id: str = "smcp-local") -> None:
        self.mesh_id = mesh_id
        self.records: list[ContributionRecord] = []
        self.peers: dict[str, PeerContribution] = {}
        self.challenges: dict[str, Challenge] = {}      # nonce -> challenge
        self.used_nonces: set[str] = set()

    # -- chain ------------------------------------------------------------
    def _append(self, peer_id: str, digest: str, accepted: bool,
                reason: str, ts: float) -> ContributionRecord:
        prev = self.records[-1].entry_hash if self.records else ""
        rec = ContributionRecord(
            seq=len(self.records), ts=ts, peer_id=peer_id, digest=digest,
            accepted=accepted, reason=reason, prev_hash=prev, entry_hash="")
        rec = ContributionRecord(**{**rec.payload(), "entry_hash": _digest(rec.payload())})
        self.records.append(rec)
        return rec

    def verify_chain(self) -> bool:
        """True when every link matches and no entry was edited after the fact."""
        prev = ""
        for i, rec in enumerate(self.records):
            if rec.seq != i or rec.prev_hash != prev:
                return False
            if rec.entry_hash != _digest(rec.payload()):
                return False
            prev = rec.entry_hash
        return True

    # -- challenge / admission -------------------------------------------
    def issue_challenge(self, peer_id: str, *, now: float,
                        ttl_s: float = 300.0) -> Challenge:
        """Issue (and remember) a single-use nonce for *peer_id*."""
        ch = Challenge.issue(self.mesh_id, peer_id, now=now, ttl_s=ttl_s)
        self.challenges[ch.nonce] = ch
        return ch

    def admit(self, report: CapacityReport, *, now: float) -> tuple[bool, str]:
        """Admit a signed capacity report. Returns ``(accepted, reason)``.

        The checks are ordered cheapest-first and every refusal is *recorded*
        (a silent drop would make the ledger unable to explain itself), which is
        why ``rejections`` is a counter a peer can be held to.
        """
        reason = self._check(report, now)
        accepted = reason == ContribReject.OK
        self._append(report.peer_id, report.digest or report.compute_digest(),
                     accepted, reason.value, now)
        peer = self.peers.get(report.peer_id)
        if peer is None:
            peer = PeerContribution(peer_id=report.peer_id)
            self.peers[report.peer_id] = peer
        if accepted:
            peer.vram_gb = report.vram_gb
            # The node's policy decision. The clamp is defence in depth, not
            # the primary guard: _check already refuses advertised > vram_gb,
            # so here it should always be a no-op. It stays because this state
            # is also reachable from a rewritten ledger on disk, from an
            # older build, and from a hand-constructed PeerContribution in a
            # test — and in none of those paths did _check run.
            peer.vram_advertised_gb = min(report.vram_advertised_gb,
                                          report.vram_gb)
            peer.vram_shared_gb = report.vram_shared_gb
            peer.ram_gb = report.ram_gb
            peer.cpu_cores = report.cpu_cores
            peer.backend = report.backend
            peer.public_key = report.public_key
            peer.sig_kind = report.sig_kind
            peer.admitted_at = now
            peer.reports += 1
            # Anchor the admitted numbers to a digest of the *capacity* (not of
            # the whole report: the nonce rotates), so a later rewrite of a
            # number is detectable via capacity_is_intact.
            peer.admitted_digest = peer.capacity_digest(self.mesh_id)
            self.used_nonces.add(report.nonce)
        else:
            peer.rejections += 1
        return accepted, reason.value

    def _check(self, report: CapacityReport, now: float) -> ContribReject:
        if report.mesh_id != self.mesh_id:
            return ContribReject.WRONG_MESH
        if not report.verify():
            return ContribReject.SIGNATURE_INVALID
        known = self.peers.get(report.peer_id)
        if known is not None and known.public_key:
            # Identity binding: a `peer_id` is *its key*, not a free-form label.
            # Without this, editing the local identity file (or replaying a
            # report under someone else's name) silently re-binds the name to a
            # new key, and every credit already earned would follow the new key.
            if report.public_key != known.public_key:
                return ContribReject.PEER_KEY_CHANGED
        if report.nonce in self.used_nonces:
            return ContribReject.NONCE_REPLAYED
        challenge = self.challenges.get(report.nonce)
        if challenge is None:
            return ContribReject.NONCE_UNKNOWN
        if challenge.expired(now):
            return ContribReject.CHALLENGE_EXPIRED
        if report.expired(now):
            return ContribReject.REPORT_EXPIRED
        if challenge.peer_id != report.peer_id:
            return ContribReject.PEER_MISMATCH
        if report.vram_gb <= 0 and report.ram_gb <= 0 and report.cpu_cores <= 0:
            return ContribReject.NO_CAPACITY
        if report.vram_advertised_gb > report.vram_gb:
            # Offering more VRAM than the node claims to physically have.
            # Fail-closed on purpose. Silently capping would keep the node
            # serving while hiding the dishonesty, and the owner of a
            # misconfigured node would never learn about it. Rejecting records
            # the attempt in the hash-chained trail and counts it, so the
            # inflation is visible and countable instead of merely bounded.
            # The cost is a legitimate node with a typo drops out — with a
            # named reason, which is the actionable outcome.
            return ContribReject.CAPACITY_OVERSTATED
        return ContribReject.OK


    # -- liveness → credit ------------------------------------------------
    def observe(self, peer_id: str, now: float, *, dt_s: float = 0.0,
                policy: "ExchangePolicy | None" = None) -> PeerContribution | None:
        """Mark *peer_id* seen and accrue credit for the observed interval.

        ``dt_s`` is the elapsed time the *observer* vouches for (from the
        heartbeat tick). Accrual is deliberately outside the ledger: it needs
        the rate, and the rate is policy, not ledger state.
        """
        peer = self.peers.get(peer_id)
        if peer is None:
            return None
        peer.last_seen = now
        if dt_s > 0:
            peer.seconds_observed += dt_s
            if policy is not None:
                peer.credits += policy.accrual(peer, dt_s)
        return peer

    # -- spend ------------------------------------------------------------
    def spend(self, peer_id: str, units: float, *,
              policy: "ExchangePolicy | None" = None,
              require_alive: bool = True) -> tuple[bool, str]:
        """Debit *units* of credit for *peer_id*'s inference.

        Refuses rather than going negative: the whole point of the exchange is
        that free inference is *earned*, so a peer with no credit simply does
        not get it. ``policy`` lets the caller require the peer to be
        currently observed (``PEER_NOT_OBSERVED``) — the default, because
        letting a departed node keep spending is a hole.
        """
        peer = self.peers.get(peer_id)
        if peer is None:
            return False, ContribReject.UNKNOWN_PEER.value
        if require_alive and not peer.alive:
            return False, ContribReject.PEER_NOT_OBSERVED.value
        if policy is not None and not policy.can_spend(peer, units):
            return False, ContribReject.INSUFFICIENT_CREDIT.value
        peer.credits_spent += units
        return True, ContribReject.OK.value

    # -- views ------------------------------------------------------------
    def admitted_peers(self, *, observed_only: bool = False
                       ) -> list[PeerContribution]:
        """Admitted peers, deterministic order: most VRAM, then id."""
        peers = [p for p in self.peers.values() if p.vram_gb or p.ram_gb]
        if observed_only:
            peers = [p for p in peers if p.alive]
        return sorted(peers, key=lambda p: (-p.vram_gb, p.peer_id))

    def total_advertised_gb(self, *, observed_only: bool = True) -> float:
        """Sum of what peers *offer* — the honest mesh-wide planning total.

        The counterpart to :meth:`total_vram_gb`, which sums the physical
        maxima. Reporting both is the point: the gap between them is how much
        hardware the owners are deliberately keeping to themselves.
        """
        return round(sum(p.vram_advertised_gb for p in
                         self.admitted_peers(observed_only=observed_only)), 3)

    def total_shared_gb(self, *, observed_only: bool = True) -> float:
        """Sum of what the mesh is using right now. Telemetry, unsigned."""
        return round(sum(p.vram_shared_gb for p in
                         self.admitted_peers(observed_only=observed_only)), 3)

    def total_vram_gb(self, *, observed_only: bool = True) -> float:
        return round(sum(p.vram_gb for p in
                         self.admitted_peers(observed_only=observed_only)), 3)

    def state_digest(self) -> str:
        """Digest of the whole exchange state (chain head + balances).

        Cheap way for two observers to agree they are looking at the same
        ledger without shipping it.
        """
        balances = {pid: round(p.credits_available, 6)
                    for pid, p in sorted(self.peers.items())}
        head = self.records[-1].entry_hash if self.records else ""
        return _digest({"head": head, "balances": balances,
                        "peers": {pid: [p.vram_gb, p.seconds_observed]
                                  for pid, p in sorted(self.peers.items())}})

    # -- persistence ------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "format": EXCHANGE_FORMAT_VERSION,
            "mesh_id": self.mesh_id,
            "records": [r.to_dict() for r in self.records],
            "peers": [p.to_dict() for p in
                      sorted(self.peers.values(), key=lambda p: p.peer_id)],
            "challenges": [c.to_dict() for c in
                           sorted(self.challenges.values(), key=lambda c: c.nonce)],
            "used_nonces": sorted(self.used_nonces),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ContributionLedger":
        led = cls(mesh_id=str(d.get("mesh_id", "smcp-local")))
        led.records = [ContributionRecord.from_dict(r)
                       for r in d.get("records", [])]
        for p in d.get("peers", []):
            peer = PeerContribution.from_dict(p)
            led.peers[peer.peer_id] = peer
        for c in d.get("challenges", []):
            ch = Challenge.from_dict(c)
            led.challenges[ch.nonce] = ch
        led.used_nonces = set(d.get("used_nonces", []))
        return led

    def save(self, path: str) -> str:
        path = str(path)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, sort_keys=True)
            fh.write("\n")
        return path

    @classmethod
    def load(cls, path: str) -> "ContributionLedger":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def __len__(self) -> int:
        return len(self.records)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (f"ContributionLedger(mesh_id={self.mesh_id!r}, "
                f"peers={len(self.peers)}, records={len(self.records)})")


# ------------------------------------------------------------------- policy
@dataclass(frozen=True)
class ExchangePolicy:
    """The rate and the rules of the exchange.

    * ``credits_per_gib_hour`` — how much credit a peer earns per GiB of
      *admitted* VRAM per hour of *observed* uptime. The default makes one
      8-GiB node earn 8 credits/hour, i.e. credits are directly proportional to
      contributed VRAM, which is the honest shape for "share VRAM, get
      inference".
    * ``credits_per_request`` / ``credits_per_ktoken`` — what inference costs.
      A request has a floor so a peer cannot spam sub-token calls for free.
    * ``baseline_credits`` — a small welcome grant for every admitted peer, so
      the exchange is usable before a peer has accrued anything. Set to 0.0 for
      a strict "earn before you spend" mesh.
    * ``require_alive_to_spend`` — a departed node loses access immediately
      (default) rather than banking credit while offline.
    """

    credits_per_gib_hour: float = 1.0
    credits_per_request: float = 0.5
    credits_per_ktoken: float = 0.01
    baseline_credits: float = 1.0
    require_alive_to_spend: bool = True
    max_credits_per_peer: float = 10_000.0

    def accrual(self, peer: PeerContribution, dt_s: float) -> float:
        """Credit earned by *peer* for ``dt_s`` seconds of observed uptime.

        Scaled by **advertised** VRAM, not by the physical maximum. This is the
        economic half of the split: a node with a 24 GiB card that offers 4 GiB
        earns 4 credits/hour, not 24. Paying for hardware the mesh was not
        allowed to use is how "share your GPU" turns into a free lunch.

        The physical number still matters, and it matters more: a node that
        raises its offer later needs the real thing to be there. But the *rate*
        follows what was offered, because that is what the mesh could plan on.
        """
        if dt_s <= 0 or peer.vram_advertised_gb <= 0:
            return 0.0
        hours = dt_s / 3600.0
        return min(self.max_credits_per_peer,
                   peer.vram_advertised_gb * self.credits_per_gib_hour * hours)

    def request_cost(self, *, tokens_in: int = 0, tokens_out: int = 0) -> float:
        """What one completion costs: a floor plus a per-token rate."""
        ktokens = (max(0, tokens_in) + max(0, tokens_out)) / 1000.0
        return self.credits_per_request + self.credits_per_ktoken * ktokens

    def entitlement(self, peer: PeerContribution) -> float:
        """Free-inference allowance of *peer*: baseline + what it has earned."""
        return round(self.baseline_credits + peer.credits_available, 6)

    def can_spend(self, peer: PeerContribution, units: float) -> bool:
        if self.require_alive_to_spend and not peer.alive:
            return False
        return peer.credits_available >= units


# ------------------------------------------------------- the metered client
class MeteredLLMClient:
    """An :class:`~delm.core.llm.LLMClient` that pays for inference with credit.

    This is the "a cambio" half of the exchange made concrete: the same pipeline
    runs, but a request is only served if the peer has earned the credit for it,
    and every served request is debited. It is a thin wrapper on purpose — the
    model-agnostic contract is untouched, so any backend (MeshLLM's
    OpenAI-compatible endpoint, a local llama.cpp, a remote provider) can sit
    behind it and be metered identically.
    """

    def __init__(self, inner: Any, ledger: ContributionLedger, peer_id: str,
                 policy: ExchangePolicy | None = None) -> None:
        self.inner = inner
        self.ledger = ledger
        self.peer_id = peer_id
        self.policy = policy or ExchangePolicy()
        #: Every decision, in order — the audit trail of the metered side.
        self.log: list[dict[str, Any]] = []
        self.served = 0
        self.refused = 0
        #: Requests that passed the credit check but whose inference failed
        #: (endpoint down, timeout, model error). These were *charged* — the
        #: debit is deliberate and happens first — so `served + failed` is what
        #: the mesh was billed for, and `served` alone is what it actually got.
        self.failed = 0

    async def complete(self, *args: Any, **kwargs: Any) -> Any:
        tokens_in = int(kwargs.get("tokens_in", 0) or 0)
        tokens_out = int(kwargs.get("tokens_out", 0) or 0)
        cost = self.policy.request_cost(tokens_in=tokens_in,
                                        tokens_out=tokens_out)
        ok, reason = self.ledger.spend(
            self.peer_id, cost, policy=self.policy,
            require_alive=self.policy.require_alive_to_spend)
        entry = {"cost": round(cost, 6), "ok": ok, "reason": reason,
                 "tokens_in": tokens_in, "tokens_out": tokens_out}
        self.log.append(entry)
        if not ok:
            self.refused += 1
            # El peer puede no estar en el ledger todavia (identidad vista
            # pero capacidad nunca admitida). Antes, formatear este mensaje
            # hacia `None.credits_available` -> AttributeError DENTRO de la
            # construccion del PermissionError, de modo que el un error que
            # debe explicar al par lo reemplazaba por un AttributeError.
            # Se formatea el saldo de forma tolerante.
            _rec = self.ledger.peers.get(self.peer_id)
            _saldo = getattr(_rec, "credits_available", None)
            _saldo_txt = f"{_saldo:.4f}" if _saldo is not None else "0.0000 (sin registro)"
            raise PermissionError(
                f"inferencia sin crédito ({reason}): {self.peer_id} necesita "
                f"{cost:.4f} y tiene {_saldo_txt} "
                f"disponibles")
        # El cobro va ANTES de la inferencia, a proposito: es lo que impide
        # que un par sin credito gaste GPU ajena (si se comprobara despues,
        # el `await` ya habria ocurrido). El coste de ese orden es que un
        # endpoint caido tambien se cobra, asi que `served` SOLO sube cuando
        # la inferencia ocurrio de verdad. Antes subia antes del `await`: un
        # 404 o un timeout contaba como servida, y el log decia `ok: True`
        # de una inferencia que nunca existio.
        try:
            out = await self.inner.complete(*args, **kwargs)
        except BaseException as exc:
            entry["ok"] = False
            entry["reason"] = f"inference_failed: {type(exc).__name__}: {exc}"
            self.failed += 1
            raise
        self.served += 1
        return out

    def stats(self) -> dict[str, Any]:
        peer = self.ledger.peers.get(self.peer_id)
        return {
            "peer_id": self.peer_id,
            "served": self.served,
            "refused": self.refused,
            "failed": self.failed,
            "credits_available": peer.credits_available if peer else 0.0,
            "entitlement": self.policy.entitlement(peer) if peer else 0.0,
            "log": list(self.log),
        }
