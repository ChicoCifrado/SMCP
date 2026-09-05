"""Admission ledger and trust gate.

Two pieces close the loop on *who may write to the shared context* and *what
happened*:

* :class:`AdmissionLedger` — an append-only, hash-chained record of every
  admission decision (accept/reject). Each entry links to the previous one's
  hash, so a tamper is detectable (``verify_chain``). This is the audit trail
  a peer can replay to reconstruct the shared context's provenance.

* :class:`TrustGate` — the admission policy. It encodes the trust model:
  which ``author_id``s are admitted (``allowlist`` / ``denylist`` /
  ``require-signed``), and it is the single choke point an agent must pass
  before its gist enters the shared context.

The ledger is deliberately in-memory and synchronous so it can be unit-tested
and replayed without I/O; a persistent backend can wrap it later.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TrustPolicy(str, Enum):
    ALLOWLIST = "allowlist"          # only listed authors
    DENYLIST = "denylist"           # everyone except listed authors
    REQUIRE_SIGNED = "require-signed"  # any author, but a valid signature is mandatory


@dataclass
class LedgerEntry:
    seq: int
    ts: float
    author_id: str
    label: str
    digest: str
    signature: bytes
    sig_kind: str
    accepted: bool
    reason: str
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq, "ts": self.ts, "author": self.author_id,
            "label": self.label, "digest": self.digest,
            "sig": self.signature.hex(), "sig_kind": self.sig_kind,
            "accepted": self.accepted, "reason": self.reason,
            "prev_hash": self.prev_hash,
        }


class AdmissionLedger:
    """Append-only, hash-chained admission log."""

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

    # -- append ------------------------------------------------------------
    def append(self, author_id: str, label: str, digest: str,
               signature: bytes, sig_kind: str, accepted: bool,
               reason: str) -> LedgerEntry:
        prev = self._entries[-1].entry_hash if self._entries else "0" * 64
        entry = LedgerEntry(
            seq=len(self._entries), ts=time.time(), author_id=author_id,
            label=label, digest=digest, signature=signature, sig_kind=sig_kind,
            accepted=accepted, reason=reason, prev_hash=prev, entry_hash="",
        )
        entry.entry_hash = self._hash(entry)
        self._entries.append(entry)
        return entry

    @staticmethod
    def _hash(e: LedgerEntry) -> str:
        blob = json.dumps(e.to_dict(), sort_keys=True, separators=(",", ":"))
        blob = blob + "|" + e.prev_hash
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    # -- read / verify ------------------------------------------------------
    def entries(self) -> list[LedgerEntry]:
        return list(self._entries)

    def by_label(self, label: str) -> list[LedgerEntry]:
        return [e for e in self._entries if e.label == label]

    def verify_chain(self) -> bool:
        """Re-compute every link; return False on any tamper."""
        prev = "0" * 64
        for e in self._entries:
            if e.prev_hash != prev:
                return False
            if AdmissionLedger._hash(e) != e.entry_hash:
                return False
            prev = e.entry_hash
        return True

    def __len__(self) -> int:
        return len(self._entries)


class TrustGate:
    """The admission policy an agent must pass before writing to C."""

    def __init__(self, policy: TrustPolicy = TrustPolicy.REQUIRE_SIGNED,
                 allowlist: set[str] | None = None,
                 denylist: set[str] | None = None) -> None:
        self.policy = policy
        self.allowlist = set(allowlist or ())
        self.denylist = set(denylist or ())

    def permit(self, author_id: str, has_signature: bool) -> tuple[bool, str]:
        if author_id in self.denylist:
            return False, "author is on the denylist"
        if self.policy == TrustPolicy.ALLOWLIST:
            if author_id not in self.allowlist:
                return False, "author not in allowlist"
        if self.policy == TrustPolicy.REQUIRE_SIGNED and not has_signature:
            return False, "a valid signature is required by policy"
        return True, "ok"
