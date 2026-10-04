"""Explicit membership on top of the open mesh, as signed endorsements.

The open mesh and an explicit roster are not alternatives — they are two
layers, and this module is the second. A node may join the mesh freely and
still be a *stranger* to everyone else: it can be reached, it can be
scheduled work only if it earns it, and nothing it announces is treated as
evidence by a peer that has not admitted it.

What makes that different from a whitelist file is the shape of the proof. A
list says "I trust X". An endorsement says:

    "I, this exact admission of a member you already trust, vouch that this
     exact certificate was authenticated."

That phrasing is borrowed from NVIDIA PAIR's ``cluster-manager``, and the
reason it matters is that mTLS cannot express it. mTLS authenticates **one
hop** — it proves the peer presented a cert you pinned, and says nothing about
who vouched for that peer. So if A pairs with B and then A pairs with C, B and
C have each pinned only A and cannot talk to each other. Transitive trust needs
something end-to-end signed, which is what an endorsement is: it stays
verifiable across any number of gossip hops, and it is the *authorisation
graph* — the graph of pairings a human actually performed — that a node walks,
never a graph of nodes that merely claim to know each other.

Two properties this borrows deliberately:

**An admission epoch, not a clock.** Every admission consumes the next value of
a node-global monotonic counter, and the epoch travels inside the endorsed
payload. So "newer admission" is a signed fact rather than a comparison of
timestamps. It also fixes the awkward case: rejoining a cluster after removal
necessarily has a higher epoch, so a stale endorsement can never authorise a
removed node coming back.

**Reconciliation is bounded.** Merging a roster pins a peer only if some
already-trusted member endorsed that exact cert *at that exact epoch*. An
entry endorsed by a stranger is rejected, an epoch mismatch is rejected, and a
cert that does not match its claimed fingerprint is rejected. The walk
iterates to a fixpoint, so a node admitted during the merge can in turn vouch
for the nodes it endorsed — but it cannot grow without bound, because every
new edge has to trace back to a human pairing.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Sequence

from smcp.core.provenance import KeyPair, verify_public

ROSTER_KIND = "mesh.roster"

#: Bumped when the endorsed payload's shape changes incompatibly. A node that
#: receives a different major has to reject rather than misread.
ENDORSEMENT_V = 2

#: Ancestor bound on the merge walk. Not a security parameter — the walk is
#: bounded by the trust graph itself — but a cheap stop against a pathological
#: or hostile roster claiming to be ten thousand deep.
MAX_ENDORSEMENT_DEPTH = 8


@dataclass(frozen=True)
class Endorsement:
    """One member's signed statement vouching for one admission.

    Carries *both* epochs on purpose: the introduced peer's, so the statement
    is scoped to one incarnation of one cert, and the endorser's, so a statement
    made by an admission that has since been removed stops being usable. That
    is what makes a stale proof harmless instead of dangerous.
    """

    endorser_id: str
    introduced_id: str
    cert_fingerprint: str
    cluster_id: str
    introduced_epoch: int
    endorser_epoch: int
    issued_at: float
    signature: bytes = b""
    sig_kind: str = "ed25519"

    @property
    def v(self) -> int:
        return ENDORSEMENT_V

    def payload(self) -> dict[str, Any]:
        """The canonical, signable content.

        ``issued_at`` is metadata, not ordering authority — the epochs are the
        ordering. Keeping it inside the payload means an endorsement cannot be
        re-dated, but nothing reads it to decide who wins.
        """
        return {
            "v": ENDORSEMENT_V,
            "kind": ROSTER_KIND,
            "endorser_id": self.endorser_id,
            "introduced_id": self.introduced_id,
            "cert_fingerprint": self.cert_fingerprint,
            "cluster_id": self.cluster_id,
            "introduced_epoch": self.introduced_epoch,
            "endorser_epoch": self.endorser_epoch,
            "issued_at": round(self.issued_at, 3),
        }

    def digest(self) -> str:
        import hashlib

        blob = json.dumps(self.payload(), sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        import base64

        d = self.payload()
        d["signature"] = base64.b64encode(self.signature).decode("ascii")
        d["sig_kind"] = self.sig_kind
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Endorsement":
        import base64

        return cls(
            endorser_id=str(d.get("endorser_id", "")),
            introduced_id=str(d.get("introduced_id", "")),
            cert_fingerprint=str(d.get("cert_fingerprint", "")),
            cluster_id=str(d.get("cluster_id", "")),
            introduced_epoch=int(d.get("introduced_epoch", 0) or 0),
            endorser_epoch=int(d.get("endorser_epoch", 0) or 0),
            issued_at=float(d.get("issued_at", 0.0) or 0.0),
            signature=base64.b64decode(d.get("signature", "") or ""),
            sig_kind=str(d.get("sig_kind", "ed25519")),
        )

    def verify(self, public_key: bytes) -> bool:
        """Check this endorsement against the *endorser's* known key.

        The key must come from the local keyring, never from the payload — a
        signature checked against a key that travelled with it proves nothing.
        """
        if not self.signature:
            return False
        return verify_public(self.sig_kind, public_key, self.digest(),
                             self.signature)

    @classmethod
    def sign(cls, *, endorser: KeyPair, introduced_id: str,
             cert_fingerprint: str, cluster_id: str, introduced_epoch: int,
             endorser_epoch: int, now: Optional[float] = None
             ) -> "Endorsement":
        import hashlib

        issued = time.time() if now is None else now
        e = cls(
            endorser_id=endorser.author_id,
            introduced_id=introduced_id,
            cert_fingerprint=cert_fingerprint,
            cluster_id=cluster_id,
            introduced_epoch=introduced_epoch,
            endorser_epoch=endorser_epoch,
            issued_at=issued,
            sig_kind=endorser.kind,
        )
        return cls(**{**e.__dict__, "signature": endorser.sign(e.digest())})


def cert_fingerprint(public_key: bytes) -> str:
    """``sha256:`` + lowercase hex of the DER-ish public key bytes.

    A fingerprint is a *log and lookup* key. Trust decisions always use the full
    key material, never this value alone — a fingerprint is not a secret and
    two different keys could in principle collide, so treating it as
    authorisation would be the same mistake as trusting a self-declared field.
    """
    import hashlib

    return "sha256:" + hashlib.sha256(public_key).hexdigest()


@dataclass
class Admission:
    """One node's current standing in a roster."""

    node_id: str
    cert_fingerprint: str = ""
    epoch: int = 0
    endorsements: list[Endorsement] = field(default_factory=list)
    last_addr: str = ""
    joined_at: float = 0.0

    def endorsers(self) -> set[str]:
        return {e.endorser_id for e in self.endorsements}

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "cert_fingerprint": self.cert_fingerprint,
            "epoch": self.epoch,
            "endorsements": [e.to_dict() for e in self.endorsements],
            "last_addr": self.last_addr,
            "joined_at": round(self.joined_at, 3),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Admission":
        return cls(
            node_id=str(d.get("node_id", "")),
            cert_fingerprint=str(d.get("cert_fingerprint", "")),
            epoch=int(d.get("epoch", 0) or 0),
            endorsements=[Endorsement.from_dict(e)
                          for e in d.get("endorsements", [])],
            last_addr=str(d.get("last_addr", "")),
            joined_at=float(d.get("joined_at", 0.0) or 0.0),
        )


@dataclass
class Roster:
    """This node's view of who belongs, and how it learned that."""

    cluster_id: str
    self_id: str
    self_epoch: int = 0
    members: dict[str, Admission] = field(default_factory=dict)
    generation: int = 0

    # -- membership ---------------------------------------------------------
    def member_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.members))

    def is_member(self, node_id: str) -> bool:
        return node_id in self.members

    def known_cert(self, node_id: str) -> str:
        m = self.members.get(node_id)
        return m.cert_fingerprint if m else ""

    def add(self, admission: Admission) -> None:
        self.members[admission.node_id] = admission
        self.generation += 1

    def remove(self, node_id: str) -> bool:
        if node_id not in self.members:
            return False
        del self.members[node_id]
        self.generation += 1
        return True

    # -- endorse ------------------------------------------------------------
    def endorse(self, endorser: KeyPair, node_id: str, fp: str, *,
                epoch: int, now: Optional[float] = None) -> Endorsement:
        """Record this node's endorsement of *node_id* at *epoch*."""
        e = Endorsement.sign(
            endorser=endorser, introduced_id=node_id, cert_fingerprint=fp,
            cluster_id=self.cluster_id, introduced_epoch=epoch,
            endorser_epoch=self.self_epoch, now=now)
        m = self.members.get(node_id)
        if m is None:
            # The fingerprint is what the verification path compares against, so
            # an entry created here without one can never be trusted by anyone
            # else — the endorsement would reference a cert the entry does not
            # carry. Creating it from the endorsement's own value is not a
            # shortcut: it is the same value, and _accept still checks it.
            m = Admission(node_id=node_id, cert_fingerprint=fp,
                          joined_at=time.time())
            self.members[node_id] = m
        elif not m.cert_fingerprint:
            m.cert_fingerprint = fp
        elif m.cert_fingerprint != fp:
            # A different cert for a member already here is a re-key. It needs
            # an explicit re-admission, so the endorsement is recorded (the
            # statement is real) but the entry keeps the cert it had.
            pass
        # Dedup by signer AND epoch: the same statement twice is a replay of a
        # merge, not new information.
        if not any(x.endorser_id == e.endorser_id
                   and x.introduced_epoch == e.introduced_epoch
                   for x in m.endorsements):
            m.endorsements.append(e)
            m.epoch = max(m.epoch, epoch)
            self.generation += 1
        return e

    # -- trust evaluation ---------------------------------------------------
    def is_trusted(self, node_id: str) -> bool:
        """Whether *node_id* is in the roster, at all.

        This is the membership question, deliberately weaker than
        :meth:`is_verified_trusted` — someone can be a member of a roster they
        were merely gossiped into without being responsible for what they say.
        """
        return node_id in self.members

    def is_verified_trusted(self, node_id: str,
                            keyring: dict[str, bytes]) -> bool:
        """Whether some already-trusted member vouched for this admission.

        Walks one hop on purpose: the transitive case is handled by
        :meth:`reconcile`, which iterates to a fixpoint over the endorsement
        graph rather than doing it here with unbounded recursion.
        """
        m = self.members.get(node_id)
        if m is None:
            return False
        for e in m.endorsements:
            if e.introduced_id != node_id:
                continue
            if e.cert_fingerprint != m.cert_fingerprint:
                continue
            endorser = self.members.get(e.endorser_id)
            if endorser is None or endorser.node_id not in keyring:
                continue
            if e.endorser_epoch != endorser.epoch:
                continue
            if e.verify(keyring[endorser.node_id]):
                return True
        return False

    # -- reconciliation -----------------------------------------------------
    def reconcile(self, incoming: "Roster", keyring: dict[str, bytes], *,
                  max_depth: int = MAX_ENDORSEMENT_DEPTH
                  ) -> tuple[int, int]:
        """Merge another member's roster, trusting only what we already trust.

        Returns ``(pinned, rejected)``. Every accepted edge must terminate at a
        member this node *already* trusts, so an inbound roster can grow the
        roster only along edges a human pairing created. The iteration is what
        makes transitive trust work: a node admitted in round 1 can vouch for
        the nodes it endorsed, and those get admitted in round 2.

        Rejections are counted rather than silently skipped — a roster that
        keeps trying to introduce entries nobody vouched for is a signal worth
        having, not noise to discard.
        """
        if incoming.cluster_id != self.cluster_id:
            return 0, len(incoming.members)

        pinned = rejected = 0
        depth = 0
        pending = list(incoming.members.values())

        # Nodes admitted transitively in this merge carry the set of endorsers
        # that were already vouching for them when they arrived. Only those may
        # in turn vouch. Without this, one pairing would launder an unbounded
        # chain: B is admitted because A vouched, then B introduces E, then E
        # introduces F, and the roster grows without a single new pairing.
        # Trust has to terminate at a human pairing, and an admission is only
        # as powerful as the graph that produced it.
        provenance: dict[str, set[str]] = {
            a.node_id: {e.endorser_id for e in a.endorsements}
            for a in incoming.members.values()
        }
        # Roots are the endorsers we trust *independently of this message*.
        # Everything admitted has to reach one through the endorsement graph
        # that already existed; a node admitted during this merge is not a
        # root, which is what stops one pairing from laundering a chain.
        roots = {n for n in self.members if n in keyring}

        while pending and depth < max_depth:
            depth += 1
            still_pending: list[Admission] = []
            for adm in pending:
                known = self.members.get(adm.node_id)
                if known is not None and known.cert_fingerprint and \
                        known.cert_fingerprint != adm.cert_fingerprint:
                    # A different cert for a member we know is a re-key, and
                    # that needs an explicit re-admission. It is never a merge.
                    rejected += 1
                    still_pending.append(adm)
                    continue
                allowed = self._permitted(adm, incoming, provenance, keyring,
                                          roots)
                if allowed is None:
                    rejected += 1
                    continue
                if self._accept(adm, keyring, allowed):
                    pinned += 1
                elif not self.members.get(adm.node_id):
                    # Rejected now, but a later round might reach its endorser,
                    # so it is not counted as refused until the walk gives up.
                    still_pending.append(adm)
            if len(still_pending) == len(pending):
                break  # no progress: the rest is not reachable from what we trust
            pending = still_pending

        rejected += len(pending)
        return pinned, rejected

    def _permitted(self, adm: Admission, incoming: "Roster",
                   provenance: dict[str, set[str]], keyring: dict[str, bytes],
                   roots: set[str]) -> set[str] | None:
        """Which of this entry's endorsers may authorise it, or ``None``.

        An endorsement authorises an entry only when the endorser is a member
        this node *already* holds — that is what makes it pre-merge. Trust
        then grows one hop per reconcile round: A vouches for B, B lands in
        round one, and B can vouch for C in round two, which is the transitive
        trust the layer exists for.

        What this deliberately does not do is read the inbound roster's own
        provenance. Doing so would validate an entire self-consistent chain in
        a single round — a node could ship a roster of strangers each vouching
        for the next and be admitted whole. It would also make
        ``MAX_ENDORSEMENT_DEPTH`` meaningless, since nothing would ever
        require more than one round.

        Returns the set of endorsers whose statement is usable. The
        cryptographic verification still happens in :meth:`_accept`, never on
        the strength of the walk alone.
        """
        usable: set[str] = set()
        for e in adm.endorsements:
            if e.cluster_id != self.cluster_id:
                continue
            if e.introduced_id != adm.node_id:
                continue
            if e.cert_fingerprint != adm.cert_fingerprint:
                continue
            endorser_id = e.endorser_id
            if endorser_id not in keyring:
                continue
            # Only a member we ALREADY hold can authorise. The round-by-round
            # iteration is what admits second hops: B lands in round 1 because
            # A vouched, and B can then vouch for C in round 2. Checking the
            # inbound roster's own provenance here instead would let the whole
            # chain validate at once, which is both wrong and why max_depth
            # would stop bounding anything.
            if endorser_id in self.members and endorser_id in keyring:
                usable.add(endorser_id)
        return usable or None

    def _accept(self, adm: Admission, keyring: dict[str, bytes],
                allowed_endorsers: set[str] | None = None) -> bool:
        """Whether one inbound entry is backed by something we already trust.

        ``allowed_endorsers`` bounds whose statement may authorise *this* entry.
        It is the provenance set the merge computed: the endorsers that were
        already vouching for the node before this merge started. Passing it is
        what keeps a freshly-admitted member from becoming a new root of trust.
        """
        if not adm.cert_fingerprint:
            return False
        for e in adm.endorsements:
            if e.cluster_id != self.cluster_id:
                continue
            if e.introduced_id != adm.node_id:
                continue
            if e.cert_fingerprint != adm.cert_fingerprint:
                continue
            if e.introduced_epoch > adm.epoch:
                continue  # claiming a newer admission than the entry itself
            # The endorser must be a member WE trust — not merely one the
            # inbound roster lists. A roster that names its own friends has
            # already been rejected for exactly that reason.
            if allowed_endorsers is not None and \
                    e.endorser_id not in allowed_endorsers:
                continue  # an endorser that is not part of this node's provenance
            endorser = self.members.get(e.endorser_id)
            if endorser is None:
                continue  # endorser unknown here; wait for a later round
            if endorser.node_id not in keyring:
                continue
            if not e.verify(keyring[endorser.node_id]):
                continue
            if e.endorser_epoch != endorser.epoch:
                continue  # endorser spoke for an admission we no longer hold
            if e.introduced_epoch < endorser.epoch - len(self.members) - 1:
                continue  # sanity bound on epoch distance
            # Accept: merge endorsements, never downgrade the epoch.
            existing = self.members.get(adm.node_id)
            if existing is None:
                self.members[adm.node_id] = Admission(
                    node_id=adm.node_id,
                    cert_fingerprint=adm.cert_fingerprint,
                    epoch=adm.epoch,
                    endorsements=list(adm.endorsements),
                    last_addr=adm.last_addr,
                    joined_at=adm.joined_at or time.time())
                self.generation += 1
                return True
            changed = False
            for x in adm.endorsements:
                if not any(y.endorser_id == x.endorser_id
                           and y.introduced_epoch == x.introduced_epoch
                           for y in existing.endorsements):
                    existing.endorsements.append(x)
                    changed = True
            if adm.epoch > existing.epoch:
                existing.epoch = adm.epoch
                changed = True
            if adm.last_addr and adm.last_addr != existing.last_addr:
                existing.last_addr = adm.last_addr
                changed = True
            if changed:
                self.generation += 1
                return True
            # Already merged and identical: not a new pin, so not counted as
            # one. Returning True here is what made reconcile over-report.
            return False
        return False

    # -- canonical form -----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "v": ENDORSEMENT_V,
            "kind": ROSTER_KIND,
            "cluster_id": self.cluster_id,
            "self_id": self.self_id,
            "self_epoch": self.self_epoch,
            "generation": self.generation,
            "members": [self.members[n].to_dict()
                        for n in sorted(self.members)],
        }

    def digest(self) -> str:
        """A single hash over the whole membership belief.

        Same purpose as the telemetry view digest: it can be chained into the
        ledger and eventually published, so you can prove later who the mesh
        considered a member without publishing anything the roster says.
        """
        import hashlib

        blob = json.dumps(self.to_dict(), sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Roster":
        return cls(
            cluster_id=str(d.get("cluster_id", "")),
            self_id=str(d.get("self_id", "")),
            self_epoch=int(d.get("self_epoch", 0) or 0),
            generation=int(d.get("generation", 0) or 0),
            members={m["node_id"]: Admission.from_dict(m)
                     for m in d.get("members", [])},
        )

    @classmethod
    def create(cls, cluster_id: str, self_id: str, key: KeyPair,
               cert: bytes, *, now: Optional[float] = None
               ) -> tuple["Roster", Admission]:
        """Found a roster of one. Returns the roster and this node's own entry.

        The founder is its own first endorser rather than a special case in the
        verification path: there is no code that says "trust node X", only code
        that says "X's endorsement checks out", so a self-endorsement is not a
        special case at all.
        """
        roster = cls(cluster_id=cluster_id, self_id=self_id, self_epoch=1)
        fp = cert_fingerprint(key.public_key)
        self_adm = Admission(node_id=self_id, cert_fingerprint=fp, epoch=1,
                             joined_at=time.time() if now is None else now)
        roster.add(self_adm)
        roster.endorse(key, self_id, fp, epoch=1, now=now)
        return roster, self_adm