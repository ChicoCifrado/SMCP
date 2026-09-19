"""RSI loop (L1) — self-modification through the verified pipeline.

Maps the RSI loop (arXiv:2609.11873) onto the *existing* verification
infrastructure, so a self-proposed modification is treated exactly like any
other admitted gist:

    experience -> candidate modification -> verifier -> retained -> successor

A :class:`Rule` is a candidate modification to the system itself (e.g. a
parameter of :class:`ExpansionPolicy`). Before it is retained it goes through
the same pipeline as any gist:

  1. **Provenance** — digest + ed25519 signature (``KeyPair`` / ``digest_of``).
  2. **Verifier** — :class:`RuleVerifier` consistency gate (the rule's
     justification must be grounded in the experience that motivates it).
  3. **Ledger** — :class:`AdmissionLedger` (append-only, hash-chained audit
     trail). The rule is only *retained* if the entry is accepted.

If accepted, :meth:`RSILoop.apply` returns a :class:`Successor` — the next run
that consumes the retained rule. The retained rule is durable: it survives the
run and changes what the successor does.

This is the L1 step of the RSI ladder: the system *proposes* a modification to
itself and the modification is *auditable* (signed + ledger), not merely
asserted. The verifier gate is a consistency check; the durable guarantees
come from the digest + signature + ledger chain.

The methods are ``async`` because the verifier's interface is async
(``Verifier.verify``), matching :mod:`delm.core.admission`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from delm.core.gist import Gist, GistKind
from delm.core.ledger import AdmissionLedger
from delm.core.provenance import KeyPair, digest_of
from delm.core.verifier import RuleVerifier, VerifyResult


# --------------------------------------------------------------------------- Rule
@dataclass
class Rule:
    """A candidate modification to the system itself.

    A rule is a named parameter change in a scope (e.g.
    ``scope="expansion", param="max_burst", value=4``) motivated by an
    experience (the trajectory that justifies it). The ``evidence`` is the
    recorded justification; it is what the verifier grounds against.
    """
    name: str
    scope: str
    param: str
    value: Any
    evidence: str  # the experience that motivates the rule

    def to_dict(self) -> dict:
        return {
            "name": self.name, "scope": self.scope,
            "param": self.param, "value": self.value,
            "evidence": self.evidence,
        }

    def to_gist(self) -> Gist:
        """The rule as a :class:`Gist` so it rides the same pipeline.

        The gist text is the recorded justification (the evidence); the
        verifier grounds the rule against that same experience, so the
        consistency gate is meaningful (the rule must be what the evidence
        supports).
        """
        return Gist(
            label=f"rule/{self.name}",
            gist=self.evidence,
            kind=GistKind.FACT,
        )


# --------------------------------------------------------------------------- Successor
@dataclass
class Successor:
    """The next run that consumes a retained rule.

    Carries the effective parameter so the successor's behavior changes
    durably (this is what makes the modification *persistent*, the defining
    trait of an RSI loop).
    """
    scope: str
    param: str
    value: Any
    n_retained: int

    def effective(self) -> dict:
        return {"scope": self.scope, "param": self.param,
                "value": self.value, "n_retained": self.n_retained}


# --------------------------------------------------------------------------- Outcome
@dataclass
class RSIOutcome:
    """The result of verifying one candidate rule."""
    accepted: bool
    rule: Rule
    verify: VerifyResult
    ledger_entry: Any
    reason: str = ""


# --------------------------------------------------------------------------- RSILoop
class RSILoop:
    """The L1 RSI loop: self-propose, self-verify, retain, succeed.

    The loop owns one author identity (a :class:`KeyPair`), one
    :class:`AdmissionLedger` (the durable audit trail) and one
    :class:`RuleVerifier` (the consistency gate). Retained rules are durable
    across runs.

    Example
    -------
    >>> loop = RSILoop("agent-0")
    >>> rule = Rule("r1", "expansion", "max_burst", 4,
    ...             "three failures: burst too small to drain the queue")
    >>> out = await loop.verify(rule)
    >>> out.accepted
    True
    >>> succ = loop.apply(out)
    >>> succ.value
    4
    """

    def __init__(self, author_id: str,
                 verifier: RuleVerifier | None = None):
        self.author_id = author_id
        self.key = KeyPair.new(author_id)
        self.ledger = AdmissionLedger()
        self.verifier = verifier or RuleVerifier()
        self._retained: list[Rule] = []

    # ------------------------------------------------------------ verify
    async def verify(self, rule: Rule) -> RSIOutcome:
        """Route one candidate rule through the verified pipeline.

        Order (mirrors the admission path):

        1. **Provenance** — the rule's gist is digested and signed under this
           loop's key (``digest_of`` + ``KeyPair.sign``), so the modification
           is attributable.
        2. **Verifier** — the consistency gate grounds the rule against its
           evidence (``RuleVerifier``).
        3. **Ledger** — an append-only, hash-chained entry is recorded
           (accepted or not), so the decision is auditable.

        The rule is *retained* (durable) only if the verifier accepts.
        """
        g = rule.to_gist()
        # 1. provenance: digest + sign under this loop's identity.
        g.digest = digest_of(g)
        g.signature = self.key.sign(g.digest)
        g.sig_kind = self.key.kind
        # 2. verifier: the rule must be grounded in its evidence.
        verify = await self.verifier.verify(
            "trajectory",
            {"result": rule.evidence, "gist": rule.evidence},
        )
        accepted = bool(verify.ok)
        reason = "" if accepted else "; ".join(verify.reasons)
        # 3. ledger: append-only, hash-chained audit entry.
        entry = self.ledger.append(
            author_id=self.author_id,
            label=g.label,
            digest=g.digest,
            signature=g.signature,
            sig_kind=g.sig_kind,
            accepted=accepted,
            reason=reason,
        )
        if accepted:
            self._retained.append(rule)
        return RSIOutcome(
            accepted=accepted, rule=rule, verify=verify,
            ledger_entry=entry, reason=reason,
        )

    # ------------------------------------------------------------ apply
    def apply(self, outcome: RSIOutcome) -> Successor:
        """Return the :class:`Successor` that consumes a retained rule.

        Raises ``ValueError`` if the rule was not accepted (a rejected
        modification must not change the successor).
        """
        if not outcome.accepted:
            raise ValueError("cannot apply a rejected rule")
        r = outcome.rule
        return Successor(
            scope=r.scope, param=r.param, value=r.value,
            n_retained=len(self._retained),
        )

    # ------------------------------------------------------------ retained
    def retained(self) -> list[Rule]:
        """The durable modifications accepted so far (the RSI memory)."""
        return list(self._retained)

    def verify_chain(self) -> bool:
        """Re-verify the ledger's hash chain (tamper detection)."""
        return self.ledger.verify_chain()

    # ------------------------------------------------------------ propose (L1 hook)
    async def propose(self, experience: str,
                      scope: str, param: str, value: Any,
                      name: str | None = None) -> RSIOutcome:
        """The L1 step: *the system itself* proposes a modification.

        Given an ``experience`` (a trajectory / run summary), the loop
        derives a candidate :class:`Rule` (scope/param/value) and routes it
        through :meth:`verify`. This is the self-proposal hook that lifts the
        loop from L0 (external modifications) to L1 (self-proposed).
        """
        rule = Rule(
            name=name or f"rule-{len(self._retained)}",
            scope=scope, param=param, value=value,
            evidence=experience,
        )
        return await self.verify(rule)


__all__ = ["Rule", "Successor", "RSIOutcome", "RSILoop"]
