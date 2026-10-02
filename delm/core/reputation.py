"""Reputation — how much of the mesh each node has actually served.

This is what the credit balance used to be, with the semantics inverted. The old
:mod:`delm.core.contrib` ledger carried a float a node *earned by existing*
(VRAM x hours) and *spent* on inference. That is gone. What remains here is a
counter and a ranking, and the difference is the whole point:

* a balance is a claim on someone else's capacity; a counter is a statement
  about the past, and it cannot be spent, transferred, or promised;
* a balance grows while a node does nothing; a counter grows only when
  :meth:`~delm.core.contrib.ContributionLedger.record_inference` is called,
  and that refuses anything without a verified anchor;
* a balance is private until someone runs an audit; a counter is the thing a
  node shows the others precisely so it *can* be checked.

**The evidence is the chain, not this module.** Every count here comes from an
anchor that :mod:`delm.core.anchor` verified against a block header — the
transaction exists, it was included, and its signature attributes it to the
membership key. Nothing here trusts the node's own count. The cost of that
choice is honest and worth stating: a node's ledger is *its assertion* until
somebody hands it a header to check against (see
:attr:`AnchorLedger.anchors` and the note in its docstring), so a ranking built
from unverified ledgers is a ranking of claims. :func:`board_from_verified`
only ever counts what passed verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from delm.core.contrib import ContributionLedger

from delm.core.anchor import AnchorLedger

__all__ = [
    "ReputationEntry",
    "ReputationBoard",
    "verified_count",
    "board_from_verified",
    "board_from_counters",
]


@dataclass(frozen=True)
class ReputationEntry:
    """One row of the ranking. Numbers, no adjectives."""

    node_id: str
    inferences_served: int = 0
    satoshis_earned: int = 0
    publishes_vram: bool = True
    vram_advertised_gb: float = 0.0
    observed_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"node_id": self.node_id,
                "inferences_served": self.inferences_served,
                "satoshis_earned": self.satoshis_earned,
                "publishes_vram": self.publishes_vram,
                "vram_advertised_gb": round(self.vram_advertised_gb, 3),
                "observed_s": round(self.observed_s, 1)}


@dataclass(frozen=True)
class ReputationBoard:
    """The ranking, ordered and deterministic.

    Order: inferences served, then satoshis, then node id. The first key is
    the one that matters — a node that served more of the mesh ranks higher no
    matter how much VRAM it advertises. Satoshis break ties, because serving
    the paid tier is serving too, and ``node_id`` is there so that two rows
    with identical numbers always come out in the same order (a ranking that
    reshuffles between runs is a ranking nobody can argue with).
    """

    entries: tuple[ReputationEntry, ...] = ()

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)

    def position(self, node_id: str) -> int | None:
        """1-based rank, or ``None`` if the node is not on the board."""
        for i, e in enumerate(self.entries, 1):
            if e.node_id == node_id:
                return i
        return None

    def get(self, node_id: str) -> ReputationEntry | None:
        return next((e for e in self.entries if e.node_id == node_id), None)

    def providers(self) -> tuple[ReputationEntry, ...]:
        """Only the rows that actually offer capacity to the mesh."""
        return tuple(e for e in self.entries if e.publishes_vram)

    def to_dict(self) -> dict[str, Any]:
        return {"entries": [e.to_dict() for e in self.entries]}

    def render(self, title: str = "=== reputación de la malla ===") -> str:
        """Deterministic text for the CLI.

        It prints satoshis in a separate column from the count *on purpose*:
        they are different things (one is evidence, the other is money), and a
        reader who sees a single "value" column infers an exchange rate that
        does not exist.
        """
        out = [title, ""]
        if not self.entries:
            out.append("— ningún nodo con historial todavía —")
            return "\n".join(out)
        out.append("  #  nodo                 inferencias  sats   ofrece  observado")
        for i, e in enumerate(self.entries, 1):
            out.append(f"  {i:>2} {e.node_id[:20]:<20} "
                       f"{e.inferences_served:>11} {e.satoshis_earned:>6} "
                       f"{e.vram_advertised_gb:>6.1f}G {e.observed_s:>9.0f}s")
        out.append("")
        out.append("la reputación es historial: no se gasta, no se transfiere y "
                   "no compra nada.")
        return "\n".join(out)


def verified_count(ledger: AnchorLedger, header: Any) -> int:
    """How many of *ledger*'s anchors verify against *header*.

    ``AnchorLedger.verify()`` returns the first failure, not a count — a ledger
    with three anchors whose third is invalid is worthless as a whole, and that
    is the right answer for a settlement decision. A *ranking* needs something
    slightly different: it needs to know how much passed, and it must not be
    able to answer "three, give or take". So each anchor is checked on its own
    against the caller's header.

    Without a header there is nothing to check against, and the honest answer is
    zero rather than "however many it claims": an unverified ledger is a claim,
    and a ranking of claims presented as a ranking of facts is the thing this
    whole design exists to avoid.
    """
    if header is None:
        return 0
    count = 0
    for i, anchor in enumerate(ledger.anchors):
        signature = ledger.signatures[i] if i < len(ledger.signatures) else ""
        inclusion = ledger.inclusions[i] if i < len(ledger.inclusions) else None
        if inclusion is None:
            continue
        ok, _ = anchor.verify(signature, inclusion, header)
        if ok:
            count += 1
    return count


def board_from_counters(ledger: ContributionLedger) -> ReputationBoard:
    """Build a board from the counters already in a :class:`ContributionLedger`.

    This is the cheap path: the ledger has been counting
    ``inferences_served`` as inferences are admitted, so the board is a
    projection. It is *not* a verification — see :func:`verified_count` for what
    that would take.
    """
    entries: list[ReputationEntry] = []
    for peer_id, peer in ledger.peers.items():
        entries.append(ReputationEntry(
            node_id=peer_id,
            inferences_served=peer.inferences_served,
            satoshis_earned=peer.satoshis_earned,
            # Solo lo que **ofrece**. Tener 24 GiB y no ofrecer ninguno es la
            # forma de un consumidor, y el board tiene que poder separarlos.
            publishes_vram=peer.vram_advertised_gb > 0,
            vram_advertised_gb=peer.vram_advertised_gb,
            observed_s=peer.seconds_observed))
    entries.sort(key=lambda e: (-e.inferences_served, -e.satoshis_earned,
                                e.node_id))
    return ReputationBoard(entries=tuple(entries))


def board_from_verified(ledgers: Mapping[str, AnchorLedger],
                        header: Any) -> ReputationBoard:
    """Build a board from anchors **verified against a block header**.

    This is the ranking that means something: each node's count is the number of
    its own anchors that survive signature **and** Merkle inclusion against
    *header*. A node with a bad ledger does not get a lower score by
    subtraction — it gets what it can prove, which is the same thing every peer
    would compute for itself.

    Satohis come from the verified anchors too, and are reported separately
    because they are money, not merit: a node paid 100 sats per inference is
    not twice as good a node.
    """
    if header is None:
        # Misma regla que `verified_count`: sin cabecera no hay contra que
        # comprobar, y el conteo decia es una afirmacion del nodo.
        return ReputationBoard()
    entries: list[ReputationEntry] = []
    for node_id, ledger in ledgers.items():
        served = 0
        sats = 0
        for i, anchor in enumerate(ledger.anchors):
            signature = ledger.signatures[i] if i < len(ledger.signatures) else ""
            inclusion = ledger.inclusions[i] if i < len(ledger.inclusions) else None
            if inclusion is None:
                continue
            ok, _ = anchor.verify(signature, inclusion, header)
            if ok:
                served += 1
                sats += max(0, anchor.satoshis)
        entries.append(ReputationEntry(node_id=node_id, inferences_served=served,
                                      satoshis_earned=sats,
                                      publishes_vram=True))
    entries.sort(key=lambda e: (-e.inferences_served, -e.satoshis_earned,
                                e.node_id))
    return ReputationBoard(entries=tuple(entries))