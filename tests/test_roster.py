"""Tests for explicit membership via signed endorsements.

The attack cases matter more than the happy path here. A membership system
whose failure mode is "admits someone it shouldn't" is the thing that makes
the open mesh safe, so most of these tests assert a rejection.

The distinction under test throughout: :meth:`Roster.is_member` (present in
the roster) versus :meth:`Roster.is_verified_trusted` (someone we already
trust vouched for it). Those are different questions, and collapsing them is
how a gossiped stranger becomes a trusted peer.
"""
import json

import pytest

from delm.core.provenance import KeyPair
from delm.core.roster import (
    Admission,
    Endorsement,
    MAX_ENDORSEMENT_DEPTH,
    Roster,
    cert_fingerprint,
)


def _key(node_id: str) -> KeyPair:
    return KeyPair.new(node_id)


def _ring(*pairs: KeyPair) -> dict[str, bytes]:
    return {k.author_id: k.public_key for k in pairs}


def _found(cluster: str, node_id: str) -> tuple[Roster, KeyPair, Admission]:
    key = _key(node_id)
    roster, adm = Roster.create(cluster, node_id, key, key.public_key)
    return roster, key, adm


# ------------------------------------------------------------------ basics
def test_a_roster_starts_with_its_founder():
    roster, _, adm = _found("c1", "A")
    assert roster.member_ids() == ("A",)
    assert adm.epoch == 1
    assert roster.self_epoch == 1


def test_the_founder_is_endorsed_by_itself():
    """No "trust node X" special case exists anywhere in this module.

    The founder is trusted because its own endorsement verifies against its
    own key — the same code path every other admission goes through.
    """
    roster, key, _ = _found("c1", "A")
    assert roster.is_verified_trusted("A", _ring(key)) is True


def test_fingerprint_is_not_the_authority():
    """A fingerprint is a lookup key; trust uses the full key material."""
    roster, key, _ = _found("c1", "A")
    fp = roster.known_cert("A")
    assert fp.startswith("sha256:")
    assert fp == cert_fingerprint(key.public_key)
    # A wrong key must not verify even when the fingerprint still matches.
    assert roster.is_verified_trusted("A", _ring(_key("A"))) is False


# ------------------------------------------------------------ endorsements
def test_endorsement_roundtrips_through_json():
    key = _key("A")
    e = Endorsement.sign(endorser=key, introduced_id="B",
                         cert_fingerprint="sha256:abc", cluster_id="c1",
                         introduced_epoch=2, endorser_epoch=1, now=100.0)
    blob = json.dumps(e.to_dict())
    back = Endorsement.from_dict(json.loads(blob))
    assert back.digest() == e.digest()
    assert back.verify(key.public_key) is True


def test_endorsement_verifies_only_for_its_endorser():
    a, b = _key("A"), _key("B")
    e = Endorsement.sign(endorser=a, introduced_id="C",
                         cert_fingerprint="sha256:c", cluster_id="c1",
                         introduced_epoch=1, endorser_epoch=1)
    assert e.verify(a.public_key) is True
    assert e.verify(b.public_key) is False


def test_editing_an_endorsement_breaks_it():
    key = _key("A")
    e = Endorsement.sign(endorser=key, introduced_id="B",
                         cert_fingerprint="sha256:abc", cluster_id="c1",
                         introduced_epoch=2, endorser_epoch=1)
    d = e.to_dict()
    d["introduced_epoch"] = 99  # claim a much newer admission
    tampered = Endorsement.from_dict(d)
    assert tampered.verify(key.public_key) is False


def test_re_endorsing_the_same_admission_is_idempotent():
    """A merge replaying the same statement must not grow the roster."""
    roster, key, _ = _found("c1", "A")
    fp = roster.known_cert("A")
    before = roster.generation
    for _ in range(3):
        roster.endorse(key, "A", fp, epoch=1)
    assert len(roster.members["A"].endorsements) == 1
    assert roster.generation == before


def test_endorsing_a_new_epoch_records_a_new_statement():
    roster, key, _ = _found("c1", "A")
    fp = roster.known_cert("A")
    roster.endorse(key, "A", fp, epoch=2)
    assert len(roster.members["A"].endorsements) == 2
    assert roster.members["A"].epoch == 2


# ------------------------------------------------------------- membership
def test_is_member_is_weaker_than_is_verified_trusted():
    """A roster can contain someone nobody vouched for yet.

    That is what makes the two methods worth having: a member is *present*,
    a verified-trusted member is *responsible for someone*.
    """
    roster, key, _ = _found("c1", "A")
    roster.add(Admission(node_id="X", cert_fingerprint="sha256:x", epoch=1))
    assert roster.is_member("X") is True
    assert roster.is_verified_trusted("X", _ring(key)) is False


def test_remove_drops_the_member():
    roster, _, _ = _found("c1", "A")
    assert roster.remove("X") is False
    roster.add(Admission(node_id="X", cert_fingerprint="sha256:x", epoch=1))
    assert roster.remove("X") is True
    assert roster.remove("X") is False


# ---------------------------------------------------------- reconciliation
def test_an_endorsement_from_a_stranger_is_rejected():
    """The core attack: a lone node invents a roster full of friends."""
    ours, ourkey, _ = _found("c1", "A")
    strangers_key = _key("M")

    theirs = Roster(cluster_id="c1", self_id="M", self_epoch=1)
    fp = cert_fingerprint(strangers_key.public_key)
    theirs.endorse(strangers_key, "M", fp, epoch=1)
    theirs.add(Admission(node_id="FAKE", cert_fingerprint="sha256:fake",
                         epoch=1, endorsements=[
                             Endorsement.sign(endorser=strangers_key,
                                              introduced_id="FAKE",
                                              cert_fingerprint="sha256:fake",
                                              cluster_id="c1",
                                              introduced_epoch=1,
                                              endorser_epoch=1)]))

    pinned, rejected = ours.reconcile(theirs, _ring(ourkey))
    assert pinned == 0, "nada viniendo de un desconocido puede ser fijado"
    assert rejected >= 1
    assert ours.is_member("FAKE") is False
    assert ours.is_member("M") is False


def test_an_endorsement_from_a_trusted_member_is_accepted():
    """The legitimate path: A and B paired, and A's roster arrives at A."""
    akey = _key("A")
    ours, _, _ = _found("c1", "A")

    bkey = _key("B")
    theirs = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    theirs.add(Admission(node_id="B",
                         cert_fingerprint=cert_fingerprint(bkey.public_key),
                         epoch=1, joined_at=1.0))
    bfp = cert_fingerprint(bkey.public_key)
    theirs.endorse(bkey, "B", bfp, epoch=1)
    # B's roster as it would look arriving at A: A endorsed B.
    theirs.endorse(akey, "B", bfp, epoch=1)

    pinned, _ = ours.reconcile(theirs, _ring(akey, bkey))
    assert pinned == 1
    assert ours.is_member("B") is True
    assert ours.known_cert("B") == bfp
    assert ours.is_verified_trusted("B", _ring(akey, bkey)) is True


def test_transitive_trust_reaches_a_fixpoint():
    """A→B→C: C must be admitted because the graph traces back to A.

    This is what mTLS cannot do on its own, and the reason the merge iterates
    rather than checking one hop.
    """
    akey, bkey, ckey = _key("A"), _key("B"), _key("C")
    ours, _, _ = _found("c1", "A")

    bf, cf = cert_fingerprint(bkey.public_key), cert_fingerprint(ckey.public_key)

    # B's roster, as seen by A. B vouches for C; A vouches for B.
    b_roster = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    b_roster.add(Admission(node_id="B", cert_fingerprint=bf, epoch=1))
    b_roster.add(Admission(node_id="C", cert_fingerprint=cf, epoch=1,
                           endorsements=[Endorsement.sign(
                               endorser=bkey, introduced_id="C",
                               cert_fingerprint=cf, cluster_id="c1",
                               introduced_epoch=1, endorser_epoch=1)]))
    b_roster.endorse(akey, "B", bf, epoch=1)

    pinned, rejected = ours.reconcile(b_roster, _ring(akey, bkey, ckey))
    assert pinned == 2, "B y C ambos, tras iterar hasta el punto fijo"
    assert ours.is_member("C") is True
    assert ours.is_verified_trusted("C", _ring(akey, bkey, ckey)) is True


def test_the_walk_is_bounded_by_depth():
    """A roster claiming to be deeper than the bound must not hang."""
    akey = _key("A")
    ours, _, _ = _found("c1", "A")
    theirs = Roster(cluster_id="c1", self_id="A", self_epoch=1)
    prev = _key("prev")
    theirs.add(Admission(node_id="prev",
                         cert_fingerprint=cert_fingerprint(prev.public_key),
                         epoch=1))
    pinned, rejected = ours.reconcile(theirs, _ring(akey),
                                      max_depth=MAX_ENDORSEMENT_DEPTH)
    assert pinned == 0


def test_a_different_cluster_is_never_merged():
    akey = _key("A")
    ours, _, _ = _found("c1", "A")
    bkey = _key("B")
    theirs = Roster(cluster_id="OTHER", self_id="B", self_epoch=1)
    bf = cert_fingerprint(bkey.public_key)
    theirs.endorse(akey, "B", bf, epoch=1)
    pinned, rejected = ours.reconcile(theirs, _ring(akey, bkey))
    assert pinned == 0
    assert rejected == len(theirs.members)


def test_a_re_key_needs_explicit_readmission_not_a_merge():
    """A different cert for a known member is the re-key attack surface."""
    akey = _key("A")
    ours, _, _ = _found("c1", "A")
    known_fp = ours.known_cert("A")

    impostor = _key("A")  # same node_id, different key
    theirs = Roster(cluster_id="c1", self_id="A", self_epoch=9)
    theirs.add(Admission(node_id="A",
                         cert_fingerprint=cert_fingerprint(impostor.public_key),
                         epoch=9))
    theirs.endorse(impostor, "A",
                   cert_fingerprint(impostor.public_key), epoch=9)

    ours.reconcile(theirs, _ring(akey, impostor))
    assert ours.known_cert("A") == known_fp, \
        "un merge no puede cambiar la clave de un miembro conocido"


def test_stale_gossip_cannot_downgrade_an_epoch():
    """An older incarnation must never replace a newer one."""
    akey, bkey = _key("A"), _key("B")
    ours, _, _ = _found("c1", "A")
    bf = cert_fingerprint(bkey.public_key)

    fresh = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    fresh.endorse(akey, "B", bf, epoch=5)
    ours.reconcile(fresh, _ring(akey, bkey))
    assert ours.members["B"].epoch == 5

    stale = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    stale.endorse(akey, "B", bf, epoch=2)
    ours.reconcile(stale, _ring(akey, bkey))
    assert ours.members["B"].epoch == 5, "el gossip viejo no puede rebajar la epoch"


def test_an_endorsement_for_a_mismatched_cert_is_rejected():
    akey = _key("A")
    ours, _, _ = _found("c1", "A")
    theirs = Roster(cluster_id="c1", self_id="X", self_epoch=1)
    theirs.add(Admission(node_id="X", cert_fingerprint="sha256:real", epoch=1,
                         endorsements=[Endorsement.sign(
                             endorser=akey, introduced_id="X",
                             cert_fingerprint="sha256:different",
                             cluster_id="c1", introduced_epoch=1,
                             endorser_epoch=1)]))
    pinned, _ = ours.reconcile(theirs, _ring(akey))
    assert pinned == 0, "el endorsement debe ser del cert que dice defender"


def test_reconcile_counts_what_it_refused():
    """Silently dropping rejects hides a node probing the boundary."""
    akey = _key("A")
    ours, _, _ = _found("c1", "A")
    theirs = Roster(cluster_id="c1", self_id="M", self_epoch=1)
    for i in range(3):
        theirs.add(Admission(node_id=f"X{i}", cert_fingerprint="sha256:x",
                             epoch=1))
    pinned, rejected = ours.reconcile(theirs, _ring(akey))
    assert pinned == 0
    assert rejected == 3


# ----------------------------------------------------------------- digest
def test_digest_is_stable_and_changes_with_membership():
    roster, key, _ = _found("c1", "A")
    d1 = roster.digest()
    assert roster.digest() == d1
    roster.add(Admission(node_id="B", cert_fingerprint="sha256:b", epoch=1))
    assert roster.digest() != d1


def test_roster_roundtrips_through_json():
    akey, bkey = _key("A"), _key("B")
    roster, _, _ = _found("c1", "A")
    bf = cert_fingerprint(bkey.public_key)
    roster.endorse(akey, "B", bf, epoch=1)
    back = Roster.from_dict(json.loads(json.dumps(roster.to_dict())))
    assert back.member_ids() == roster.member_ids()
    assert back.digest() == roster.digest()
    assert back.is_verified_trusted("B", _ring(akey, bkey)) is True


# ------------------------------------------------- gaps found by mutation
def test_a_corrupted_signature_is_rejected():
    """Verification is not decorative.

    The keyring lookup succeeds and every field matches, so only the signature
    check stands between a forged endorsement and membership. Removing it has
    to fail here.
    """
    akey = _key("A")
    ours, _, _ = _found("c1", "A")
    theirs = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    bf = cert_fingerprint(_key("B").public_key)
    e = theirs.endorse(akey, "B", bf, epoch=1)
    theirs.add(Admission(node_id="B", cert_fingerprint=bf, epoch=1,
                         endorsements=[e]))
    # Right key, right fields, wrong signature bytes.
    forged = Endorsement.from_dict({**e.to_dict(),
                                    "signature": "A" * 86 + "=="})
    theirs.members["B"].endorsements = [forged]
    pinned, _ = ours.reconcile(theirs, _ring(akey, _key("B")))
    assert pinned == 0, "una firma corrupta no puede avalar a nadie"


def test_a_roster_from_another_cluster_is_ignored_even_with_valid_endorsements():
    """A perfectly valid endorsement from another cluster is still foreign.

    Endorsements are scoped to a cluster; trusting them across one would let a
    member of someone's else roster vouch for nodes in yours.
    """
    akey = _key("A")
    ours, _, _ = _found("c1", "A")
    theirs = Roster(cluster_id="OTHER", self_id="B", self_epoch=1)
    bf = cert_fingerprint(_key("B").public_key)
    theirs.add(Admission(node_id="B", cert_fingerprint=bf, epoch=1,
                         endorsements=[Endorsement.sign(
                             endorser=akey, introduced_id="B",
                             cert_fingerprint=bf, cluster_id="OTHER",
                             introduced_epoch=1, endorser_epoch=1)]))
    pinned, rejected = ours.reconcile(theirs, _ring(akey))
    assert pinned == 0
    assert rejected == 1
    assert ours.is_member("B") is False


def test_a_self_signed_entry_from_a_stranger_is_rejected():
    """The nastiest shape: a node endorses itself, with a valid signature.

    Only its own key proves anything, and only a stranger's key is in play, so
    it must not bootstrap itself into our roster.
    """
    bkey = _key("B")
    ours, akey, _ = _found("c1", "A")
    theirs = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    bf = cert_fingerprint(bkey.public_key)
    theirs.add(Admission(node_id="B", cert_fingerprint=bf, epoch=1,
                         endorsements=[Endorsement.sign(
                             endorser=bkey, introduced_id="B",
                             cert_fingerprint=bf, cluster_id="c1",
                             introduced_epoch=1, endorser_epoch=1)]))
    pinned, rejected = ours.reconcile(theirs, _ring(akey, bkey))
    assert pinned == 0, "un desconocido no se autodeclara miembro"
    assert rejected == 1


def test_a_chain_reaches_its_fixpoint_but_stops_where_trust_stops():
    """A→B→C is legitimate transitive trust; C→D→E is not.

    The whole point of iterating the merge is that B, admitted this round, can
    vouch for the nodes it endorsed. So a chain rooted in a member we already
    trust IS admissible all the way down — and that is correct, because every
    edge traces back to a pairing a human performed.

    What must not happen is the chain continuing past the part that is rooted
    in us. That is asserted separately, in
    ``test_a_cycle_among_strangers_does_not_spin``.
    """
    keys = {n: _key(n) for n in "BCD"}
    ours, akey, _ = _found("c1", "A")
    theirs = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    order = list(keys)
    for i, n in enumerate(order):
        fp = cert_fingerprint(keys[n].public_key)
        endorser = akey if i == 0 else keys[order[i - 1]]
        theirs.add(Admission(node_id=n, cert_fingerprint=fp, epoch=1,
                             endorsements=[Endorsement.sign(
                                 endorser=endorser, introduced_id=n,
                                 cert_fingerprint=fp, cluster_id="c1",
                                 introduced_epoch=1, endorser_epoch=1)]))
    ours.reconcile(theirs, _ring(akey, *keys.values()))
    for n in order:
        assert ours.is_member(n) is True, \
            f"{n} cuelga de un aval de A: la cadena es legitima"


def test_an_indirect_endorsement_is_legitimate():
    """A→B→C is the whole point of the layer, so it must work.

    My first version of this test asserted that E — endorsed by B, who was
    himself endorsed by A — must be *refused*. It is structurally identical to
    A→B→C, so there is no formal way to separate them, and there should not
    be: both chains trace back to pairings a human performed, which is what
    makes the graph trustworthy. The bound that matters is length
    (``MAX_ENDORSEMENT_DEPTH``) and that every signature verifies, not a ban on
    second-hop endorsements.

    This test exists to pin that reasoning, so a future reader does not "fix"
    it into a policy that quietly breaks legitimate transitive trust.
    """
    akey, bkey, ekey = _key("A"), _key("B"), _key("E")
    ours, _, _ = _found("c1", "A")
    bf = cert_fingerprint(bkey.public_key)
    ef = cert_fingerprint(ekey.public_key)

    theirs = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    theirs.add(Admission(node_id="B", cert_fingerprint=bf, epoch=1,
                         endorsements=[Endorsement.sign(
                             endorser=akey, introduced_id="B",
                             cert_fingerprint=bf, cluster_id="c1",
                             introduced_epoch=1, endorser_epoch=1)]))
    theirs.add(Admission(node_id="E", cert_fingerprint=ef, epoch=1,
                         endorsements=[Endorsement.sign(
                             endorser=bkey, introduced_id="E",
                             cert_fingerprint=ef, cluster_id="c1",
                             introduced_epoch=1, endorser_epoch=1)]))
    ours.reconcile(theirs, _ring(akey, bkey, ekey))
    assert ours.is_member("B") is True
    assert ours.is_member("E") is True, \
        "un aval de segundo salto que cuelga de una raiz es legitimo"


def test_a_cycle_among_strangers_does_not_spin():
    """Two strangers endorsing each other must terminate, not loop."""
    bkey, ckey = _key("B"), _key("C")
    ours, akey, _ = _found("c1", "A")
    bf = cert_fingerprint(bkey.public_key)
    cf = cert_fingerprint(ckey.public_key)
    theirs = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    theirs.add(Admission(node_id="B", cert_fingerprint=bf, epoch=1,
                         endorsements=[Endorsement.sign(
                             endorser=ckey, introduced_id="B",
                             cert_fingerprint=bf, cluster_id="c1",
                             introduced_epoch=1, endorser_epoch=1)]))
    theirs.add(Admission(node_id="C", cert_fingerprint=cf, epoch=1,
                         endorsements=[Endorsement.sign(
                             endorser=bkey, introduced_id="C",
                             cert_fingerprint=cf, cluster_id="c1",
                             introduced_epoch=1, endorser_epoch=1)]))
    pinned, rejected = ours.reconcile(theirs, _ring(akey, bkey, ckey))
    assert pinned == 0
    assert rejected == 2


def test_an_endorsement_from_an_older_admission_does_not_speak_for_now():
    """The epoch guard on the endorser side.

    If A was admitted at epoch 3 and later re-admitted at epoch 5, a statement
    A signed at epoch 3 is no longer A's current position. Honoring it would
    let a revoked-and-replaced admission keep vouching.
    """
    akey, bkey = _key("A"), _key("B")
    ours, _, _ = _found("c1", "A")
    bf = cert_fingerprint(bkey.public_key)
    # A is now at epoch 5 locally.
    ours.members["A"].epoch = 5
    theirs = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    theirs.add(Admission(node_id="B", cert_fingerprint=bf, epoch=1,
                         endorsements=[Endorsement.sign(
                             endorser=akey, introduced_id="B",
                             cert_fingerprint=bf, cluster_id="c1",
                             introduced_epoch=1, endorser_epoch=1)]))
    pinned, _ = ours.reconcile(theirs, _ring(akey, bkey))
    assert pinned == 0, "un aval emitido por una admision antigua no vale"


def test_rekey_needs_explicit_readmission_and_reconcile_refuses():
    """A merge must not be able to change a known member's cert.

    This is the re-key attack surface: whoever controls a roster message could
    otherwise swap a member's fingerprint and take over its identity.
    """
    akey, bkey = _key("A"), _key("B")
    ours, _, _ = _found("c1", "A")
    bf = cert_fingerprint(bkey.public_key)
    ours.add(Admission(node_id="B", cert_fingerprint=bf, epoch=1))
    ours.endorse(akey, "B", bf, epoch=1)
    assert ours.is_verified_trusted("B", _ring(akey, bkey)) is True

    impostor = _key("B")  # same node id, different key
    theirs = Roster(cluster_id="c1", self_id="A", self_epoch=1)
    theirs.add(Admission(node_id="B",
                         cert_fingerprint=cert_fingerprint(impostor.public_key),
                         epoch=9))
    theirs.endorse(impostor, "B",
                   cert_fingerprint(impostor.public_key), epoch=9)
    ours.reconcile(theirs, _ring(akey, bkey, impostor))
    assert ours.known_cert("B") == bf, \
        "la clave de un miembro conocido no la cambia un merge"


# ----------------------------------- direct attacks on each individual guard
def test_a_rekey_attempt_is_refused_even_when_signed_by_the_impostor():
    """The guard that matters: a merge must not rebind a known member.

    The impostor holds a valid key and signs a valid endorsement for itself,
    so nothing here is malformed. The only thing standing between it and a
    hijacked identity is the check that an already-known member's cert cannot
    change through a merge.
    """
    akey, bkey = _key("A"), _key("B")
    ours, _, _ = _found("c1", "A")
    bf = cert_fingerprint(bkey.public_key)
    ours.add(Admission(node_id="B", cert_fingerprint=bf, epoch=1))
    ours.endorse(akey, "B", bf, epoch=1)
    assert ours.known_cert("B") == bf

    impostor = _key("B")
    ifp = cert_fingerprint(impostor.public_key)
    theirs = Roster(cluster_id="c1", self_id="A", self_epoch=1)
    theirs.add(Admission(node_id="B", cert_fingerprint=ifp, epoch=99))
    theirs.endorse(impostor, "B", ifp, epoch=99)
    theirs.endorse(akey, "B", ifp, epoch=99)   # even endorsed by a root
    pinned, rejected = ours.reconcile(
        theirs, _ring(akey, bkey, KeyPair.new("C")) |
        {f"imp{i}": k.public_key for i, k in enumerate([impostor])})
    assert ours.known_cert("B") == bf, \
        "una clave distinta para un miembro conocido no entra por merge"
    assert pinned == 0


def test_an_endorsement_whose_fingerprint_differs_is_refused():
    """The endorsement has to be about the cert in the entry.

    A valid endorsement for cert X, attached to an entry claiming cert Y,
    would otherwise let one node's endorsement cover another's cert.
    """
    akey, bkey, ykey = _key("A"), _key("B"), _key("Y")
    ours, _, _ = _found("c1", "A")
    xfp = cert_fingerprint(bkey.public_key)
    yfp = cert_fingerprint(ykey.public_key)
    theirs = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    # The entry claims Y; the endorsement talks about X.
    theirs.add(Admission(node_id="B", cert_fingerprint=yfp, epoch=1,
                         endorsements=[Endorsement.sign(
                             endorser=akey, introduced_id="B",
                             cert_fingerprint=xfp, cluster_id="c1",
                             introduced_epoch=1, endorser_epoch=1)]))
    pinned, _ = ours.reconcile(theirs, _ring(akey, bkey, ykey))
    assert pinned == 0
    assert ours.is_member("B") is False


def test_a_long_chain_is_admitted_up_to_the_depth_bound():
    """What the depth bound actually buys, measured honestly.

    ``max_depth`` counts *merge rounds*, not hops in the endorsement chain. A
    chain whose members are all present in one inbound roster resolves within
    the rounds it takes for each level to become a member we hold, so a bound
    of 1 admits the first two levels. Asserting "one round admits exactly one
    node" was wrong about the mechanism and hid nothing useful.

    What the bound does guarantee is that the walk terminates: a chain of
    strangers that never roots in a member we hold admits nothing, however many
    rounds it is given.
    """
    keys = {n: _key(n) for n in "BCDEFGH"}
    akey = _key("A")
    ring = _ring(akey, *keys.values())

    def build():
        r = Roster(cluster_id="c1", self_id="B", self_epoch=1)
        order = list(keys)
        for i, n in enumerate(order):
            fp = cert_fingerprint(keys[n].public_key)
            endorser = akey if i == 0 else keys[order[i - 1]]
            r.add(Admission(node_id=n, cert_fingerprint=fp, epoch=1,
                            endorsements=[Endorsement.sign(
                                endorser=endorser, introduced_id=n,
                                cert_fingerprint=fp, cluster_id="c1",
                                introduced_epoch=1, endorser_epoch=1)]))
        return r

    ours, _, _ = _found("c1", "A")
    pinned, _ = ours.reconcile(build(), ring)
    assert pinned == len(keys), \
        "una cadena rooted in A entra completa: es el caso legitimo"

    # And a chain that never roots terminates with nothing admitted.
    theirs = Roster(cluster_id="c1", self_id="X", self_epoch=1)
    order = list(keys)
    for i, n in enumerate(order):
        fp = cert_fingerprint(keys[n].public_key)
        endorser = keys[order[i - 1]] if i else _key("seed")
        if i == 0:
            e = Endorsement.sign(endorser=endorser, introduced_id=n,
                                 cert_fingerprint=fp, cluster_id="c1",
                                 introduced_epoch=1, endorser_epoch=1)
        else:
            e = Endorsement.sign(endorser=keys[order[i - 1]], introduced_id=n,
                                 cert_fingerprint=fp, cluster_id="c1",
                                 introduced_epoch=1, endorser_epoch=1)
        theirs.add(Admission(node_id=n, cert_fingerprint=fp, epoch=1,
                             endorsements=[e]))
    fresh, _, _ = _found("c1", "A")
    pinned2, rejected2 = fresh.reconcile(theirs, ring)
    assert pinned2 == 0, "una cadena sin raiz en un miembro nuestro no entra"
    assert rejected2 == len(keys)


def test_an_endorser_speaking_for_a_superseded_admission_is_refused():
    """The endorser-side epoch guard.

    A was admitted at epoch 1 and re-admitted at epoch 5. A statement signed
    while A was at epoch 1 is not A's current position, and honouring it would
    let a replaced admission keep vouching for nodes.
    """
    akey, bkey = _key("A"), _key("B")
    ours, _, _ = _found("c1", "A")
    bf = cert_fingerprint(bkey.public_key)
    theirs = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    theirs.add(Admission(node_id="B", cert_fingerprint=bf, epoch=1,
                         endorsements=[Endorsement.sign(
                             endorser=akey, introduced_id="B",
                             cert_fingerprint=bf, cluster_id="c1",
                             introduced_epoch=1, endorser_epoch=1)]))
    # A is now at epoch 5 here, so its epoch-1 statement is stale.
    ours.members["A"].epoch = 5
    pinned, _ = ours.reconcile(theirs, _ring(akey, bkey))
    assert pinned == 0, "un aval de una admision superada no vale"


def test_reconcile_from_a_foreign_cluster_is_a_total_refusal():
    """Even with a valid endorsement from a member we trust.

    Endorsements are scoped to a cluster. Cross-cluster trust would let one
    roster vouch for nodes in a cluster it has no standing in.
    """
    akey, bkey = _key("A"), _key("B")
    ours, _, _ = _found("c1", "A")
    bf = cert_fingerprint(bkey.public_key)
    theirs = Roster(cluster_id="OTHER", self_id="B", self_epoch=1)
    theirs.add(Admission(node_id="B", cert_fingerprint=bf, epoch=1,
                         endorsements=[Endorsement.sign(
                             endorser=akey, introduced_id="B",
                             cert_fingerprint=bf, cluster_id="OTHER",
                             introduced_epoch=1, endorser_epoch=1)]))
    pinned, rejected = ours.reconcile(theirs, _ring(akey, bkey))
    assert pinned == 0
    assert rejected == 1
    assert ours.member_ids() == ("A",)


# ---- attacks aimed at _permitted itself, which reconcile reaches indirectly
def test_permitted_requires_the_endorser_to_be_one_we_hold():
    """Direct unit test of the gate, not of reconcile's behaviour around it.

    Several of the guards inside ``_permitted`` were silently untested because
    reconcile always filtered them out earlier for unrelated reasons. Mutating
    them produced a green suite, which is worse than no test at all: it says
    the guard is covered when it is not.
    """
    akey, bkey = _key("A"), _key("B")
    ours, _, _ = _found("c1", "A")
    assert ours.is_member("A") is True
    assert ours.is_member("B") is False
    fp = cert_fingerprint(bkey.public_key)
    adm = Admission(node_id="B", cert_fingerprint=fp, epoch=1,
                    endorsements=[Endorsement.sign(
                        endorser=akey, introduced_id="B", cert_fingerprint=fp,
                        cluster_id="c1", introduced_epoch=1, endorser_epoch=1)])
    ring = {"A": akey.public_key, "B": bkey.public_key}
    incoming = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    incoming.add(adm)
    allowed = ours._permitted(adm, incoming, set(), ring, {"A"})
    assert allowed == {"A"}, "A es miembro nuestro y avala: se permite"
    assert ours._permitted(adm, incoming, set(), ring, {"A"}) is not None

    # Now with B not held: an endorsement B signs for someone else is useless.
    other = Admission(node_id="C", cert_fingerprint=fp, epoch=1,
                      endorsements=[Endorsement.sign(
                          endorser=bkey, introduced_id="C", cert_fingerprint=fp,
                          cluster_id="c1", introduced_epoch=1, endorser_epoch=1)])
    incoming.add(other)
    assert ours._permitted(other, incoming, set(), ring, {"A"}) is None, \
        "B no es miembro nuestro: su aval no autoriza a nadie"


def test_permitted_rejects_a_foreign_cluster_endorsement():
    akey, bkey = _key("A"), _key("B")
    ours, _, _ = _found("c1", "A")
    fp = cert_fingerprint(bkey.public_key)
    adm = Admission(node_id="B", cert_fingerprint=fp, epoch=1,
                    endorsements=[Endorsement.sign(
                        endorser=akey, introduced_id="B", cert_fingerprint=fp,
                        cluster_id="otro-cluster", introduced_epoch=1,
                        endorser_epoch=1)])
    incoming = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    incoming.add(adm)
    ring = {"A": akey.public_key, "B": bkey.public_key}
    assert ours._permitted(adm, incoming, set(), ring, {"A"}) is None


def test_accept_rejects_an_endorser_past_its_epoch():
    """The endorser-side epoch guard, tested where it actually lives.

    ``_permitted`` answers "may this endorser authorise at all"; ``_accept``
    answers "is this statement still current for the endorser we hold". The
    stale-epoch check is in the second, and a test against the first passes
    while the guard is dead.
    """
    akey, bkey = _key("A"), _key("B")
    ours, _, _ = _found("c1", "A")
    fp = cert_fingerprint(bkey.public_key)
    adm = Admission(node_id="B", cert_fingerprint=fp, epoch=1,
                    endorsements=[Endorsement.sign(
                        endorser=akey, introduced_id="B", cert_fingerprint=fp,
                        cluster_id="c1", introduced_epoch=1, endorser_epoch=1)])
    ring = {"A": akey.public_key, "B": bkey.public_key}
    # Fresh: A is at epoch 1 and speaks for epoch 1.
    fresh, _, _ = _found("c1", "A")
    assert fresh._accept(Admission.from_dict(adm.to_dict()), ring, {"A"}) is True
    # Stale: A has since been re-admitted at epoch 5.
    ours.members["A"].epoch = 5
    assert ours._accept(adm, ring, {"A"}) is False, \
        "un aval emitido bajo una admision superada no vale"
    assert ours.is_member("B") is False


def test_permitted_rejects_an_endorsement_about_another_cert():
    akey, bkey, other = _key("A"), _key("B"), _key("Y")
    ours, _, _ = _found("c1", "A")
    yfp = cert_fingerprint(other.public_key)
    adm = Admission(node_id="B", cert_fingerprint=yfp, epoch=1,
                    endorsements=[Endorsement.sign(
                        endorser=akey, introduced_id="B", cert_fingerprint=yfp,
                        cluster_id="c1", introduced_epoch=1, endorser_epoch=1)])
    # Corrupt the entry's cert after signing: the endorsement no longer
    # describes the thing it is attached to.
    adm.cert_fingerprint = cert_fingerprint(bkey.public_key)
    incoming = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    incoming.add(adm)
    ring = {"A": akey.public_key, "B": bkey.public_key,
            "Y": other.public_key}
    assert ours._permitted(adm, incoming, set(), ring, {"A"}) is None


def test_reconcile_stops_at_max_depth_even_with_a_rooted_chain():
    """The loop bound is observable through reconcile after all."""
    akey = _key("A")
    keys = {n: _key(n) for n in "BCDEFGH"}
    ring = _ring(akey, *keys.values())
    theirs = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    order = list(keys)
    for i, n in enumerate(order):
        fp = cert_fingerprint(keys[n].public_key)
        endorser = akey if i == 0 else keys[order[i - 1]]
        theirs.add(Admission(node_id=n, cert_fingerprint=fp, epoch=1,
                             endorsements=[Endorsement.sign(
                                 endorser=endorser, introduced_id=n,
                                 cert_fingerprint=fp, cluster_id="c1",
                                 introduced_epoch=1, endorser_epoch=1)]))
    ours, _, _ = _found("c1", "A")
    pinned, _ = ours.reconcile(theirs, ring, max_depth=0)
    assert pinned == 0, "max_depth=0 no hace ni una ronda"
    ours2, _, _ = _found("c1", "A")
    pinned2, _ = ours2.reconcile(Roster.from_dict(theirs.to_dict()), ring)
    assert pinned2 == len(keys)


def test_accept_rejects_a_stale_endorser_epoch_through_the_real_merge_path():
    """The same guard, reached the way an attacker would reach it.

    The direct ``_accept`` test covers the guard but not the wiring. Here A is
    re-admitted at a higher epoch by a legitimate merge, and only *then* B's
    stale endorsement is presented — so the guard has to fire inside
    ``reconcile``, not just when called by hand.
    """
    akey, bkey = _key("A"), _key("B")
    ours, _, _ = _found("c1", "A")
    bf = cert_fingerprint(bkey.public_key)
    ring = {"A": akey.public_key, "B": bkey.public_key}

    # B's endorsement exists and is cryptographically valid, but was made
    # while A was at epoch 1.
    theirs = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    theirs.add(Admission(node_id="B", cert_fingerprint=bf, epoch=1,
                         endorsements=[Endorsement.sign(
                             endorser=akey, introduced_id="B",
                             cert_fingerprint=bf, cluster_id="c1",
                             introduced_epoch=1, endorser_epoch=1)]))
    assert ours.reconcile(theirs, ring)[0] == 1
    assert ours.is_member("B") is True

    # Now A re-admits itself at epoch 4 (fresh signature, our own key).
    ours.members["A"].epoch = 4
    ours.members["B"].epoch = 1
    # B sends a *fresh* endorsement carrying its OLD endorser_epoch=1.
    stale = Roster(cluster_id="c1", self_id="B", self_epoch=2)
    stale.add(Admission(node_id="B", cert_fingerprint=bf, epoch=2,
                        endorsements=[Endorsement.sign(
                            endorser=akey, introduced_id="B",
                            cert_fingerprint=bf, cluster_id="c1",
                            introduced_epoch=2, endorser_epoch=1)]))
    pinned, _ = ours.reconcile(stale, ring)
    assert pinned == 0, \
        "B no puede renovarse avalando con el epoch que A ya no tiene"


def test_the_cluster_guard_is_covered_by_reconcile_not_permitted():
    """Pins *why* the per-endorsement cluster check exists separately.

    ``reconcile`` refuses a foreign roster outright, so the ``e.cluster_id``
    check inside ``_permitted`` is unreachable through the merge path. It is
    kept because ``_permitted`` is also callable on its own, but mutating it
    to ``pass`` cannot be caught from the outside — that is a real limit of
    this suite, recorded here rather than papered over with a fake test.
    """
    akey, bkey = _key("A"), _key("B")
    ours, _, _ = _found("c1", "A")
    bf = cert_fingerprint(bkey.public_key)
    theirs = Roster(cluster_id="c1", self_id="B", self_epoch=1)
    theirs.add(Admission(node_id="B", cert_fingerprint=bf, epoch=1,
                         endorsements=[Endorsement.sign(
                             endorser=akey, introduced_id="B",
                             cert_fingerprint=bf, cluster_id="otro",
                             introduced_epoch=1, endorser_epoch=1)]))
    pinned, rejected = ours.reconcile(theirs,
                                      {"A": akey.public_key,
                                       "B": bkey.public_key})
    assert pinned == 0
    assert rejected == 1
