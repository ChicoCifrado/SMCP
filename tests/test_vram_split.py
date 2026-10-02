"""Three VRAM numbers: what the hardware has, what the owner offers, what the
mesh is using.

Before this, one field did three incompatible jobs. A node's physical maximum
was also its offer to the mesh and also what placement planned against, so
inflating the claim bought more routing *and* proportionally more credit
(``credits_per_gib_hour`` scaled by the same number). The tests below pin the
separation. They are mostly hostile: the interesting cases are the ones where
a node lies about itself, because that is what the split has to survive.
"""

from __future__ import annotations

import time
from dataclasses import replace
from typing import Any

import pytest

from delm.core import contrib as C
from delm.core.contrib import (
    CapacityReport,
    ContribReject,
    ContributionLedger,
    ExchangePolicy,
    PeerContribution,
    capacity_claim_status,
    capacity_is_intact,
)


def _key(tmp_path, peer_id="local"):
    from delm.core.provenance import KeyPair

    return KeyPair.new(peer_id, kind="ed25519")


def _admit(led, key, now, *, peer_id="local", mesh_id="smcp-local",
           vram=16.0, advertised=None, shared=0.0, ram=0.0, cores=0,
           backend="cuda", nonce=None):
    """Build, sign and admit one report. Returns (accepted, reason, report)."""
    ch = led.issue_challenge(peer_id, now=now, ttl_s=60.0)
    rep = CapacityReport(
        mesh_id=mesh_id, peer_id=peer_id,
        vram_gb=vram,
        vram_advertised_gb=(vram if advertised is None else advertised),
        vram_shared_gb=shared,
        ram_gb=ram, cpu_cores=cores, backend=backend,
        nonce=nonce or ch.nonce, issued_at=now, expires_at=now + 600.0,
    ).sign(key)
    ok, reason = led.admit(rep, now=now)
    return ok, reason, rep


# ------------------------------------------------------------------ the three
def test_physical_advertised_and_shared_are_three_separate_numbers():
    p = PeerContribution(peer_id="n", vram_gb=16.0, vram_advertised_gb=4.0,
                         vram_shared_gb=1.5)
    assert p.vram_gb == 16.0          # what the hardware has
    assert p.vram_advertised_gb == 4.0  # what the owner offers
    assert p.vram_shared_gb == 1.5    # what the mesh is using
    assert p.vram_available_gb == 2.5  # what routing may plan


def test_available_is_advertised_minus_used():
    p = PeerContribution(peer_id="n", vram_gb=24.0, vram_advertised_gb=8.0,
                         vram_shared_gb=3.0)
    assert p.vram_available_gb == 5.0


def test_available_ignores_the_physical_headline():
    """The whole point: planning against 24 GiB that were never offered is how
    a plan gets admitted and then fails at run time.
    """
    p = PeerContribution(peer_id="n", vram_gb=24.0, vram_advertised_gb=2.0)
    assert p.vram_available_gb == 2.0
    assert p.vram_available_gb < p.vram_gb


def test_available_is_floored_at_zero_not_negative():
    p = PeerContribution(peer_id="n", vram_gb=8.0, vram_advertised_gb=4.0,
                         vram_shared_gb=9.0)
    assert p.vram_available_gb == 0.0


def test_available_clamps_an_offer_above_the_physical_claim():
    p = PeerContribution(peer_id="n", vram_gb=16.0, vram_advertised_gb=80.0)
    assert p.vram_available_gb == 16.0


def test_shared_gb_above_advertised_yields_zero_not_a_negative():
    p = PeerContribution(peer_id="n", vram_gb=16.0, vram_advertised_gb=4.0,
                         vram_shared_gb=11.0)
    assert p.vram_available_gb == 0.0


# ------------------------------------------------------- signing, and what is
def test_advertised_is_signed_and_anchored():
    led = ContributionLedger()
    key = _key(None)
    now = time.time()
    _admit(led, key, now, vram=16.0, advertised=6.0)
    peer = led.peers["local"]
    assert peer.vram_advertised_gb == 6.0
    assert capacity_is_intact(peer, led.mesh_id) is True


def test_rewriting_the_offer_after_admission_is_detectable():
    led = ContributionLedger()
    key = _key(None)
    now = time.time()
    _admit(led, key, now, vram=16.0, advertised=6.0)
    peer = led.peers["local"]
    peer.vram_advertised_gb = 16.0
    assert capacity_is_intact(peer, led.mesh_id) is False


def test_rewriting_the_physical_number_is_detectable():
    led = ContributionLedger()
    key = _key(None)
    now = time.time()
    _admit(led, key, now, vram=16.0, advertised=16.0)
    peer = led.peers["local"]
    peer.vram_gb = 80.0
    assert capacity_is_intact(peer, led.mesh_id) is False


def test_shared_gb_is_not_in_the_signed_capacity_digest():
    """Telemetry is allowed to move. Capacity is not.

    ``vram_shared_gb`` changes every heartbeat, so anchoring it to a signature
    taken at admission would mark every honest peer as tampered-with within a
    minute. It must not be in ``capacity_digest`` — and a test that only checked
    round-tripping would miss that, because both fields round-trip fine.
    """
    kwargs: dict[str, Any] = {"mesh_id": "m", "peer_id": "p", "vram_gb": 16.0,
                              "vram_advertised_gb": 8.0, "ram_gb": 0.0,
                              "cpu_cores": 0, "backend": "cuda"}
    d0 = CapacityReport.capacity_digest(**kwargs)
    d1 = CapacityReport.capacity_digest(**kwargs)
    assert d0 == d1
    # The digest function has no shared parameter at all, which is the point.
    import inspect

    params = set(inspect.signature(CapacityReport.capacity_digest).parameters)
    assert "vram_shared_gb" not in params
    assert "vram_advertised_gb" in params


def test_a_changed_shared_gb_does_not_break_the_integrity_check():
    led = ContributionLedger()
    key = _key(None)
    now = time.time()
    _admit(led, key, now, vram=16.0, advertised=8.0, shared=1.0)
    peer = led.peers["local"]
    assert capacity_is_intact(peer, led.mesh_id) is True
    peer.vram_shared_gb = 7.0
    assert capacity_is_intact(peer, led.mesh_id) is True


def test_the_report_signature_covers_the_offer():
    key = _key(None)
    now = time.time()
    rep = CapacityReport(mesh_id="m", peer_id="p", vram_gb=16.0,
                         vram_advertised_gb=8.0, nonce="n", issued_at=now,
                         expires_at=now + 60.0).sign(key)
    assert rep.verify() is True
    forged = CapacityReport(mesh_id="m", peer_id="p", vram_gb=16.0,
                            vram_advertised_gb=16.0, nonce="n", issued_at=now,
                            expires_at=now + 60.0)
    # Same digest and signature as the honest report, but the offer changed.
    # CapacityReport is frozen, so this has to be a replacement — which is also
    # exactly what an attacker with a signing oracle-free payload would face.
    forged = replace(forged, digest=rep.digest, signature=rep.signature,
                     sig_kind=rep.sig_kind, public_key=rep.public_key)
    assert forged.verify() is False


def test_shared_gb_survives_a_dict_round_trip():
    rep = CapacityReport(mesh_id="m", peer_id="p", vram_gb=16.0,
                         vram_advertised_gb=8.0, vram_shared_gb=2.5)
    back = CapacityReport.from_dict(rep.to_dict())
    assert back.vram_shared_gb == 2.5
    assert back.vram_advertised_gb == 8.0


# -------------------------------------------------------------- fail-closed
def test_offering_more_than_the_node_has_is_refused():
    led = ContributionLedger()
    key = _key(None)
    now = time.time()
    ok, reason, _ = _admit(led, key, now, vram=16.0, advertised=80.0)
    assert ok is False
    assert reason == ContribReject.CAPACITY_OVERSTATED.value


def test_the_refusal_keeps_the_offer_out_of_the_ledger():
    led = ContributionLedger()
    key = _key(None)
    now = time.time()
    _admit(led, key, now, vram=16.0, advertised=80.0)
    peer = led.peers["local"]
    assert peer.vram_advertised_gb == 0.0
    assert peer.vram_available_gb == 0.0


def test_the_refusal_is_recorded_in_the_chain():
    """A refusal that leaves no trace cannot be audited, and the point of
    fail-closed is that the attempt is countable.
    """
    led = ContributionLedger()
    key = _key(None)
    now = time.time()
    _admit(led, key, now, vram=16.0, advertised=80.0)
    assert len(led) == 1
    rec = led.records[-1]
    assert rec.accepted is False
    assert rec.reason == ContribReject.CAPACITY_OVERSTATED.value
    assert led.peers["local"].rejections == 1


def test_offering_exactly_the_physical_maximum_is_allowed():
    led = ContributionLedger()
    key = _key(None)
    now = time.time()
    ok, reason, _ = _admit(led, key, now, vram=16.0, advertised=16.0)
    assert ok is True, reason
    assert led.peers["local"].vram_advertised_gb == 16.0


def test_offering_a_share_is_allowed():
    led = ContributionLedger()
    key = _key(None)
    now = time.time()
    ok, _, _ = _admit(led, key, now, vram=16.0, advertised=1.0)
    assert ok is True
    assert led.peers["local"].vram_available_gb == 1.0


# ---------------------------------------------------------------- economics
def test_credit_follows_the_offer_not_the_hardware():
    """The inflation fix, stated as an economic assertion.

    A node with a 24 GiB card offering 4 GiB earns for 4 GiB. Paying the 24
    would mean the mesh pays for hardware it was never allowed to use.
    """
    pol = ExchangePolicy(credits_per_gib_hour=1.0)
    big_offer = PeerContribution(peer_id="a", vram_gb=24.0,
                                 vram_advertised_gb=4.0)
    small_offer = PeerContribution(peer_id="b", vram_gb=24.0,
                                   vram_advertised_gb=24.0)
    c1 = pol.accrual(big_offer, 3600.0)
    c2 = pol.accrual(small_offer, 3600.0)
    assert c1 == pytest.approx(4.0)
    assert c2 == pytest.approx(24.0)
    assert c1 < c2


def test_a_node_that_offers_nothing_earns_nothing():
    pol = ExchangePolicy()
    p = PeerContribution(peer_id="a", vram_gb=24.0, vram_advertised_gb=0.0)
    assert pol.accrual(p, 3600.0) == 0.0


def test_halving_the_offer_halves_the_credit():
    pol = ExchangePolicy(credits_per_gib_hour=1.0)
    full = PeerContribution(peer_id="a", vram_gb=8.0, vram_advertised_gb=8.0)
    half = PeerContribution(peer_id="b", vram_gb=8.0, vram_advertised_gb=4.0)
    assert pol.accrual(half, 7200.0) == pytest.approx(pol.accrual(full, 3600.0))


# ------------------------------------------------------------------- totals
def _two_peers(led, now):
    ka, kb = _key(None, "a"), _key(None, "b")
    _admit(led, ka, now, peer_id="a", vram=16.0, advertised=4.0, shared=1.0)
    _admit(led, kb, now, peer_id="b", vram=8.0, advertised=8.0, shared=2.0)


def test_the_three_totals_are_reported_separately():
    led = ContributionLedger()
    now = time.time()
    _two_peers(led, now)
    assert led.total_vram_gb(observed_only=False) == 24.0
    assert led.total_advertised_gb(observed_only=False) == 12.0
    assert led.total_shared_gb(observed_only=False) == 3.0


def test_the_gap_between_physical_and_offered_is_visible():
    """12 GiB of hardware the owners are deliberately not sharing — a number
    the mesh could not see before this split.
    """
    led = ContributionLedger()
    now = time.time()
    _two_peers(led, now)
    assert led.total_vram_gb(observed_only=False) - \
        led.total_advertised_gb(observed_only=False) == 12.0


# ------------------------------------------------------- detection cross-check
def test_claim_matching_detection_agrees():
    p = PeerContribution(peer_id="n", vram_gb=16.0, vram_advertised_gb=8.0)
    assert capacity_claim_status(p, detected_vram_gb=16.0) == "agree"


def test_claim_above_detection_is_flagged():
    p = PeerContribution(peer_id="n", vram_gb=80.0, vram_advertised_gb=8.0)
    assert capacity_claim_status(p, detected_vram_gb=16.0) == \
        "claim_exceeds_detected"


def test_no_detection_is_unknown():
    p = PeerContribution(peer_id="n", vram_gb=16.0, vram_advertised_gb=8.0)
    assert capacity_claim_status(p, detected_vram_gb=None) == "unknown"
    assert capacity_claim_status(p, detected_vram_gb=0.0) == "unknown"


def test_detection_without_a_claim_is_reported_as_such():
    p = PeerContribution(peer_id="n")
    assert capacity_claim_status(p, detected_vram_gb=16.0) == "detected_only"


def test_rounding_noise_between_smi_and_sysfs_is_tolerated():
    p = PeerContribution(peer_id="n", vram_gb=16.0, vram_advertised_gb=8.0)
    assert capacity_claim_status(p, detected_vram_gb=15.98) == "agree"


def test_the_flag_does_not_correct_the_claim():
    """Detection and claim come from the same host over the same channel, so
    neither is evidence. The cross-check reports disagreement and leaves the
    signed number standing — otherwise a detection hiccup would let an
    unauthenticated channel eject a real, identified node.
    """
    p = PeerContribution(peer_id="n", vram_gb=80.0, vram_advertised_gb=8.0)
    assert capacity_claim_status(p, detected_vram_gb=16.0) == \
        "claim_exceeds_detected"
    assert p.vram_gb == 80.0
    assert p.vram_available_gb == 8.0


# -------------------------------------------------------------- persistence
def test_the_ledger_survives_a_json_round_trip():
    led = ContributionLedger()
    now = time.time()
    _two_peers(led, now)
    blob = led.to_dict()
    back = ContributionLedger.from_dict(blob)
    assert back.peers["a"].vram_advertised_gb == 4.0
    assert back.peers["a"].vram_shared_gb == 1.0
    assert back.peers["b"].vram_advertised_gb == 8.0
    assert back.total_advertised_gb(observed_only=False) == 12.0


def test_integrity_survives_a_json_round_trip():
    led = ContributionLedger()
    now = time.time()
    _two_peers(led, now)
    back = ContributionLedger.from_dict(led.to_dict())
    assert capacity_is_intact(back.peers["a"], back.mesh_id) is True
    back.peers["a"].vram_advertised_gb = 16.0
    assert capacity_is_intact(back.peers["a"], back.mesh_id) is False


def test_legacy_state_without_the_new_fields_loads_as_zero_offer():
    """Honest about what an old ledger means.

    A ledger written before the split has ``vram_gb`` and nothing else. Reading
    it as *offer* = physical would silently grant the old behaviour back, and
    reading it as 0 would quietly eject every peer on upgrade. Reporting 0 for
    the offer and keeping the physical number is the safe reading: the peer is
    known, has hardware, and is offering nothing until it re-reports.
    """
    legacy = {"mesh_id": "smcp-local",
              "peers": [{"peer_id": "local", "vram_gb": 16.0}],
              "records": [], "challenges": [], "used_nonces": []}
    back = ContributionLedger.from_dict(legacy)
    peer = back.peers["local"]
    assert peer.vram_gb == 16.0
    assert peer.vram_advertised_gb == 0.0
    assert peer.vram_available_gb == 0.0


# ------------------------- holes found by mutation, closed after the fact
def test_a_15_percent_overstatement_is_still_refused():
    """Mutation survivor, and it is a real gap.

    Loosening the check to ``advertised > vram * 1.5`` left the suite green.
    Nothing asserted that an offer is refused at *any* margin above the
    physical figure, only that 80-on-16 is refused. The rule has no tolerance
    band at all, so a test now pins an offer that is barely over.
    """
    led = ContributionLedger()
    key = _key(None)
    now = time.time()
    ok, reason, _ = _admit(led, key, now, vram=16.0, advertised=16.5)
    assert ok is False
    assert reason == ContribReject.CAPACITY_OVERSTATED.value


def test_an_overstatement_by_one_hundredth_is_refused():
    led = ContributionLedger()
    key = _key(None)
    now = time.time()
    ok, reason, _ = _admit(led, key, now, vram=16.0, advertised=16.01)
    assert ok is False, "la regla no admite margen"
    assert reason == ContribReject.CAPACITY_OVERSTATED.value


def test_telemetry_never_enters_the_signed_report_payload():
    """Mutation survivor: putting ``vram_shared_gb`` into ``payload()`` left
    the suite green.

    It still verifies, because both sides would sign the same extra field — the
    mutation is invisible to any signature test. It is caught only by checking
    the *set of signed fields* directly, which is the property that matters:
    a per-heartbeat number must not be part of a signature taken once.
    """
    rep = CapacityReport(mesh_id="m", peer_id="p", vram_gb=16.0,
                         vram_advertised_gb=8.0, vram_shared_gb=3.0)
    assert "vram_shared_gb" not in rep.payload()
    # The counterfactual: if it were there, this field's value would change the
    # digest, which is exactly what must not be true of telemetry.
    d_with = CapacityReport(mesh_id="m", peer_id="p", vram_gb=16.0,
                            vram_advertised_gb=8.0, vram_shared_gb=3.0)
    d_without = CapacityReport(mesh_id="m", peer_id="p", vram_gb=16.0,
                               vram_advertised_gb=8.0, vram_shared_gb=0.0)
    assert d_with.compute_digest() == d_without.compute_digest(), \
        "la telemetría no debe mover el digest firmado"


def test_the_shared_total_still_respects_observed_only():
    """Mutation survivor: summing ``self.peers`` instead of the filtered view.

    A dead peer still counts toward the mesh-wide usage figure, so a plan sees
    capacity in use that nobody is using.
    """
    led = ContributionLedger()
    key = _key(None)
    now = time.time()
    _admit(led, key, now, vram=16.0, advertised=8.0, shared=4.0)
    led.observe("local", now, dt_s=0.0)
    assert led.total_shared_gb(observed_only=True) == 4.0
    assert led.peers["local"].alive is True
    # Retire it and the observed-only total must drop to zero.
    led.peers["local"].last_seen = 0.0
    assert led.total_shared_gb(observed_only=True) == 0.0
    assert led.total_shared_gb(observed_only=False) == 4.0


def test_planning_never_uses_the_physical_headline():
    """Mutation survivor in ``placement``: routing against ``vram_gb``.

    The stage-level view proved the split exists, but nothing asserted the
    *plan* honours it. A node offering 2 of 24 must not receive a 20 GiB
    slice, so the oversized stage must be impossible.
    """
    from delm.core.placement import ModelSpec, Stage, plan_placement

    led = ContributionLedger()
    key = _key(None)
    now = time.time()
    _admit(led, key, now, vram=24.0, advertised=2.0)
    led.observe("local", now, dt_s=3600.0)

    spec = ModelSpec(name="grande", memory_required_gb=20.0)
    plan = plan_placement(spec, led, policy=ExchangePolicy(), reserve_gb=0.0)
    if plan.ok and plan.stages:
        for stage in plan.stages:
            assert stage.memory_gb <= stage.peer_vram_available_gb + 1e-9, \
                "una rebanada no puede superar lo disponible"
            assert stage.memory_gb <= stage.peer_advertised_gb + 1e-9
    else:
        # Not planning at all is also acceptable: the whole point is that the
        # headline figure cannot buy routing the node never offered.
        assert plan.ok is False
    assert Stage(peer_id="x", memory_gb=1.0, peer_vram_gb=24.0,
                 peer_advertised_gb=2.0).peer_vram_available_gb == 2.0
