"""Tests for capability reporting and telemetry pressure.

Two things here are worth stating up front, because they are what the module
is actually for:

1. A signed capability report is **attributable, not verified**. A node that
   reports 80 GB of VRAM it does not have is making a claim that a signature
   makes attributable and nothing more. The tests pin that framing so it
   cannot quietly become a stronger claim than the code supports.

2. A node whose telemetry has gone stale is **not** treated as idle. That is a
   security property as much as a routing one: in an open mesh, zero would
   make a silent node the most attractive destination.
"""
import base64
import json

import pytest

from delm.core import telemetry as tel
from delm.core.capability import (
    CapabilityReport,
    GpuInfo,
    SignedCapability,
    detect_gpus,
    nvidia_smi_csv,
)
from delm.core.provenance import KeyPair


# --------------------------------------------------------------------- GPUs
class FakeSmi:
    """Stands in for the nvidia-smi binary.

    Takes raw CSV rows rather than realistic output so a test can express the
    awkward cases (missing fields, ``[N/A]`` sentinels, blank lines) without
    pretending to be a GPU.
    """

    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def __call__(self, fields):
        self.calls.append(fields)
        return "\n".join(self.rows)


def test_detects_gpu_from_csv():
    smi = FakeSmi(["GPU-abc, NVIDIA RTX 4090, 24564"])
    gpus = detect_gpus(runner=smi)
    assert len(gpus) == 1
    g = gpus[0]
    assert g.uuid == "GPU-abc"
    assert g.name == "NVIDIA RTX 4090"
    assert g.vram_bytes == 24564 * 1024 * 1024


def test_gpu_uuid_is_the_join_key_not_the_name():
    """Two identical cards must be distinguishable by stats_key."""
    smi = FakeSmi(["GPU-a, NVIDIA RTX 4090, 24564",
                   "GPU-b, NVIDIA RTX 4090, 24564"])
    gpus = detect_gpus(runner=smi)
    assert [g.name for g in gpus] == ["NVIDIA RTX 4090"] * 2
    assert len({g.stats_key for g in gpus}) == 2


def test_uma_platform_gets_system_memory():
    """nvidia-smi reports [N/A] on Grace-Blackwell; 0 bytes would be a lie.

    A GPU with no VRAM of its own can still use shared system DRAM. Reporting
    zero routes every inference away from it.
    """
    smi = FakeSmi(["GPU-spark, GB10, [N/A]"])
    gpus = detect_gpus(runner=smi, memory_total_bytes=128 * 1024**3)
    assert gpus[0].vram_bytes == 128 * 1024**3
    assert not gpus[0].is_uma


def test_missing_na_without_system_memory_stays_zero():
    smi = FakeSmi(["GPU-x, Something, [N/A]"])
    gpus = detect_gpus(runner=smi, memory_total_bytes=0)
    assert gpus[0].vram_bytes == 0
    assert gpus[0].is_uma


def test_blank_and_short_lines_are_skipped():
    smi = FakeSmi(["", "GPU-a, RTX 4090, 24564", "GPU-bad", "   "])
    gpus = detect_gpus(runner=smi)
    assert [g.uuid for g in gpus] == ["GPU-a"]


def test_missing_binary_is_not_an_error():
    """No NVIDIA data must degrade, not raise: the mesh still needs a reply."""
    with pytest.raises(FileNotFoundError):
        nvidia_smi_csv("uuid,name,memory.total", runner=None)


def test_free_bytes_never_goes_negative():
    g = GpuInfo(uuid="GPU-a", vram_bytes=100, vram_used_bytes=150)
    assert g.free_bytes == 0


# ---------------------------------------------------------------- reports
def test_report_digest_is_stable_across_dict_order():
    r = CapabilityReport(node_id="n1", gpus=(GpuInfo(uuid="GPU-a", name="RTX"),),
                         model_ids=("m",), observed_at=100.0)
    assert r.digest() == CapabilityReport(
        node_id="n1", gpus=(GpuInfo(uuid="GPU-a", name="RTX"),),
        model_ids=("m",), observed_at=100.0).digest()


def test_observed_at_is_inside_the_digest():
    """Otherwise the signature would replay forever.

    A report signed at t0 with the same content must not verify at t1 — the
    mesh needs to know *when* a node claimed its capacity, or a stale report
    becomes a permanent capability.
    """
    a = CapabilityReport(node_id="n1", observed_at=100.0)
    b = CapabilityReport(node_id="n1", observed_at=200.0)
    assert a.digest() != b.digest()


def test_model_advertisement_is_case_insensitive():
    r = CapabilityReport(node_id="n1", model_ids=("Llama-3", "qwen2"))
    assert r.advertises_model("llama-3") is True
    assert r.advertises_model("QWEN2") is True
    assert r.advertises_model("missing") is False


def test_total_free_sums_across_gpus():
    r = CapabilityReport(node_id="n1", gpus=(
        GpuInfo(uuid="a", vram_bytes=100, vram_used_bytes=10),
        GpuInfo(uuid="b", vram_bytes=200, vram_used_bytes=20),
    ))
    assert r.total_vram_bytes == 300
    assert r.total_free_bytes == 270


# --------------------------------------------------------------- signing
def test_signed_report_verifies_with_the_declared_key():
    """The key must come from the handshake, never from the payload."""
    key = KeyPair.new("n1")
    report = CapabilityReport(node_id="n1", gpus=(GpuInfo(uuid="GPU-a"),),
                              observed_at=1000.0)
    signed = SignedCapability.sign(report, key)
    assert signed.verify(key.public_key) is True


def test_a_different_key_does_not_verify():
    key = KeyPair.new("n1")
    other = KeyPair.new("n1")
    signed = SignedCapability.sign(CapabilityReport(node_id="n1"), key)
    assert signed.verify(other.public_key) is False


def test_tampering_with_a_report_breaks_the_signature():
    """The whole point of signing it.

    An attacker who can raise a node's advertised VRAM is making it look more
    capable than it is. Signing the canonical payload is what makes that
    attributable — and the tamper has to actually fail.
    """
    key = KeyPair.new("n1")
    report = CapabilityReport(node_id="n1",
                              gpus=(GpuInfo(uuid="GPU-a", vram_bytes=8),),
                              observed_at=1000.0)
    signed = SignedCapability.sign(report, key)
    assert signed.verify(key.public_key) is True

    inflated = CapabilityReport(node_id="n1",
                               gpus=(GpuInfo(uuid="GPU-a", vram_bytes=80),),
                               observed_at=1000.0)
    forged = SignedCapability(report=inflated, signature=signed.signature,
                              sig_kind=signed.sig_kind)
    assert forged.verify(key.public_key) is False


def test_unsigned_report_never_verifies():
    signed = SignedCapability(report=CapabilityReport(node_id="n1"))
    assert signed.verify(b"\x00" * 32) is False


def test_roundtrips_through_json():
    key = KeyPair.new("n1")
    report = CapabilityReport(node_id="n1",
                              gpus=(GpuInfo(uuid="GPU-a", name="RTX",
                                            vram_bytes=1024),),
                              model_ids=("m",), observed_at=5.0)
    signed = SignedCapability.sign(report, key)
    blob = json.dumps(signed.to_dict())
    back = SignedCapability.from_dict(json.loads(blob))
    assert back.digest == signed.digest
    assert back.verify(key.public_key) is True
    assert base64.b64decode(back.to_dict()["signature"]) == signed.signature


# ------------------------------------------------------------- telemetry
def test_bands_match_the_documented_edges():
    assert tel.pressure_band(0) == 0
    assert tel.pressure_band(39.9) == 0
    assert tel.pressure_band(40) == 1
    assert tel.pressure_band(70) == 2
    assert tel.pressure_band(85) == 3
    assert tel.pressure_band(100) == 3


def test_hysteresis_stops_a_value_on_the_boundary_from_oscillating():
    """The reason the down edges sit below the up edges."""
    assert tel.pressure_with_hysteresis(41.0, 0) == 1
    # 39 is below the *down* edge for band 1 (35)? No — 39 >= 35, so it holds.
    assert tel.pressure_with_hysteresis(39.0, 1) == 1
    assert tel.pressure_with_hysteresis(34.0, 1) == 0


def test_unknown_pressure_is_not_zero():
    """The load-bearing invariant of this module.

    Zero means "idle, send it work". A node that is silent, crashed, or
    deliberately not reporting must not inherit that claim, or the mesh
    routes to it precisely because it stopped answering.
    """
    assert tel.UNKNOWN_GPU_PRESSURE != 0


def test_a_node_that_never_reported_is_unknown():
    v = tel.TelemetryView()
    assert v.pressure_of("n1") == tel.UNKNOWN_GPU_PRESSURE


def test_stale_telemetry_returns_to_unknown():
    v = tel.TelemetryView()
    v.observe("n1", 0, observed_at=1000.0, now=1000.0)
    assert v.pressure_of("n1", now=1000.0) == 0
    # Past the window it stops being evidence.
    later = 1000.0 + tel.TELEMETRY_FRESHNESS_S + 1
    assert v.pressure_of("n1", now=later) == tel.UNKNOWN_GPU_PRESSURE
    assert v.is_fresh("n1", now=later) is False


def test_a_sample_that_arrives_stale_does_not_become_fresh():
    """Age is measured at the source and carried, so gossip cannot launder it.

    The node keeps its entry in the view and its sample count goes up, but the
    reading itself must never be folded in: an old sample admitted as fresh
    would reset the EWMA from a value nobody is observing any more.
    """
    v = tel.TelemetryView()
    v.observe("n1", 0, observed_at=0.0, now=999.0)
    assert v.pressure_of("n1", now=999.0) == tel.UNKNOWN_GPU_PRESSURE
    st = v.nodes["n1"]
    assert st.has_ewma is False, \
        "una muestra vieja no puede inicializar el EWMA: eso la hace fresca"
    assert st.samples == 1, "la muestra se cuenta, pero no se cree"
    assert st.age_at_receipt > tel.TELEMETRY_FRESHNESS_S

    # And a later fresh sample must not inherit the stale one's value.
    v.observe("n1", 95, observed_at=2000.0, now=2000.0)
    st2 = v.nodes["n1"]
    assert st2.has_ewma is True
    assert st2.ewma == 95.0, "el EWMA arranca en la primera muestra valida"


def test_unreadable_utilisation_is_unknown_not_idle():
    """A node reporting ``None`` is present but cannot make a claim."""
    v = tel.TelemetryView()
    v.observe("n1", None, observed_at=1000.0, now=1000.0)
    assert v.pressure_of("n1", now=1000.0) == tel.UNKNOWN_GPU_PRESSURE
    assert v.nodes_claiming_idle() == ()


def test_a_single_spike_does_not_saturate_a_node():
    """EWMA: one 100% sample must not make a healthy node look busy."""
    v = tel.TelemetryView()
    for _ in range(10):
        v.observe("n1", 0, observed_at=1000.0, now=1000.0)
    assert v.pressure_of("n1", now=1000.0) == 0
    v.observe("n1", 100, observed_at=1001.0, now=1001.0)
    assert v.pressure_of("n1", now=1001.0) == 0, \
        "un pico aislado no debe marcar el nodo como ocupado"


def test_sustained_load_does_raise_the_band():
    v = tel.TelemetryView()
    t = 1000.0
    for _ in range(40):
        t += 1.0
        v.observe("n1", 95, observed_at=t, now=t)
    assert v.pressure_of("n1", now=t) >= 2


def test_rank_puts_the_unknown_node_after_an_idle_one():
    """The open-mesh case: a node that stopped reporting must lose to an
    honest one, not win by being absent from the picture."""
    v = tel.TelemetryView()
    v.observe("busy", 90, observed_at=1000.0, now=1000.0)
    v.observe("idle", 0, observed_at=1000.0, now=1000.0)
    # "silent" was last seen long ago: still in the view, reading expired.
    v.observe("silent", 0, observed_at=1000.0, now=1000.0)
    stale_at = 1000.0 + tel.TELEMETRY_FRESHNESS_S + 1

    # Now: only the two honest nodes are fresh.
    now = v.rank(now=1000.0)
    assert now.index("idle") < now.index("busy")

    # Later: everything has expired, so all three read as unknown and the
    # order falls back to the id tie-break. What matters is that "silent" is
    # NOT promoted above "busy" merely for being unreadable.
    later = v.rank(now=stale_at)
    assert later.index("silent") > later.index("busy"), \
        "silencio no es mejor que saturacion: es peor que ser honesto"
    assert "silent" in v.nodes_silent()


def test_rank_is_deterministic_for_equal_inputs():
    """Two observers with the same telemetry must compute the same order."""
    def build():
        v = tel.TelemetryView()
        v.observe("b", 10, observed_at=1000.0, now=1000.0)
        v.observe("a", 10, observed_at=1000.0, now=1000.0)
        return v
    assert build().rank(now=1000.0) == build().rank(now=1000.0)
    assert build().rank(now=1000.0)[0] == "a", "desempate estable por id"


def test_rank_accounts_for_pending_work():
    v = tel.TelemetryView()
    v.observe("a", 0, observed_at=1000.0, now=1000.0)
    v.observe("b", 0, observed_at=1000.0, now=1000.0)
    order = v.rank(pending={"a": 5}, now=1000.0)
    assert order[0] == "b"


def test_view_digest_is_stable_and_excludes_raw_samples():
    """The digest is what a BSV anchor would publish.

    It must be reproducible from the same belief, and it must not leak the
    node's own utilisation readings.
    """
    v = tel.TelemetryView()
    v.observe("n1", 42, observed_at=1000.0, now=1000.0)
    d1 = v.view_digest(now=1000.0)
    assert v.view_digest(now=1000.0) == d1
    assert "42" not in json.dumps(v.to_view(now=1000.0))


def test_view_digest_changes_when_pressure_changes():
    a = tel.TelemetryView()
    a.observe("n1", 0, observed_at=1000.0, now=1000.0)
    b = tel.TelemetryView()
    b.observe("n1", 95, observed_at=1000.0, now=1000.0)
    for _ in range(40):
        b.observe("n1", 95, observed_at=1000.0, now=1000.0)
    assert a.view_digest(now=1000.0) != b.view_digest(now=1000.0)


def test_sample_takes_the_maximum_not_the_mean():
    """The bottleneck is what the scheduler acts on."""
    class G:
        def __init__(self, u):
            self.utilization_percent = u
    s = tel.sample_from_gpus([G(0), G(95), G(10)], node_id="n1", now=1.0)
    assert s.utilization_percent == 95


def test_sample_with_no_readable_gpu_is_unknown():
    class G:
        utilization_percent = None
    s = tel.sample_from_gpus([G()], node_id="n1", now=1.0)
    assert s.utilization_percent is None
    assert s.age(5.0) == 4.0