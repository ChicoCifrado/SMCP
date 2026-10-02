"""What a node can actually do, and the signed proof that it says so.

NVIDIA PAIR reads GPU telemetry the obvious way: ``nvidia-smi --query-gpu``
and a few fields on the mDNS record. That is fine for a LAN where every node
is already on the same wire and implicitly trusted by virtue of being on it.

It is not enough for SMCP's open mesh, where any host can join and announce
whatever it likes. The difference is not the number of fields — it is that a
PAIR node *declares* its VRAM and a SMCP node has to *say* it with a key that
the admission gate already knows. A false capability report is then
attributable rather than anonymous.

What this module deliberately does **not** do, because it cannot:

* verify that the GPU exists (that needs an attestation authority, and until
  one exists a signed claim stays a signed claim);
* verify that the reported free VRAM is really free (that needs observation
  over time, which :mod:`delm.core.telemetry` provides for pressure, not for
  capacity).

So the honest framing is: **attributable, not verified.** A node that lies is
identifiable; a node that lies is not prevented. Pretending otherwise would
repeat the bug this project already fixed once — trusting an announcement
before verifying it.

The telemetry shape itself follows ``services/shared/noderec`` from PAIR:
four fields, nothing more, because more fields is more surface to lie about.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from delm.core.provenance import KeyPair, verify_public

#: Hard ceiling on one ``nvidia-smi`` call. The tool normally answers in well
#: under 100 ms, but on a wedged driver it can hang forever, and a node whose
#: capability probe hangs cannot answer the mesh either. Same reasoning as
#: PAIR's 3 s ceiling.
NVIDIA_SMI_TIMEOUT_S = 3.0

#: A GPU whose utilisation cannot be read is reported at the unknown band
#: rather than as idle. See :mod:`delm.core.telemetry` for why "unknown" is
#: deliberately not zero.
UNKNOWN_UTILIZATION: Optional[int] = None

CAPABILITY_KIND = "node.capability"


@dataclass(frozen=True)
class GpuInfo:
    """One GPU as the node itself describes it.

    ``uuid`` is the join key against the dynamic collector, exactly as PAIR
    uses it: ``name`` is marketing text and can repeat across identical
    cards, while the GPU UUID is stable across reboots and driver reloads.
    """

    uuid: str
    name: str = ""
    vram_bytes: int = 0
    vram_used_bytes: int = 0
    utilization_percent: Optional[int] = None

    @property
    def stats_key(self) -> str:
        """The key this GPU's dynamic samples are recorded under."""
        return self.uuid

    @property
    def is_uma(self) -> bool:
        """True when the GPU reports no VRAM of its own (shared system RAM)."""
        return self.vram_bytes == 0

    @property
    def free_bytes(self) -> int:
        if self.vram_bytes <= 0:
            return 0
        return max(0, self.vram_bytes - self.vram_used_bytes)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"uuid": self.uuid}
        if self.name:
            d["name"] = self.name
        if self.vram_bytes:
            d["vram_bytes"] = self.vram_bytes
        if self.vram_used_bytes:
            d["vram_used_bytes"] = self.vram_used_bytes
        if self.utilization_percent is not None:
            d["utilization_percent"] = self.utilization_percent
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GpuInfo":
        util = d.get("utilization_percent")
        return cls(
            uuid=str(d.get("uuid", "")),
            name=str(d.get("name", "")),
            vram_bytes=int(d.get("vram_bytes", 0) or 0),
            vram_used_bytes=int(d.get("vram_used_bytes", 0) or 0),
            utilization_percent=None if util is None else int(util),
        )


def _mb_to_bytes(mb: int) -> int:
    return mb * 1024 * 1024


def _is_na(value: str) -> bool:
    """Whether an nvidia-smi CSV field is a sentinel rather than a number.

    UMA platforms (Grace-Blackwell, DGX Spark) return ``[N/A]`` or
    ``[Not Supported]`` for memory queries because the GPU shares system DRAM.
    Treating that as ``0`` would report a capable GPU as having no memory at
    all, which routes every inference away from it.
    """
    v = value.strip().strip("[]").strip().lower()
    return v in {"n/a", "na", "not supported", "not available", "", "none"}


def _parse_int(value: str) -> Optional[int]:
    if _is_na(value):
        return None
    try:
        return int(float(value.strip()))
    except ValueError:
        return None


def nvidia_smi_csv(fields: str, *, timeout: float = NVIDIA_SMI_TIMEOUT_S,
                   runner: Any = None) -> str:
    """Run ``nvidia-smi --query-gpu=<fields> --format=csv,noheader,nounits``.

    ``runner`` is injectable so the detection path is testable without a GPU.
    A missing binary is not an error here — it means "no NVIDIA data", and the
    caller degrades to whatever fallback it has.
    """
    if runner is not None:
        return str(runner(fields))
    exe = shutil.which("nvidia-smi")
    if exe is None:
        raise FileNotFoundError("nvidia-smi no esta en el PATH")
    proc = subprocess.run(
        [exe, f"--query-gpu={fields}", "--format=csv,noheader,nounits"],
        capture_output=True, text=True, timeout=timeout, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"nvidia-smi devolvio {proc.returncode}: {proc.stderr.strip()[:200]}")
    return proc.stdout


def detect_gpus(*, runner: Any = None, memory_total_bytes: int = 0
                ) -> list[GpuInfo]:
    """Enumerate this node's NVIDIA GPUs, or return ``[]`` if there are none.

    Static pass (uuid, name, total VRAM) only. Utilization is sampled later by
    :mod:`delm.core.telemetry` because it changes; pinning it here would make
    every capability announcement stale the moment it was signed.
    """
    out = nvidia_smi_csv("uuid,name,memory.total", runner=runner)
    gpus: list[GpuInfo] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue
        gpu_uuid, name = parts[0], parts[1]
        if not gpu_uuid or _is_na(gpu_uuid):
            continue
        vram_mb = _parse_int(parts[2]) if len(parts) > 2 else None
        vram = 0 if vram_mb is None else _mb_to_bytes(vram_mb)
        # UMA: nvidia-smi says [N/A] and the GPU really can use system DRAM.
        if vram == 0 and memory_total_bytes > 0:
            vram = memory_total_bytes
        gpus.append(GpuInfo(uuid=gpu_uuid, name=name, vram_bytes=vram))
    return gpus


def detect_memory_total() -> int:
    """Total system RAM, used only to fill a UMA GPU's VRAM figure."""
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        return 0


@dataclass(frozen=True)
class CapabilityReport:
    """One node's self-described capacity, plus who said so.

    ``model_ids`` is the list of models this node claims to serve. PAIR gates
    routing on exactly this list and nothing else — which is a *gate over what
    the node declared*, not over what the node can do. Keeping the same field
    name makes the comparison honest: this is the same weak gate, only signed.
    """

    node_id: str
    gpus: tuple[GpuInfo, ...] = ()
    model_ids: tuple[str, ...] = ()
    backend: str = ""
    observed_at: float = 0.0

    # -- derived ------------------------------------------------------------
    @property
    def gpu_count(self) -> int:
        return len(self.gpus)

    @property
    def total_vram_bytes(self) -> int:
        return sum(g.vram_bytes for g in self.gpus)

    @property
    def total_free_bytes(self) -> int:
        return sum(g.free_bytes for g in self.gpus)

    @property
    def advertises(self) -> tuple[str, ...]:
        """Every model id this node claims, lowercased for comparison."""
        return tuple(sorted({m.strip().lower() for m in self.model_ids if m.strip()}))

    def advertises_model(self, model: str) -> bool:
        """Whether the node *claims* this model. A claim, not a capability."""
        wanted = model.strip().lower()
        return bool(wanted) and wanted in self.advertises

    def serves(self, min_free_bytes: int) -> bool:
        """Whether free VRAM alone is enough — still a self-report."""
        return self.total_free_bytes >= min_free_bytes

    # -- canonical form -----------------------------------------------------
    def payload(self) -> dict[str, Any]:
        """The canonical, signable content.

        ``observed_at`` is part of the payload on purpose: without it the
        signature would be replayable forever, which is the same class of bug
        as the one fixed in the mesh handshake.
        """
        return {
            "v": 1,
            "node_id": self.node_id,
            "backend": self.backend,
            "gpus": [g.to_dict() for g in self.gpus],
            "model_ids": list(self.advertises),
            "observed_at": round(self.observed_at, 3),
        }

    def digest(self) -> str:
        import hashlib

        blob = json.dumps(self.payload(), sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = self.payload()
        d["digest"] = self.digest()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CapabilityReport":
        return cls(
            node_id=str(d.get("node_id", "")),
            gpus=tuple(GpuInfo.from_dict(g) for g in d.get("gpus", [])),
            model_ids=tuple(d.get("model_ids", [])),
            backend=str(d.get("backend", "")),
            observed_at=float(d.get("observed_at", 0.0) or 0.0),
        )


@dataclass(frozen=True)
class SignedCapability:
    """A capability report with the node's signature over it.

    Carrying the signature rather than a bare report is what makes a false
    claim attributable. It does not make it false-proof, and the docstring on
    :mod:`delm.core.capability` says so out loud.
    """

    report: CapabilityReport
    signature: bytes = b""
    sig_kind: str = "ed25519"

    @property
    def node_id(self) -> str:
        return self.report.node_id

    @property
    def digest(self) -> str:
        return self.report.digest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "report": self.report.to_dict(),
            "sig_kind": self.sig_kind,
            "signature": base64.b64encode(self.signature).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SignedCapability":
        report = CapabilityReport.from_dict(d.get("report", {}))
        sig = base64.b64decode(d.get("signature", "") or "")
        return cls(report=report, signature=sig,
                   sig_kind=str(d.get("sig_kind", "ed25519")))

    def verify(self, public_key: bytes) -> bool:
        """Check the signature against a key the admission gate already knows.

        The key must come from :meth:`SecureSharedContext.register_key` — one
        that was declared in a handshake, never one that rode in with the
        report. A signature verified against a key the payload itself carried
        would prove nothing at all.
        """
        if not self.signature:
            return False
        return verify_public(self.sig_kind, public_key, self.digest,
                             self.signature)

    @classmethod
    def sign(cls, report: CapabilityReport, key: KeyPair) -> "SignedCapability":
        """Sign the report's canonical digest, the same way gists are signed."""
        return cls(report=report, signature=key.sign(report.digest()),
                   sig_kind=key.kind)


def local_report(node_id: str, model_ids: Sequence[str] = (),
                 *, backend: str = "", now: float | None = None,
                 runner: Any = None) -> CapabilityReport:
    """Build this node's report by probing its own hardware."""
    gpus = detect_gpus(runner=runner, memory_total_bytes=detect_memory_total())
    return CapabilityReport(
        node_id=node_id,
        gpus=tuple(gpus),
        model_ids=tuple(model_ids),
        backend=backend,
        observed_at=time.time() if now is None else now,
    )