"""Tests de ``delm.core.requirements`` — requisitos inmutables y admisión.

Cubre:
* ``MeshRequirements`` — inmutabilidad y hash de política.
* ``ReleaseAttestation`` — verificación de provenance (provenance de build).
* ``AdmissionEvaluator`` — gates de versión, generación y atestación.
"""
from __future__ import annotations

import pytest

from delm.core.requirements import (
    AdmissionEvaluator,
    MeshRequirements,
    ReleaseAttestation,
    RejectReason,
)


# ---------------------------------------------------------------------------
# MeshRequirements — inmutabilidad y hash
# ---------------------------------------------------------------------------
def test_requirements_immutable():
    req = MeshRequirements(mesh_id="m1", version_floor=(1, 0),
                           protocol_generation=2)
    with pytest.raises(Exception):
        req.version_floor = (2, 0)  # type: ignore[misc]


def test_policy_hash_stable():
    a = MeshRequirements(mesh_id="m1", version_floor=(1, 0),
                         protocol_generation=2,
                         release_signer_keys=("k1",))
    b = MeshRequirements(mesh_id="m1", version_floor=(1, 0),
                         protocol_generation=2,
                         release_signer_keys=("k1",))
    assert a.policy_hash() == b.policy_hash()


def test_policy_hash_differs_on_change():
    a = MeshRequirements(mesh_id="m1", version_floor=(1, 0),
                         protocol_generation=2)
    b = MeshRequirements(mesh_id="m1", version_floor=(1, 1),
                         protocol_generation=2)
    assert a.policy_hash() != b.policy_hash()


# ---------------------------------------------------------------------------
# ReleaseAttestation — provenance de build
# ---------------------------------------------------------------------------
def _attested(attested_digest: bytes, digest: str, signer: str) -> ReleaseAttestation:
    """Construye una atestación cuyo blob contiene el digest atestado."""
    return ReleaseAttestation(
        signer_key=signer,
        binary_digest=digest,
        signed_blobs=(attested_digest,),
    )


def test_attestation_ok():
    digest = "deadbeef"
    att = ReleaseAttestation(
        signer_key="k1", binary_digest=digest,
        signed_blobs=(b"deadbeef",),  # blob contiene el digest atestado
    )
    ok, reason = att.verify(trusted_signers=("k1",))
    assert ok is True
    assert reason == RejectReason.OK


def test_attestation_untrusted_signer():
    att = ReleaseAttestation(
        signer_key="k-evil", binary_digest="d", signed_blobs=(b"d",),
    )
    ok, reason = att.verify(trusted_signers=("k1",))
    assert ok is False
    assert reason == RejectReason.RELEASE_SIGNER_UNTRUSTED


def test_attestation_no_blobs():
    att = ReleaseAttestation(signer_key="k1", binary_digest="d",
                            signed_blobs=())
    ok, reason = att.verify(trusted_signers=("k1",))
    assert ok is False
    assert reason == RejectReason.BUILD_PROOF_INVALID


# ---------------------------------------------------------------------------
# AdmissionEvaluator — gates
# ---------------------------------------------------------------------------
def _req(mesh_id: str = "m1",
         version_floor: tuple[int, int] = (1, 0),
         protocol_generation: int = 1,
         require_release_attestation: bool = False,
         release_signer_keys: tuple[str, ...] = ()) -> MeshRequirements:
    return MeshRequirements(
        mesh_id=mesh_id,
        version_floor=version_floor,
        protocol_generation=protocol_generation,
        require_release_attestation=require_release_attestation,
        release_signer_keys=release_signer_keys,
    )


def test_admit_ok():
    ev = AdmissionEvaluator(_req())
    d = ev.evaluate(version=(1, 0), protocol_generation=1)
    assert d.admitted is True
    assert d.reason == RejectReason.OK


def test_reject_version_below_floor():
    ev = AdmissionEvaluator(_req(version_floor=(1, 0)))
    d = ev.evaluate(version=(0, 9), protocol_generation=1)
    assert d.admitted is False
    assert d.reason == RejectReason.VERSION_BELOW_FLOOR


def test_reject_generation_mismatch():
    ev = AdmissionEvaluator(_req(protocol_generation=2))
    d = ev.evaluate(version=(1, 0), protocol_generation=1)
    assert d.admitted is False
    assert d.reason == RejectReason.GENERATION_MISMATCH


def test_reject_certified_required():
    ev = AdmissionEvaluator(_req(require_release_attestation=True,
                                 release_signer_keys=("k1",)))
    d = ev.evaluate(version=(1, 0), protocol_generation=1, attestation=None)
    assert d.admitted is False
    assert d.reason == RejectReason.CERTIFIED_BINARY_REQUIRED


def test_admit_with_valid_attestation():
    ev = AdmissionEvaluator(_req(require_release_attestation=True,
                                 release_signer_keys=("k1",)))
    att = ReleaseAttestation(signer_key="k1", binary_digest="d",
                            signed_blobs=(b"d",))
    d = ev.evaluate(version=(1, 0), protocol_generation=1, attestation=att)
    assert d.admitted is True
    assert d.reason == RejectReason.OK


def test_reject_invalid_attestation():
    ev = AdmissionEvaluator(_req(require_release_attestation=True,
                                 release_signer_keys=("k1",)))
    att = ReleaseAttestation(signer_key="k-evil", binary_digest="d",
                            signed_blobs=(b"d",))
    d = ev.evaluate(version=(1, 0), protocol_generation=1, attestation=att)
    assert d.admitted is False
    assert d.reason == RejectReason.RELEASE_SIGNER_UNTRUSTED
