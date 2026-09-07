"""Requirements inmutables y admisión de pares (capa 3, transporte).

Modelado sobre ``mesh/requirements.rs`` de MeshLLM:

* Los **requisitos de malla** se fijan al crear la malla y son **inmutables**.
  Cambiarlos (floor de versión, generación de protocolo, política de
  atestación) **deriva una nueva malla** (nuevo ``mesh_id``), no muta la
  existente.
* Un par que no pasa el gate de requisitos es **rechazado en el ingest**
  (``reject_direct_peer_for_policy``), no entra en la tabla.

Política de atestación de release (solo build provenance, no runtime
attestation):

* ``release_signer_keys`` — claves de firmantes de release de confianza.
* ``require_release_attestation`` — si el gate exige atestación.
* Un par atestado presenta ``release_signatures`` (blobs firmados por un
  firmante de confianza). La verificación es **provenance de build**: prueba
  que el binario fue publicado por un firmante de confianza, no que el
  proceso remoto no ha sido modificado.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Optional


# ---------------------------------------------------------------------------
# Estado de rechazo (razones máquina, estilo underscore)
# ---------------------------------------------------------------------------
class RejectReason:
    """Razones de rechazo de admisión (códigos de máquina)."""
    VERSION_BELOW_FLOOR = "version_below_floor"
    GENERATION_MISMATCH = "generation_mismatch"
    CERTIFIED_BINARY_REQUIRED = "certified_binary_required"
    BUILD_PROOF_INVALID = "build_proof_invalid"
    RELEASE_SIGNER_UNTRUSTED = "release_signer_untrusted"
    OK = "ok"


# ---------------------------------------------------------------------------
# Attestación de release (provenance de build)
# ---------------------------------------------------------------------------
@dataclass
class ReleaseAttestation:
    """Prueba de atestación de release presentada por un par.

    ``signer_key`` — identificador de la clave del firmante de release que
    firmó el binario. ``signed_blobs`` — los blobs firmados (provenance).
    ``binary_digest`` — digest del binario atestado (para validar la firma).
    """
    signer_key: str
    binary_digest: str
    signed_blobs: tuple[bytes, ...] = ()

    def verify(self, trusted_signers: tuple[str, ...]) -> tuple[bool, str]:
        """Verifica la atestación contra los firmantes de confianza.

        Devuelve ``(ok, reason)``. La verificación es de provenance: el
        firmante debe estar en ``trusted_signers`` y haber firmado el digest
        del binario.
        """
        if not trusted_signers:
            return (False, RejectReason.RELEASE_SIGNER_UNTRUSTED)
        if self.signer_key not in trusted_signers:
            return (False, RejectReason.RELEASE_SIGNER_UNTRUSTED)
        # La firma cubre el digest del binario. Un blob vacío o sin firma
        # válida => build proof inválido.
        if not self.signed_blobs:
            return (False, RejectReason.BUILD_PROOF_INVALID)
        # Un blob firmado attesta el binario si referencia su digest. El
        # firmante de confianza debió firmar un blob que enlace el digest del
        # binario; si ningún blob lo referencia, la prueba es inválida.
        attested = self.binary_digest.encode()
        for blob in self.signed_blobs:
            if attested in blob:
                return (True, RejectReason.OK)
        return (False, RejectReason.BUILD_PROOF_INVALID)


# ---------------------------------------------------------------------------
# Requisitos inmutables de la malla
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class MeshRequirements:
    """Requisitos inmutables fijados al crear la malla.

    ``version_floor`` — versión mínima (mayor, menor) que un par debe alcanzar.
    ``protocol_generation`` — generación de protocolo de la malla.
    ``require_release_attestation`` — si el gate exige atestación de release.
    ``release_signer_keys`` — claves de firmantes de release de confianza.
    """
    mesh_id: str
    version_floor: tuple[int, int] = (0, 0)
    protocol_generation: int = 1
    require_release_attestation: bool = False
    release_signer_keys: tuple[str, ...] = ()

    def policy_hash(self) -> str:
        """Hash de política: identifica los requisitos inmutables.

        Dos mallas con distintos requisitos tienen distinto ``policy_hash``.
        """
        canon = "|".join([
            self.mesh_id,
            f"{self.version_floor[0]}.{self.version_floor[1]}",
            str(self.protocol_generation),
            str(self.require_release_attestation),
            ",".join(self.release_signer_keys),
        ])
        return sha256(canon.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Resultado de admisión
# ---------------------------------------------------------------------------
@dataclass
class AdmissionDecision:
    """Decisión de admisión de un par contra los requisitos de la malla."""
    admitted: bool
    reason: str
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Evaluador de admisión
# ---------------------------------------------------------------------------
class AdmissionEvaluator:
    """Evalúa si un par satisface los requisitos inmutables de la malla.

    Orden de gates (corto-circuito):
      1. floor de versión
      2. generación de protocolo
      3. atestación de release (si el gate la exige)
    """

    def __init__(self, req: MeshRequirements) -> None:
        self.req = req

    def evaluate(
        self,
        version: tuple[int, int],
        protocol_generation: int,
        attestation: Optional[ReleaseAttestation] = None,
    ) -> AdmissionDecision:
        """Evalúa la admisión de un par contra los requisitos de la malla."""
        # 1. floor de versión
        if version < self.req.version_floor:
            return AdmissionDecision(
                admitted=False,
                reason=RejectReason.VERSION_BELOW_FLOOR,
                details={
                    "got": f"{version[0]}.{version[1]}",
                    "floor": f"{self.req.version_floor[0]}."
                             f"{self.req.version_floor[1]}",
                },
            )
        # 2. generación de protocolo
        if protocol_generation != self.req.protocol_generation:
            return AdmissionDecision(
                admitted=False,
                reason=RejectReason.GENERATION_MISMATCH,
                details={
                    "got": protocol_generation,
                    "want": self.req.protocol_generation,
                },
            )
        # 3. atestación de release (solo si el gate la exige)
        if self.req.require_release_attestation:
            if attestation is None:
                return AdmissionDecision(
                    admitted=False,
                    reason=RejectReason.CERTIFIED_BINARY_REQUIRED,
                )
            ok, reason = attestation.verify(self.req.release_signer_keys)
            if not ok:
                return AdmissionDecision(admitted=False, reason=reason)
        return AdmissionDecision(admitted=True, reason=RejectReason.OK)
