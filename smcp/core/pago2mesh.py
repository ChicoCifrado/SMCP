"""pago2mesh — creación de mesh privada con firma y ancla BSV.

Scaffold inicial. El flujo completo (pago x402, ancla on-chain) se
implementará en fases posteriores. Este módulo define las estructuras y
la firma de creación.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Callable, Mapping, Optional, Tuple

from smcp.core.provenance import KeyPair
from smcp.core.requirements import MeshRequirements

REQUIRED_PAYMENT_HEADERS = (
    "x-bsv-beef",
    "x-bsv-sender",
    "x-bsv-nonce",
    "x-bsv-time",
    "x-bsv-vout",
)


def validate_payment_headers(headers: Mapping[str, str]) -> bool:
    """Verifica la presencia de los headers x402/BRC-121 requeridos."""
    lowered = {k.lower(): v for k, v in headers.items()}
    return all(h in lowered and str(lowered[h]).strip() != "" for h in REQUIRED_PAYMENT_HEADERS)


def parse_beef(b64: str) -> bytes:
    """Decodifica un blob BEEF base64 y valida que no este vacio."""
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception as exc:
        raise ValueError("invalid beef") from exc
    if not raw:
        raise ValueError("empty beef")
    return raw


def validate_timestamp(time_str: str, now_ms: int, window_ms: int = 30000) -> bool:
    """Valida frescura del timestamp (ventana en ms)."""
    try:
        ts = int(time_str)
    except (TypeError, ValueError):
        return False
    return abs(now_ms - ts) <= window_ms


def validate_payment(
    headers: Mapping[str, str],
    now_ms: int,
    internalize: Optional[Callable[[bytes, str, str, str, int], Tuple[bool, bool]]] = None,
) -> Tuple[bool, str]:
    """Valida un pago x402/BRC-121 completo.

    Devuelve (ok, reason). Si se proporciona `internalize`, se invoca con
    (beef_bytes, nonce, time, sender, vout) y debe devolver (ok, is_merge).
    """
    if not validate_payment_headers(headers):
        return False, "missing headers"
    if not validate_timestamp(headers["x-bsv-time"], now_ms):
        return False, "stale timestamp"
    try:
        beef = parse_beef(headers["x-bsv-beef"])
    except ValueError:
        return False, "invalid beef"
    if internalize is not None:
        try:
            vout = int(headers["x-bsv-vout"])
        except (TypeError, ValueError):
            return False, "invalid vout"
        ok, is_merge = internalize(
            beef, headers["x-bsv-nonce"], headers["x-bsv-time"], headers["x-bsv-sender"], vout
        )
        if not ok:
            return False, "internalization failed"
        if is_merge:
            return False, "replay"
    return True, "ok"


@dataclass
class MeshCreationPayload:
    """Payload canónico firmado al crear una mesh."""
    mesh_id: str
    policy_hash: str
    version_floor: Tuple[int, int]
    timestamp_ms: int
    pub_key_b64: str


@dataclass
class Pago2MeshResult:
    """Resultado de la creación de una mesh."""
    mesh_id: str
    policy_hash: str
    created: bool
    anchor_txid: Optional[str] = None


class Pago2Mesh:
    """Crea una mesh privada firmada por el usuario."""

    def __init__(self, signer: KeyPair) -> None:
        self.signer = signer

    def build_payload(
        self,
        mesh_id: str,
        version_floor: Tuple[int, int] = (0, 0),
        timestamp_ms: int = 0,
    ) -> MeshCreationPayload:
        req = MeshRequirements(mesh_id=mesh_id, version_floor=version_floor)
        return MeshCreationPayload(
            mesh_id=mesh_id,
            policy_hash=req.policy_hash(),
            version_floor=version_floor,
            timestamp_ms=timestamp_ms,
            pub_key_b64=base64.b64encode(self.signer.public_key).decode(),
        )

    def sign_payload(self, payload: MeshCreationPayload) -> bytes:
        canon = (
            f"{payload.mesh_id}|{payload.policy_hash}|"
            f"{payload.version_floor[0]}.{payload.version_floor[1]}|"
            f"{payload.timestamp_ms}|{payload.pub_key_b64}"
        )
        return self.signer.sign(canon)

    def create(
        self,
        mesh_id: str,
        version_floor: Tuple[int, int] = (0, 0),
        timestamp_ms: int = 0,
    ) -> Pago2MeshResult:
        payload = self.build_payload(mesh_id, version_floor, timestamp_ms)
        _ = self.sign_payload(payload)
        return Pago2MeshResult(
            mesh_id=mesh_id,
            policy_hash=payload.policy_hash,
            created=True,
        )
