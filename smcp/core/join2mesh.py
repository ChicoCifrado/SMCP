"""join2mesh — unión pagada a una mesh privada con handshake firmado.

Scaffold inicial. El flujo completo (pago x402, admisión, ancla) se
implementará en fases posteriores.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Callable, Mapping, Optional, Tuple

from smcp.core.provenance import KeyPair

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
    """Valida un pago x402/BRC-121 completo."""
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
class JoinHandshake:
    """Handshake firmado por el nodo candidato."""
    peer_id: str
    mesh_id: str
    pub_key_b64: str
    timestamp_ms: int
    signature: bytes = b""


class Join2Mesh:
    """Une un nodo a una mesh privada firmando el handshake."""

    def __init__(self, signer: KeyPair) -> None:
        self.signer = signer

    def build_handshake(
        self,
        peer_id: str,
        mesh_id: str,
        timestamp_ms: int = 0,
    ) -> JoinHandshake:
        pub = base64.b64encode(self.signer.public_key).decode()
        canon = f"{peer_id}|{mesh_id}|{pub}|{timestamp_ms}"
        sig = self.signer.sign(canon)
        return JoinHandshake(
            peer_id=peer_id,
            mesh_id=mesh_id,
            pub_key_b64=pub,
            timestamp_ms=timestamp_ms,
            signature=sig,
        )

    def verify_pubkey(self, handshake: JoinHandshake, trusted_pubkey: bytes) -> bool:
        """Verifica que la clave del handshake coincida con la vinculada."""
        try:
            return base64.b64decode(handshake.pub_key_b64) == trusted_pubkey
        except Exception:
            return False
