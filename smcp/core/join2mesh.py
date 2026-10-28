"""join2mesh — unión pagada a una mesh privada con handshake firmado.

Scaffold inicial. El flujo completo (pago x402, admisión, ancla) se
implementará en fases posteriores.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Optional

from smcp.core.provenance import KeyPair


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
