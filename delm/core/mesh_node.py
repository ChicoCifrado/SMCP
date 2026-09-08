"""Nodo de malla (capa 3) — un par SMCP.

Un :class:`MeshNode` es un par que:

* **Anuncia** su estado (``PeerAnnouncement``) por gossip.
* **Evalúa** la admisión de pares contra los ``MeshRequirements`` inmutables.
* **Mantiene** su ``HeartbeatTracker`` y detecta caídas de vecinos.
* **Publica gists** firmados (con su :class:`KeyPair`) y **los difunde**.
* **Recibe gists** de otros pares, **verifica la firma** contra la key pública
  del autor y los admite en su :class:`SecureSharedContext`.

El nodo es **opaco al transporte**: usa un :class:`MeshTransport` (in-memory o
QUIC) para mover datagramas. La semántica (gossip, gist, heartbeat) la aplica
aquí, no en el transporte.

Formato de datagrama (plano de control, primer byte del mensaje):

* ``0x01`` ANNOUNCE  — ``PeerAnnouncement`` (gossip).
* ``0x02`` GIST     — gist firmado + key pública del autor.
* ``0x03`` HEARTBEAT— latido (para el ``HeartbeatTracker``).
* ``0x06`` PEER_DOWN— aviso de caída de un par.
* ``0x07`` PEER_LEAVE— aviso de salida de un par.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Optional

from delm.core.gossip import GossipTable, PeerAnnouncement
from delm.core.heartbeat import HeartbeatTracker
from delm.core.provenance import KeyPair
from delm.core.requirements import AdmissionEvaluator, MeshRequirements
from delm.core.secure_context import SecureSharedContext
from delm.core.transport import MeshTransport

# Tipos de mensaje (plano de control)
MSG_ANNOUNCE = 0x01
MSG_GIST = 0x02
MSG_HEARTBEAT = 0x03
MSG_PEER_DOWN = 0x06
MSG_PEER_LEAVE = 0x07


# ---------------------------------------------------------------------------
# Codificación de datagramas
# ---------------------------------------------------------------------------
def encode_msg(kind: int, payload: bytes) -> bytes:
    """Encabezado de 1 byte + payload."""
    return bytes([kind]) + payload


def decode_msg(data: bytes) -> tuple[int, bytes]:
    """Devuelve ``(kind, payload)``."""
    if not data:
        raise ValueError("datagrama vacío")
    return data[0], data[1:]


def _ann_to_json(ann: PeerAnnouncement) -> str:
    return json.dumps({
        "peer_id": ann.peer_id,
        "version": list(ann.version),
        "capabilities": list(ann.capabilities),
        "addr": list(ann.addr),
        "latency_ms": ann.latency_ms,
        "first_joined_mesh_ts": ann.first_joined_mesh_ts,
        "mesh_id": ann.mesh_id,
        "mesh_policy_hash": ann.mesh_policy_hash,
    }, sort_keys=True)


def _json_to_ann(d: dict) -> PeerAnnouncement:
    return PeerAnnouncement(
        peer_id=d["peer_id"],
        version=tuple(d["version"]),
        capabilities=tuple(d["capabilities"]),
        addr=tuple(d["addr"]),
        latency_ms=d.get("latency_ms"),
        first_joined_mesh_ts=d.get("first_joined_mesh_ts"),
        mesh_id=d.get("mesh_id", ""),
        mesh_policy_hash=d.get("mesh_policy_hash", ""),
    )


# ---------------------------------------------------------------------------
# Nodo de malla
# ---------------------------------------------------------------------------
class MeshNode:
    """Un par SMCP: gossip + requirements + heartbeat + contexto seguro."""

    def __init__(
        self,
        peer_id: str,
        version: tuple[int, int],
        capabilities: tuple[str, ...],
        transport: MeshTransport,
        ctx: SecureSharedContext,
        key: KeyPair,
        req: MeshRequirements,
        heartbeat: Optional[HeartbeatTracker] = None,
        ttl_secs: int = 30,
    ) -> None:
        self.peer_id = peer_id
        self.version = version
        self.capabilities = capabilities
        self.transport = transport
        self.ctx = ctx
        self.key = key
        self.req = req
        self.heartbeat = heartbeat or HeartbeatTracker(ttl_secs=ttl_secs)
        self.table = GossipTable(version_floor=req.version_floor)
        self.evaluator = AdmissionEvaluator(req)
        self.mesh_id = req.mesh_id
        self.policy_hash = req.policy_hash()
        self._now = 0
        self._neighbors: set[str] = set()
        # Registra la propia key en el contexto (el par puede admitir).
        self.ctx.register_key(self.peer_id, key.public_key, key.kind)

    # -- reloj lógico --------------------------------------------------------
    def tick(self) -> None:
        """Avanza el reloj lógico un paso."""
        self._now += 1

    @property
    def now(self) -> int:
        return self._now

    # -- anuncio propio ------------------------------------------------------
    def self_announcement(self) -> PeerAnnouncement:
        """El anuncio de este par (para difundir por gossip)."""
        return PeerAnnouncement(
            peer_id=self.peer_id,
            version=self.version,
            capabilities=self.capabilities,
            addr=(self.peer_id,),
            first_joined_mesh_ts=self._now,
            mesh_id=self.mesh_id,
            mesh_policy_hash=self.policy_hash,
        )

    # -- firma / publicación de gists ---------------------------------------
    def sign_gist(self, gist: Any) -> Any:
        """Firma ``gist`` con la key de este par y lo devuelve.

        El gist debe estar *final* (su contenido no cambiará), porque la firma
        cubre el digest canónico.
        """
        from delm.core.provenance import digest_of
        gist.author_id = self.peer_id
        gist.digest = digest_of(gist)
        gist.signature = self.key.sign(gist.digest)
        gist.sig_kind = self.key.kind
        return gist

    def publish_gist(self, gist: Any) -> bytes:
        """Firma ``gist`` y devuelve el datagrama para difundir."""
        self.sign_gist(gist)
        payload = json.dumps({
            "label": gist.label,
            "gist": gist.gist,
            "kind": getattr(gist.kind, "value", str(gist.kind)),
            "raw": getattr(gist, "raw", None),
            "author_id": gist.author_id,
            "digest": gist.digest,
            "signature": base64.b64encode(gist.signature).decode(),
            "sig_kind": gist.sig_kind,
            "pub_key": base64.b64encode(self.key.public_key).decode(),
        }, sort_keys=True).encode()
        return encode_msg(MSG_GIST, payload)

    # -- recepción de datagramas -------------------------------------------
    def on_datagram(self, from_id: str, payload: bytes) -> None:
        """Procesa un datagrama entrante (decodifica y despacha)."""
        kind, body = decode_msg(payload)
        if kind == MSG_ANNOUNCE:
            self.handle_announce(from_id, _json_to_ann(json.loads(body)))
        elif kind == MSG_GIST:
            self.handle_gist(from_id, json.loads(body))
        elif kind == MSG_HEARTBEAT:
            self.handle_heartbeat(from_id, json.loads(body))
        elif kind == MSG_PEER_DOWN:
            self.handle_peer_down(from_id, json.loads(body))
        elif kind == MSG_PEER_LEAVE:
            self.handle_peer_leave(from_id, json.loads(body))
        else:
            raise ValueError(f"tipo de datagrama desconocido: {kind:#x}")

    # -- despachadores -------------------------------------------------------
    def handle_announce(self, from_id: str, ann: PeerAnnouncement) -> None:
        """Recibe un anuncio de un par (directo o re-difundido)."""
        # El par anunciante se registra como vecino y en la tabla.
        self._neighbors.add(from_id)
        # Admite el par en la tabla (con floor de versión).
        self.table.ingest_transitive(ann, bridge=from_id, now=self._now)

    def handle_gist(self, from_id: str, d: dict) -> None:
        """Recibe un gist firmado: verifica la firma y lo admite en su ctx.

        Registra la key pública del autor en el contexto y admite el gist; si
        la firma no verifica, el gist **no** entra (el ctx lo rechaza).
        """
        from delm.core.gist import Gist, GistKind
        # Reconstruye el gist.
        kind = GistKind(d["kind"]) if d["kind"] in {k.value for k in GistKind} else GistKind.FACT
        gist = Gist(label=d["label"], gist=d["gist"], kind=kind)
        gist.raw = d.get("raw")
        # Key pública del autor (la registra para verificar).
        pub = base64.b64decode(d["pub_key"])
        self.ctx.register_key(d["author_id"], pub, d["sig_kind"])
        # Firma del gist.
        gist.author_id = d["author_id"]
        gist.digest = d["digest"]
        gist.signature = base64.b64decode(d["signature"])
        gist.sig_kind = d["sig_kind"]
        # Admite en el contexto (verifica la firma contra la key registrada).
        try:
            self.ctx.admit(gist)
        except Exception:
            # Firma inválida / taint: el gist no entra. El nodo lo descarta.
            return

    def handle_heartbeat(self, from_id: str, d: dict) -> None:
        """Recibe un heartbeat de un par: actualiza el tracker."""
        self._neighbors.add(from_id)
        self.heartbeat.beat(from_id, self._now)

    def handle_peer_down(self, from_id: str, d: dict) -> None:
        """Recibe un aviso de caída: marca el par down en el tracker."""
        self.heartbeat.mark_down(d.get("peer_id", from_id), self._now)

    def handle_peer_leave(self, from_id: str, d: dict) -> None:
        """Recibe un aviso de salida: retira el par."""
        self._neighbors.discard(from_id)
        self.table.remove_peer(from_id)
        self.heartbeat.remove(from_id)

    # -- envío ---------------------------------------------------------------
    def send_announce(self, to: str) -> None:
        """Envía el propio anuncio a ``to``."""
        self.transport.send(to, encode_msg(
            MSG_ANNOUNCE, _ann_to_json(self.self_announcement()).encode()))

    def send_heartbeat(self, to: str) -> None:
        """Envía un heartbeat a ``to``."""
        self.transport.send(to, encode_msg(
            MSG_HEARTBEAT, json.dumps({"peer_id": self.peer_id}).encode()))

    def send_peer_down(self, to: str, peer_id: str) -> None:
        """Envía un aviso de caída a ``to``."""
        self.transport.send(to, encode_msg(
            MSG_PEER_DOWN, json.dumps({"peer_id": peer_id}).encode()))

    def send_peer_leave(self, to: str, peer_id: str) -> None:
        """Envía un aviso de salida a ``to``."""
        self.transport.send(to, encode_msg(
            MSG_PEER_LEAVE, json.dumps({"peer_id": peer_id}).encode()))

    # -- ciclo de vida ---------------------------------------------------------
    def run_tick(self) -> list[tuple[str, bytes]]:
        """Un paso del ciclo: procesa datagramas entrantes y emite salidas.

        Devuelve las salidas enviadas en este tick (para tests/observabilidad).
        """
        sent: list[tuple[str, bytes]] = []
        # 1. Procesa los datagramas entrantes.
        for from_id, payload in self.transport.poll():
            self.on_datagram(from_id, payload)
        # 2. Envía su anuncio a los vecinos (gossip) y su heartbeat.
        for nbr in list(self._neighbors):
            self.send_announce(nbr)
            self.send_heartbeat(nbr)
            sent.append((nbr, b"tick"))
        # 3. Avanza el reloj.
        self.tick()
        return sent
