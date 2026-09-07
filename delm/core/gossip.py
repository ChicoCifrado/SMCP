"""Gossip — propagación de estado de pares (capa 3, transporte) de SMCP.

Modelado sobre ``mesh/gossip.rs`` de MeshLLM: cada par anuncia su estado a sus
vecinos directos; esos vecinos **re-difunden** (gossip transitorio) para que la
malla completa se aprenda sin coordinador central.

Reglas clave (de MeshLLM):

* **floor de versión** — un par por debajo del ``version_floor`` se rechaza en
  el ingest y nunca se re-difunde (``MIN_REBROADCAST_VERSION``).
* **regla path-rich** — un anuncio transitorio solo avanza ``addr`` si es
  *al menos tan path-rich* como el existente; no se sobreescribe una dirección
  directa rica por una transitoria débil.
* **cambio significativo** — solo se re-propaga si algo significativo cambió.

El plano de control multiplexa bi-streams por **primer byte** (equivalente al
``mesh-llm/1`` de MeshLLM): aquí se fijan los bytes de stream de control.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Plano de control: primer byte del bi-stream (equiv. mesh-llm-protocol)
# ---------------------------------------------------------------------------
STREAM_GOSSIP = 0x01            # handshake de admisión + canal de gossip
STREAM_ROUTE_REQUEST = 0x05     # solicitud de ruta (pasivo/solicitante)
STREAM_PEER_DOWN = 0x06         # aviso de caída de par
STREAM_PEER_LEAVE = 0x07        # aviso de salida de par
STREAM_DIRECT_PATH = 0x0e       # establecimiento de camino directo


# ---------------------------------------------------------------------------
# Anuncio de estado
# ---------------------------------------------------------------------------
@dataclass
class PeerAnnouncement:
    """Anuncio de estado de un par: lo que un par publica en el gossip.

    ``addr`` es la lista de direcciones alcanzables; su **riqueza** es
    ``len(addr)``. Un anuncio más path-rich lleva más direcciones.
    """
    peer_id: str
    version: tuple[int, int]
    capabilities: tuple[str, ...] = ()   # capacidades de capa (capas 1-4)
    addr: tuple[str, ...] = ()            # direcciones; richness = len(addr)
    latency_ms: Optional[int] = None
    first_joined_mesh_ts: Optional[int] = None
    mesh_id: str = ""
    mesh_policy_hash: str = ""

    def richness(self) -> int:
        """Riqueza de la dirección: número de direcciones anunciadas."""
        return len(self.addr)


# ---------------------------------------------------------------------------
# Estado local de un par (directo o transitorio)
# ---------------------------------------------------------------------------
@dataclass
class PeerInfo:
    """Estado local de un par conocido (vía directa o transitoria)."""
    peer_id: str
    version: tuple[int, int]
    capabilities: tuple[str, ...]
    addr: tuple[str, ...]
    latency_ms: Optional[int]
    last_seen: int
    last_mentioned: int
    direct: bool = False
    first_joined_mesh_ts: Optional[int] = None
    mesh_id: str = ""
    mesh_policy_hash: str = ""

    def richness(self) -> int:
        return len(self.addr)


# ---------------------------------------------------------------------------
# Tabla de pares con re-difusión transitoria
# ---------------------------------------------------------------------------
class GossipTable:
    """Tabla de pares con floor de versión y regla path-rich.

    Ingesta anuncios directos (vecinos) y transitorios (re-difundidos por un
    bridge), y produce los anuncios que este nodo debe re-difundir.
    """

    def __init__(self, version_floor: tuple[int, int] = (0, 0)) -> None:
        self.version_floor = version_floor
        self.peers: dict[str, PeerInfo] = {}

    # -- floor de versión ----------------------------------------------------
    def version_allowed(self, version: tuple[int, int]) -> bool:
        """Un par está permitido si ``version >= version_floor``."""
        return version >= self.version_floor

    # -- ingest directo ------------------------------------------------------
    def ingest_direct(self, ann: PeerAnnouncement, now: int) -> str:
        """Ingesta un anuncio de un **vecino directo** (vía QUIC directa)."""
        if not self.version_allowed(ann.version):
            return "version_below_floor"
        self.peers[ann.peer_id] = PeerInfo(
            peer_id=ann.peer_id,
            version=ann.version,
            capabilities=ann.capabilities,
            addr=ann.addr,
            latency_ms=ann.latency_ms,
            last_seen=now,
            last_mentioned=now,
            direct=True,
            first_joined_mesh_ts=ann.first_joined_mesh_ts,
            mesh_id=ann.mesh_id,
            mesh_policy_hash=ann.mesh_policy_hash,
        )
        return "accepted"

    # -- ingest transitorio (re-difundido por un bridge) ----------------------
    def ingest_transitive(self, ann: PeerAnnouncement, bridge: str,
                          now: int) -> str:
        """Ingesta un anuncio **transitorio** (re-difundido por ``bridge``).

        Aplica la **regla path-rich**: ``addr`` solo avanza si el anuncio
        entrante es al menos tan path-rich como el existente.
        """
        if not self.version_allowed(ann.version):
            return "version_below_floor"
        existing = self.peers.get(ann.peer_id)
        if existing is None:
            self.peers[ann.peer_id] = PeerInfo(
                peer_id=ann.peer_id,
                version=ann.version,
                capabilities=ann.capabilities,
                addr=ann.addr,
                latency_ms=ann.latency_ms,
                last_seen=now,
                last_mentioned=now,
                direct=False,
                first_joined_mesh_ts=ann.first_joined_mesh_ts,
                mesh_id=ann.mesh_id,
                mesh_policy_hash=ann.mesh_policy_hash,
            )
            return "accepted"
        # regla path-rich: addr solo avanza si es al menos tan path-rich
        if len(ann.addr) >= len(existing.addr):
            existing.addr = ann.addr
        # el transitorio lleva el estado completo: sobreescribir el resto
        existing.version = ann.version
        existing.capabilities = ann.capabilities
        existing.mesh_id = ann.mesh_id
        existing.mesh_policy_hash = ann.mesh_policy_hash
        if ann.latency_ms is not None:
            existing.latency_ms = ann.latency_ms
        existing.last_seen = now
        existing.last_mentioned = now
        return "updated"

    # -- re-difusión ----------------------------------------------------------
    def _announcement_from(self, info: PeerInfo) -> PeerAnnouncement:
        return PeerAnnouncement(
            peer_id=info.peer_id,
            version=info.version,
            capabilities=info.capabilities,
            addr=info.addr,
            latency_ms=info.latency_ms,
            first_joined_mesh_ts=info.first_joined_mesh_ts,
            mesh_id=info.mesh_id,
            mesh_policy_hash=info.mesh_policy_hash,
        )

    def collect_rebroadcasts(self, now: int,
                             stale_cutoff: int) -> list[PeerAnnouncement]:
        """Anuncios que este nodo debe re-difundir.

        Solo pares **no-stale** (``last_seen >= stale_cutoff``) y **por encima
        del floor**. Es el equivalente a ``collect_rebroadcast_announcements``.
        """
        out: list[PeerAnnouncement] = []
        for info in self.peers.values():
            if info.last_seen < stale_cutoff:
                continue  # stale
            if not self.version_allowed(info.version):
                continue
            out.append(self._announcement_from(info))
        return out

    # -- cambio significativo -------------------------------------------------
    @staticmethod
    def meaningful_changed(old: PeerInfo, new: PeerInfo) -> bool:
        """¿Cambió algo significativo entre dos estados del par?"""
        return (
            old.version != new.version
            or old.capabilities != new.capabilities
            or len(old.addr) != len(new.addr)
            or old.latency_ms != new.latency_ms
            or old.mesh_id != new.mesh_id
        )

    # -- retiro ---------------------------------------------------------------
    def remove_peer(self, peer_id: str) -> bool:
        """Retira un par de la tabla. Devuelve ``True`` si existía."""
        return self.peers.pop(peer_id, None) is not None

    def get(self, peer_id: str) -> PeerInfo | None:
        return self.peers.get(peer_id)
