"""Heartbeat y detección de caída de pares (capa 3, transporte).

Modelado sobre ``mesh/heartbeat.rs`` de MeshLLM: cada par emite un heartbeat
periódico; si un par no lo emite dentro de la ventana de frescura, se le
marca ``down`` y se emite ``CTRL_PEER_DOWN`` para que la caída se propague
por el gossip.

Reglas:

* ``ttl_secs`` — ventana de frescura. Un par es fresco si
  ``now - last_heartbeat <= ttl_secs``.
* El heartbeat actualiza ``last_heartbeat`` y ``last_seen``.
* ``mark_down`` devuelve ``True`` si el par pasó a ``down`` (para disparar
  el ``CTRL_PEER_DOWN``).
* ``is_fresh`` / ``is_down`` son consultas puras sobre la frescura.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PeerHeartbeat:
    """Estado de heartbeat de un par."""
    peer_id: str
    last_heartbeat: int = 0
    last_seen: int = 0
    down: bool = False
    down_at: Optional[int] = None


class HeartbeatTracker:
    """Rastrea heartbeats y detección de caída de pares.

    ``ttl_secs`` es la ventana de frescura. Un par sin heartbeat dentro de la
    ventana se marca ``down``.
    """

    def __init__(self, ttl_secs: int = 30) -> None:
        self.ttl_secs = ttl_secs
        self.peers: dict[str, PeerHeartbeat] = {}

    # -- registro -----------------------------------------------------------
    def register(self, peer_id: str, now: int) -> None:
        """Registra un par y marca su heartbeat inicial en ``now``."""
        hb = self.peers.get(peer_id)
        if hb is None:
            self.peers[peer_id] = PeerHeartbeat(
                peer_id=peer_id, last_heartbeat=now, last_seen=now
            )
        else:
            hb.last_heartbeat = now
            hb.last_seen = now

    # -- heartbeat -----------------------------------------------------------
    def beat(self, peer_id: str, now: int) -> None:
        """Emite un heartbeat del par en ``now``."""
        hb = self.peers.get(peer_id)
        if hb is None:
            self.register(peer_id, now)
            return
        hb.last_heartbeat = now
        hb.last_seen = now
        # un heartbeat revierte el estado down
        if hb.down:
            hb.down = False
            hb.down_at = None

    # -- consultas puras -----------------------------------------------------
    def is_fresh(self, peer_id: str, now: int) -> bool:
        """Un par es fresco si ``now - last_heartbeat <= ttl_secs``."""
        hb = self.peers.get(peer_id)
        if hb is None:
            return False
        return (now - hb.last_heartbeat) <= self.ttl_secs

    def is_down(self, peer_id: str) -> bool:
        """El par está marcado ``down``."""
        hb = self.peers.get(peer_id)
        return hb is not None and hb.down

    # -- detección de caída ---------------------------------------------------
    def mark_down(self, peer_id: str, now: int) -> bool:
        """Marca el par ``down`` en ``now``.

        Devuelve ``True`` si el par **pasó** a ``down`` (para disparar
        ``CTRL_PEER_DOWN``); ``False`` si ya estaba ``down``.
        """
        hb = self.peers.get(peer_id)
        if hb is None:
            return False
        if not hb.down:
            hb.down = True
            hb.down_at = now
            return True
        return False

    def sweep(self, now: int) -> list[str]:
        """Barrido periódico: marca ``down`` a los pares no frescos.

        Devuelve la lista de pares que **pasaron** a ``down`` en este barrido
        (para emitir ``CTRL_PEER_DOWN`` por cada uno).
        """
        newly_down: list[str] = []
        for peer_id, hb in self.peers.items():
            if not self.is_fresh(peer_id, now) and self.mark_down(peer_id, now):
                newly_down.append(peer_id)
        return newly_down

    # -- retiro ---------------------------------------------------------------
    def remove(self, peer_id: str) -> None:
        """Retira un par del rastreador."""
        self.peers.pop(peer_id, None)
