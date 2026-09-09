"""Malla (capa 3) — un conjunto de nodos conectados.

:class:`MeshNetwork` es el contenedor de una malla: crea nodos, conecta sus
transportes, drena hasta convergencia (los datagramas dejan de fluir) y
expone el estado de la malla (pares, gists admitidos).

Dos modos de transporte:

* **in-proceso (por defecto)** — ``InMemoryTransport``: los nodos comparten un
  :class:`_Bus`; el drenado es determinista y sin latencia.

* **QUIC (``QuicSwarm``)** — cada nodo usa un :class:`QuicTransport` sobre un
  :class:`QuicSwarm` compartido; el drenado bombea el handshake + datagramas
  (``pump``) en cada tick. Es el transporte de despliegue multi-nodo real.

Convergencia: ``drain`` itera ``tick`` sobre todos los nodos hasta que una
pasada completa no produzca ningún datagrama nuevo (punto fijo del gossip).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from delm.core.gossip import GossipTable
from delm.core.heartbeat import HeartbeatTracker
from delm.core.provenance import KeyPair
from delm.core.requirements import MeshRequirements
from delm.core.secure_context import SecureSharedContext
from delm.core.transport import InMemoryTransport, QuicTransport, _Bus
from delm.core.mesh_node import MeshNode


@dataclass
class MeshStatus:
    """Estado de la malla tras un drenado."""
    peers: int
    admitted_gists: int
    ticks: int
    converged: bool = True


class MeshNetwork:
    """Una malla de nodos conectados.

    ``requirements`` son los requisitos inmutables de la malla (el ``mesh_id``
    y el floor de versión). Cada nodo lleva su propio
    :class:`SecureSharedContext` (los gists se admiten **localmente**, por
    nodo, tras verificar la firma del autor).
    """

    def __init__(self, requirements: MeshRequirements, swarm: Any = None,
                 nostr: Any = None) -> None:
        self.requirements = requirements
        self.nodes: dict[str, MeshNode] = {}
        self._bus = _Bus()
        # ``swarm`` es un ``QuicSwarm`` compartido (modo QUIC) o ``None``
        # (modo in-proceso, ``InMemoryTransport``).
        self._swarm = swarm
        # ``nostr`` es un ``NostrSwarm`` (modo Nostr, la malla **sobre red**):
        # cada nodo usa un :class:`~delm.core.nostr.NostrTransport` (el relay
        # de red hace el fan-out). Si no, ``None``.
        self._nostr = nostr
        self._ticks = 0

    # -- creación de nodos ----------------------------------------------------
    def add_node(self, peer_id: str,
                 version: tuple[int, int],
                 capabilities: tuple[str, ...] = ()) -> MeshNode:
        """Crea un nodo y lo añade a la malla.

        El transporte depende del modo:

        * **Nostr** (``nostr``): ``NostrSwarm.add_peer`` genera la ``NostrKey``
          y el ``peer_id`` del nodo es su ``pubkey`` x-only (hex de 64); el
          transporte es un :class:`~delm.core.nostr.NostrTransport` (el relay
          de red hace el fan-out).
        * **QUIC** (``swarm``): ``QuicSwarm.add_peer`` y un ``QuicTransport``.
        * **in-proceso** (por defecto): ``InMemoryTransport`` sobre el bus.
        """
        if peer_id in self.nodes:
            raise ValueError(f"nodo ya existe: {peer_id!r}")
        ctx = SecureSharedContext()
        if self._nostr is not None:
            # El pubkey es la identidad del nodo en la malla Nostr.
            real_id = self._nostr.add_peer(peer_id)
            key = KeyPair.new(real_id)
            transport = self._nostr.transport_for(real_id)
            node_id = real_id
        else:
            node_id = peer_id
            key = KeyPair.new(peer_id)
            if self._swarm is not None:
                self._swarm.add_peer(peer_id)
                transport = QuicTransport(self._swarm, peer_id)
            else:
                transport = InMemoryTransport(self._bus, peer_id)
        node = MeshNode(
            peer_id=node_id,
            version=version,
            capabilities=capabilities,
            transport=transport,
            ctx=ctx,
            key=key,
            req=self.requirements,
        )
        self.nodes[node.peer_id] = node
        return node

    # -- drenado / convergencia ----------------------------------------------
    def tick_all(self) -> int:
        """Un paso: drena un tick sobre **todos** los nodos.

        En modo QUIC, antes de procesar se bombea el swarm (handshake +
        datagramas). En modo Nostr, se drena la bandeja entrante de cada
        nodo (la cuenta para la convergencia). Devuelve el nº de
        datagramas producidos en este paso.
        """
        if self._swarm is not None:
            pumped = self._swarm.pump()
        else:
            pumped = 0
        produced = pumped
        for node in self.nodes.values():
            if self._nostr is not None:
                # Nostr: drena la bandeja entrante (la cuenta para
                # convergencia) y la pasa a run_tick.
                incoming = node.transport.poll()
                produced += len(incoming)
                node.run_tick(incoming=incoming)
            elif self._swarm is None:
                # In-memory: cuenta los datagramas pendientes en el bus.
                produced += len(self._bus.queue(node.peer_id))
                node.run_tick()
            else:
                # QUIC: el conteo es el pump (ya en produced); run_tick drena.
                node.run_tick()
        self._ticks += 1
        return produced

    def drain(self, max_ticks: int = 50) -> MeshStatus:
        """Drena la malla hasta convergencia (punto fijo del gossip).

        Convergencia: dos pasos consecutivos sin datagramas nuevos. Devuelve el
        :class:`MeshStatus`.
        """
        quiet = 0
        for _ in range(max_ticks):
            produced = self.tick_all()
            if produced == 0:
                quiet += 1
                if quiet >= 1:
                    break
            else:
                quiet = 0
        return self.status()

    # -- estado ---------------------------------------------------------------
    def status(self) -> MeshStatus:
        """Estado de la malla: pares y gists admitidos (suma por nodo)."""
        admitted = sum(len(n.ctx) for n in self.nodes.values())
        return MeshStatus(
            peers=len(self.nodes),
            admitted_gists=admitted,
            ticks=self._ticks,
        )

    def peers(self) -> list[str]:
        """Identificadores de los nodos de la malla."""
        return list(self.nodes)

    def other_peers(self, peer_id: str) -> list[str]:
        """Todos los nodos salvo ``peer_id`` (para el broadcast)."""
        return [p for p in self.nodes if p != peer_id]

    def __len__(self) -> int:
        return len(self.nodes)

    def __iter__(self):
        return iter(self.nodes.values())
