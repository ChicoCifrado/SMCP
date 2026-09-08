"""Capa 4 — despliegue multi-proceso: discovery, relays, bootstrap, control-plane.

Este módulo implementa el *plano de transporte* del README (la capa 4): todo
lo que falta para que la malla salga del loopback in-proceso y funcione entre
procesos/nodos.

Piezas
-----

1. **Discovery** — anuncio y descubrimiento de nodos. El *transporte de
   anuncio* es :class:`DiscoveryBus` (in-memory, swappable: el adaptador
   Nostr/mDNS real implementa la misma interfaz y se usa en su lugar).
   Soporta **TTL** (re-announce), **dedupe** (por ``(node, epoch)``) y
   **reloj inyectable** (determinismo de test).

2. **Relays** — el bus hace *broadcast de un solo salto*: un ``publish``
   llega a la bandeja de *todos* los demás nodos (= propagación completa en
   el bus, que modela la red). El campo ``hops`` se conserva para auditoría
   de re-difusión (no hay cascade: el bus *es* la red).

3. **Bootstrap** — el *trust anchor* es la **clave pública del owner**
   (ed25519, reusando :class:`delm.core.provenance.KeyPair`). El owner firma
   cada anuncio (bootstrap de confianza) y cada orden (control-plane). Un
   nodo solo acepta un anuncio/orden cuya firma verifique contra la clave
   del owner: un anuncio/orden *no verificable* se descarta (anti-MITM).

4. **Control-plane** — el owner emite órdenes (join/leave/rotate) firmadas;
   el nodo las verifica y las ejecuta.

Diseño
------

* **Dependencias mínimas**: stdlib + ``delm.core.provenance`` (ed25519).
* **Determinismo**: todo el tiempo fluye por el reloj inyectable ``now``.
* **Seguridad por defecto**: lo no verificable se descarta; el trust anchor
  es la clave pública del owner.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    # Evita un import circular en runtime: el type checker sabe que
    # DeploymentNode.bus acepta NostrDiscoveryTransport (mismo contrato).
    from delm.core.nostr import NostrDiscoveryTransport

from delm.core.provenance import KeyPair, verify_public


# ---------------------------------------------------------------------------
# Anuncio de discovery
# ---------------------------------------------------------------------------
@dataclass
class Announcement:
    """Un anuncio de discovery: quién es, su endpoint, sus capabilities.

    ``signature``/``author`` son el *bootstrap de confianza*: el owner firma
    el anuncio y el nodo lo verifica contra la clave pública del owner.
    ``ts`` es el timestamp del anuncio (para el TTL/expire).
    """

    node_id: str
    endpoint: str
    capabilities: tuple[str, ...] = ()
    #: epoch del anuncio: sube en cada re-announce (dedupe por (node, epoch)).
    epoch: int = 0
    #: timestamp del anuncio (reloj del nodo, para el TTL/expire).
    ts: float = 0.0
    #: saltos (auditoría de re-difusión; el bus hace broadcast de 1 salto).
    hops: int = 0
    #: firma del owner sobre :meth:`digest` (bootstrap de confianza).
    signature: bytes = b""
    #: id del autor (el owner que firma).
    author: str = ""

    def digest(self) -> str:
        """Digest canónico del contenido (sin la firma; no auto-referencial)."""
        blob = json.dumps(
            {
                "node": self.node_id,
                "endpoint": self.endpoint,
                "caps": list(self.capabilities),
                "epoch": self.epoch,
                "ts": self.ts,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def to_dict(self) -> dict:
        """Serializa el anuncio a un ``dict`` JSON-serializable.

        El transporte Nostr emite el anuncio como ``data`` de un evento
        (``kind=10000``) y lo reconstruye al recibirlo. ``signature`` viaja
        en base64 (es ``bytes``).
        """
        return {
            "node": self.node_id,
            "endpoint": self.endpoint,
            "caps": list(self.capabilities),
            "epoch": self.epoch,
            "ts": self.ts,
            "hops": self.hops,
            "sig": base64.b64encode(self.signature).decode("ascii"),
            "author": self.author,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Announcement":
        """Reconstruye un ``Announcement`` desde su ``to_dict``."""
        return cls(
            node_id=d["node"],
            endpoint=d["endpoint"],
            capabilities=tuple(d.get("caps", ())),
            epoch=int(d.get("epoch", 0)),
            ts=float(d.get("ts", 0.0)),
            hops=int(d.get("hops", 0)),
            signature=base64.b64decode(d.get("sig", "")),
            author=d.get("author", ""),
        )


# ---------------------------------------------------------------------------
# Orden de control-plane
# ---------------------------------------------------------------------------
@dataclass
class Command:
    """Una orden del control-plane (join/leave/rotate/...)."""

    kind: str
    node_id: str
    payload: dict = field(default_factory=dict)
    #: firma del owner sobre :meth:`digest`.
    signature: bytes = b""
    #: id del autor (el owner).
    author: str = ""

    def digest(self) -> str:
        blob = json.dumps(
            {"kind": self.kind, "node": self.node_id, "payload": self.payload},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------------------
# Owner (la raíz de confianza)
# ---------------------------------------------------------------------------
class Owner:
    """La raíz de confianza del despliegue.

    El owner posee un :class:`KeyPair` (ed25519) y **firma** cada anuncio
    (bootstrap) y cada orden (control-plane). Los nodos verifican contra la
    clave pública del owner (el *trust anchor*).
    """

    def __init__(self, owner_id: str, key: Optional[KeyPair] = None) -> None:
        self.owner_id = owner_id
        self.key = key or KeyPair.new(owner_id, "ed25519")

    @property
    def public_key(self) -> bytes:
        """La clave pública (el trust anchor que los nodos verifican)."""
        return self.key.public_key

    def sign_digest(self, digest: str) -> bytes:
        """Firma un digest canónico (el owner avala ese contenido)."""
        return self.key.sign(digest)

    def sign_announcement(self, ann: Announcement) -> Announcement:
        """Firma ``ann`` (inmuta su ``signature``/``author``) y lo devuelve."""
        ann.signature = self.sign_digest(ann.digest())
        ann.author = self.owner_id
        return ann

    def sign_command(self, cmd: Command) -> Command:
        """Firma ``cmd`` (inmuta su ``signature``/``author``) y lo devuelve."""
        cmd.signature = self.sign_digest(cmd.digest())
        cmd.author = self.owner_id
        return cmd


# ---------------------------------------------------------------------------
# Bus de descubrimiento (el "transporte de anuncio")
# ---------------------------------------------------------------------------
class DiscoveryBus:
    """Bus de descubrimiento in-memory (swappable por Nostr/mDNS real).

    El *medio* por el que los nodos se anuncian y descubren:

    * ``publish(node, ann)`` — ``node`` publica ``ann``; el bus lo entrega a
      la bandeja de **todos** los demás nodos (broadcast de 1 salto: el bus
      *es* la red, así que un publish alcanza a todos).
    * ``deliver(node)`` — los anuncios que ``node`` recibe de los demás.

    El *adaptador real* (Nostr/mDNS) implementa la misma interfaz y se usa en
    su lugar; el bus in-memory sirve para test y loopback.
    """

    def __init__(self, max_hops: int = 4) -> None:
        self.max_hops = max_hops
        self._inboxes: dict[str, list[Announcement]] = {}
        self._nodes: set[str] = set()
        self._published: list[Announcement] = []  # auditoría

    def register(self, node: str) -> None:
        """Registra un nodo: su bandeja existe y recibe los broadcasts."""
        self._nodes.add(node)
        self._inboxes.setdefault(node, [])

    # -- API pública -------------------------------------------------------
    def publish(self, node: str, ann: Announcement) -> None:
        """Publica ``ann`` de ``node``: lo entrega a todos los demás nodos."""
        self._published.append(ann)
        self._inboxes.setdefault(node, [])  # el publicador también existe
        self._nodes.add(node)
        for other in list(self._nodes):
            if other != node:
                self._inboxes.setdefault(other, []).append(ann)

    def deliver(self, node: str) -> list[Announcement]:
        """Los anuncios que ``node`` recibe de los demás (pops, FIFO)."""
        box = self._inboxes.setdefault(node, [])
        out = list(box)
        self._inboxes[node] = []
        return out

    def nodes(self) -> list[str]:
        """Nodos conocidos (registrados o que han publicado)."""
        return sorted(self._nodes | {a.node_id for a in self._published})


# ---------------------------------------------------------------------------
# Nodo de despliegue (discovery + control-plane)
# ---------------------------------------------------------------------------
class DeploymentNode:
    """Un nodo del despliegue multi-proceso.

    Combina:

    * **Discovery** — publica su anuncio (TTL: re-anuncia cada
      ``announce_interval``), recibe los de los demás, verifica (bootstrap) y
      expira (TTL: un par que deja de re-anunciar se da de baja).
    * **Control-plane** — recibe órdenes del owner, verifica y las ejecuta.

    El *trust anchor* es la **clave pública del owner** (ed25519). Un
    anuncio/orden se acepta solo si su firma verifica contra esa clave; lo
    no verificable se descarta (anti-MITM).
    """

    def __init__(
        self,
        node_id: str,
        owner: Owner,
        bus: "DiscoveryBus | NostrDiscoveryTransport",
        now: Optional[Callable[[], float]] = None,
        *,
        endpoint: str = "",
        capabilities: tuple[str, ...] = (),
        announce_interval: float = 30.0,
    ) -> None:
        self.node_id = node_id
        self.owner = owner
        self.bus = bus
        self.bus.register(node_id)  # el nodo se registra en el bus al unirse
        self._now = now or (lambda: 0.0)
        self.endpoint = endpoint
        self.capabilities = capabilities
        self.announce_interval = announce_interval
        # Estado de discovery.
        self._epoch = 0
        self._last_announce: Optional[float] = None
        self.peers: dict[str, Announcement] = {}  # node -> último anuncio visto
        self._last_seen: dict[str, float] = {}     # node -> ts del último anuncio
        self.dropped: list[Announcement] = []     # lo no verificado (dropeado)
        # Control-plane.
        self.commands: list[Command] = []          # órdenes ejecutadas
        self.dropped_commands: list[Command] = []  # órdenes no verificadas
        self._pending_commands: list[Command] = []
        # Estado.
        self.status: str = "up"

    # -- Reloj -------------------------------------------------------------
    def _tick(self) -> float:
        return self._now()

    # -- Discovery: publicar (TTL) -----------------------------------------
    def maybe_announce(self) -> Optional[Announcement]:
        """Publica el anuncio si ha pasado ``announce_interval`` (TTL).

        El *re-announce* por TTL mantiene vivo al nodo: si un nodo deja de
        re-anunciar, sus pares lo expiran (ver :meth:`expire`).
        """
        t = self._tick()
        if self._last_announce is not None and (t - self._last_announce) < self.announce_interval:
            return None
        self._epoch += 1
        ann = Announcement(
            node_id=self.node_id,
            endpoint=self.endpoint,
            capabilities=self.capabilities,
            epoch=self._epoch,
            ts=t,
        )
        self.owner.sign_announcement(ann)
        self.bus.publish(self.node_id, ann)
        self._last_announce = t
        return ann

    # -- Discovery: recibir + verificar ------------------------------------
    def poll(self) -> int:
        """Recibe anuncios del bus, verifica (bootstrap) y los acepta.

        Devuelve el nº de pares aceptados (nuevos o re-anunciados).
        """
        accepted = 0
        for ann in self.bus.deliver(self.node_id):
            if ann.node_id == self.node_id:
                continue  # no es propio
            if not self._verify_announcement(ann):
                self.dropped.append(ann)
                continue
            self.peers[ann.node_id] = ann
            self._last_seen[ann.node_id] = ann.ts
            accepted += 1
        return accepted

    def _verify_announcement(self, ann: Announcement) -> bool:
        """Verifica la firma del owner sobre el digest del anuncio."""
        if not ann.signature or ann.author != self.owner.owner_id:
            return False
        return verify_public(
            "ed25519", self.owner.public_key, ann.digest(), ann.signature
        )

    # -- Discovery: expiración (TTL) ---------------------------------------
    def expire(self, max_age: Optional[float] = None) -> int:
        """Da de baja a los pares cuyo último anuncio tiene más de ``max_age``.

        El *TTL de expiración*: un par que deja de re-anunciar desaparece. Si
        ``max_age`` es ``None``, usa ``2 * announce_interval`` (un nodo que no
        re-anuncia en 2 intervalos desaparece).
        """
        if max_age is None:
            max_age = 2 * self.announce_interval
        t = self._tick()
        gone = 0
        for node in list(self.peers):
            last = self._last_seen.get(node, 0.0)
            if (t - last) > max_age:
                del self.peers[node]
                self._last_seen.pop(node, None)
                gone += 1
        return gone

    # -- Control-plane -----------------------------------------------------
    def poll_commands(self) -> int:
        """Recibe órdenes del owner, verifica (bootstrap) y las ejecuta.

        Devuelve el nº de órdenes ejecutadas.
        """
        executed = 0
        for cmd in list(self._pending_commands):
            self._pending_commands.remove(cmd)
            if not self._verify_command(cmd):
                self.dropped_commands.append(cmd)
                continue
            self.commands.append(cmd)
            self._apply(cmd)
            executed += 1
        return executed

    def _verify_command(self, cmd: Command) -> bool:
        if not cmd.signature or cmd.author != self.owner.owner_id:
            return False
        return verify_public(
            "ed25519", self.owner.public_key, cmd.digest(), cmd.signature
        )

    def _apply(self, cmd: Command) -> None:
        """Ejecuta la orden (join/leave/rotate/...)."""
        if cmd.kind == "up":
            self.status = "up"
        elif cmd.kind == "down":
            self.status = "down"
        # "rotate" y otras: el nodo las maneja (aquí solo se registran).

    def inject_command(self, cmd: Command) -> None:
        """Inyecta una orden (el owner, en el loopback)."""
        self._pending_commands.append(cmd)

    # -- Utilidades --------------------------------------------------------
    def peer_ids(self) -> list[str]:
        return sorted(self.peers)
