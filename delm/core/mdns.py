"""Capa 4 — transporte de descubrimiento mDNS (swappable con ``DiscoveryBus``).

El anuncio de discovery de la Capa 4 (:class:`~delm.core.deployment.DiscoveryBus`)
es un *transporte swappable*: ``NostrDiscoveryTransport`` (vía un relay Nostr)
y este módulo (vía mDNS/DNS-SD) implementan el **mismo contrato**
(``register``/``publish``/``deliver``/``nodes``), así
:class:`~delm.core.deployment.DeploymentNode` los usa sin cambiar.

**mDNS** es el medio *local* (LAN): un nodo publica su servicio y los demás
lo descubren por *multicast* (``224.0.0.251``, por defecto). No hay relay:
el broadcast lo hace el propio medio. Por eso el *medio* aquí es un
:class:`MdnsBus` (el "bus" mDNS): ``publish`` entrega el anuncio a **todos**
los demás nodos (el multicast), y ``deliver`` devuelve lo que un nodo ha
recibido.

* :class:`MdnsBus` — el medio mDNS **in-memory** (swappable por un back-end
  real de ``zeroconf``/``aiozeroconf``). Es el camino por defecto del test
  (sin red), igual que :class:`~delm.core.nostr.NostrRelay` lo es para Nostr.
* :class:`MdnsDiscoveryTransport` — el *transporte de descubrimiento*:
  envuelve un :class:`MdnsBus` y expone el contrato de ``DiscoveryBus``.

El *adaptador real* (``zeroconf``) implementa el mismo contrato de
``MdnsBus`` (``register``/``publish``/``deliver``/``nodes``) y se usa en su
lugar; es un **extra opcional** (no se instala por defecto), igual que
``websockets``/``aioquic``.
"""
from __future__ import annotations

from typing import Any, List


# ---------------------------------------------------------------------------
# El medio mDNS (in-memory, swappable por zeroconf)
# ---------------------------------------------------------------------------
class MdnsBus:
    """El medio mDNS **in-memory** (swappable por ``zeroconf``).

    Modela el *multicast* mDNS: ``publish(node, ann)`` entrega ``ann`` a la
    bandeja de **todos** los demás nodos (el broadcast del medio); ``deliver``
    devuelve lo que un nodo ha recibido de los demás.

    El *back-end real* (``zeroconf``/``aiozeroconf``) implementa el mismo
    contrato (``register``/``publish``/``deliver``/``nodes``) y se usa en su
    lugar; este in-memory es el camino por defecto del test (sin red), igual
    que :class:`~delm.core.nostr.NostrRelay` lo es para Nostr.
    """

    def __init__(self) -> None:
        self._inboxes: dict[str, list] = {}
        self._nodes: set[str] = set()
        self._published: list = []  # auditoría (los anuncios vistos)

    def register(self, node: str) -> None:
        """Registra un nodo: su bandeja existe y recibe el multicast."""
        self._nodes.add(node)
        self._inboxes.setdefault(node, [])

    def publish(self, node: str, ann: Any) -> None:
        """Publica ``ann`` de ``node``: lo entrega a **todos** los demás.

        El *multicast* mDNS: el anuncio alcanza a cada nodo registrado (salvo
        el publicador, que ya lo tiene).
        """
        self._published.append(ann)
        self._nodes.add(node)
        self._inboxes.setdefault(node, [])
        for other in list(self._nodes):
            if other != node:
                self._inboxes.setdefault(other, []).append(ann)

    def deliver(self, node: str) -> List[Any]:
        """Los anuncios que ``node`` ha recibido de los demás (FIFO)."""
        box = self._inboxes.setdefault(node, [])
        out = list(box)
        self._inboxes[node] = []
        return out

    def nodes(self) -> List[str]:
        """Nodos conocidos (registrados o que han publicado)."""
        known = set(self._nodes)
        for a in self._published:
            nid = getattr(a, "node_id", None)
            if nid is not None:
                known.add(nid)
        return sorted(known)


# ---------------------------------------------------------------------------
# El transporte de descubrimiento mDNS (swappable con DiscoveryBus)
# ---------------------------------------------------------------------------
class MdnsDiscoveryTransport:
    """El *transporte de descubrimiento* mDNS (swappable con ``DiscoveryBus``).

    Implementa el **mismo contrato** que
    :class:`~delm.core.deployment.DiscoveryBus`
    (``register``/``publish``/``deliver``/``nodes``), así
    :class:`~delm.core.deployment.DeploymentNode` lo usa sin cambiar:

    .. code-block:: python

        bus = MdnsDiscoveryTransport(MdnsBus())
        node = DeploymentNode("A", owner, bus, now=...)

    ``publish(node, ann)`` entrega el anuncio de ``node`` a **todos** los
    demás nodos (el multicast mDNS); ``deliver(node)`` devuelve lo que
    ``node`` ha recibido. El *medio* es un :class:`MdnsBus` (in-memory por
    defecto, swappable por un back-end real de ``zeroconf``).
    """

    def __init__(self, bus: MdnsBus) -> None:
        self.bus = bus

    def register(self, node: str) -> None:
        """Registra un nodo en el medio mDNS."""
        self.bus.register(node)

    def publish(self, node: str, ann: Any) -> None:
        """Publica el anuncio de ``node`` (multicast a todos los demás)."""
        self.bus.publish(node, ann)

    def deliver(self, node: str) -> List[Any]:
        """Los anuncios que ``node`` ha recibido de los demás."""
        return self.bus.deliver(node)

    def nodes(self) -> List[str]:
        """Nodos conocidos (registrados o que han publicado)."""
        return self.bus.nodes()
