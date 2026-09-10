"""Tests de la Capa 4 — transporte de descubrimiento mDNS.

El :class:`~delm.core.mdns.MdnsDiscoveryTransport` es *swappable* con
:class:`~delm.core.deployment.DiscoveryBus`: implementa el mismo contrato
(``register``/``publish``/``deliver``/``nodes``), así
:class:`~delm.core.deployment.DeploymentNode` lo usa sin cambiar.

Estos tests cubren:

* **Mismo contrato que ``DiscoveryBus``** — ``DeploymentNode`` funciona con
  ``MdnsDiscoveryTransport`` igual que con ``DiscoveryBus``.
* **Multicast** — un anuncio de ``A`` llega a *todos* los demás nodos (el
  broadcast del medio mDNS), no solo a uno.
* **Bootstrap** — el nodo verifica la firma del owner (trust anchor); un
  anuncio no firmado se descarta (igual que por el bus in-memory).
* **Swappable** — ``MdnsDiscoveryTransport`` y ``DiscoveryBus`` son
  intercambiables en ``DeploymentNode`` (mismo comportamiento).
"""
from __future__ import annotations

import pytest

from delm.core.deployment import (
    Announcement,
    DiscoveryBus,
    DeploymentNode,
    Owner,
)
from delm.core.mdns import MdnsBus, MdnsDiscoveryTransport


# -- fixtures ---------------------------------------------------------------
@pytest.fixture
def owner() -> Owner:
    return Owner("owner-1")


@pytest.fixture
def mdns() -> MdnsDiscoveryTransport:
    return MdnsDiscoveryTransport(MdnsBus())


def _node(owner: Owner, bus, nid: str, t: float = 0.0) -> DeploymentNode:
    return DeploymentNode(nid, owner, bus, now=lambda: t, endpoint=f"ep-{nid}")


# -- Mismo contrato que DiscoveryBus ----------------------------------------
def test_mdns_same_contract_as_discovery_bus(owner, mdns):
    """``DeploymentNode`` funciona con ``MdnsDiscoveryTransport``.

    ``A`` anuncia; ``B`` lo recibe y lo verifica (bootstrap). El transporte
    mDNS expone el mismo contrato que ``DiscoveryBus``, así ``DeploymentNode``
    no cambia.
    """
    a = _node(owner, mdns, "A")
    b = _node(owner, mdns, "B")
    a.maybe_announce()
    assert b.poll() == 1
    assert "A" in b.peer_ids()
    # El anuncio de A está firmado por el owner (trust anchor).
    assert b.peers["A"].author == owner.owner_id


def test_mdns_multicast_reaches_all(owner, mdns):
    """Un anuncio de ``A`` llega a *todos* los demás (el multicast mDNS).

    El broadcast del medio mDNS: ``A`` publica y ``B`` y ``C`` lo reciben
    ambos (no solo uno).
    """
    a = _node(owner, mdns, "A")
    b = _node(owner, mdns, "B")
    c = _node(owner, mdns, "C")
    a.maybe_announce()
    assert b.poll() == 1
    assert c.poll() == 1
    assert "A" in b.peer_ids()
    assert "A" in c.peer_ids()


def test_mdns_two_way(owner, mdns):
    """``A`` y ``B`` se descubren mutuamente (cada uno anuncia, el otro lo ve)."""
    a = _node(owner, mdns, "A")
    b = _node(owner, mdns, "B")
    a.maybe_announce()
    b.maybe_announce()
    a.poll()
    b.poll()
    assert "B" in a.peer_ids()
    assert "A" in b.peer_ids()


# -- Bootstrap (firma del owner) --------------------------------------------
def test_mdns_bootstrap_tampered_dropped(owner, mdns):
    """Un anuncio *no firmado* (no del owner) se descarta.

    Igual que por el bus in-memory: el nodo verifica la firma del owner
    (trust anchor); un anuncio sin firma válida entra en ``dropped``.
    """
    a = _node(owner, mdns, "A")
    b = _node(owner, mdns, "B")
    # Un anuncio sin firma (signature vacío) -> b lo descarta.
    bad = Announcement(node_id="A", endpoint="ep-A", epoch=1, ts=0.0)
    mdns.publish("A", bad)
    assert b.poll() == 0
    assert len(b.dropped) == 1


def test_mdns_wrong_owner_key_dropped(owner, mdns):
    """Un anuncio firmado por *otro* owner se descarta (trust anchor)."""
    other = Owner("owner-2")
    a = _node(owner, mdns, "A")
    b = _node(owner, mdns, "B")
    bad = Announcement(node_id="A", endpoint="ep-A", epoch=1, ts=0.0)
    other.sign_announcement(bad)  # firmado por owner-2, no por owner-1
    mdns.publish("A", bad)
    assert b.poll() == 0
    assert len(b.dropped) == 1


# -- Swappable con DiscoveryBus ---------------------------------------------
def test_mdns_swappable_with_discovery_bus(owner):
    """``MdnsDiscoveryTransport`` y ``DiscoveryBus`` son intercambiables.

    El mismo escenario (``A`` anuncia, ``B`` recibe) da el mismo resultado
    con cualquiera de los dos transportes: ``DeploymentNode`` no cambia.
    """
    # Con DiscoveryBus (el in-memory de la Capa 4).
    bus = DiscoveryBus()
    a1 = _node(owner, bus, "A")
    b1 = _node(owner, bus, "B")
    a1.maybe_announce()
    r_bus = b1.poll()
    in_bus = "A" in b1.peer_ids()

    # Con MdnsDiscoveryTransport (el medio mDNS).
    mdns = MdnsDiscoveryTransport(MdnsBus())
    a2 = _node(owner, mdns, "A")
    b2 = _node(owner, mdns, "B")
    a2.maybe_announce()
    r_mdns = b2.poll()
    in_mdns = "A" in b2.peer_ids()

    # Mismo resultado: los dos transportes son swappable.
    assert r_bus == r_mdns == 1
    assert in_bus == in_mdns == True


# -- El medio mDNS (MdnsBus) -----------------------------------------------
def test_mdns_bus_deliver_fifo():
    """El medio mDNS entrega en FIFO y limpia la bandeja al ``deliver``."""
    bus = MdnsBus()
    bus.register("A")
    bus.register("B")
    a1 = Announcement(node_id="A", endpoint="e", epoch=1, ts=0.0)
    a2 = Announcement(node_id="A", endpoint="e", epoch=2, ts=1.0)
    bus.publish("A", a1)
    bus.publish("A", a2)
    got = bus.deliver("B")
    assert [x.epoch for x in got] == [1, 2]
    # La bandeja queda vacía tras el deliver.
    assert bus.deliver("B") == []


def test_mdns_bus_nodes_lists_publishers():
    """``nodes`` lista los nodos registrados y los que han publicado."""
    bus = MdnsBus()
    bus.register("A")
    assert bus.nodes() == ["A"]
    a1 = Announcement(node_id="B", endpoint="e", epoch=1, ts=0.0)
    bus.publish("B", a1)  # B publica sin estar registrado
    assert bus.nodes() == ["A", "B"]
