"""Tests de la Capa 4 — despliegue multi-proceso (discovery, relays, bootstrap,
control-plane).

Corresponde al README (``Tests`` → capa 4):

* **Discovery**: el owner firma, un nodo publica, otro lo descubre.
* **Relays**: el bus hace broadcast (un publish llega a todos los demás).
* **Bootstrap**: un anuncio/orden *no verificable* (firma falsa) se descarta.
* **TTL / re-announce**: un nodo solo re-anuncia tras el intervalo.
* **Expire**: un nodo que deja de anunciar lo expiran sus pares.
* **Control-plane**: el owner emite órdenes firmadas; el nodo las ejecuta.
"""

from __future__ import annotations

import pytest

from delm.core.deployment import (
    Command,
    DiscoveryBus,
    DeploymentNode,
    Owner,
)


# -- fixtures ---------------------------------------------------------------
@pytest.fixture
def owner() -> Owner:
    return Owner("owner-1")


@pytest.fixture
def bus() -> DiscoveryBus:
    return DiscoveryBus()


def _node(owner: Owner, bus: DiscoveryBus, nid: str, t: float = 0.0) -> DeploymentNode:
    return DeploymentNode(
        nid, owner, bus, now=lambda: t, endpoint=f"ep-{nid}"
    )


# -- Discovery ---------------------------------------------------------------
def test_discovery_owner_signs_node_discovered(owner, bus):
    """El owner firma, A publica, B lo descubre (bootstrap OK)."""
    a = _node(owner, bus, "A")
    b = _node(owner, bus, "B")
    a.maybe_announce()
    assert b.poll() == 1          # B recibe el anuncio de A
    assert "A" in b.peer_ids()
    # El anuncio de A está firmado por el owner (trust anchor).
    assert b.peers["A"].author == owner.owner_id


def test_discovery_broadcast_reaches_all(owner, bus):
    """Relays: un publish de A llega a B y C (broadcast del bus)."""
    a = _node(owner, bus, "A")
    b = _node(owner, bus, "B")
    c = _node(owner, bus, "C")
    a.maybe_announce()
    assert b.poll() == 1
    assert c.poll() == 1
    assert "A" in b.peer_ids() and "A" in c.peer_ids()


def test_discovery_two_way(owner, bus):
    """A y B se descubren mutuamente (cada uno anuncia, el otro lo ve)."""
    a = _node(owner, bus, "A")
    b = _node(owner, bus, "B")
    a.maybe_announce()
    b.maybe_announce()
    # Cada uno recibe el del otro (el propio no se recibe).
    a.poll()
    b.poll()
    assert "B" in a.peer_ids()
    assert "A" in b.peer_ids()


# -- Bootstrap (firma falsa se descarta) --------------------------------------
def test_bootstrap_tampered_announcement_dropped(owner, bus):
    """Un anuncio con firma *falsa* (no del owner) se descarta."""
    a = _node(owner, bus, "A")
    b = _node(owner, bus, "B")
    # A publica, pero el owner *no* firma (signature vacío) -> B lo descarta.
    from delm.core.deployment import Announcement
    bad = Announcement(node_id="A", endpoint="ep-A", epoch=1, ts=0.0)
    bus.publish("A", bad)
    assert b.poll() == 0          # nada aceptado
    assert len(b.dropped) == 1    # quedó en el dropeo


def test_bootstrap_wrong_owner_key_dropped(owner, bus):
    """Un anuncio firmado por *otro* owner (clave distinta) se descarta."""
    other = Owner("owner-2")
    a = _node(owner, bus, "A")
    b = _node(owner, bus, "B")
    from delm.core.deployment import Announcement
    bad = Announcement(node_id="A", endpoint="ep-A", epoch=1, ts=0.0)
    other.sign_announcement(bad)  # firmado por owner-2, no por owner-1
    bus.publish("A", bad)
    assert b.poll() == 0
    assert len(b.dropped) == 1


# -- TTL / re-announce --------------------------------------------------------
def test_ttl_node_reannounces_after_interval(owner, bus):
    """Un nodo solo re-anuncia tras el intervalo (TTL)."""
    t = [0.0]
    a = DeploymentNode(
        "A", owner, bus, now=lambda: t[0], endpoint="ep-A",
        announce_interval=10.0,
    )
    a.maybe_announce()           # t=0 -> anuncia
    assert a.maybe_announce() is None  # t=5 -> aún no (5 < 10)
    t[0] = 11.0
    assert a.maybe_announce() is not None  # t=11 -> re-anuncia


def test_expire_node_gone_after_silence(owner, bus):
    """Un nodo que deja de anunciar lo expiran sus pares (TTL)."""
    t = [0.0]
    a = DeploymentNode(
        "A", owner, bus, now=lambda: t[0], endpoint="ep-A",
        announce_interval=10.0,
    )
    b = DeploymentNode(
        "B", owner, bus, now=lambda: t[0], endpoint="ep-B",
        announce_interval=10.0,
    )
    a.maybe_announce()
    assert b.poll() == 1
    assert "A" in b.peer_ids()
    # A deja de anunciar; B lo expira tras 2*interval = 20.
    t[0] = 21.0
    b.poll()
    assert b.expire() == 1       # A expirado
    assert "A" not in b.peer_ids()


# -- Control-plane -------------------------------------------------------------
def test_control_plane_up_command_executed(owner, bus):
    """El owner firma 'up'; el nodo lo ejecuta (status -> up)."""
    a = _node(owner, bus, "A")
    cmd = Command(kind="up", node_id="A")
    owner.sign_command(cmd)
    a.inject_command(cmd)
    assert a.poll_commands() == 1
    assert a.status == "up"


def test_control_plane_tampered_command_dropped(owner, bus):
    """Una orden con firma *falsa* se descarta (no se ejecuta)."""
    a = _node(owner, bus, "A")
    # Orden firmada por *otro* owner -> el nodo la descarta.
    other = Owner("owner-2")
    cmd = Command(kind="down", node_id="A")
    other.sign_command(cmd)
    a.inject_command(cmd)
    assert a.poll_commands() == 0
    assert len(a.dropped_commands) == 1
    assert a.status == "up"      # no cambió (la orden no se ejecutó)


def test_control_plane_down_command_executed(owner, bus):
    """El owner firma 'down'; el nodo lo ejecuta (status -> down)."""
    a = _node(owner, bus, "A")
    cmd = Command(kind="down", node_id="A")
    owner.sign_command(cmd)
    a.inject_command(cmd)
    a.poll_commands()
    assert a.status == "down"


# -- Transporte Nostr (swappable con DiscoveryBus) --------------------------
def test_nostr_transport_same_contract_as_discovery_bus(owner):
    """El transporte Nostr implementa el mismo contrato que ``DiscoveryBus``.

    ``NostrDiscoveryTransport`` se usa en ``DeploymentNode`` en lugar de
    ``DiscoveryBus``: ``A`` anuncia, ``B`` lo recibe, y el relay **verificó
    la firma BIP340** del evento (no lo descargó). El anuncio llega igual que
    por el bus in-memory (mismo contrato).
    """
    from delm.core.nostr import NostrKey, NostrRelay, NostrDiscoveryTransport

    relay = NostrRelay()
    key = NostrKey.new()
    nbus = NostrDiscoveryTransport(relay, key)
    a = DeploymentNode("A", owner, nbus, now=lambda: 0.0, endpoint="ep-A")
    b = DeploymentNode("B", owner, nbus, now=lambda: 0.0, endpoint="ep-B")
    a.maybe_announce()
    assert b.poll() == 1
    assert "A" in b.peer_ids()
    # El relay aceptó el evento (firmado, no descargado).
    assert len(relay.events()) == 1
    assert len(relay.dropped()) == 0


def test_nostr_transport_relay_rejects_bad_signature(owner):
    """El relay del transporte Nostr descarta un evento cuya firma no verifica.

    Un evento fabricado con una firma de *otra* clave no verifica contra su
    ``pubkey``: el relay lo descarta y el anuncio **no** llega al otro nodo.
    (El transporte real solo emite eventos firmados por su ``key``, así esto
    cubre el caso de un evento corrupto/falsificado en el relay.)
    """
    from delm.core.nostr import NostrEvent, NostrKey, NostrRelay, NostrDiscoveryTransport

    relay = NostrRelay()
    key = NostrKey.new()
    nbus = NostrDiscoveryTransport(relay, key)
    b = DeploymentNode("B", owner, nbus, now=lambda: 0.0, endpoint="ep-B")
    # Un evento con la pubkey de `key` pero firmado por OTRA clave.
    other = NostrKey.new()
    ev = NostrEvent.signed(other, 0, 10000, [["d", "A"]], "x")
    ev.pubkey = key.pubkey  # pubkey de `key`, firma de `other` -> no verifica
    relay.publish(ev)
    assert len(relay.dropped()) == 1
    assert len(relay.events()) == 0
    # Nada llegó a B (el relay no lo aceptó).
    assert b.poll() == 0


def test_nostr_transport_network_form(owner):
    """:class:`NostrDiscoveryTransport` en **forma de red** (vía
    :class:`NostrRelayClient`).

    Dos nodos, cada uno con su propio transporte ligado a su propio
    :class:`NostrRelayClient` (un ``NostrRelayServer`` de red de por medio).
    ``A`` anuncia; el relay emite al cliente de ``B``; ``B`` lo recibe (vía
    ``deliver`` que lee la bandeja entrante del cliente). Mismo contrato que
    la forma in-memory: ``DeploymentNode`` no cambia.

    Es **async** (el relay emite en su thread), así se espera a que ``B`` lo
    reciba (polling), como en ``test_mesh.py::test_mesh_pipeline_runs_over_quic``.
    """
    import time
    from delm.core.nostr import (
        NostrKey,
        NostrRelayServer,
        NostrRelayClient,
        NostrDiscoveryTransport,
    )
    server = NostrRelayServer()
    server.start()
    cA = cB = None
    try:
        key = NostrKey.new()
        cA = NostrRelayClient(f"ws://127.0.0.1:{server.port}")
        cA.connect()
        cB = NostrRelayClient(f"ws://127.0.0.1:{server.port}")
        cB.connect()
        busA = NostrDiscoveryTransport(cA, key)
        busB = NostrDiscoveryTransport(cB, key)
        a = DeploymentNode("A", owner, busA, now=lambda: 0.0, endpoint="ep-A")
        b = DeploymentNode("B", owner, busB, now=lambda: 0.0, endpoint="ep-B")
        a.maybe_announce()
        # B lo recibe (el relay emitió al cliente de B; esperarlo, es async).
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if b.poll() == 1:
                break
            time.sleep(0.05)
        assert "A" in b.peer_ids()
        # El anuncio de A está firmado por el owner (trust anchor).
        assert b.peers["A"].author == owner.owner_id
    finally:
        if cA is not None:
            cA.close()
        if cB is not None:
            cB.close()
        server.stop()
