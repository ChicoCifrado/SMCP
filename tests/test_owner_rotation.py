"""Tests de rotación/revocación de la clave del owner (Capa 4, control-plane).

Cubre la issue #4 (ciclo de vida de la clave del owner):

- **Rotación legítima**: el owner rota (``Owner.rotate``), el nodo aplica
  (``poll_commands``), ``current_owner_key`` pasa a la nueva clave y los
  anuncios/órdenes posteriores firmados con la nueva clave se aceptan.
- **Cadena rota**: una rotación firmada con una clave no vigente (no la
  ``current_owner_key`` del nodo) no verifica y se descarta (no se aplica).
- **Doble gasto**: dos rotaciones concurrentes desde la misma cadena vigente
  -> solo una se aplica (la primera vista; la segunda no verifica porque
  ``current_owner_key`` ya avanzó). La regla es determinista: la primera en
  ``poll_commands`` gana.

La cadena de confianza es append-only: ``rotation_history`` registra cada
eslabón (old -> new) y ``current_owner_key`` es el eslabón vigente.
"""
from __future__ import annotations

import pytest

from delm.core.deployment import (
    Command,
    DeploymentNode,
    DiscoveryBus,
    Owner,
)
from delm.core.provenance import KeyPair


# ------------------------------------------------------------------ helpers
def _setup():
    """Un owner, un bus y un nodo. Devuelve (owner, bus, node)."""
    owner = Owner("owner-a")
    bus = DiscoveryBus()
    node = DeploymentNode("n1", owner, bus)
    return owner, bus, node


def _new_owner_key() -> KeyPair:
    """Una clave nueva (la que el owner rotará a)."""
    return KeyPair.new("owner-a")


# ------------------------------------------------------------------ rotación legítima
def test_rotate_applies_and_advances_current_key():
    """El owner rota, el nodo aplica, current_owner_key avanza."""
    owner, bus, node = _setup()
    assert node.current_owner_key == owner.public_key  # inicial

    new_key = _new_owner_key()
    cmd = owner.rotate(new_key)
    node.inject_command(cmd)
    applied = node.poll_commands()

    assert applied == 1
    # current_owner_key avanza a la nueva clave.
    assert node.current_owner_key == new_key.public_key
    # El histórico registra el eslabón (append, inmutable).
    assert len(node.rotation_history) == 1
    assert node.rotation_history[0]["new_key"] == new_key.public_key
    # La orden queda en ``commands`` (ejecutada), no en ``dropped_commands``.
    assert len(node.commands) == 1
    assert len(node.dropped_commands) == 0


def test_after_rotate_new_key_signs_accepted_announcements():
    """Tras rotar, los anuncios firmados con la NUEVA clave se aceptan.

    El owner avanza (``advance``) y firma con la nueva clave; el nodo
    verifica contra ``current_owner_key`` (la nueva) y acepta.
    """
    owner, bus, node = _setup()
    new_key = _new_owner_key()
    cmd = owner.rotate(new_key)
    node.inject_command(cmd)
    node.poll_commands()
    # El owner avanza a la nueva clave.
    owner.advance(new_key)
    assert owner.public_key == new_key.public_key

    # El owner firma un anuncio con la NUEVA clave (la vigente).
    from delm.core.deployment import Announcement
    ann = Announcement(node_id="n2", endpoint="e", epoch=1, ts=1.0)
    owner.sign_announcement(ann)
    # El nodo lo recibe y lo verifica contra current_owner_key (nueva).
    assert node._verify_announcement(ann)


def test_after_rotate_new_key_signs_accepted_commands():
    """Tras rotar, las órdenes firmadas con la NUEVA clave se aceptan."""
    owner, bus, node = _setup()
    new_key = _new_owner_key()
    node.inject_command(owner.rotate(new_key))
    node.poll_commands()
    owner.advance(new_key)

    # El owner emite una orden (up) firmada con la nueva clave.
    cmd = Command(kind="up", node_id="n1")
    owner.sign_command(cmd)
    node.inject_command(cmd)
    applied = node.poll_commands()
    assert applied == 1
    assert node.status == "up"
    assert len(node.dropped_commands) == 0


# ------------------------------------------------------------------ cadena rota
def test_rotate_signed_with_non_current_key_is_dropped():
    """Una rotación firmada con una clave NO vigente no verifica.

    El nodo tiene ``current_owner_key`` = K0. Una orden firmada con una
    clave ajena (K_other) no verifica contra K0 y se descarta (no se
    aplica: ``current_owner_key`` no cambia, el histórico no crece).
    """
    owner, bus, node = _setup()
    # Una clave ajena (no la del owner, no la vigente).
    other = KeyPair.new("attacker")
    # El owner emite una rotate, pero la FIRMAMOS con la clave ajena
    # (simula un MITM que re-firma con su clave).
    cmd = Command(
        kind="rotate", node_id="",
        payload={"new_public_key": __import__("base64").b64encode(
            other.public_key).decode("ascii")},
    )
    cmd.signature = other.sign(cmd.digest())  # firmada por el atacante
    cmd.author = owner.owner_id
    node.inject_command(cmd)
    applied = node.poll_commands()

    # No se aplica: no verifica contra current_owner_key (K0).
    assert applied == 0
    assert len(node.dropped_commands) == 1
    assert len(node.rotation_history) == 0
    # current_owner_key no cambia.
    assert node.current_owner_key == owner.public_key


def test_stale_command_after_rotation_is_dropped():
    """Tras rotar a K1, una orden firmada con K0 (la anterior) se descarta.

    El nodo tiene ``current_owner_key`` = K1. Una orden firmada con K0 (la
    clave anterior) no verifica contra K1 y se descarta: es la detección de
    orden stale / replay (una orden de la cadena anterior no vale).
    """
    owner, bus, node = _setup()
    # Rota a K1 (aplicada; firmada con K0, la clave inicial).
    k1 = _new_owner_key()
    node.inject_command(owner.rotate(k1))
    node.poll_commands()
    assert node.current_owner_key == k1.public_key
    # owner aún tiene K0 (no ha hecho advance): sign_command firma con K0.
    stale = Command(kind="up", node_id="n1")
    owner.sign_command(stale)
    node.inject_command(stale)
    applied = node.poll_commands()
    # No se aplica: firmada con K0, no verifica contra K1.
    assert applied == 0
    assert len(node.dropped_commands) == 1
    # El histórico no crece (la stale no es una rotación aplicada).
    assert len(node.rotation_history) == 1


# ------------------------------------------------------------------ doble gasto
def test_double_spend_only_first_applies():
    """Dos rotaciones concurrentes desde la misma cadena vigente.

    El owner emite dos ``rotate`` hacia la MISMA new_key desde K0. La primera
    se aplica (current_owner_key -> new_key). La segunda, firmada con K0,
    ya no verifica contra current_owner_key (que ahora es new_key) y se
    descarta. Solo una se aplica: el histórico tiene un eslabón.
    """
    owner, bus, node = _setup()
    new_key = _new_owner_key()
    # Dos rotaciones concurrentes hacia la misma new_key.
    cmd1 = owner.rotate(new_key)
    cmd2 = owner.rotate(new_key)
    node.inject_command(cmd1)
    node.inject_command(cmd2)
    applied = node.poll_commands()

    # Solo la primera se aplica (la segunda no verifica tras la primera).
    assert applied == 1
    assert len(node.dropped_commands) == 1
    # El histórico tiene un solo eslabón (no dos).
    assert len(node.rotation_history) == 1
    # current_owner_key es new_key (la primera aplicó).
    assert node.current_owner_key == new_key.public_key


def test_double_spend_distinct_keys_only_first_applies():
    """Dos rotaciones concurrentes hacia CLAVES distintas.

    cmd1 -> K1, cmd2 -> K2, ambas firmadas con K0. La primera (K1) se aplica
    (current_owner_key -> K1). La segunda (K2), firmada con K0, no verifica
    contra current_owner_key (K1) y se descarta. current_owner_key = K1.
    """
    owner, bus, node = _setup()
    k1 = _new_owner_key()
    k2 = _new_owner_key()
    cmd1 = owner.rotate(k1)
    cmd2 = owner.rotate(k2)
    node.inject_command(cmd1)
    node.inject_command(cmd2)
    applied = node.poll_commands()

    assert applied == 1
    assert len(node.dropped_commands) == 1
    assert len(node.rotation_history) == 1
    # La primera (K1) ganó; current_owner_key es K1, no K2.
    assert node.current_owner_key == k1.public_key


# ------------------------------------------------------------------ histórico
def test_rotation_history_is_append_only():
    """El histórico es append-only: cada rotación añade un eslabón."""
    owner, bus, node = _setup()
    # Tres rotaciones encadenadas (K0 -> K1 -> K2 -> K3).
    keys = [_new_owner_key() for _ in range(3)]
    for k in keys:
        node.inject_command(owner.rotate(k))
        node.poll_commands()
        owner.advance(k)
    # Tres eslabones en el histórico (append-only).
    assert len(node.rotation_history) == 3
    # Cada eslabón enlaza: el old_key del siguiente es el new_key del previo.
    for i in range(len(node.rotation_history) - 1):
        assert node.rotation_history[i]["new_key"] == \
            node.rotation_history[i + 1]["old_key"]
    # El último eslabón es la clave vigente.
    assert node.current_owner_key == node.rotation_history[-1]["new_key"]
