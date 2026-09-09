"""Tests del transporte QUIC entre hosts (:class:`QuicHostNode`).

Verifican que el transporte QUIC entre hosts funciona de punta a punta
sobre sockets reales: los nodos corren en threads distintos, cada uno con
su event loop asyncio, y el datagrama viaja por la red (no se entrega
directamente).

Cubre:

* **Framing**: el framing length-prefix parte los datagramas al
  reconstruirlos en ``poll``.
* **Round-trip 1 par**: cliente → servidor → cliente.
* **Malla completa (3 nodos)**: A, B, C, cada uno habla con cada otro.
"""
from __future__ import annotations

import time

from delm.core.quic_host import (
    QuicHostSwarm,
    _deframe,
    _frame,
)


# ---------------------------------------------------------------------------
# Framing (length-prefix) — mismo que QuicSwarm
# ---------------------------------------------------------------------------
def test_frame_deframe_round_trip():
    """El framing length-prefix parte los datagramas al reconstruirlos."""
    # Un datagrama.
    msgs, rest = _deframe(_frame(b"hello"))
    assert msgs == [b"hello"]
    assert rest == b""
    # Varios datagramas en el mismo buffer (coalescidos).
    buf = _frame(b"a") + _frame(b"bb") + _frame(b"ccc")
    msgs, rest = _deframe(buf)
    assert msgs == [b"a", b"bb", b"ccc"]
    assert rest == b""
    # Un datagrama parcial (queda en el resto).
    buf = _frame(b"hello")[:6]  # 4 (longitud) + 2 bytes del payload
    msgs, rest = _deframe(buf)
    assert msgs == []
    assert len(rest) == 6


# ---------------------------------------------------------------------------
# Round-trip 1 par
# ---------------------------------------------------------------------------
def test_quic_host_round_trip():
    """Cliente → servidor → cliente: el datagrama viaja por la red.

    El cliente y el servidor corren en threads distintos, cada uno con su
    event loop asyncio. El datagrama viaja por la red (no se entrega
    directamente).
    """
    swarm = QuicHostSwarm()
    swarm.add_peer("A", "127.0.0.1")
    swarm.add_peer("B", "127.0.0.1")
    swarm.start()
    try:
        # A envía a B.
        swarm.transport_for("A").send("B", b"hola-quic")
        # B recibe (por la red).
        deadline = time.time() + 15
        received = None
        while time.time() < deadline:
            msgs = swarm.transport_for("B").poll()
            if msgs:
                received = msgs[0][1]  # (from, payload)
                break
            time.sleep(0.05)
        assert received == b"hola-quic", f"B no recivio: {received!r}"
        # B responde a A.
        swarm.transport_for("B").send("A", b"hola-vuelta")
        deadline = time.time() + 15
        received2 = None
        while time.time() < deadline:
            msgs = swarm.transport_for("A").poll()
            if msgs:
                received2 = msgs[0][1]
                break
            time.sleep(0.05)
        assert received2 == b"hola-vuelta", f"A no recivio: {received2!r}"
    finally:
        swarm.close()


# ---------------------------------------------------------------------------
# Malla completa (3 nodos)
# ---------------------------------------------------------------------------
def test_quic_host_mesh_full():
    """Malla completa: A, B, C, cada uno habla con cada otro.

    El swarm asigna puertos (un por par) y cada nodo corre en su thread.
    Cada nodo envía un datagrama a cada otro; se verifica que cada uno
    recibe los de cada otro.
    """
    swarm = QuicHostSwarm()
    for nid in ("A", "B", "C"):
        swarm.add_peer(nid, "127.0.0.1")
    swarm.start()
    try:
        # Cada nodo envía un datagrama a cada otro.
        for nid in ("A", "B", "C"):
            for other in ("A", "B", "C"):
                if other != nid:
                    swarm.transport_for(nid).send(
                        other, f"from-{nid}".encode()
                    )
        # Cada nodo recibe los de cada otro (3 nodos, cada uno recibe 2).
        deadline = time.time() + 20
        received: dict[str, set] = {"A": set(), "B": set(), "C": set()}
        while time.time() < deadline:
            for nid in ("A", "B", "C"):
                msgs = swarm.transport_for(nid).poll()
                for _frm, payload in msgs:
                    received[nid].add(payload.decode())
            if all(len(v) >= 2 for v in received.values()):
                break
            time.sleep(0.05)
        # Verifica que cada nodo recivio los 2 datagramas (de cada otro).
        for nid in ("A", "B", "C"):
            assert len(received[nid]) >= 2, (
                f"{nid} no recivio todos: {received[nid]}"
            )
    finally:
        swarm.close()
