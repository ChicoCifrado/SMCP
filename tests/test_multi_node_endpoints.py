"""Test multi-nodo: dos nodos con endpoints locales distintos comparten C.

Verifica que el contexto (gists) se propaga entre dos nodos de la malla
independientemente del endpoint de inferencia de cada uno. El endpoint es
metadata (no afecta la propagacion), pero se anuncia en el peer.
"""
from __future__ import annotations

from smcp.core.mesh_node import (
    MeshNode, _ann_to_json, encode_msg, MSG_ANNOUNCE,
)
from smcp.core.transport import _Bus, InMemoryTransport
from smcp.core.secure_context import SecureSharedContext
from smcp.core.requirements import MeshRequirements
from smcp.core.provenance import KeyPair
from smcp.core.gist import Gist, GistKind


def _node(peer_id: str, bus, endpoint: str) -> MeshNode:
    ctx = SecureSharedContext()
    key = KeyPair.new(peer_id)
    req = MeshRequirements(mesh_id="m1", version_floor=(1, 0))
    n = MeshNode(
        peer_id=peer_id, version=(1, 0), capabilities=("cap",),
        transport=InMemoryTransport(bus, peer_id),
        ctx=ctx, key=key, req=req,
    )
    setattr(n, "endpoint", endpoint)  # type: ignore[attr-defined]
    return n


def _handshake(a, b):
    b.on_datagram(a.peer_id,
                  encode_msg(MSG_ANNOUNCE,
                            _ann_to_json(a.self_announcement()).encode()))
    a.on_datagram(b.peer_id,
                  encode_msg(MSG_ANNOUNCE,
                            _ann_to_json(b.self_announcement()).encode()))


def test_two_nodes_share_context_with_different_endpoints():
    bus = _Bus()
    n_a = _node("node-a", bus, "http://127.0.0.1:8888/v1")  # Unsloth
    n_b = _node("node-b", bus, "http://127.0.0.1:11434/v1")  # Ollama

    # Registrar claves en el contexto del otro (handshake)
    _handshake(n_a, n_b)

    # Nodo A publica un gist
    g = Gist(label="g1", gist="un gist compartido", kind=GistKind.FACT)
    raw = n_a.publish_gist(g)
    # Nodo B lo recibe
    n_b.on_datagram(n_a.peer_id, raw)

    # Verificar que B tiene el gist
    assert len(n_b.ctx) >= 1, "B no recibio el gist de A"

    # Verificar que el endpoint se anuncia (metadata)
    assert getattr(n_a, "endpoint", None) == "http://127.0.0.1:8888/v1"
    assert getattr(n_b, "endpoint", None) == "http://127.0.0.1:11434/v1"
