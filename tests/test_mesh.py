"""Tests de la capa 3 integrada — transporte, nodo, malla, pipeline.

Cubre:
* ``transport`` — ``InMemoryTransport`` (cola entrante, poll) y el contrato.
* ``mesh_node`` — firma/publicación de gists, recepción (firma verificada),
  heartbeat, ciclo de vida.
* ``mesh_network`` — nodos, drenado, convergencia, estado.
* ``mesh_pipeline`` — el pipeline corre **sobre la malla** y converge.
"""
from __future__ import annotations

import asyncio

import pytest

from delm.core.gist import Gist, GistKind
from delm.core.llm import FakeLLMClient
from delm.core.provenance import KeyPair
from delm.core.requirements import MeshRequirements
from delm.core.secure_context import SecureSharedContext
from delm.core.task_queue import Task
from delm.core.transport import InMemoryTransport, QuicTransport, _Bus, MeshTransport
from delm.core.mesh_node import (
    MeshNode, MSG_ANNOUNCE, MSG_GIST, MSG_HEARTBEAT,
    encode_msg, decode_msg,
)
from delm.core.mesh_network import MeshNetwork
from delm.core.mesh_pipeline import MeshPipeline


# ===========================================================================
# transport
# ===========================================================================

def test_inmemory_send_and_poll():
    bus = _Bus()
    a = InMemoryTransport(bus, "a")
    b = InMemoryTransport(bus, "b")
    a.send("b", b"hola")
    a.send("b", b"mundo")
    got = b.poll()
    assert got == [("a", b"hola"), ("a", b"mundo")]


def test_inmemory_poll_empty():
    bus = _Bus()
    a = InMemoryTransport(bus, "a")
    assert a.poll() == []


def test_inmemory_is_mesh_transport():
    bus = _Bus()
    a = InMemoryTransport(bus, "a")
    assert isinstance(a, MeshTransport)


def test_encode_decode_roundtrip():
    data = encode_msg(MSG_GIST, b"payload")
    kind, body = decode_msg(data)
    assert kind == MSG_GIST
    assert body == b"payload"


def test_decode_empty_raises():
    with pytest.raises(ValueError):
        decode_msg(b"")


# ===========================================================================
# mesh_node
# ===========================================================================

def _node(peer_id: str, bus: _Bus) -> MeshNode:
    ctx = SecureSharedContext()
    key = KeyPair.new(peer_id)
    req = MeshRequirements(mesh_id="m1", version_floor=(1, 0))
    return MeshNode(
        peer_id=peer_id, version=(1, 0), capabilities=("cap",),
        transport=InMemoryTransport(bus, peer_id),
        ctx=ctx, key=key, req=req,
    )


def test_node_publish_gist_signs_and_encodes():
    bus = _Bus()
    n = _node("n1", bus)
    g = Gist(label="g1", gist="un gist", kind=GistKind.FACT)
    raw = n.publish_gist(g)
    kind, body = decode_msg(raw)
    assert kind == MSG_GIST
    # El gist está firmado bajo la key del nodo.
    assert g.digest
    assert g.signature
    assert g.author_id == "n1"


def test_node_receives_gist_and_admits():
    bus = _Bus()
    n1 = _node("n1", bus)
    n2 = _node("n2", bus)
    # n1 publica y n2 recibe.
    g = Gist(label="g1", gist="un gist", kind=GistKind.FACT)
    n1.publish_gist(g)
    # n2 recibe el datagrama (lo emite n1 por el bus).
    for from_id, payload in n1.transport.poll() if False else []:
        pass
    # Envia el datagrama de n1 a n2 directamente.
    raw = n1.publish_gist(Gist(label="g2", gist="otro", kind=GistKind.FACT))
    n2.on_datagram("n1", raw)
    # El gist admitido aparece en el ctx de n2.
    assert len(n2.ctx) == 1
    assert n2.ctx.get("g2") is not None


def test_node_heartbeat_marks_down():
    bus = _Bus()
    n = _node("n1", bus)
    n.heartbeat.beat("ghost", now=10)
    # Un par no visto tras la ventana se marca down.
    n.heartbeat.sweep(now=100)
    assert n.heartbeat.is_down("ghost") is True


def test_node_announce_roundtrip():
    bus = _Bus()
    n1 = _node("n1", bus)
    n2 = _node("n2", bus)
    # n1 envía su anuncio a n2.
    n1.send_announce("n2")
    # n2 lo recibe.
    got = n2.transport.poll()
    assert len(got) == 1
    from_id, payload = got[0]
    n2.on_datagram(from_id, payload)
    # El anuncio queda en la tabla de n2.
    assert "n1" in n2.table.peers


# ===========================================================================
# mesh_network
# ===========================================================================

def test_network_add_node_and_status():
    req = MeshRequirements(mesh_id="m1", version_floor=(1, 0))
    net = MeshNetwork(req)
    net.add_node("n1", version=(1, 0))
    net.add_node("n2", version=(1, 0))
    st = net.status()
    assert st.peers == 2
    assert st.admitted_gists == 0


def test_network_duplicate_node_raises():
    req = MeshRequirements(mesh_id="m1")
    net = MeshNetwork(req)
    net.add_node("n1", version=(1, 0))
    with pytest.raises(ValueError):
        net.add_node("n1", version=(1, 0))


def test_network_drain_converges():
    req = MeshRequirements(mesh_id="m1", version_floor=(1, 0))
    net = MeshNetwork(req)
    net.add_node("n1", version=(1, 0))
    net.add_node("n2", version=(1, 0))
    # Un drenado converge (punto fijo del gossip).
    st = net.drain()
    assert st.converged is True
    assert st.ticks >= 1


def test_network_other_peers():
    req = MeshRequirements(mesh_id="m1")
    net = MeshNetwork(req)
    net.add_node("n1", version=(1, 0))
    net.add_node("n2", version=(1, 0))
    net.add_node("n3", version=(1, 0))
    assert set(net.other_peers("n1")) == {"n2", "n3"}


# ===========================================================================
# mesh_pipeline
# ===========================================================================

def _run(coro):
    return asyncio.run(coro)


def test_mesh_pipeline_runs_and_converges():
    llm = FakeLLMClient()
    req = MeshRequirements(mesh_id="m1", version_floor=(1, 0),
                           protocol_generation=1)
    pipe = MeshPipeline(llm=llm, n_workers=4, requirements=req)
    tasks = [Task(label=f"t{i}", body=f"do {i}", kind="solve") for i in range(4)]
    out = _run(pipe.run(tasks))
    # El pipeline corre sobre la malla y converge.
    assert out.mesh_status.converged is True
    assert out.mesh_status.peers == 4
    # Cada nodo tiene el conjunto completo de gists (convergencia).
    sizes = [len(n.ctx) for n in pipe.mesh]
    assert len(set(sizes)) == 1, f"no converge: {sizes}"
    # El nº de gists únicos == nº de workers (uno por worker).
    assert sizes[0] == 4
    # La respuesta se produce.
    assert out.answer


def test_mesh_pipeline_runs_over_quic():
    """El pipeline corre **sobre QUIC** (aioquic) y converge igual.

    Mismo contrato que :func:`test_mesh_pipeline_runs_and_converges`, pero el
    transporte es un :class:`~delm.core.transport.QuicSwarm` (handshake
    ECDSA P-256 + ALPN ``smcp/1`` + datos bidireccionales), no el bus
    in-memory. La malla converge y cada nodo recibe todos los gists.
    """
    llm = FakeLLMClient()
    req = MeshRequirements(mesh_id="m1", version_floor=(1, 0),
                           protocol_generation=1)
    pipe = MeshPipeline(llm=llm, n_workers=4, requirements=req, quic=True)
    # Verifica que el transporte es QUIC (no in-memory).
    assert pipe._swarm is not None
    assert any(isinstance(n.transport, QuicTransport) for n in pipe.mesh)
    tasks = [Task(label=f"t{i}", body=f"do {i}", kind="solve") for i in range(4)]
    out = _run(pipe.run(tasks))
    # El pipeline corre sobre QUIC y converge.
    assert out.mesh_status.converged is True
    assert out.mesh_status.peers == 4
    # Cada nodo tiene el conjunto completo de gists (convergencia).
    sizes = [len(n.ctx) for n in pipe.mesh]
    assert len(set(sizes)) == 1, f"no converge: {sizes}"
    assert sizes[0] == 4
    # La respuesta se produce.
    assert out.answer


def test_mesh_pipeline_secure_admission():
    """Los gists se admiten de forma segura (firmados) por la malla."""
    llm = FakeLLMClient()
    req = MeshRequirements(mesh_id="m1", version_floor=(1, 0))
    pipe = MeshPipeline(llm=llm, n_workers=2, requirements=req)
    tasks = [Task(label="t0", body="x", kind="solve")]
    out = _run(pipe.run(tasks))
    # El gist admitido está firmado (digest + signature presentes).
    node = next(iter(pipe.mesh))
    gists = list(node.ctx)
    assert len(gists) == 1
    g = gists[0]
    assert g.digest
    assert g.signature
    assert g.author_id
