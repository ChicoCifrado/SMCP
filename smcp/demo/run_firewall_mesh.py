"""Nodo de la prueba de fuego: inferencia real sobre QUIC (red real).

Lee el portmap, construye el nodo QUIC (servidor o cliente), lo envuelve
en un MeshNode, y resuelve una tarea: reason -> admit -> firma -> publica
el gist por QUIC al otro nodo. Ambos convergen al mismo contexto.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from typing import cast

from smcp.core.admission import AdmissionPipeline
from smcp.core.gist import Gist, GistKind
from smcp.core.mesh_node import MeshNode, MeshTransport
from smcp.core.provenance import KeyPair
from smcp.core.quic_host import QuicHostNode, QuicHostTransport
from smcp.core.requirements import MeshRequirements
from smcp.core.secure_context import SecureSharedContext
from smcp.core.task_queue import Task, TaskQueue
from smcp.core.llm import OpenAICompatibleClient
from smcp.core.verifier import RuleVerifier


async def run_node(tmpdir: str, name: str, task_body: str) -> None:
    with open(os.path.join(tmpdir, "portmap")) as f:
        portmap = json.load(f)
    me = portmap[name]
    role, port = me["role"], me["port"]
    my_host = me.get("host", "127.0.0.1")
    other_name = me["peer"]
    other = portmap[other_name]
    if role == "serve":
        peer_spec = (role, my_host, port)
    else:
        peer_spec = (role, other.get("host", "127.0.0.1"), other["port"])

    node = QuicHostNode(name, my_host, {other_name: peer_spec})
    node.start()
    transport = cast(MeshTransport, QuicHostTransport(node))

    ctx = SecureSharedContext()
    req = MeshRequirements(mesh_id="mesh-firewall", version_floor=(1, 0))
    mesh = MeshNode(
        peer_id=name, version=(1, 0), capabilities=(),
        transport=transport, ctx=ctx, key=KeyPair.new(name), req=req,
    )

    llm = OpenAICompatibleClient(
        model="unsloth/Qwen3.8-27B-GGUF",
        base_url=os.environ.get("DELM_BASE_URL", "http://127.0.0.1:8888/v1"),
        api_key="",
        timeout=240.0,
    )
    admission = AdmissionPipeline(llm=llm, verifier=RuleVerifier())

    # Gossip: anuncia hasta conocer al otro nodo.
    t0 = time.time()
    while time.time() - t0 < 60:
        mesh.send_announce(other_name)
        mesh.run_tick()
        if other_name in mesh._neighbors:
            break
        await asyncio.sleep(0.5)
    if other_name not in mesh._neighbors:
        raise SystemExit(f"{name}: no recibio el anuncio de {other_name}")

    # Resuelve la tarea (reason -> compress -> verify -> firma -> admit).
    task = Task(label=f"{name}-task", body=task_body, kind="solve", deps=[])
    raw = await llm.complete(task.body, system="Responde con un hecho concreto.")
    outcome = await admission.admit_source(
        ctx, task.label, raw, question=task.body,
        author_id=name, key=mesh.key)
    if outcome.admitted and outcome.gist is not None:
        # Publica el gist firmado por QUIC al otro nodo.
        payload = mesh.publish_gist(outcome.gist)
        transport.send(other_name, payload)

    # Drena hasta converger (recibir el gist del otro).
    t0 = time.time()
    while time.time() - t0 < 120:
        mesh.run_tick()
        if len(ctx) >= 2:
            break
        await asyncio.sleep(0.5)

    result = {"name": name, "gists": sorted(ctx.labels())}
    with open(os.path.join(tmpdir, f"{name}.result"), "w") as f:
        json.dump(result, f)
    node.close()


def main() -> None:
    argv = sys.argv[1:]
    role = argv[0] if argv else ""
    if role == "mesh-node":
        asyncio.run(run_node(argv[1], argv[2], argv[3]))
    else:
        raise SystemExit(f"rol desconocido: {role}")


if __name__ == "__main__":
    main()
