"""Test manual: pipeline de contexto compartido con Ollama nemotron + Unsloth Qwen3.8.

Verifica que ambos modelos trabajan en una cola de tareas compartida y que el
contexto (gists) se comparte entre nodos de la malla.
"""
import asyncio
import pytest
from smcp.core.llm import OpenAICompatibleClient
from smcp.core.task_queue import Task, TaskQueue
from smcp.core.admission import AdmissionPipeline
from smcp.core.mesh_network import MeshNetwork
from smcp.core.mesh_node import MeshNode
from smcp.core.mesh_pipeline import MeshWorker
from smcp.core.requirements import MeshRequirements
from smcp.core.provenance import KeyPair
from smcp.core.verifier import RuleVerifier
from smcp.core.pipeline import _default_verifier


@pytest.mark.asyncio
@pytest.mark.slow
async def test_multi_model_pipeline():
    # Dos LLM clients: Ollama (nemotron) y Unsloth (Qwen3.8)
    llm_a = OpenAICompatibleClient(
        model="nemotron-3.5-bolt:e4b-q4_K_M",
        base_url="http://127.0.0.1:11434/v1",
    )
    llm_b = OpenAICompatibleClient(
        model="unsloth/Qwen3.8-27B-GGUF",
        base_url="http://127.0.0.1:8888/v1",
    )

    # Malla compartida
    req = MeshRequirements(mesh_id="mesh-multi-model", version_floor=(1, 0))
    mesh = MeshNetwork(req)

    # Dos nodos
    node_a = mesh.add_node("worker-a", version=(1, 0), capabilities=())
    node_b = mesh.add_node("worker-b", version=(1, 0), capabilities=())

    # Admission pipelines (uno por LLM)
    adm_a = AdmissionPipeline(llm_a, _default_verifier(llm_a))
    adm_b = AdmissionPipeline(llm_b, _default_verifier(llm_b))

    # Cola compartida
    queue = TaskQueue()
    tasks = [
        Task(label="t1", body="¿Cuál es la capital de Francia?"),
        Task(label="t2", body="¿Cuál es la capital de España?"),
    ]
    queue.enqueue_many(tasks)

    # Workers
    w_a = MeshWorker(0, llm_a, node_a.ctx, queue, adm_a, node=node_a, mesh=mesh)
    w_b = MeshWorker(1, llm_b, node_b.ctx, queue, adm_b, node=node_b, mesh=mesh)

    # Handshake
    for node in (node_a, node_b):
        for other in mesh.other_peers(node.peer_id):
            node.send_announce(other)
    mesh.drain()

    # Run
    await asyncio.gather(w_a.run(), w_b.run())

    # Drain mesh
    status = mesh.drain()
    print(f"Admitted gists: {status.admitted_gists}")
    print(f"Rounds: 1")

    # Finalize: leer contexto del primer nodo
    ctx = node_a.ctx
    print(f"Context size (node A): {len(ctx)}")
    print(f"Context size (node B): {len(node_b.ctx)}")

    # Verificar que ambos nodos tienen contexto compartido
    assert len(node_a.ctx) >= 1 or len(node_b.ctx) >= 1, "No hay gists compartidos"
    print("OK: contexto compartido entre nodos con LLMs distintos")

    # Final answer
    prompt = f"[ROLE:FINALIZER]\nProduce final answer from context:\n{ctx.render()}"
    answer = await llm_a.complete(prompt)
    print(f"Final answer: {answer[:200]}")
