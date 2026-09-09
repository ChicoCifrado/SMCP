"""Pipeline sobre la malla (capa 3) — ``DelmPipeline`` corriendo sobre la malla.

La diferencia con :class:`~delm.core.pipeline.DelmPipeline` es el **camino del
gist**: aquí cada worker no escribe en un ``ctx`` global, sino que **publica el
gist por la malla** (firma + envía a los demás nodos) y lo admite en el
``SecureSharedContext`` **de su propio nodo**. Al drenarse la malla, todos los
nodos han recibido todos los gists, y la finalización lee de la malla.

Es el mismo bucle de :mod:`delm.core.pipeline` (claim → reason → admit), pero
el ``ctx`` de cada worker es el de su nodo, y el admit **también** publica por
la malla. Reutiliza :class:`~delm.core.pipeline.Worker` sobreescribiendo
``_admit``.
"""
from __future__ import annotations

import asyncio
from typing import Callable, Optional

from delm.core.admission import AdmissionPipeline
from delm.core.gist import Gist, GistKind
from delm.core.llm import LLMClient
from delm.core.pipeline import Worker, WorkerResult, _default_verifier
from delm.core.provenance import KeyPair
from delm.core.requirements import MeshRequirements
from delm.core.mesh_network import MeshNetwork
from delm.core.mesh_node import MeshNode
from delm.core.task_queue import Task, TaskQueue


class MeshWorker(Worker):
    """Un worker que corre **sobre la malla**.

    Su ``ctx`` es el :class:`SecureSharedContext` de su nodo. Al admitir un
    gist, además de admitirlo localmente, **lo publica por la malla** (firma +
    envía a los demás nodos), para que la malla lo propague.
    """

    def __init__(self, worker_id: int, llm: LLMClient, ctx, queue: TaskQueue,
                 admission: AdmissionPipeline, node: MeshNode,
                 mesh: MeshNetwork,
                 author_id: Optional[str] = None,
                 key: Optional[KeyPair] = None,
                 metrics=None) -> None:
        super().__init__(
            worker_id, llm, ctx, queue, admission,
            author_id=author_id or node.peer_id,
            key=key or node.key,
            metrics=metrics,
        )
        self.node = node
        self.mesh = mesh

    async def _admit(self, task: Task, raw: str):
        outcome = await super()._admit(task, raw)
        # Publica el gist admitido por la malla (firma + envía a los demás).
        if outcome.admitted and outcome.gist is not None:
            self._publish(outcome.gist)
        return outcome

    def _publish(self, gist: Gist) -> None:
        """Firma ``gist`` y lo envía a los demás nodos de la malla."""
        payload = self.node.publish_gist(gist)
        for other in self.mesh.other_peers(self.node.peer_id):
            self.node.transport.send(other, payload)


class MeshPipeline:
    """El bucle de DELM corriendo **sobre la malla**.

    ``n_workers`` nodos, uno por worker. Cada worker admite en el ``ctx`` de su
    nodo y **publica el gist por la malla**. Al final, drena la malla y
    finaliza leyendo de la malla.

    Es el mismo contrato que :class:`~delm.core.pipeline.DelmPipeline`
    (``run(initial_tasks)``), pero el gist viaja por la malla.
    """

    def __init__(self, llm: LLMClient, n_workers: int = 4,
                 requirements: Optional[MeshRequirements] = None,
                 secure: bool = True,
                 metrics=None,
                 quic: bool = False,
                 nostr: bool = False) -> None:
        self.llm = llm
        self.n_workers = n_workers
        self.secure = secure
        self.metrics = metrics
        if requirements is None:
            requirements = MeshRequirements(mesh_id="mesh-default")
        self.requirements = requirements
        # Modo QUIC: un ``QuicSwarm`` compartido (transporte real). Si no,
        # ``None`` (in-memory, por defecto).
        if quic:
            from delm.core.transport import QuicSwarm
            self._swarm = QuicSwarm()
        else:
            self._swarm = None
        # Modo Nostr: la malla corre **sobre red** (un relay Nostr hace el
        # fan-out). Un ``NostrSwarm`` compartido; si no, ``None``.
        if nostr:
            from delm.core.transport import NostrSwarm
            self._nostr = NostrSwarm()
        else:
            self._nostr = None
        self.mesh = MeshNetwork(requirements, swarm=self._swarm,
                                 nostr=self._nostr)
        # Un nodo por worker.
        self._nodes: list[MeshNode] = [
            self.mesh.add_node(f"worker-{i}", version=(1, 0), capabilities=())
            for i in range(n_workers)
        ]
        # Un AdmissionPipeline por worker (verificación local).
        self._admissions: list[AdmissionPipeline] = [
            AdmissionPipeline(llm, _default_verifier(llm)) for _ in self._nodes
        ]

    # -- run ---------------------------------------------------------------
    async def run(self, initial_tasks: list[Task],
                  max_rounds: int = 8) -> "MeshPipelineOutcome":
        queue = TaskQueue()
        queue.enqueue_many(initial_tasks)
        workers = [
            MeshWorker(
                i, self.llm, self._nodes[i].ctx, queue, self._admissions[i],
                node=self._nodes[i], mesh=self.mesh, metrics=self.metrics,
            )
            for i in range(self.n_workers)
        ]
        rounds = 0
        while rounds < max_rounds:
            # Todos los workers corren en paralelo sobre la malla.
            await asyncio.gather(*(w.run() for w in workers))
            rounds += 1
            if queue.is_empty():
                break
            if not queue.eligible_labels():
                break
        # Drena la malla hasta convergencia (los gists se propagan).
        status = self.mesh.drain()
        answer = await self._finalize()
        return MeshPipelineOutcome(
            answer=answer,
            admitted_gists=status.admitted_gists,
            rounds=rounds,
            workers=[w.result for w in workers],
            mesh_status=status,
        )

    # -- finalize ----------------------------------------------------------
    async def _finalize(self) -> str:
        """Finaliza leyendo de la malla (el ``ctx`` del primer nodo).

        Tras el drenado, el primer nodo ha recibido todos los gists (el
        broadcast llega a todos), así su ``ctx`` es la vista completa.
        """
        ctx = self._nodes[0].ctx
        prompt = (
            "[ROLE:FINALIZER]\n"
            "Produce the final answer strictly from the verified shared "
            "context below. Do not introduce new claims.\n"
            f"shared context:\n{ctx.render()}"
        )
        return await self.llm.complete(prompt)


class MeshPipelineOutcome:
    """Resultado de :meth:`MeshPipeline.run`."""

    def __init__(self, answer: str, admitted_gists: int, rounds: int,
                 workers: list[WorkerResult], mesh_status) -> None:
        self.answer = answer
        self.admitted_gists = admitted_gists
        self.rounds = rounds
        self.workers = workers
        self.mesh_status = mesh_status
