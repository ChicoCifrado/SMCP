"""test_mesh_v3: los flujos v3 dentro del bucle del nodo.

La integración: un nodo de malla (:class:`MeshNode`)
con el despachador :class:`MeshV3` inyectado. El
bucle (:meth:`MeshNode.run_tick`) drena el transporte
**una vez** y cada datagrama va a su plano — gossip
(0x01-0x07) al nodo, el bloque v3 (0x08-0x0D) al
despachador. Nada corre en hilos aparte: el join y
el intercambio son datagramas más, atendidos en el
mismo drenaje.

Y el descubrimiento de herramientas al arrancar
(:func:`smcp.core.tools.discover_tools`): el nodo
usa lo que el host tiene — el modelo que el MeshLLM
ofrece, el llmfit del PATH — y lo reporta.

Lo que sujetan los tests, en orden de importancia:

1. el nodo real, de punta a punta: gossip, join
   por el cable (dentro de ``run_tick``) e
   inferencia pedida, servida, firmada y cobrada;
2. el descubrimiento: MeshLLM sondeado, llmfit
   encontrado con su versión;
3. que el reporte dice lo que falta (sin MeshLLM
   ni llmfit el nodo arranca igual, con su doble
   determinista).
"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from smcp.core.bsv_keys import Secp256k1KeyPair
from smcp.core.contrib import ContributionLedger
from smcp.core.inscripcion import ORDINAL_SATOSHIS
from smcp.core.intercambio import (
    DEFAULT_FEE_SATOSHIS,
    InferenceServer,
)
from smcp.core.join import found
from smcp.core.llm import FakeLLMClient, OpenAICompatibleClient
from smcp.core.mensajeria import (
    InferenceRequester,
    InferenceResponder,
    MeshV3,
)
from smcp.core.mesh_node import MeshNode
from smcp.core.provenance import KeyPair
from smcp.core.registro import InferenceRegistry
from smcp.core.requirements import MeshRequirements
from smcp.core.secure_context import SecureSharedContext
from smcp.core.tiers import PER_INFERENCE_SATOSHIS
from smcp.core.tools import discover_tools, llm_from_report
from smcp.core.transport import InMemoryTransport, _Bus
from smcp.core.txbuild import TxIn

from test_mensajeria import MESH, NOW, _FakeArc, _admit

_TICK = 0.005


def _nodos() -> tuple[
        MeshNode, MeshNode, MeshV3, MeshV3,
        InMemoryTransport, InMemoryTransport,
        ContributionLedger, InferenceRegistry,
        Secp256k1KeyPair]:
    """Dos nodos de malla con el v3 inyectado, sobre
    un bus in-memory compartido.

    B sirve inferencias (su modelo es el doble
    determinista — el de verdad lo descubre el
    despliegue, con :func:`smcp.core.tools.discover_tools`).
    """
    bus = _Bus()
    a_t, b_t = InMemoryTransport(bus, "A"), InMemoryTransport(bus, "B")

    # El servidor de inferencias de B.
    bkey = Secp256k1KeyPair.new("B")
    led = ContributionLedger(MESH)
    _admit(led, "B", 8.0)
    registry = InferenceRegistry()
    responder = InferenceResponder(
        transport=b_t,
        server=InferenceServer(
            server_key=bkey, llm=FakeLLMClient(),
            arc=_FakeArc(), ledger=led, peer_id="B",
            registry=registry,
        ),
    )

    # El estado del join de cada nodo: su roster
    # fundado (la clave es la del nodo — la misma
    # que firma gists y handshakes).
    a_id, b_id = KeyPair.new("A"), KeyPair.new("B")
    a_roster, a_keyring = found(MESH, "A", a_id, now=NOW)
    b_roster, b_keyring = found(MESH, "B", b_id, now=NOW)

    a_v3 = MeshV3(
        transport=a_t, roster=a_roster,
        key=a_id, keyring=a_keyring,
    )
    b_v3 = MeshV3(
        transport=b_t, roster=b_roster,
        key=b_id, keyring=b_keyring,
        responder=responder,
    )

    # Los nodos de malla (gossip) con el v3 inyectado.
    req = MeshRequirements(mesh_id=MESH, version_floor=(1, 0))
    a_node = MeshNode(
        "A", (1, 0), (), transport=a_t,
        ctx=SecureSharedContext(), key=a_id, req=req, v3=a_v3,
    )
    b_node = MeshNode(
        "B", (1, 0), (), transport=b_t,
        ctx=SecureSharedContext(), key=b_id, req=req, v3=b_v3,
    )
    return (a_node, b_node, a_v3, b_v3, a_t, b_t,
            led, registry, bkey)


def test_el_nodo_corre_los_flujos_v3_en_su_bucle() -> None:
    """Gossip, join e intercambio — todo en ``run_tick``.

    El bucle de B corre en su hilo (un nodo
    desplegado); el de A se mueve a mano desde el
    hilo principal. El join completa **dentro** del
    bucle y la inferencia se pide, sirve, firma y
    cobra entre los dos nodos.
    """
    (a_node, b_node, a_v3, _b_v3, a_t, _b_t,
     led, registry, _bkey) = _nodos()

    # El bucle de B corre en su hilo.
    stop = threading.Event()

    def _bucle() -> None:
        while not stop.is_set():
            b_node.run_tick()
            time.sleep(_TICK)

    hilo = threading.Thread(target=_bucle, daemon=True)
    hilo.start()
    try:
        # Gossip: el primer anuncio es conocimiento
        # de fuera de banda (el portmap); de ahí en
        # más, los anuncios se cruzan solos.
        a_node.send_announce("B")
        b_node.send_announce("A")
        for _ in range(50):
            a_node.run_tick()
            time.sleep(_TICK)
            if "B" in a_node._neighbors and "A" in b_node._neighbors:
                break
        assert "B" in a_node._neighbors
        assert "A" in b_node._neighbors

        # El join: A lo inicia y los dos bucles lo
        # mueven — los mensajes del join son datagramas
        # más, en el mismo drenaje.
        a_v3.start_join("B")
        for _ in range(100):
            a_node.run_tick()
            time.sleep(_TICK)
            if a_v3.results:
                break
        assert a_v3.results, "el join no completó"
        resultado = a_v3.results[0]
        assert resultado.mutual
        assert resultado.authenticated is True

        # La inferencia: A pide (su transporte lo
        # drena la petición misma), B sirve dentro de
        # su bucle, A paga, B cobra.
        akey = Secp256k1KeyPair.new("A")
        requester = InferenceRequester(transport=a_t, key=akey)
        response, tx = requester.request(
            to="B", prompt="hola", mesh_id=MESH,
            funding=TxIn("ab" * 32, 0),
        )
        assert response == "OK"
        assert tx.inputs[0].script_sig       # el fondeo, firmado

        # El cobro llega en el bucle de B.
        deadline = time.monotonic() + 5.0
        while not led.peers["B"].inferences_served:
            if time.monotonic() >= deadline:
                raise AssertionError("el servidor no cobró a tiempo")
            time.sleep(0.01)
    finally:
        stop.set()
        hilo.join(timeout=5)

    # El libro tiene la inferencia, con el txid de la
    # tx que A firmó, y B cobró lo que la tarifa deja.
    rec = registry.by_txid(tx.txid())
    assert rec is not None
    assert rec.mesh_id == MESH
    assert rec.requester_pubkey == akey.public_key.hex()
    assert led.peers["B"].inferences_served == 1
    assert led.peers["B"].satoshis_earned == (
        PER_INFERENCE_SATOSHIS - ORDINAL_SATOSHIS
        - DEFAULT_FEE_SATOSHIS
    )


class _ModelsHandler(BaseHTTPRequestHandler):
    """Un MeshLLM mínimo: ``/v1/models`` con un modelo."""

    def do_GET(self) -> None:
        if self.path.endswith("/models"):
            cuerpo = json.dumps(
                {"data": [{"id": "mesh-model-fake"}]},
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(cuerpo)))
            self.end_headers()
            self.wfile.write(cuerpo)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass        # silencio


def _fake_llmfit(tmp_path: Path) -> str:
    """Un llmfit falso: responde ``--version``."""
    script = tmp_path / "llmfit"
    script.write_text("#!/bin/sh\necho 'llmfit, version 9.9.9-test'\n")
    script.chmod(0o755)
    return str(script)


def test_descubre_el_meshllm_y_el_llmfit(tmp_path: Path) -> None:
    """Al arrancar: el modelo que MeshLLM ofrece y el
    llmfit del host, con su versión."""
    servidor = HTTPServer(("127.0.0.1", 0), _ModelsHandler)
    hilo = threading.Thread(target=servidor.serve_forever,
                            daemon=True)
    hilo.start()
    try:
        url = f"http://127.0.0.1:{servidor.server_address[1]}/v1"
        reporte = discover_tools(
            mesh_llm_url=url, llmfit_bin=_fake_llmfit(tmp_path),
        )
    finally:
        servidor.shutdown()
    assert reporte.mesh_llm_model == "mesh-model-fake"
    assert reporte.llmfit is not None
    assert reporte.llmfit_version == "9.9.9"
    # El modelo que sirve el nodo es el que descubrió.
    llm = llm_from_report(reporte)
    assert isinstance(llm, OpenAICompatibleClient)
    assert llm.model == "mesh-model-fake"


def test_el_reporte_dice_lo_que_falta() -> None:
    """Sin MeshLLM ni llmfit: el nodo arranca igual,
    y el reporte lo dice (no es una degradación
    silenciosa)."""
    # Un MeshLLM que no responde (puerto cerrado) y
    # un llmfit que no existe.
    reporte = discover_tools(
        mesh_llm_url="http://127.0.0.1:1/v1",
        llmfit_bin="/nonexistent/llmfit",
        timeout_s=1.0,
    )
    assert reporte.mesh_llm_model is None
    assert reporte.llmfit is None
    assert reporte.llmfit_version is None
    # ... y el nodo sirve con su doble determinista.
    llm = llm_from_report(reporte)
    assert isinstance(llm, FakeLLMClient)
