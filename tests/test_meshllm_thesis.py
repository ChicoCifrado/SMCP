"""La tesis contra un endpoint REAL (opt-in, ``slow``).

Por qué este archivo y ``test_exchange_thesis.py`` son distintos:

* ``test_exchange_thesis.py`` prueba la cadena **offline**, con anclas
  verificadas contra una cabecera construida en el test. Es la que corre en CI.
* Este prueba que la cadena cierra contra **una inferencia de verdad**: una
  llamada a un endpoint OpenAI-compatible de verdad, con un modelo de verdad.

Eso ultimo es lo que los tests offline no pueden ver. Que el nodo pueda
**anclar** lo que sirvió contra hardware real: el contenido de la respuesta no
se publica (la decisión de `anchor.py` sigue en pie), pero el registro tiene que
construirse, firmarse con la clave de membresía y admitir la inclusion de la
transacción. Si eso fallara contra un endpoint de verdad, el historial no
subiría y el intercambio no existiría.

``slow`` y opt-in: se skipea si no hay endpoint. Sin CI hard-dependency.

Lo que **ya no** se prueba aqui, y por qué: que el crédito decided si la
inferencia se servía. No hay crédito — el valor es el satoshi y se mueve en la
cadena—, así que la mediación que queda es de otro sitio y ya está cubierta
offline: un nodo que no ofrece VRAM no recibe carga (``test_placement.py``) y
una inferencia sin ancla no sube ningún contador (``test_exchange_thesis.py``).

Run manual::

    MESH_LLM_URL=http://127.0.0.1:9337/v1 \
      python -m pytest tests/test_meshllm_thesis.py -m slow -v
"""
from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request

import pytest

from delm.core.anchor import AnchorLedger, AnchorRecord
from delm.core.bsv_keys import Secp256k1KeyPair
from delm.core.contrib import CapacityReport, ContributionLedger
from delm.core.llm import OpenAICompatibleClient
from delm.core.membership import BlockHeader, InclusionProof, MembershipOutput, merkle_root
from delm.core.placement import ModelSpec, plan_placement
from delm.core.provenance import KeyPair
from delm.core.reputation import board_from_counters

MESH_URL = os.environ.get("MESH_LLM_URL", "http://127.0.0.1:8888/v1")
PROBE_TIMEOUT = float(os.environ.get("MESH_PROBE_TIMEOUT", "10.0"))
#: Un modelo con razonamiento se come el presupuesto de tokens en razonar y
#: devuelve `finish_reason="length"` con la respuesta vacia. Por eso el
#: default es holgado: el objetivo es una cadena, no una frase.
MAX_TOKENS = int(os.environ.get("MESH_MAX_TOKENS", "256"))


# --------------------------------------------------------------- helpers
def _probe(url: str) -> str | None:
    """Primer ``model.id`` de ``{url}/models``, o ``None`` si no hay endpoint."""
    try:
        with urllib.request.urlopen(url + "/models", timeout=PROBE_TIMEOUT) as r:
            data = json.loads(r.read())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, OSError, ValueError):
        return None
    models = data.get("data", [])
    return models[0].get("id") if models else None


def _admit(led: ContributionLedger, peer: str, vram: float, key: KeyPair,
           mesh: str, now: float, *, seconds: float = 1800.0) -> bool:
    """Firma y admite una capacidad, y marca el nodo como observado."""
    ch = led.issue_challenge(peer, now=now)
    rep = CapacityReport(mesh_id=mesh, peer_id=peer, vram_gb=vram,
                         vram_advertised_gb=vram, ram_gb=32.0, cpu_cores=8,
                         nonce=ch.nonce, issued_at=now,
                         expires_at=now + 3600).sign(key)
    ok, _ = led.admit(rep, now=now)
    if ok and seconds:
        led.observe(peer, now, dt_s=seconds)
    return ok


def _served_inference(model_id: str) -> str:
    """One real completion. Returns the text the endpoint produced.

    ``MESH_LLM_KEY`` defaults to **empty**: el endpoint local (Unsloth,
    la malla MeshLLM) no exige auth, y cualquier `Authorization` no
    vacío lo hace rechazar (401). Vacío es lo que activa el camino
    sin auth de `OpenAICompatibleClient` (que quita la cabecera).
    """
    client = OpenAICompatibleClient(model=model_id, base_url=MESH_URL,
                                    api_key=os.environ.get("MESH_LLM_KEY",
                                                           ""),
                                    timeout=120.0)
    out = asyncio.run(client.complete(
        "responde con una sola palabra: listo", max_tokens=MAX_TOKENS))
    assert isinstance(out, str) and out.strip(), "respuesta vacía del endpoint"
    return out


# ------------------------------------------------------------------- la tesis
@pytest.mark.slow
def test_a_real_inference_can_be_anchored_and_counted():
    """El nodo sirve de verdad, y lo que sirvió lo puede demostrar.

    El paso que importa es el ultimo: la respuesta **no** se publica (el
    contenido no va al ancla, por decision de diseno), pero el registro se
    construye y verifica. Si contra un endpoint real el ancla no se pudiera
    armar, el historial no subiria nunca y el intercambio seria decorativo.
    """
    model_id = _probe(MESH_URL)
    if model_id is None:
        pytest.skip(f"sin endpoint en {MESH_URL} (MESH_LLM_URL)")

    mesh, now = "malla-real", 1_000.0
    led = ContributionLedger(mesh)
    assert _admit(led, "n1", 8.0, KeyPair.new("n1"), mesh, now)

    # 1. la malla coloca carga aqui: ofrece VRAM, asi que es proveedor
    plan = plan_placement(ModelSpec(name=model_id, memory_required_gb=4.0), led)
    assert plan.ok and plan.peers == ("n1",)

    # 2. otro nodo pide una inferencia y el nodo la sirve de verdad
    text = _served_inference(model_id)
    assert text.strip()

    # 3. el nodo ancla lo que sirvió, sin publicar el contenido.
    # Una transacción por inferencia: la tx que se ancla **es** la
    # que lleva el output de membresía, y la inclusión es de esa
    # misma transacción — no de otra (anchor.py lo exige).
    membership_key = Secp256k1KeyPair.new("n1-members")
    requester_key = Secp256k1KeyPair.new("quien-pide")
    txid = "9a" * 32
    record = AnchorRecord(
        membership_txid=txid, membership_vout=0,
        membership_pubkey=membership_key.public_key.hex(),
        requester_pubkey=requester_key.public_key.hex(),
        satoshis=100, occurred_at=1_700_000_000)
    leaf = bytes.fromhex(txid)[::-1]
    inclusion = InclusionProof(txid=txid, index=0, path=[],
                              merkle_root=merkle_root([leaf]).hex(),
                              height=900_000)
    header = BlockHeader(merkle_root=inclusion.merkle_root, height=900_000)
    signature = record.sign(membership_key)

    # 4. el ancla verifica, y el contenido sigue sin publicarse
    ok, why = record.verify(signature, inclusion, header)
    assert ok, why
    assert record.content_sha256 == ""

    chain = AnchorLedger(membership_outputs=[MembershipOutput(
        txid=txid, vout=0, satoshis=1000, script_hash="bb" * 32)])
    appended, why2 = chain.append(record, inclusion, signature)
    assert appended, why2

    # 5. y solo entonces el historial sube
    assert led.record_inference("n1", txid=txid,
                                satoshis=record.satoshis)[0] is True
    board = board_from_counters(led)
    assert board.position("n1") == 1
    assert board.get("n1").inferences_served == 1
    assert board.get("n1").satoshis_earned == 100


@pytest.mark.slow
def test_a_second_real_inference_moves_the_counter_again():
    """Dos inferencias reales, dos entradas en el historial. El ranking no miente."""
    model_id = _probe(MESH_URL)
    if model_id is None:
        pytest.skip(f"sin endpoint en {MESH_URL} (MESH_LLM_URL)")

    mesh, now = "malla-real-2", 1_000.0
    led = ContributionLedger(mesh)
    assert _admit(led, "n1", 8.0, KeyPair.new("n1"), mesh, now)
    membership_key = Secp256k1KeyPair.new("n1-members")
    requester_key = Secp256k1KeyPair.new("quien-pide")

    for i in range(2):
        _served_inference(model_id)
        txid = f"{i:02x}" * 32
        record = AnchorRecord(
            membership_txid="cc" * 32, membership_vout=0,
            membership_pubkey=membership_key.public_key.hex(),
            requester_pubkey=requester_key.public_key.hex(),
            satoshis=100, occurred_at=1_700_000_000)
        assert led.record_inference("n1", txid=txid,
                                    satoshis=record.satoshis)[0] is True

    assert led.peers["n1"].inferences_served == 2
    assert board_from_counters(led).get("n1").satoshis_earned == 200


@pytest.mark.slow
def test_a_real_endpoint_failure_does_not_move_the_counter():
    """Un endpoint caido no produce inferencia que contar.

    Es el mismo bug que P2 corrigio en el cliente medido —"`served` contaba
    inferencias que nunca ocurrieron"— transported a la regla nueva: lo que
    sube el historial es un ancla, y un ancla exige una transaccion minada. Si
    la llamada falla no hay nada que anclar, y el contador se queda quieto.
    """
    mesh, now = "malla-real-3", 1_000.0
    led = ContributionLedger(mesh)
    assert _admit(led, "n1", 8.0, KeyPair.new("n1"), mesh, now)

    model_id = _probe("http://127.0.0.1:1/v1")   # puerto cerrado, a proposito
    assert model_id is None
    # No hubo inferencia, luego no hay ancla, luego no hay historial.
    assert led.peers["n1"].inferences_served == 0
    # Y lo que se intentaria contar sin prueba, el ledger lo rechaza.
    assert led.record_inference("n1", txid="")[0] is False
    assert board_from_counters(led).get("n1").inferences_served == 0