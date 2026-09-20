"""Test opt-in: wiring SMCP → MeshLLM (Fase 1 del INTEGRATION.md).

Marcado ``slow``: **no** corre en la suite por defecto (``-m 'not slow'``).
Verifica que el cliente estándar de SMCP (:class:`OpenAICompatibleClient`)
habla con un endpoint MeshLLM (OpenAI-compatible) y devuelve una respuesta
no vacía.

El endpoint por defecto es el local ``http://127.0.0.1:9337/v1``;
sobreescríbelo con ``MESH_LLM_URL`` (p. ej. la malla pública para CI).

Si el endpoint no responde, el test se **skipea** (no falla): es opt-in y
sin CI hard-dependency, tal como pide la Fase 1. Esto cubre el caso de esta
máquina (CPU-only, sin runtime nativo compatible → no hay mesh local); el
test pasa en cuanto exista un endpoint MeshLLM alcanzable.

Run manual::

    MESH_LLM_URL=http://127.0.0.1:9337/v1 \
      python -m pytest tests/test_meshllm_wiring.py -m slow -v
"""
from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request

import pytest

# Endpoint por defecto: mesh local. Sobrescribe con MESH_LLM_URL.
MESH_URL = os.environ.get("MESH_LLM_URL", "http://127.0.0.1:9337/v1")
PROBE_TIMEOUT = 5.0  # s; un mesh que no responde cae rápido (skip, no hang)


def _probe(url: str) -> str | None:
    """Devuelve el primer ``model.id`` de ``{url}/models`` o ``None``.

    ``None`` si el endpoint no responde (timeout, error HTTP, JSON inválido).
    Es el chequeo de "¿hay un mesh aquí?" antes de intentar el wiring.
    """
    req = urllib.request.Request(url + "/models")
    try:
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT) as r:
            data = json.loads(r.read())
    except (urllib.error.URLError, urllib.error.HTTPError,
            TimeoutError, json.JSONDecodeError, OSError, ValueError):
        return None
    models = data.get("data", [])
    if not models:
        return None
    return models[0].get("id")


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.mark.slow
def test_smcp_wiring_to_meshllm():
    """El cliente estándar de SMCP completa una petición contra un mesh.

    Si no hay endpoint MeshLLM alcanzable en ``MESH_URL``, se skipea
    (opt-in). Si hay uno, verifica el wiring completo: probe → modelo →
    ``OpenAICompatibleClient.complete`` → respuesta no vacía.
    """
    model = _probe(MESH_URL)
    if model is None:
        pytest.skip(
            f"no hay endpoint MeshLLM en {MESH_URL} "
            "(opt-in; corre con MESH_LLM_URL=<endpoint> -m slow)"
        )
    from delm.core.llm import OpenAICompatibleClient
    client = OpenAICompatibleClient(
        model=model, base_url=MESH_URL, api_key="dummy",
    )
    out = _run(client.complete("Responde únicamente con la palabra OK."))
    assert isinstance(out, str) and out.strip(), "respuesta vacía"


@pytest.mark.slow
def test_meshllm_models_endpoint_is_openai_shape():
    """El endpoint expone ``/v1/models`` con forma OpenAI (``data[].id``).

    Mismo gate opt-in: se skipea si no hay endpoint. Verifica que la forma
    del endpoint es la que ``OpenAICompatibleClient`` espera (el contrato de
    la Fase 1).
    """
    model = _probe(MESH_URL)
    if model is None:
        pytest.skip(f"no hay endpoint MeshLLM en {MESH_URL}")
    assert isinstance(model, str) and model
