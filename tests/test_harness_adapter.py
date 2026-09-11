"""Tests del adaptador DeepSeek Harness (``delm/core/harness_client.py``).

El adaptador expone el runtime de agente del DeepSeek Harness (tool use,
subagentes, sesiones) tras la interfaz ``LLMClient``. Dos tests:

* ``test_harness_client_imports_without_sdk`` — el módulo se importa *sin*
  ``deepseek_harness`` (import lazy). Corre en la suite por defecto.
* ``test_harness_adapter_turn`` — un turno real contra el servidor local
  (requiere ``deepseek_harness`` + servidor activo). Marcado ``slow``.

El diseño es opt-in: el módulo no se importa a module load, así la suite por
defecto corre sin el SDK (y su runtime de 268 MB) instalado.
"""
from __future__ import annotations

import importlib

import pytest


def test_harness_client_imports_without_sdk():
    """El módulo se importa sin forzar el import del SDK (import lazy).

    ``harness_client`` no debe arrastrar ``deepseek_harness`` a import time:
    el import del SDK es lazy (dentro de ``_ensure``). Así la suite por
    defecto corre sin el SDK instalado, y el módulo sigue siendo importable
    para inspeccionar su API.
    """
    had_sdk = "deepseek_harness" in __import__("sys").modules
    mod = importlib.import_module("delm.core.harness_client")
    # Si el SDK no estaba cargado, importar el módulo no lo añade.
    if not had_sdk:
        assert "deepseek_harness" not in __import__("sys").modules
    # El módulo expone la API pública (adaptador + builder).
    assert hasattr(mod, "HarnessLLMClient")
    assert hasattr(mod, "build_harness_client")


def test_harness_client_is_an_llmclient():
    """``HarnessLLMClient`` implementa la interfaz ``LLMClient``.

    Un worker puede sustituir ``OpenAICompatibleClient`` por
    ``HarnessLLMClient`` sin cambiar su código: ambos exponen
    ``complete``/``complete_json``.
    """
    from delm.core.llm import LLMClient
    mod = importlib.import_module("delm.core.harness_client")
    assert issubclass(mod.HarnessLLMClient, LLMClient)


@pytest.mark.slow
def test_harness_adapter_turn():
    """Un turno real del adaptador contra el servidor local.

    Requiere ``deepseek_harness`` instalado y el servidor local activo
    (127.0.0.1:8888). Si falta, se skip. Verifica que ``complete`` devuelve
    el texto final del agente (el modelo responde "OK").
    """
    import asyncio
    import sys
    import urllib.request

    pytest.importorskip("deepseek_harness")

    # El servidor local debe estar activo.
    try:
        urllib.request.urlopen("http://127.0.0.1:8888/v1/models", timeout=5)
    except Exception:
        pytest.skip("servidor local 127.0.0.1:8888 no activo")

    mod = importlib.import_module("delm.core.harness_client")
    client = mod.HarnessLLMClient(
        model="unsloth/Qwen3.8-27B-GGUF",
        base_url="http://127.0.0.1:8888/v1",
    )
    try:
        out = asyncio.run(client.complete("Say exactly: OK"))
    finally:
        client.close()
    assert "OK" in out
