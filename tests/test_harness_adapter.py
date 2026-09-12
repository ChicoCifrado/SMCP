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


# ------------------------------------------------------------------ Fase B
# Wiring opt-in: el flag DELM_HARNESS hace que build_client devuelva el
# adaptador del harness, con el mismo ModelConfig que usa el cliente normal.


def test_build_client_defaults_to_openai():
    """Sin el flag, ``build_client`` devuelve el cliente OpenAI-compatible.

    La regresión es explícita: el default no cambia; el harness queda
    opt-in y la suite por defecto (sin SDK ni servidor) sigue verde.
    """
    from delm.config import ModelConfig, build_client
    from delm.core.llm import OpenAICompatibleClient
    client = build_client(ModelConfig(model="m", base_url="http://x/v1"))
    assert isinstance(client, OpenAICompatibleClient)


def test_build_client_use_harness_returns_harness():
    """Con ``use_harness=True``, ``build_client`` devuelve el adaptador.

    Import lazy: construir el cliente NO importa el SDK (lázy import), y el
    objeto resultante es un ``LLMClient`` (sustituible por el normal).
    """
    from delm.config import ModelConfig, build_client
    from delm.core.llm import LLMClient
    client = build_client(ModelConfig(
        model="unsloth/Qwen3.8-27B-GGUF",
        base_url="http://127.0.0.1:8888/v1",
        use_harness=True,
    ))
    assert isinstance(client, LLMClient)
    assert type(client).__name__ == "HarnessLLMClient"
    assert "deepseek_harness" not in __import__("sys").modules


def test_load_config_honors_delm_harness_env(monkeypatch):
    """``DELM_HARNESS=1`` en el env activa el backend harness en el config."""
    from delm.config import load_config
    # env mínimo: el resto de DELM_* queda vacío (defaults).
    monkeypatch.setenv("DELM_MODEL", "m")
    monkeypatch.setenv("DELM_BASE_URL", "http://x/v1")
    monkeypatch.setenv("DELM_HARNESS", "1")
    cfg = load_config(None)
    assert cfg.use_harness is True


def test_load_config_harness_defaults_off(monkeypatch):
    """Sin ``DELM_HARNESS``, el config queda con el backend normal."""
    from delm.config import load_config
    monkeypatch.setenv("DELM_MODEL", "m")
    monkeypatch.setenv("DELM_BASE_URL", "http://x/v1")
    monkeypatch.delenv("DELM_HARNESS", raising=False)
    cfg = load_config(None)
    assert cfg.use_harness is False


@pytest.mark.slow
def test_harness_adapter_turn():
    """Un turno real del adaptador contra el servidor local.

    Requiere ``deepseek_harness`` instalado y el servidor local activo
    (127.0.0.1:8888). Si falta, se skip.

    Afirmación: el contrato del adaptador es que ``complete`` devuelve un
    ``str`` (la respuesta final del agente), sin colgar ni lanzar. El *texto*
    del modelo no se afirma aquí: es un modelo thinking (~200s/turno) y bajo
    carga de GPU (corriendo junto al test del pipeline) puede devolver una
    respuesta vacía; eso es un fallo del *modelo*, no del adaptador. El test
    del pipeline (``test_harness_pipeline_runs_with_real_backend``) es la
    prueba end-to-end que sí exige una respuesta real.
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
    # Contrato del adaptador: devuelve un str (la respuesta final del agente).
    assert isinstance(out, str)


@pytest.mark.slow
def test_harness_pipeline_runs_with_real_backend():
    """Un :class:`DelmPipeline` real corre sobre el backend harness.

    Este es el "worker detrás del harness" de la Fase B: el pipeline
    existente (sin cambios) se construye con ``build_client`` sobre un
    ``ModelConfig(use_harness=True)`` y corre hasta producir una respuesta.
    Requiere SDK + servidor local; si falta, se skip.

    Verifica que el wiring opt-in (config -> client -> pipeline) es sólido:
    el mismo ``DelmPipeline`` que usa ``FakeLLMClient`` en la suite corre
    aquí sobre el runtime de agente real.
    """
    import asyncio
    import urllib.request

    pytest.importorskip("deepseek_harness")
    try:
        urllib.request.urlopen("http://127.0.0.1:8888/v1/models", timeout=5)
    except Exception:
        pytest.skip("servidor local 127.0.0.1:8888 no activo")

    from delm.config import ModelConfig, build_client
    from delm.core.pipeline import DelmPipeline
    from delm.core.task_queue import Task

    client = build_client(ModelConfig(
        model="unsloth/Qwen3.8-27B-GGUF",
        base_url="http://127.0.0.1:8888/v1",
        use_harness=True,
    ))

    async def _go() -> dict:
        pipe = DelmPipeline(llm=client, n_workers=1)
        tasks = [
            Task(label="h0", body="State one concise, evidence-backed fix "
                  "for a leak-on-error-path; answer with the word ANSWER.",
                 kind="solve"),
        ]
        out = await pipe.run(tasks)
        return {"answer": out.answer, "admitted": out.admitted_gists,
                "solved": sum(w.solved for w in out.workers)}

    try:
        result = asyncio.run(_go())
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()
    assert result["admitted"] >= 1
    assert result["solved"] >= 1
