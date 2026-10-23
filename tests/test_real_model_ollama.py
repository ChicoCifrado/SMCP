"""Tests contra un modelo REAL (no mockeado) via OpenAI-compatible endpoint.

Estos tests se salta si no hay un endpoint real disponible (DELM_BASE_URL
no set o no responde). Se activan con:

    DELM_MODEL="nemotron-3.5-bolt:e4b-q4_K_M" \\
    DELM_BASE_URL="http://127.0.0.1:11434/v1" \\
    pytest tests/test_real_model_ollama.py -v

Son lentos (el modelo real tarda ~25s por run) y se marcan con @pytest.mark.slow.
"""
from __future__ import annotations

import asyncio
import os

import httpx
import pytest

from smcp.config import ModelConfig, build_client
from smcp.core.llm import OpenAICompatibleClient
from smcp.core.pipeline import SmcpPipeline
from smcp.core.task_queue import Task


def _endpoint_available() -> bool:
    base = os.environ.get("DELM_BASE_URL")
    if not base:
        return False
    try:
        r = httpx.get(base.rstrip("/") + "/models", timeout=5.0)
        return r.status_code < 500
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(
    not _endpoint_available(),
    reason="no real model endpoint available (set DELM_BASE_URL)",
)


@pytest.mark.slow
def test_real_model_pipeline_end_to_end():
    model = os.environ.get("DELM_MODEL", "nemotron-3.5-bolt:e4b-q4_K_M")
    base_url = os.environ["DELM_BASE_URL"]
    config = ModelConfig(model=model, base_url=base_url)
    client = build_client(config)
    assert isinstance(client, OpenAICompatibleClient)

    async def _go():
        pipe = SmcpPipeline(llm=client, n_workers=2)
        tasks = [
            Task(label="t0", body="Solve the toy defect.", kind="solve"),
            Task(label="t1", body="Solve the toy defect.", kind="solve"),
        ]
        return await pipe.run(tasks)

    result = asyncio.run(_go())
    assert result.admitted_gists >= 1
    assert result.answer and len(result.answer) > 0


@pytest.mark.slow
def test_real_model_client_issues_http_calls():
    model = os.environ.get("DELM_MODEL", "nemotron-3.5-bolt:e4b-q4_K_M")
    base_url = os.environ["DELM_BASE_URL"]
    config = ModelConfig(model=model, base_url=base_url)
    client = build_client(config)

    async def _go():
        return await client.complete("Say hello in one word.")

    out = asyncio.run(_go())
    assert isinstance(out, str) and len(out) > 0
