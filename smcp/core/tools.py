"""Las herramientas del nodo — descubiertas al arrancar.

Qué resuelve este módulo
--------------------------
Un nodo desplegado no pinkea sus herramientas: el
modelo que sirve lo da el **MeshLLM** que haya al
lado (o el que ``MESH_LLM_URL`` apunte) y el asesor
de encaje es el **llmfit** que el host tenga. Al
arrancar, el nodo las **descubre**: usa lo que
haya, y lo reporta. Ninguna versión está escrita
en el código — lo que el host despliega es lo que
el nodo usa.

Piezas
------

1. **MeshLLM** — se sondea ``GET {url}/models``
   (el endpoint OpenAI-compatible del mesh); el
   primer modelo de la lista es el que sirve. Si
   el mesh no responde, el reporte lo dice
   (``mesh_llm_model=None``) y el nodo arranca
   igual, con su doble determinista (el de los
   tests — nunca una degradación silenciosa: el
   reporte dice cuál de los dos es).
2. **llmfit** — se busca el ejecutable como lo
   hace :class:`smcp.core.llmfit.LlmfitRunner`
   (explícito, ``$DELM_LLMFIT_BIN``, ``PATH`` o
   ``python -m llmfit``) y se lee su versión con
   ``--version``. Si no hay llmfit, el reporte
   lo dice.

El cable del reporte es el despliegue::

    reporte = discover_tools()
    llm = llm_from_report(reporte)        # lo que hay
    servidor = InferenceServer(llm=llm, ...)
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.request
from dataclasses import dataclass

from smcp.core.llm import FakeLLMClient, LLMClient, OpenAICompatibleClient
from smcp.core.llmfit import LlmfitNotFound, LlmfitRunner
from smcp.core.placement import DEFAULT_MESH_ENDPOINT

# Una versión: "1.1.16", "1.2", "1.2.3-rc1" ...
_VERSION = re.compile(r"\d+\.\d+(?:\.\d+)?")


@dataclass(frozen=True)
class ToolReport:
    """Lo que el nodo encontró al arrancar."""

    mesh_llm_url: str
    """El MeshLLM que se sondeó."""

    mesh_llm_model: str | None
    """El modelo que el MeshLLM ofrece (``None`` si no responde)."""

    llmfit: str | None
    """El comando que invoca a llmfit (``None`` si no hay)."""

    llmfit_version: str | None
    """La versión de llmfit (``None`` si no se pudo leer)."""


def discover_tools(
    *,
    mesh_llm_url: str = DEFAULT_MESH_ENDPOINT,
    llmfit_bin: str | None = None,
    timeout_s: float = 30.0,
) -> ToolReport:
    """Descubre las herramientas del host.

    El MeshLLM se sondea con ``GET {url}/models``;
    llmfit se busca y se lee su versión. Lo que
    falte se reporta como ``None`` — el nodo arranca
    con lo que haya, no con lo que el código espera.
    """
    model = _probe_mesh_llm(mesh_llm_url, timeout_s=timeout_s)
    llmfit, version = _find_llmfit(llmfit_bin)
    return ToolReport(
        mesh_llm_url=mesh_llm_url,
        mesh_llm_model=model,
        llmfit=llmfit,
        llmfit_version=version,
    )


def llm_from_report(
    report: ToolReport, *, api_key: str | None = None,
) -> LLMClient:
    """El modelo que sirve el nodo: lo que MeshLLM descubrió.

    Sin MeshLLM (el reporte no trae modelo) el nodo
    arranca igual, con su doble determinista — es
    el mismo fallback que los tests, no una degradación
    silenciosa: el reporte dice cuál de los dos es.
    """
    if report.mesh_llm_model is not None:
        return OpenAICompatibleClient(
            model=report.mesh_llm_model,
            base_url=report.mesh_llm_url,
            api_key=api_key or os.environ.get("MESH_LLM_API_KEY") or "",
        )
    return FakeLLMClient()


def _probe_mesh_llm(url: str, *, timeout_s: float) -> str | None:
    """El primer modelo que ofrece el MeshLLM.

    ``None`` si el mesh no responde, no habla JSON
    o no trae modelos: el reporte lo dice, el nodo
    no se cae.
    """
    try:
        with urllib.request.urlopen(
            f"{url.rstrip('/')}/models", timeout=timeout_s,
        ) as respuesta:
            datos = json.loads(respuesta.read().decode("utf-8"))
        return str(datos["data"][0]["id"])
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        return None


def _find_llmfit(binary: str | None) -> tuple[str | None, str | None]:
    """El llmfit del host y su versión (``None`` si no hay)."""
    runner = LlmfitRunner(binary)
    try:
        prefijo = runner.command_prefix()
    except LlmfitNotFound:
        return None, None
    version = _llmfit_version(prefijo, timeout_s=runner.timeout_s)
    return " ".join(prefijo), version


def _llmfit_version(prefijo: list[str], *, timeout_s: float) -> str | None:
    """La versión de llmfit (su ``--version``; ``None`` si no se puede)."""
    try:
        proc = subprocess.run(
            [*prefijo, "--version"], capture_output=True, text=True,
            timeout=timeout_s,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    hallazgo = _VERSION.search(proc.stdout or proc.stderr or "")
    return hallazgo.group(0) if hallazgo else None
