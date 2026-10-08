"""API tests — las herramientas del nodo (`/api/tools`).

El contrato que se fija aquí:

* **El reporte dice la verdad del host.** El endpoint
  descubre en vivo: el modelo que MeshLLM ofrece (o
  ``None`` si no responde) y el llmfit del host con su
  versión (o ``None`` si no hay). Lo que se fija es la
  **forma** — los valores dependen del host.
* **Un llmfit que no existe se dice** (``None``), no se
  inventa; y una versión sin llmfit que la diga no ocurre.
* **El MeshLLM se sonda donde se pida** — y si no
  responde, el reporte lo dice (``None``), no se cae.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from smcp.web.app import app


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def test_el_reporte_tiene_la_forma_del_host(client: TestClient):
    r = client.get("/api/tools")
    assert r.status_code == 200
    j = r.json()
    assert j["mesh_llm_url"]
    # Lo que haya en el host: modelo o None, nunca otra cosa.
    assert j["mesh_llm_model"] is None or isinstance(
        j["mesh_llm_model"], str)
    assert j["llmfit"] is None or isinstance(j["llmfit"], str)
    assert j["llmfit_version"] is None or isinstance(
        j["llmfit_version"], str)
    # Si hay versión, hay un llmfit que la diga.
    if j["llmfit_version"] is not None:
        assert j["llmfit"] is not None


def test_un_llmfit_inexistente_se_dice(client: TestClient):
    r = client.get(
        "/api/tools", params={"llmfit_bin": "/nonexistent/llmfit"})
    assert r.status_code == 200
    j = r.json()
    assert j["llmfit"] is None
    assert j["llmfit_version"] is None


def test_el_meshllm_se_sonda_donde_se_pida(client: TestClient):
    r = client.get(
        "/api/tools", params={"mesh_llm_url": "http://127.0.0.1:9/v1"})
    assert r.status_code == 200
    j = r.json()
    assert j["mesh_llm_url"] == "http://127.0.0.1:9/v1"
    # Un MeshLLM que no responde: el reporte lo dice.
    assert j["mesh_llm_model"] is None
