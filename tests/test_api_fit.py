"""API tests — `delm fit` en la web (GET /api/fit, POST /api/fit/apply).

Por qué estos tests no necesitan llmfit instalado (el resto de la suite
tampoco depende de un binario externo):

* el adaptador se sustituye por un `LlmfitRunner` con `catalog()` falso, así
  que se prueba el **contrato de la API** —validación de filtros, forma del
  payload, veredicto, apply— y no el parseo de llmfit (eso vive en
  `test_llmfit.py`);
* la config se redirige a `tmp_path` con el mismo monkeypatch que usa
  `test_api_actions.py`, de modo que **ningún test escribe la config real**;
* el caso "llmfit no está" se fuerza con un runner que lanza `LlmfitNotFound`:
  la UI tiene que poder pintar el hint de instalación, así que no puede ser un
  error HTTP.

Dos invariantes que se comprueban aquí porque son las que más caro salen al
integrarlo: el veredicto se calcula sobre el catálogo **entero** (una fila
`too_tight` que la tabla esconde sigue siendo juzgada) y ningún secret aparece
en ninguna respuesta.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from smcp.web import api as smcp_api
from smcp.web.app import app
from smcp.core.llmfit import (
    FitReport,
    FitRow,
    LlmfitNotFound,
    LlmfitRunner,
    SystemProfile,
)
from smcp.web.api import MANAGER

SYSTEM = {
    "total_ram_gb": 31.3, "available_ram_gb": 22.0, "cpu_cores": 12,
    "cpu_name": "Intel(R) Core(TM) i7-5930K", "has_gpu": True,
    "gpu_name": "NVIDIA GeForce RTX 4060 Ti", "gpu_vram_gb": 16.0,
    "gpu_count": 1, "unified_memory": False, "backend": "CUDA",
}

MODELS = [
    {"name": "Qwen/Qwen2.5-Coder-7B-Instruct-AWQ", "provider": "Qwen",
     "params_b": 7.62, "use_case": "Code generation", "category": "Coding",
     "fit_level": "Perfect", "fit_label": "Perfect", "run_mode": "GPU",
     "runtime": "llama.cpp", "best_quant": "AWQ-4bit", "score": 90.0,
     "estimated_tps": 41.6, "memory_required_gb": 4.8,
     "disk_size_gb": 3.8, "effective_context_length": 8192,
     "estimate_confidence": "estimated", "installed": False},
    {"name": "Qwen/Qwen3-30B-A3B", "provider": "Qwen", "params_b": 30.0,
     "use_case": "General purpose", "category": "General",
     "fit_level": "Marginal", "fit_label": "Marginal", "run_mode": "GPU",
     "runtime": "llama.cpp", "best_quant": "Q3_K_M", "score": 60.0,
     "estimated_tps": 34.9, "memory_required_gb": 15.6,
     "disk_size_gb": 14.0, "effective_context_length": 8192,
     "estimate_confidence": "estimated", "installed": False},
    {"name": "meta-llama/Llama-3.1-405B", "provider": "Meta", "params_b": 405.0,
     "use_case": "General purpose", "category": "General",
     "fit_level": "Too Tight", "fit_label": "Too Tight", "run_mode": "CPU",
     "runtime": "llama.cpp", "best_quant": "Q4_K_M", "score": 30.0,
     "estimated_tps": 0.8, "memory_required_gb": 249.19,
     "disk_size_gb": 230.0, "effective_context_length": 2048,
     "estimate_confidence": "estimated", "installed": False},
]


@pytest.fixture()
def client():
    MANAGER._active = None
    MANAGER._history.clear()
    with TestClient(app) as c:
        yield c
    MANAGER._active = None
    MANAGER._history.clear()


@pytest.fixture()
def fake_llmfit(monkeypatch):
    """Sustituye el discovery+subprocess de llmfit por un catálogo fijo.

    Registra también los kwargs con los que se pidió el catálogo, para poder
    comprobar que los overrides de hardware llegan al runner.
    """
    seen: dict = {}

    def catalog(self, *, limit=None, profile=None, memory=None, ram=None,
                cpu_cores=None, max_context=None):
        seen.update(limit=limit, profile=profile, memory=memory, ram=ram,
                    cpu_cores=cpu_cores, max_context=max_context)
        return FitReport.from_payload({"system": SYSTEM, "models": MODELS,
                                       "total_models": 9872})

    monkeypatch.setattr(LlmfitRunner, "catalog", catalog)
    return seen


@pytest.fixture()
def no_llmfit(monkeypatch):
    def boom(self, **kw):
        raise LlmfitNotFound("llmfit no esta instalado. Instala el binario:\n"
                             "  uv tool install -U llmfit")
    monkeypatch.setattr(LlmfitRunner, "catalog", boom)


@pytest.fixture()
def cfg_path(tmp_path, monkeypatch):
    """Redirige la config a tmp: ningún test toca la del repo."""
    fake = tmp_path / "model_config.yaml"
    monkeypatch.setattr(smcp_api, "_config_path", lambda: fake)
    from smcp.config import load_config as _lc
    monkeypatch.setattr(smcp_api, "_load_cfg",
                        lambda: _lc(fake) if fake.exists() else _lc(None))
    return fake


# --------------------------------------------------------------------- GET
def test_fit_returns_system_rows_and_verdict(client, fake_llmfit):
    r = client.get("/api/fit", params={"limit": 5})
    assert r.status_code == 200
    j = r.json()
    assert j["available"] is True
    assert j["system"]["gpu_name"] == "NVIDIA GeForce RTX 4060 Ti"
    assert j["total_models"] == 9872
    # Por defecto fuera lo que no cabe: 3 filas, 2 pintadas.
    assert [m["name"] for m in j["models"]] == [MODELS[0]["name"],
                                                MODELS[1]["name"]]
    assert j["check"]["model"] == "" or "matched" in j["check"]
    assert "hint" not in j
    assert j["secs"] >= 0


def test_fit_limit_and_filters_are_applied(client, fake_llmfit):
    r = client.get("/api/fit", params={"limit": 1, "use_case": "coding"})
    j = r.json()
    assert [m["name"] for m in j["models"]] == [MODELS[0]["name"]]

    r = client.get("/api/fit", params={"include_too_tight": "true", "limit": 9})
    assert len(r.json()["models"]) == 3

    r = client.get("/api/fit", params={"search": "405b", "include_too_tight": "true"})
    assert [m["name"] for m in r.json()["models"]] == [MODELS[2]["name"]]

    r = client.get("/api/fit", params={"sort": "params", "include_too_tight": "true"})
    names = [m["name"] for m in r.json()["models"]]
    # Descendente: el mismo criterio que score/tps (lo mejor, primero).
    assert names == [MODELS[2]["name"], MODELS[1]["name"], MODELS[0]["name"]]

    r = client.get("/api/fit", params={"min_fit": "perfect", "limit": 9})
    assert len(r.json()["models"]) == 1


def test_fit_verdict_judges_rows_the_table_hides(client, fake_llmfit, cfg_path):
    """La fila `too_tight` no se pinta, pero sí se juzga: por eso vale 2.

    Es el bug caro que justificaría `delm fit --check`: un modelo que no cabe
    disappearing de la tabla y el veredicto cayendo a "desconocido".
    """
    cfg_path.write_text('model: "meta-llama/Llama-3.1-405B"\n'
                        'base_url: "http://127.0.0.1:9/v1"\n', encoding="utf-8")
    r = client.get("/api/fit", params={"limit": 5})
    assert r.status_code == 200
    j = r.json()
    check = j["check"]
    assert check["matched"] is True
    assert check["runnable"] is False
    assert check["fit_level"] == "too_tight"
    assert check["exit_code"] == 2
    assert check["suggestions"] == [MODELS[0]["name"], MODELS[1]["name"]]
    # Y la fila que no cabe no aparece en la tabla.
    assert all(m["name"] != MODELS[2]["name"] for m in j["models"])


def test_fit_verdict_of_a_fitting_model_exits_zero(client, fake_llmfit, cfg_path):
    cfg_path.write_text('model: "Qwen/Qwen3-30B-A3B"\n', encoding="utf-8")
    check = client.get("/api/fit").json()["check"]
    assert check["runnable"] is True
    assert check["exit_code"] == 0
    assert check["best_quant"] == "Q3_K_M"
    assert check["memory_required_gb"] == 15.6


def test_fit_verdict_of_a_served_local_id_resolves(client, fake_llmfit,
                                                   cfg_path):
    """El `:tag` que sirve un runtime local se normaliza a su fila."""
    cfg_path.write_text('model: "Qwen/Qwen2.5-Coder-7B-Instruct-AWQ-GGUF"\n',
                        encoding="utf-8")
    check = client.get("/api/fit").json()["check"]
    assert check["matched"] is True and check["runnable"] is True
    assert check["row_name"] == MODELS[0]["name"]


def test_fit_verdict_unknown_model_is_not_a_failure(client, fake_llmfit,
                                                    cfg_path):
    cfg_path.write_text('model: "mi-org/modelo-privado"\n', encoding="utf-8")
    check = client.get("/api/fit").json()["check"]
    assert check["matched"] is False
    assert check["exit_code"] == 0


def test_fit_never_exposes_secrets(client, fake_llmfit, cfg_path):
    cfg_path.write_text(
        'model: "Qwen/Qwen2.5-Coder-7B-Instruct-AWQ"\n'
        'base_url: "http://127.0.0.1:9/v1"\n'
        'api_key: "sk-secret-value-1234567890"\n', encoding="utf-8")
    body = client.get("/api/fit").text
    assert "sk-secret-value-1234567890" not in body
    assert "api_key" not in json.loads(body)


def test_fit_forwards_hardware_overrides(client, fake_llmfit):
    client.get("/api/fit", params={"memory": "24G", "ram": "64G",
                                   "cpu_cores": 8, "max_context": 8192})
    assert fake_llmfit["memory"] == "24G"
    assert fake_llmfit["ram"] == "64G"
    assert fake_llmfit["cpu_cores"] == 8
    assert fake_llmfit["max_context"] == 8192
    # El catálogo llega entero: el veredicto no puede depender de la vista.
    assert fake_llmfit["limit"] is None


def test_fit_rejects_unknown_filter_values(client, fake_llmfit):
    for key, bad in (("min_fit", "excelente"), ("runtime", "tensorrt"),
                     ("sort", "flavor"), ("use_case", "traduccion")):
        r = client.get("/api/fit", params={key: bad})
        assert r.status_code == 400, key
        assert key.split("_")[0] in r.json()["detail"]


def test_fit_validates_numeric_bounds(client, fake_llmfit):
    assert client.get("/api/fit", params={"limit": 0}).status_code == 422
    assert client.get("/api/fit", params={"limit": 51}).status_code == 422
    assert client.get("/api/fit", params={"cpu_cores": 0}).status_code == 422
    assert client.get("/api/fit", params={"timeout_s": 0}).status_code == 422


def test_fit_without_llmfit_is_not_an_http_error(client, no_llmfit):
    """La UI tiene que poder pintar el hint de instalación, no un 500."""
    r = client.get("/api/fit")
    assert r.status_code == 200
    j = r.json()
    assert j["available"] is False
    assert "uv tool install" in j["hint"]
    assert j["models"] == [] and j["total_models"] == 0
    assert j["check"]["matched"] is False


# -------------------------------------------------------------------- apply
def test_fit_apply_writes_the_model_with_llmfit_notes(client, fake_llmfit,
                                                      cfg_path):
    r = client.post("/api/fit/apply", json={
        "model": "Qwen/Qwen2.5-Coder-7B-Instruct-AWQ",
        "base_url": "http://127.0.0.1:9337/v1",
    })
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert j["model"] == "Qwen/Qwen2.5-Coder-7B-Instruct-AWQ"
    assert "api_key" not in j
    text = cfg_path.read_text(encoding="utf-8")
    assert 'model: "Qwen/Qwen2.5-Coder-7B-Instruct-AWQ"' in text
    # El veredicto que justificó la elección viaja al YAML, no se pierde.
    assert "AWQ-4bit" in text
    assert "41.6 tok/s" in text
    assert "3.8G" in text


def test_fit_apply_resolves_a_served_id_to_the_catalog_name(client, fake_llmfit,
                                                            cfg_path):
    r = client.post("/api/fit/apply",
                    json={"model": "Qwen/Qwen2.5-Coder-7B-Instruct-AWQ-GGUF"})
    assert r.json()["model"] == "Qwen/Qwen2.5-Coder-7B-Instruct-AWQ"


def test_fit_apply_keeps_the_existing_base_url(client, fake_llmfit, cfg_path):
    cfg_path.write_text('model: "viejo"\nbase_url: "http://127.0.0.1:9337/v1"\n',
                        encoding="utf-8")
    r = client.post("/api/fit/apply",
                    json={"model": "Qwen/Qwen3-30B-A3B"})
    assert r.status_code == 200
    assert r.json()["base_url"] == "http://127.0.0.1:9337/v1"
    assert r.json()["updated"] == ["model"]


def test_fit_apply_never_echoes_the_api_key(client, fake_llmfit, cfg_path):
    r = client.post("/api/fit/apply", json={
        "model": "Qwen/Qwen3-30B-A3B", "api_key": "sk-secret-1234567890"})
    assert "sk-secret-1234567890" not in r.text
    assert r.json()["api_key_set"] is True
    assert r.json()["api_key_masked"] != "sk-secret-1234567890"


def test_fit_apply_without_llmfit_still_writes_the_model(client, no_llmfit,
                                                         cfg_path):
    """Adoptar un modelo no depende de llmfit: solo se pierden las notas."""
    r = client.post("/api/fit/apply", json={"model": "mi/modelo-local"})
    assert r.status_code == 200
    assert r.json()["model"] == "mi/modelo-local"
    text = cfg_path.read_text(encoding="utf-8")
    assert 'model: "mi/modelo-local"' in text
    assert "tok/s" not in text


def test_fit_apply_rejects_an_empty_model(client, fake_llmfit):
    assert client.post("/api/fit/apply", json={"model": ""}).status_code == 422
    assert client.post("/api/fit/apply", json={}).status_code == 422


def test_fit_apply_rejects_an_absurd_timeout(client, fake_llmfit):
    r = client.post("/api/fit/apply", json={"model": "m", "timeout_s": 99999})
    assert r.status_code == 422


# ------------------------------------------------- el escritor compartido
def test_put_config_still_goes_through_the_shared_writer(client, cfg_path):
    """`PUT /api/config` y `POST /api/fit/apply` comparten `_persist_config`.

    El refactor que extrajo el escritor no puede cambiar el contrato de la ruta
    que ya existía.
    """
    r = client.put("/api/config", json={"model": "m1", "base_url": "http://x/v1"})
    assert r.status_code == 200
    j = r.json()
    assert j["model"] == "m1" and j["updated"] == ["base_url", "model"]
    assert "m1" in cfg_path.read_text(encoding="utf-8")
    # Y put_config sin cambios sigue siendo un 400 explícito.
    assert client.put("/api/config", json={}).status_code == 400
