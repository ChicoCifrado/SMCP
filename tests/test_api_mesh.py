"""API tests — la malla en la web (`/api/mesh/*`).

El contrato que se fija aquí, y por qué:

* **La web y la CLI ven la misma malla.** Es la razón de que
  `default_state_path()` viva en el core y no duplicado en cada superficie: si
  la UI y la shell apuntaran a ficheros distintos, contributory desde el
  navegador no se vería en `delm mesh status`. Estos tests contribution por la
  API y luego leen por la CLI (subprocess) para probarlo de verdad.
* **La identidad es una sola.** El mismo fichero de clave, así que la
  contribución hecha desde la web es atribuible al mismo nodo que la de la
  shell.
* **Nada de secretos ni de la clave privada** en ninguna respuesta, y el
  endpoint de check dice explícitamente lo que *no* prueba (la existencia de la
  VRAM): es la mitad del contrato de este endpoint.
* **Rechazos = 400 con motivo**, no 500: un rechazo del ledger es una
  respuesta legítima de la malla (p. ej. `peer_key_changed`).

La config de malla se redirige a `tmp_path` con el mismo patrón que
`test_api_actions.py`: **ningún test escribe el estado real de la malla.**
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

import smcp_api
from api_server import app
from delm.core.contrib import ContributionLedger
from delm.core.provenance import KeyPair
from smcp_api import MANAGER

MESH = "malla-api-test"


@pytest.fixture()
def client():
    MANAGER._active = None
    MANAGER._history.clear()
    with TestClient(app) as c:
        yield c
    MANAGER._active = None
    MANAGER._history.clear()


@pytest.fixture()
def mesh_paths(tmp_path, monkeypatch):
    """Point the API's state + identity at tmp (and restore after)."""
    state = tmp_path / "mesh_exchange.json"
    ident = tmp_path / "mesh_identity.json"
    monkeypatch.setattr(smcp_api, "_mesh_state_path", lambda: state)
    monkeypatch.setattr(smcp_api, "_mesh_identity_path", lambda: ident)
    return state, ident


def contribute(client: TestClient, peer: str, vram: float, **kw) -> dict:
    r = client.post("/api/mesh/contribute", params={"mesh_id": MESH},
                    json={"peer_id": peer, "vram_gb": vram, "ram_gb": 64,
                          "cpu_cores": 12, **kw})
    assert r.status_code == 200, r.text
    return r.json()


def observe(client: TestClient, peer: str, seconds: float) -> dict:
    r = client.post("/api/mesh/observe", params={"mesh_id": MESH},
                    json={"peer_id": peer, "seconds": seconds})
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------------- estado
def test_mesh_starts_empty(client, mesh_paths):
    r = client.get("/api/mesh", params={"mesh_id": MESH})
    assert r.status_code == 200
    j = r.json()
    assert j["peers"] == []
    assert j["vram_verified_gb"] == 0.0
    assert j["chain_ok"] is True
    assert j["chain_entries"] == 0
    assert j["endpoint"].startswith("http")


def test_contribute_admits_and_persists(client, mesh_paths):
    state, ident = mesh_paths
    j = contribute(client, "nodo-a", 16.0)
    assert j["ok"] is True and j["reason"] == "ok"
    assert j["sig_kind"] == "ed25519" and len(j["digest"]) == 64
    assert state.exists() and ident.exists()

    led = ContributionLedger.load(str(state))
    assert led.peers["nodo-a"].vram_gb == 16.0
    assert led.verify_chain() is True


def test_contribute_reuses_one_identity(client, mesh_paths):
    _, ident = mesh_paths
    contribute(client, "nodo-a", 16.0)
    first = json.loads(ident.read_text(encoding="utf-8"))["public_key"]
    contribute(client, "nodo-a", 24.0)
    second = json.loads(ident.read_text(encoding="utf-8"))["public_key"]
    assert first == second          # mismo nodo, no dos


def test_observe_accrues_credit(client, mesh_paths):
    contribute(client, "nodo-a", 8.0)
    j = observe(client, "nodo-a", 3600)
    assert j["credits"] == pytest.approx(8.0)
    assert j["seconds_observed"] == 3600.0
    view = client.get("/api/mesh", params={"mesh_id": MESH}).json()
    assert view["peers"][0]["alive"] is True
    assert view["vram_verified_gb"] == pytest.approx(8.0)


def test_observe_of_an_unknown_peer_is_400(client, mesh_paths):
    r = client.post("/api/mesh/observe", params={"mesh_id": MESH},
                    json={"peer_id": "fantasma", "seconds": 60})
    assert r.status_code == 400
    assert "no está admitido" in r.json()["detail"]


def test_contribute_validates_its_input(client, mesh_paths):
    r = client.post("/api/mesh/contribute", params={"mesh_id": MESH},
                    json={"peer_id": "a", "vram_gb": -1})
    assert r.status_code == 422
    r = client.post("/api/mesh/contribute", params={"mesh_id": MESH},
                    json={"peer_id": "", "vram_gb": 1})
    assert r.status_code == 422
    r = client.post("/api/mesh/contribute", params={"mesh_id": MESH},
                    json={"peer_id": "a", "vram_gb": 1, "ttl_s": 10 ** 9})
    assert r.status_code == 422


def test_a_rebound_identity_is_refused_with_400(client, mesh_paths):
    """Editar el fichero de clave no cambia de nodo: la malla lo rechaza."""
    state, ident = mesh_paths
    contribute(client, "nodo-a", 16.0)
    blob = json.loads(ident.read_text(encoding="utf-8"))
    blob["private_key"] = "11" * 32
    ident.write_text(json.dumps(blob), encoding="utf-8")
    r = client.post("/api/mesh/contribute", params={"mesh_id": MESH},
                    json={"peer_id": "nodo-a", "vram_gb": 999.0})
    assert r.status_code == 400
    assert "peer_key_changed" in r.json()["detail"]
    assert ContributionLedger.load(str(state)).peers["nodo-a"].vram_gb == 16.0


# -------------------------------------------------------------------- plan
def test_plan_without_llmfit_using_explicit_memory(client, mesh_paths):
    contribute(client, "nodo-a", 16.0)
    observe(client, "nodo-a", 3600)
    r = client.get("/api/mesh/plan", params={
        "mesh_id": MESH, "model": "Qwen/Qwen3-32B", "memory_gb": 40,
        "layers": 64})
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is False
    assert j["reason"] == "insufficient_mesh_vram"
    assert "faltan 24.0G" in " ".join(j["notes"])
    assert j["available"] is True


def test_plan_splits_and_carries_mesh_context(client, mesh_paths):
    contribute(client, "nodo-a", 16.0)
    observe(client, "nodo-a", 3600)
    contribute(client, "nodo-b", 24.0)
    observe(client, "nodo-b", 3600)
    j = client.get("/api/mesh/plan", params={
        "mesh_id": MESH, "model": "Qwen/Qwen3-32B", "memory_gb": 36,
        "layers": 64}).json()
    assert j["ok"] is True
    assert j["node_count"] == 2
    assert sum(s["memory_gb"] for s in j["stages"]) == pytest.approx(36.0)
    # El plan viene con el contexto de la malla: una sola llamada responde
    # "quién aporta" y "quién lo hospeda".
    assert j["vram_verified_gb"] == pytest.approx(40.0)
    assert len(j["peers"]) == 2
    assert j["mesh_id"] == MESH


def test_plan_uses_llmfit_when_no_memory_is_given(client, mesh_paths,
                                                 monkeypatch):
    from delm.core.llmfit import FitReport

    payload = {"models": [{
        "name": "Qwen/Qwen3-30B-A3B", "params_b": 30.0,
        "memory_required_gb": 15.6, "best_quant": "Q3_K_M",
        "fit_level": "marginal", "estimated_tps": 34.9, "runtime": "llama.cpp",
    }], "total_models": 1}
    monkeypatch.setattr("delm.core.llmfit.LlmfitRunner.catalog",
                        lambda self, **kw: FitReport.from_payload(payload))
    contribute(client, "nodo-a", 24.0)
    observe(client, "nodo-a", 3600)
    j = client.get("/api/mesh/plan", params={
        "mesh_id": MESH, "model": "Qwen/Qwen3-30B-A3B"}).json()
    assert j["ok"] is True
    assert j["memory_required_gb"] == pytest.approx(15.6)
    assert "llmfit" in j["llmfit"]


def test_plan_without_llmfit_is_not_an_http_error(client, mesh_paths,
                                                  monkeypatch):
    from delm.core.llmfit import LlmfitNotFound

    def boom(self, **kw):
        raise LlmfitNotFound("llmfit no esta instalado")

    monkeypatch.setattr("delm.core.llmfit.LlmfitRunner.catalog", boom)
    j = client.get("/api/mesh/plan", params={
        "mesh_id": MESH, "model": "m"}).json()
    assert j["available"] is False
    assert "no esta instalado" in j["hint"]
    # Y la página sigue pudiendo pintar el estado de la malla.
    assert j["mesh_id"] == MESH and j["peers"] == []


def test_plan_of_an_unknown_model_is_400_with_the_escape_hatch(client,
                                                               mesh_paths,
                                                               monkeypatch):
    from delm.core.llmfit import FitReport

    monkeypatch.setattr("delm.core.llmfit.LlmfitRunner.catalog",
                        lambda self, **kw: FitReport.from_payload({"models": []}))
    r = client.get("/api/mesh/plan", params={"mesh_id": MESH, "model": "nope"})
    assert r.status_code == 400
    assert "memory_gb" in r.json()["detail"]


def test_plan_requires_a_model(client, mesh_paths):
    assert client.get("/api/mesh/plan", params={"mesh_id": MESH}).status_code == 422


# ------------------------------------------------------------------ check
def test_check_reports_chain_and_balances(client, mesh_paths):
    contribute(client, "nodo-a", 8.0)
    observe(client, "nodo-a", 600)
    j = client.get("/api/mesh/check", params={"mesh_id": MESH}).json()
    assert j["ok"] is True
    assert j["chain_ok"] is True
    assert j["negative_balances"] == []
    assert j["not_proven"] and "atestación" in j["not_proven"]


def test_check_detects_a_tampered_chain(client, mesh_paths):
    state, _ = mesh_paths
    contribute(client, "nodo-a", 8.0)
    observe(client, "nodo-a", 600)
    blob = json.loads(state.read_text(encoding="utf-8"))
    blob["records"][0]["digest"] = "0" * 64
    state.write_text(json.dumps(blob), encoding="utf-8")
    j = client.get("/api/mesh/check", params={"mesh_id": MESH}).json()
    assert j["ok"] is False and j["chain_ok"] is False


def test_check_lists_refusals(client, mesh_paths):
    contribute(client, "nodo-a", 8.0)
    observe(client, "nodo-a", 600)
    _, ident = mesh_paths
    blob = json.loads(ident.read_text(encoding="utf-8"))
    blob["private_key"] = "22" * 32
    ident.write_text(json.dumps(blob), encoding="utf-8")
    client.post("/api/mesh/contribute", params={"mesh_id": MESH},
                json={"peer_id": "nodo-a", "vram_gb": 999.0})
    j = client.get("/api/mesh/check", params={"mesh_id": MESH}).json()
    assert j["rejections"] == 1
    assert j["refusals"][-1]["reason"] == "peer_key_changed"


# ------------------------------------------------------------------ secretos
def test_no_response_ever_contains_the_private_key(client, mesh_paths):
    _, ident = mesh_paths
    contribute(client, "nodo-a", 16.0)
    observe(client, "nodo-a", 3600)
    priv = json.loads(ident.read_text(encoding="utf-8"))["private_key"]
    for path, params in (("/api/mesh", {"mesh_id": MESH}),
                         ("/api/mesh/check", {"mesh_id": MESH}),
                         ("/api/mesh/plan", {"mesh_id": MESH, "model": "m",
                                             "memory_gb": 8})):
        body = client.get(path, params=params).text
        assert priv not in body
        assert "private_key" not in body
        assert "signature" not in body


def test_identity_path_is_reported_but_not_its_content(client, mesh_paths):
    j = contribute(client, "nodo-a", 16.0)
    assert j["identity_path"].endswith("mesh_identity.json")


# ------------------------------------------------- web y CLI, una sola malla
def test_the_cli_sees_what_the_web_contributed(client, mesh_paths, tmp_path):
    """La prueba de que son la misma malla: API escribe, CLI lee.

    Se lanza `python -m delm mesh status` como subprocess apuntando al mismo
    ``--state``, porque es el contrato público de la CLI y no su función interna.
    """
    state, _ = mesh_paths
    contribute(client, "nodo-a", 16.0)
    observe(client, "nodo-a", 3600)
    p = subprocess.run(
        [sys.executable, "-m", "delm", "mesh", "status", "--state", str(state),
         "--mesh-id", MESH],
        capture_output=True, text=True, timeout=120,
    )
    assert p.returncode == 0, p.stderr
    assert "nodo-a" in p.stdout
    assert "16.0G verificados" in p.stdout
    assert "íntegra" in p.stdout


def test_a_mismatched_mesh_id_does_not_inherit_balances(client, mesh_paths):
    contribute(client, "nodo-a", 16.0)
    observe(client, "nodo-a", 3600)
    other = client.get("/api/mesh", params={"mesh_id": "otra"}).json()
    assert other["mesh_id"] == "otra"
    assert other["peers"] == []          # no hereda saldos de otra malla
    assert other["vram_verified_gb"] == 0.0
