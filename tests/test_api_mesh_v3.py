"""API tests — la red v3 en la web (`/api/mesh/v3`).

El contrato que se fija aquí:

* **La consola y el core ven la misma red.** El endpoint mueve
  la misma coreografía que ``tests/test_mesh_v3.py`` (gossip,
  join, inferencia) sobre el mismo core — no hay una segunda
  implementación en la web.
* **El cable es el stream.** Cada datagrama v3 (handshake,
  roster, petición, respuesta, términos, pago) viaja por el
  SSE, en orden, con su dirección.
* **El estado dice la verdad.** ``joined`` trae la confianza
  mutua; ``served`` la nota de finalización del pago;
  ``settled`` el cobro; el estado terminal es ``done``.
* **404 con motivo** para una sesión que no existe.
"""
from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from smcp.core.inscripcion import NOTAS_COMPLETADO
from smcp.web.app import app
from smcp.web.api import _MESH_V3


@pytest.fixture()
def client():
    _MESH_V3.clear()
    with TestClient(app) as c:
        yield c
    _MESH_V3.clear()


def _wait_done(client: TestClient, sid: str,
               timeout: float = 30.0) -> dict:
    """Espera a que la sesión termine y devuelve su header."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        st = client.get(f"/api/mesh/v3/{sid}")
        assert st.status_code == 200
        hdr = st.json()
        if hdr["status"] in ("done", "error"):
            return hdr
        time.sleep(0.1)
    raise AssertionError("la sesión no terminó a tiempo")


def test_la_red_v3_completa(client: TestClient):
    """Dos nodos se emparejan y sirven una inferencia."""
    r = client.post("/api/mesh/v3", json={"prompt": "hola red"})
    assert r.status_code == 200
    hdr = r.json()
    assert hdr["id"].startswith("mesh-")
    assert hdr["prompt"] == "hola red"

    final = _wait_done(client, hdr["id"])
    assert final["status"] == "done", final.get("error")

    eventos = _MESH_V3[hdr["id"]].events
    tipos = [e["type"] for e in eventos]
    assert "gossip" in tipos
    assert "joined" in tipos
    assert "settled" in tipos
    assert "done" in tipos

    joined = next(e for e in eventos if e["type"] == "joined")
    assert joined["mutual"] is True
    assert joined["authenticated"] is True

    settled = next(e for e in eventos if e["type"] == "settled")
    assert settled["inferences"] >= 1
    assert settled["earned"] > 0

    # Al completar la inferencia, el pago dice al
    # receptor una de las notas fijas — siempre del
    # vocabulario, nunca texto libre.
    served = next(e for e in eventos if e["type"] == "served")
    assert served["nota"] in NOTAS_COMPLETADO

    # La secuencia de la inferencia por el cable, en orden.
    wires = [e for e in eventos if e["type"] == "wire"]
    seq = [(w["frm"], w["to"], w["kind"]) for w in wires]
    assert ("A", "B", "request") in seq
    assert ("B", "A", "response") in seq
    assert ("B", "A", "terms") in seq
    assert ("A", "B", "payment") in seq
    # El handshake cruza antes que el roster, y el roster
    # antes que la petición.
    kinds = [w["kind"] for w in wires]
    assert kinds.index("handshake") < kinds.index("roster")
    assert kinds.index("roster") < kinds.index("request")


def test_el_sse_entrega_el_cable(client: TestClient):
    """El stream de eventos: el cable en vivo hasta el fin."""
    r = client.post("/api/mesh/v3", json={"prompt": "stream"})
    assert r.status_code == 200
    sid = r.json()["id"]

    tipos: list[str] = []
    with client.stream("GET", f"/api/mesh/v3/{sid}/events") as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith(
            "text/event-stream")
        for linea in resp.iter_lines():
            if not linea.startswith("data: "):
                continue
            ev = json.loads(linea[6:])
            tipos.append(ev["type"])
            if ev["type"] == "end":
                assert ev["status"] == "done"
                break
    assert "joined" in tipos
    assert "done" in tipos
    assert "end" in tipos


def test_sesion_inexistente_es_404(client: TestClient):
    """Una sesión que no existe se dice, no se inventa."""
    r = client.get("/api/mesh/v3/no-existe")
    assert r.status_code == 404
    r2 = client.get("/api/mesh/v3/no-existe/events")
    assert r2.status_code == 404
