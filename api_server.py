"""DeLM/SMCP — API server.

Expone las funciones del proyecto a la UI de Three.js:
  - /api/functions  -> lista de funciones disponibles
  - /api/run/<name> -> ejecuta la función (subprocess) y devuelve JSON
  - /api/status     -> estado del proyecto (tests, demos, módulos)

Sirve también el directorio web/ estático.
Uso:  python api_server.py   ->  http://127.0.0.1:8099
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent          # .../delm
WEB = ROOT / "web"
sys.path.insert(0, str(ROOT))                 # para `import delm`

app = FastAPI(title="DeLM/SMCP API")
# Localhost-only UI: do not open CORS to arbitrary origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8099",
        "http://localhost:8099",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Interactive session API (runs, context, ledger, demos, health).
from smcp_api import router as smcp_router  # noqa: E402

app.include_router(smcp_router)

# ------------------------------------------------------------------ funciones
# Cada función: (id, etiqueta, descripción, comando)
FUNCTIONS = [
    {
        "id": "demo",
        "label": "Pipeline DeLM",
        "desc": "Demo end-to-end: cola, workers, verificación, admisión, "
                "despliegue selectivo y finalización (sin API key).",
        "cmd": [sys.executable, "-m", "delm.demo.run_demo"],
        "slow": False,
    },
    {
        "id": "security",
        "label": "Capa de seguridad",
        "desc": "Capas 1+2: digest, firma ed25519, inmutabilidad y ledger "
                "append-only (agente legítimo, malicioso y manipulado).",
        "cmd": [sys.executable, "-m", "delm.demo.run_security_demo"],
        "slow": False,
    },
    {
        "id": "taint",
        "label": "Anti prompt-injection",
        "desc": "Capa 4: taint + filtro de inyección; el contenido malicioso "
                "queda cuarentenado y el flujo sigue.",
        "cmd": [sys.executable, "-m", "delm.demo.run_taint_demo"],
        "slow": False,
    },
    {
        "id": "multihost",
        "label": "Multi-host (QUIC)",
        "desc": "Dos nodos DeLM sobre QUIC: gossip, relay y drenado de cola "
                "(lento — abre puertos).",
        "cmd": [sys.executable, "-m", "delm.demo.run_multihost_demo"],
        "slow": True,
    },
    {
        "id": "tests",
        "label": "Suite de tests",
        "desc": "Suite por defecto (-m 'not slow', -q). 285 tests; los slow "
                "se corren aparte.",
        "cmd": [sys.executable, "-m", "pytest", "tests/", "-m", "not slow", "-q", "--no-header", "-p", "no:cacheprovider"],
        "slow": False,
    },
]

_BY_ID = {f["id"]: f for f in FUNCTIONS}


# ------------------------------------------------------------------ run
def _run(cmd: list[str], timeout: int) -> dict:
    """Ejecuta un comando y captura salida/estado."""
    t0 = time.time()
    try:
        p = subprocess.run(
            cmd, cwd=str(ROOT),
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        return {
            "ok": p.returncode == 0,
            "code": p.returncode,
            "secs": round(time.time() - t0, 2),
            "stdout": p.stdout[-20000:],
            "stderr": p.stderr[-20000:],
        }
    except subprocess.TimeoutExpired as e:
        return {
            "ok": False, "code": -1, "secs": round(time.time() - t0, 2),
            "stdout": (e.stdout or "")[-20000:] if isinstance(e.stdout, str) else "",
            "stderr": f"timeout {timeout}s",
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "code": -1, "secs": round(time.time() - t0, 2),
                "stdout": "", "stderr": str(e)}


# ------------------------------------------------------------------ rutas
@app.get("/api/functions")
def get_functions():
    return FUNCTIONS


@app.get("/api/status")
def status():
    """Estado resumido del proyecto (lectura en vivo del filesystem)."""
    core = sorted((ROOT / "delm" / "core").glob("*.py"))
    core = [p.name for p in core if not p.name.startswith("_")]
    tests = sorted((ROOT / "tests").glob("test_*.py"))
    # Conteo de `def test_` por archivo (aprox. coleccionable; el total
    # exacto lo da `pytest --collect-only` — el README es la fuente de verdad).
    test_fns = 0
    for p in tests:
        try:
            test_fns += p.read_text(encoding="utf-8").count("def test_")
        except OSError:
            pass
    demos = sorted((ROOT / "delm" / "demo").glob("run_*.py"))
    return {
        "core_modules": len(core),
        "core": core,
        "test_files": len(tests),
        "test_fns": test_fns,
        "demos": [p.stem for p in demos],
        "functions": len(FUNCTIONS),
        "web_pages": len(list((WEB).glob("*.html"))),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }


@app.post("/api/run/{fid}")
def run(fid: str):
    if fid not in _BY_ID:
        return {"ok": False, "error": f"función desconocida: {fid}"}
    f = _BY_ID[fid]
    # timeout por función (tests slow en WSL: QUIC/RED)
    timeouts = {"tests": 240, "multihost": 180}
    timeout = timeouts.get(fid, 60)
    return _run(f["cmd"], timeout)


# ------------------------------------------------------------------ estático
# Montar web/ en / (después de las rutas API para que estas ganen prioridad)
app.mount("/", StaticFiles(directory=str(WEB), html=True), name="web")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8099, log_level="info")
