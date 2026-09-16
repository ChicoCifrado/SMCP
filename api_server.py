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
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

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
        "desc": "Suite por defecto (-m 'not slow', -q). 231 tests; los slow "
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
    """Estado resumido del proyecto."""
    # Contar módulos y tests
    core = sorted((ROOT / "delm" / "core").glob("*.py"))
    core = [p.name for p in core if not p.name.startswith("_")]
    tests = sorted((ROOT / "tests").glob("test_*.py"))
    return {
        "core_modules": len(core),
        "core": core,
        "test_files": len(tests),
        "functions": len(FUNCTIONS),
        "web_pages": len(list((WEB).glob("*.html"))),
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
