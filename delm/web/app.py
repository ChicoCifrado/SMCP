"""DeLM/SMCP — la app FastAPI de la web.

Expone las funciones del proyecto a la UI:
  - /api/functions  -> lista de funciones disponibles
  - /api/run/<name> -> ejecuta la función (subprocess) y devuelve JSON
  - /api/status     -> estado del proyecto (tests, demos, módulos)

Monta además el router interactivo de :mod:`delm.web.api` bajo ``/api/*`` y
sirve los estáticos de ``delm/web/static``.

Uso:  ``delm-serve-web``  (o ``python -m delm.web.app``)  ->  http://127.0.0.1:8099

**El checkout no es obligatorio.** Las demos son módulos instalados y se
lanzan desde cualquier sitio; lo que necesita el árbol de fuentes es correr
la *suite* y contar ``tests/`` y ``delm/core/``. Sin checkout, ``/api/status``
lo dice con ``repo: false`` y explica cual es la parte no disponible, para
que la UI pueda apagar ese botón en vez de mostrar un cero que parece un dato.
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

from delm.web import REPO_ROOT, STATIC

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
from delm.web.api import router as smcp_router

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
        "desc": "Suite por defecto (-m 'not slow'). 297 tests; los slow "
                "se corren aparte. La API resume el resultado.",
        # Sin -q: pytest emite la línea final "N passed …" (con -q se omite
        # si no hay warnings y el parser de resumen no tendría qué leer).
        "cmd": [sys.executable, "-m", "pytest", "tests/", "-m", "not slow", "--no-header", "-p", "no:cacheprovider"],
        "slow": False,
    },
]

_BY_ID = {f["id"]: f for f in FUNCTIONS}

# Líneas de progreso de pytest: puntos/letras + porcentaje entre corchetes.
_PROGRESS_RE = re.compile(r"^[.\sFEsxXipP]*\[\s*\d+%\]\s*$")
_SUMMARY_N_RE = re.compile(r"(\d+)\s+(failed|error|passed|skipped|deselected|xfailed|xpassed|warnings?)", re.I)
_WARN_RE = re.compile(
    r"^=+\s*warnings summary\s*=+\s*$[\s\S]*?(?=^=+\s+\w|^-- Docs:|\Z)",
    re.M | re.I,
)
_DOC_RE = re.compile(r"^-- Docs:\s+https?://\S+\s*$", re.M)


def _parse_pytest(stdout: str, stderr: str) -> dict:
    """Resumen estructurado de la salida de pytest (para la UI).

    Separa: headline (`297 passed · 0 failed`), cuerpo limpio (sin puntos de
    progreso ni bloque de warnings) y el texto de warnings aparte.
    """
    text = (stdout or "") + ("\n" + stderr if stderr else "")
    counts: dict[str, int] = {}
    summary_line = ""
    for line in reversed(text.splitlines()):
        s = line.strip().strip("=").strip()
        if not s or "warnings summary" in s.lower() or s.startswith("short test summary"):
            continue
        hits = dict((k.lower().rstrip("s"), int(n)) for n, k in _SUMMARY_N_RE.findall(s))
        # Línea final real lleva al menos "passed" o "failed"/"error".
        if "passed" in hits or "failed" in hits or "error" in hits:
            counts = hits
            summary_line = s
            break

    warn_m = _WARN_RE.search(text)
    warnings_text = ""
    if warn_m:
        warnings_text = _DOC_RE.sub("", warn_m.group(0)).strip("\n")
    elif re.search(r"\b(\d+)\s+warnings?\b", summary_line or "", re.I):
        # Sin bloque (p.ej. filtrado); al menos contamos del headline.
        pass

    # Cuerpo: quitar progreso, bloque de warnings y línea Docs.
    body_lines: list[str] = []
    in_warn = False
    for line in (stdout or "").splitlines():
        if _PROGRESS_RE.match(line):
            continue
        if re.match(r"^=+\s*warnings summary\s*=+\s*$", line, re.I):
            in_warn = True
            continue
        if in_warn:
            if re.match(r"^=+\s+\w", line) or _DOC_RE.match(line) or re.match(r"^=+\s*\d+\s+(passed|failed)", line, re.I):
                in_warn = False
                if not _PROGRESS_RE.match(line) and not _DOC_RE.match(line):
                    body_lines.append(line)
            continue
        if _DOC_RE.match(line):
            continue
        body_lines.append(line)
    body = "\n".join(body_lines).strip()
    # Quitar el resumen final ya reflejado en el headline (no duplicar).
    if summary_line:
        # La línea final puede ir rodeada de '='.
        body = re.sub(
            r"(?:^|\n)=*\s*" + re.escape(summary_line) + r"\s*=*(?=\n|$)",
            "",
            body,
        ).strip()

    passed = counts.get("passed", 0)
    failed = counts.get("failed", 0)
    errors = counts.get("error", 0)
    skipped = counts.get("skipped", 0)
    warnings_n = counts.get("warning", 0)
    parts = [f"{passed} passed", f"{failed} failed"]
    if errors:
        parts.append(f"{errors} error")
    if skipped:
        parts.append(f"{skipped} skipped")
    if warnings_n:
        parts.append(f"{warnings_n} warning" if warnings_n == 1 else f"{warnings_n} warnings")
    headline = " · ".join(parts) if counts else ""

    return {
        "headline": headline,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
        "warnings": warnings_n,
        "body": body,
        "warnings_text": warnings_text,
        "parsed": bool(counts),
    }


# ------------------------------------------------------------------ run
def _run(cmd: list[str], timeout: int) -> dict:
    """Ejecuta un comando y captura salida/estado.

    El ``cwd`` es la raíz del repo **si existe**; sin checkout, los módulos
    instalados se lanzan desde donde viva el usuario (las demos y la API no
    necesitan el árbol de fuentes). La *suite* sí lo necesita y lo dice ella
    misma en su error, en vez de que esto adivine un directorio.
    """
    cwd = str(REPO_ROOT) if REPO_ROOT is not None else None
    t0 = time.time()
    try:
        p = subprocess.run(
            cmd, cwd=cwd,
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
    """Estado resumido del proyecto (lectura en vivo del filesystem).

    Lo que se cuenta es lo que vive en el **checkout** (modulos de core,
    ficheros de test, demos del repo). En una instalacion sin checkout eso no
    existe, y la respuesta lo dice con ``repo: false`` + ``unavailable`` en
    vez de devolver ceros: un `0` aqui es indistinguible de "el proyecto
    tiene cero tests", que es la lectura que haria la UI.

    Lo que NO depende del checkout —la lista de funciones, el numero de
    paginas de la UI, y si la suite es ejecutable— se responde siempre, para
    que la vista siga siendo util sin arbol de fuentes.
    """
    root = REPO_ROOT
    base: dict[str, object] = {
        "repo": root is not None,
        "functions": len(FUNCTIONS),
        "web_pages": len(list(STATIC.glob("*.html"))),
        # Las demos son modulos INSTALADOS (`delm.demo.*`), no ficheros del
        # checkout: se cuentan desde el paquete, asi que el numero es real
        # con o sin arbol de fuentes. Contarlo por `root` seria mentir en la
        # direccion contraria — untrue-zero cuando el paquete si las trae.
        "demos": sorted(
            p.stem for p in
            (Path(__file__).resolve().parent.parent / "demo").glob("run_*.py")),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    if root is None:
        # Sin checkout: la UI puede apagar "correr tests" y el conteo de
        # modulos, pero las demos (modulos instalados) siguen disponibles.
        base["unavailable"] = [
            "tests",       # correr la suite requiere el arbol de fuentes
            "test_files",  # idem: `tests/` no viaja en el wheel
            "test_fns",
            "core",        # `delm/core/` si esta instalado, pero no como arbol
        ]
        return base

    core = sorted((root / "delm" / "core").glob("*.py"))
    core_names = [p.name for p in core if not p.name.startswith("_")]
    tests = sorted((root / "tests").glob("test_*.py"))
    # Conteo de `def test_` por archivo (aprox. coleccionable; el total
    # exacto lo da `pytest --collect-only` — el README es la fuente de verdad).
    test_fns = 0
    for p in tests:
        try:
            test_fns += p.read_text(encoding="utf-8").count("def test_")
        except OSError:
            pass
    base.update({
        "core_modules": len(core_names),
        "core": core_names,
        "test_files": len(tests),
        "test_fns": test_fns,
        # `demos` ya viene en `base`, contado desde el paquete instalado.
    })
    return base


@app.post("/api/run/{fid}")
def run(fid: str):
    if fid not in _BY_ID:
        return {"ok": False, "error": f"función desconocida: {fid}"}
    if fid == "tests" and REPO_ROOT is None:
        # Opción 2 (degradar con aviso, no con un cero): la suite necesita el
        # arbol de fuentes. Se responde con un motivo accionable en vez de
        # dejar que pytest falle con "file or directory not found".
        return {
            "ok": False,
            "code": -1,
            "error": (
                "correr la suite requiere el checkout del repo: `tests/` no "
                "viaja en el wheel. Clona el repo o usa `delm test`."
            ),
            "requires_repo": True,
        }
    f = _BY_ID[fid]
    # timeout por función (tests slow en WSL: QUIC/RED)
    timeouts = {"tests": 240, "multihost": 180}
    timeout = timeouts.get(fid, 60)
    result = _run(f["cmd"], timeout)
    if fid == "tests":
        summary = _parse_pytest(result.get("stdout") or "", result.get("stderr") or "")
        result["summary"] = summary
        if summary["parsed"]:
            # Cuerpo limpio siempre (puede ir vacío si todo pasó);
            # no caer al stdout crudo con puntos de progreso.
            result["stdout"] = summary["body"]
            result["stderr"] = summary["warnings_text"]
    return result


# ------------------------------------------------------------------ estático
# Montar los estáticos en / (después de las rutas API para que estas ganen
# prioridad). Van desde el PAQUETE, no desde el checkout: por eso la UI
# funciona igual instalada que en desarrollo.
app.mount("/", StaticFiles(directory=str(STATIC), html=True), name="web")


def main() -> None:
    """Punto de entrada de ``delm-serve-web``.

    Bind a 127.0.0.1 por diseno: es una UI de inspeccion local con capacidad
    de lanzar la suite del repo, no un servicio para exponer.
    """
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8099, log_level="info")


if __name__ == "__main__":
    main()
