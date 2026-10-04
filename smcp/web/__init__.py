"""Delm/web — el paquete de la capa web (API + UI estática).

Este paquete es lo que convierte la web en **superficie instalable**: antes
vivía en `api_server.py` / `smcp_api.py` en la raíz del repo, fuera del
paquete `delm`, así que el wheel no lo shippeaba. `pip install delm[web]`
instalaba `fastapi` + `uvicorn` para un módulo que no existía en la
instalación, y la UI solo se podía lanzar con `cd` al checkout.

Layout:

  app.py      -> la app FastAPI (rutas de estado/funciones + estático)
  api.py      -> el router de la API interactiva (sesiones, scan, mesh…)
  static/     -> la UI (HTML/CSS/JS, sin build step) + el wordmark OTF

**Un checkout no es un requisito para arrancar la UI, pero sí para todo lo
que inspecciona el repo en disco.** Las demos son módulos instalados y se
lanzan en cualquier sitio; correr la *suite* y contar `tests/` y
`delm/core/` requiere el árbol de fuentes. Esa distinción se expone en
`/api/status` con `repo` (`True`/`False`) y, cuando es `False`, la UI puede
decir por qué un botón está apagado en vez de devolver un cero silencioso.
"""
from __future__ import annotations

from pathlib import Path

#: La raíz del paquete `smcp.web` (…/site-packages/delm/web).
WEB_ROOT = Path(__file__).resolve().parent
#: Los estáticos que sirve la UI. Son datos de paquete, no código: por eso
#: están declarados en `[tool.setuptools.package-data]` y no se served desde
#: el checkout.
STATIC = WEB_ROOT / "static"


def find_repo_root() -> Path | None:
    """La raíz del checkout del repo, o ``None`` en una instalación.

    Se sube desde este archivo buscando un directorio que contenga a la vez
    ``delm/core`` y ``pyproject.toml``. Devolver ``None`` —y no una ruta
    inventada— es lo que permite a la UI distinguir "no hay checkout" de
    "hay checkout pero está vacío", en vez de mostrar ceros.
    """
    here = WEB_ROOT
    for cand in (here, *here.parents):
        if (cand / "pyproject.toml").is_file() and (cand / "smcp" / "core").is_dir():
            return cand
    # Un checkout donde `delm` es el propio paquete en editable-install.
    if (here.parent / "pyproject.toml").is_file() and (here.parent / "smcp" / "core").is_dir():
        return here.parent
    return None


#: Raíz del repo resuelta en import time. ``None`` = instalación sin checkout.
REPO_ROOT = find_repo_root()

__all__ = ["WEB_ROOT", "STATIC", "REPO_ROOT", "find_repo_root"]
