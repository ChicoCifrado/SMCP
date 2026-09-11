#!/usr/bin/env python3
"""Check de conciliación README (issue #8).

La convención del proyecto: el README declara un conteo de tests
("N tests en verde") que debe **cuadrar** con el total real de tests
(``pytest --collect-only -q`` con los ``addopts`` por defecto, i.e.
``-m 'not slow'``).

Este script extrae el conteo declarado en el ``README.md`` y lo compara
contra ``pytest --collect-only -q``. Si no coinciden, **rompe el CI** —
así se fuerza la convención de actualizar el README al añadir/quitar
tests.

Uso::

    python scripts/check_readme_count.py

Sale con código 0 si cuadran, 1 si no (con un mensaje explicativo).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"


def declared_count() -> int:
    """Extrae el conteo declarado en el README ('N tests en verde')."""
    text = README.read_text(encoding="utf-8")
    # El README lo declara como: - **225 tests en verde** (...)
    m = re.search(r"\*\*(\d+)\s+tests en verde\*\*", text)
    if not m:
        sys.exit(
            "ERROR: no se encuentra el conteo '**N tests en verde**' en el "
            "README. La convención requiere ese marcador para la conciliación."
        )
    return int(m.group(1))


def collected_count() -> int:
    """Total de tests reales: ``pytest --collect-only -q`` (con addopts).

    El ``-q`` de ``--collect-only`` imprime una línea por archivo de test
    con su conteo (``tests/test_foo.py: 12``). Se suma. Los ``addopts`` por
    defecto (``-m 'not slow'``) se aplican, así el total coincide con la
    suite que corre el CI y con el conteo del README.
    """
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    # Suma las líneas 'tests/test_foo.py: N'.
    total = 0
    for line in out.stdout.splitlines():
        line = line.strip()
        # Formato: 'tests/test_foo.py: 12' (ruta relativa + ': ' + entero).
        m = re.match(r"^[\w/]+\.py:\s*(\d+)$", line)
        if m:
            total += int(m.group(1))
    if total == 0:
        sys.exit(
            "ERROR: no se pudo contar tests de la salida de "
            "'pytest --collect-only -q'. Salida:\n" + (out.stdout or out.stderr)
        )
    return total


def main() -> None:
    declared = declared_count()
    collected = collected_count()
    if declared != collected:
        sys.exit(
            f"ERROR: el README declara {declared} tests, pero "
            f"'pytest --collect-only -q' da {collected}. "
            f"Actualiza el README al añadir/quitar tests "
            f"(convención: el conteo debe cuadrar con la suite real)."
        )
    print(f"OK: el README y 'pytest --collect-only -q' cuadran ({declared} tests).")


if __name__ == "__main__":
    main()
