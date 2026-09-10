"""Tests de la demo multi-host (2 nodos, procesos distintos).

Verifica que la demo converge: el orquestador arranca 2 nodos (en procesos
distintos) que se conectan entre sí (sobre **QUIC**, el default) o sobre
**Nostr** (el modo ``--nostr``) y convergen al mismo conjunto de gists.

La demo es un test de **integración** (subprocess + handshake QUIC + red);
es **lenta** (el handshake QUIC en WSL tarda ~60-120s). Se marca con
``@pytest.mark.slow`` para poder excludirla en CI rápidos.

Uso::

    python -m delm.demo.run_multihost_demo            # QUIC (default)
    python -m delm.demo.run_multihost_demo --nostr   # Nostr (relay)
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest


def _run_demo(args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    """Corre la demo (``python -m delm.demo.run_multihost_demo <args>``).

    El orquestador arranca los nodos (subprocess), verifica la convergencia
    y muestra ``=== demo OK ===``. Si la demo no converge, el orquestador
    lanza (assert) y el subprocess termina con código no-0.
    """
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "delm.demo.run_multihost_demo", *args],
        capture_output=True, text=True, timeout=timeout, env=env,
    )


@pytest.mark.slow
def test_demo_quic_converges():
    """La demo (default, **QUIC**) converge: 2 nodos, procesos distintos.

    El orquestador arranca 2 nodos sobre QUIC (``B`` servidor, ``A`` cliente)
    que publican un gist cada uno y convergen al mismo conjunto de 2 gists.
    El orquestador muestra ``=== demo OK ===`` si converge.
    """
    res = _run_demo([], timeout=300)
    assert res.returncode == 0, (
        f"la demo QUIC no converge (rc={res.returncode}):\n"
        f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}"
    )
    # El orquestador muestra la convergencia y el OK.
    assert "demo OK" in res.stdout, f"falta 'demo OK' en:\n{res.stdout}"
    # La convergencia: A == B (mismo conjunto de gists).
    assert "convergencia" in res.stdout, f"falta 'convergencia' en:\n{res.stdout}"


def test_demo_nostr_converges():
    """La demo (``--nostr``) converge: 2 nodos, procesos distintos, Nostr.

    El modo Nostr (el anterior, con un relay) sigue disponible: el orquestador
    arranca un relay ``NostrRelayServer`` + 2 nodos que convergen al mismo
    conjunto de gists. Verifica que el modo Nostr no se rompa (regresión).
    """
    res = _run_demo(["--nostr"], timeout=300)
    assert res.returncode == 0, (
        f"la demo Nostr no converge (rc={res.returncode}):\n"
        f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}"
    )
    assert "demo OK" in res.stdout, f"falta 'demo OK' en:\n{res.stdout}"
