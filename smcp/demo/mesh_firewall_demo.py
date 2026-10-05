"""Orquestador de la prueba de fuego: dos agentes en procesos distintos,
red real (eth0), inferencia local (:8888/v1) y gists firmados por QUIC.

Nodo B (servidor) escucha en 0.0.0.0:<port>.
Nodo A (cliente) conecta por la IP real de la maquina.
Ambos resuelven su tarea, publican el gist firmado y convergen.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile


def _free_port() -> int:
    s = socket.socket()
    s.bind(("0.0.0.0", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main() -> None:
    import subprocess as sp
    host = sp.check_output(
        ["ip", "route", "get", "1.1.1.1"], text=True
    ).split("src ")[1].split()[0]
    port_b = _free_port()
    tmpdir = tempfile.mkdtemp(prefix="smcp_mesh_firewall_")
    # Serve en la IP real de la maquina (no 0.0.0.0): aioquic
    # bindea el UDP socket en esa interfaz y el cliente la
    # alcanza. 0.0.0.0 no se reporta en ss y el enlace no
    # sube en WSL.
    portmap = {
        "A": {"role": "connect", "host": host, "port": port_b, "peer": "B"},
        "B": {"role": "serve", "host": host, "port": port_b, "peer": "A"},
    }
    with open(os.path.join(tmpdir, "portmap"), "w") as f:
        json.dump(portmap, f)
    procs = {}
    try:
        for nm, task in (
            ("A", "Hecho verificable del nodo A: la malla transporta gists firmados."),
            ("B", "Hecho verificable del nodo B: dos agentes convergen sobre QUIC."),
        ):
            procs[nm] = subprocess.Popen(
                [sys.executable, "-m", "smcp.demo.run_firewall_mesh",
                 "mesh-node", tmpdir, nm, task],
                env={**os.environ, "PYTHONPATH": os.getcwd()},
                stderr=subprocess.DEVNULL,
            )
        for nm in procs:
            procs[nm].wait(timeout=300)
            if procs[nm].returncode != 0:
                raise SystemExit(
                    f"el nodo {nm} salio con codigo {procs[nm].returncode}")
        ra = json.load(open(os.path.join(tmpdir, "A.result")))
        rb = json.load(open(os.path.join(tmpdir, "B.result")))
        print("=== SMCP prueba de fuego (malla + inferencia, 2 agentes, red real) ===")
        print(f"host WSL           : {host}")
        print(f"puerto B (serve)   : {port_b} (bind 0.0.0.0)")
        print(f"gists A            : {ra['gists']}")
        print(f"gists B            : {rb['gists']}")
        assert ra["gists"] == rb["gists"], (
            f"no converge: A={ra['gists']} B={rb['gists']}")
        assert len(ra["gists"]) >= 2, f"esperaba >=2 gists, {ra['gists']}"
        print("convergencia       : A == B (mismo contexto compartido)")
        print("=== PRUEBA DE FUEGO OK ===")
    finally:
        for p in procs.values():
            p.terminate()


if __name__ == "__main__":
    main()
