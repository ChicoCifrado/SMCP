"""Prueba de fuego: dos agentes en endpoints de red distintos sobre QUIC.

Nodo B (servidor) escucha en 0.0.0.0:<port> (no loopback).
Nodo A (cliente) se conecta a <host_wsl>:<port> por la red real.
Ambos publican un gist y deben converger (mismo conjunto de gists).

Diferencia con run_multihost_demo.py: aqui el transporte cruza la
pila de red (eth0, no lo), con certs auto-firmados y verificacion
de identidad post-handshake (CN = peer_id).
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
    # IP de esta maquina (WSL) — por donde el cliente conecta.
    import subprocess as sp
    host = sp.check_output(
        ["ip", "route", "get", "1.1.1.1"], text=True
    ).split("src ")[1].split()[0]
    port_b = _free_port()
    tmpdir = tempfile.mkdtemp(prefix="smcp_firewall_quic_")
    portmap = {
        "A": {"role": "connect", "host": host, "port": port_b, "peer": "B"},
        "B": {"role": "serve", "host": "0.0.0.0", "port": port_b, "peer": "A"},
    }
    with open(os.path.join(tmpdir, "portmap"), "w") as f:
        json.dump(portmap, f)
    procs = {}
    try:
        for nm, gist in (
            ("A", "CONSTRAINT-A: agente A publica su gist por QUIC."),
            ("B", "CONSTRAINT-B: agente B publica su gist por QUIC."),
        ):
            procs[nm] = subprocess.Popen(
                [sys.executable, "-m", "smcp.demo.run_multihost_demo",
                 "quic-node", tmpdir, nm, gist],
                stderr=subprocess.DEVNULL,
            )
        for nm in procs:
            procs[nm].wait(timeout=120)
            if procs[nm].returncode != 0:
                raise SystemExit(
                    f"el nodo {nm} salio con codigo {procs[nm].returncode}")
        ra = json.load(open(os.path.join(tmpdir, "A.result")))
        rb = json.load(open(os.path.join(tmpdir, "B.result")))
        print("=== SMCP prueba de fuego (2 agentes, red real, QUIC) ===")
        print(f"host WSL           : {host}")
        print(f"puerto B (serve)   : {port_b} (bind 0.0.0.0)")
        print(f"gists A            : {ra['gists']}")
        print(f"gists B            : {rb['gists']}")
        assert ra["gists"] == rb["gists"], (
            f"no converge: A={ra['gists']} B={rb['gists']}")
        assert len(ra["gists"]) == 2, f"esperaba 2 gists, {ra['gists']}"
        print("convergencia       : A == B (mismo conjunto de gists)")
        print("=== PRUEBA DE FUEGO OK ===")
    finally:
        for p in procs.values():
            p.terminate()


if __name__ == "__main__":
    main()
