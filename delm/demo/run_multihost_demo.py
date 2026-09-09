"""Demo multi-host: 2 nodos en procesos distintos, sobre Nostr (capa 3).

Demuestra que la malla (capa 3) corre **sobre red** vía Nostr: un relay
(``NostrRelayServer``) en un proceso, y 2 nodos en procesos distintos que
intercambian gossip/heartbeat/gists por Nostr y convergen al mismo conjunto
de gists.

El punto de entrada arranca los 3 procesos y verifica la convergencia:

* ``relay``: arranca el ``NostrRelayServer`` y escribe el puerto en
  ``<tmpdir>/port``.
* ``node A`` / ``node B``: leen el puerto, se conectan, y por Nostr:
  se anuncian (gossip), se intercambian heartbeats y publican un gist
  cada uno; al final cada nodo tiene los 2 gists (el suyo + el del otro).

Uso::

    python -m delm.demo.run_multihost_demo            # orquesta los 3 procesos
    # (los subprocesos se invocan como:)
    python -m delm.demo.run_multihost_demo relay <tmpdir>
    python -m delm.demo.run_multihost_demo node <tmpdir> <name> <gist>
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# utilidades de proceso
# ---------------------------------------------------------------------------
def _wait_file(path: str, timeout: float = 30.0) -> None:
    """Espera a que ``path`` exista y no esté vacío."""
    t0 = time.time()
    while not os.path.exists(path):
        if time.time() - t0 > timeout:
            raise TimeoutError(f"timeout esperando {path}")
        time.sleep(0.05)
    t0 = time.time()
    while os.path.getsize(path) == 0:
        if time.time() - t0 > timeout:
            raise TimeoutError(f"timeout esperando contenido de {path}")
        time.sleep(0.05)


def _read_port(path: str) -> int:
    with open(path) as f:
        return int(f.read().strip())


# ---------------------------------------------------------------------------
# rol: relay
# ---------------------------------------------------------------------------
def _run_relay(tmpdir: str) -> None:
    """Arranca el ``NostrRelayServer`` y escribe el puerto en ``<tmpdir>/port``."""
    from delm.core.nostr import NostrRelayServer

    server = NostrRelayServer()
    server.start()
    port = server.port
    with open(os.path.join(tmpdir, "port"), "w") as f:
        f.write(str(port))
    # El orquestador mata este proceso; solo queda a la espera.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# rol: nodo
# ---------------------------------------------------------------------------
def _gossip_until_other(node, timeout: float = 20.0) -> str:
    """Bucle de gossip: envía el announce hasta recibir el del otro nodo.

    Devuelve el ``pubkey`` del otro nodo (el que aparece en ``node._neighbors``).
    """
    t0 = time.time()
    while time.time() - t0 < timeout:
        # Anuncia (to="" -> el relay lo entrega a todos los conectados).
        node.send_announce("")
        # Drena (procesa los entrantes: recibe el announce del otro).
        node.run_tick()
        if node._neighbors:
            return next(iter(node._neighbors))
        time.sleep(0.05)
    raise TimeoutError("timeout en gossip (no recibió el announce del otro)")


def _drain_until(node, min_gists: int = 2, timeout: float = 20.0) -> None:
    """Drena hasta que ``node.ctx`` tenga al menos ``min_gists`` gists."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        node.run_tick()
        if len(node.ctx) >= min_gists:
            return
        time.sleep(0.05)
    raise TimeoutError(f"timeout en drenado (no recibió {min_gists} gists)")


def _run_node(name: str, tmpdir: str, gist_text: str) -> None:
    """Un nodo de la malla: se conecta al relay y converge por Nostr."""
    from delm.core.nostr import NostrKey, NostrRelayClient, NostrTransport
    from delm.core.mesh_node import MeshNode
    from delm.core.secure_context import SecureSharedContext
    from delm.core.requirements import MeshRequirements
    from delm.core.provenance import KeyPair
    from delm.core.gist import Gist, GistKind

    # Espera el puerto (el relay lo escribe).
    _wait_file(os.path.join(tmpdir, "port"))
    port = _read_port(os.path.join(tmpdir, "port"))

    # Identidad de red (NostrKey, BIP340) + transporte Nostr.
    key = NostrKey.new()
    pubkey = key.pubkey.hex()
    client = NostrRelayClient(f"ws://127.0.0.1:{port}")
    client.connect()
    transport = NostrTransport(client, key)

    # Nodo de malla (firma gists con una KeyPair ed25519).
    ctx = SecureSharedContext()
    req = MeshRequirements(mesh_id="mesh-demo", version_floor=(1, 0))
    node = MeshNode(
        peer_id=pubkey, version=(1, 0), capabilities=(),
        transport=transport, ctx=ctx, key=KeyPair.new(pubkey), req=req,
    )

    # 1. Gossip: recibe el announce del otro nodo (aprende su pubkey).
    other = _gossip_until_other(node)

    # 2. Publica su gist: lo firma, lo admite en su ctx y lo envía al otro.
    g = Gist(label=f"{name}-gist", gist=gist_text, kind=GistKind.FACT)
    raw = node.publish_gist(g)
    node.ctx.admit(g)          # el nodo admite su propio gist
    node.transport.send(other, raw)

    # 3. Drena hasta recibir el gist del otro (convergencia).
    _drain_until(node, min_gists=2)

    # 4. Escribe el resultado (el orquestador lo lee).
    result = {"name": name, "pubkey": pubkey, "gists": sorted(ctx.labels())}
    with open(os.path.join(tmpdir, f"{name}.result"), "w") as f:
        json.dump(result, f)
    client.close()


# ---------------------------------------------------------------------------
# orquestador
# ---------------------------------------------------------------------------
def _main_orchestrator() -> None:
    """Arranca los 3 procesos (relay + 2 nodos) y verifica la convergencia."""
    tmpdir = tempfile.mkdtemp(prefix="smcp_multihost_")
    relay = subprocess.Popen(
        [sys.executable, "-m", "delm.demo.run_multihost_demo", "relay", tmpdir],
    )
    try:
        # Espera el puerto.
        _wait_file(os.path.join(tmpdir, "port"))
        # Arranca los 2 nodos (en procesos distintos).
        a = subprocess.Popen(
            [sys.executable, "-m", "delm.demo.run_multihost_demo",
             "node", tmpdir, "A", "CONSTRAINT-A: el nodo A publica su gist."],
        )
        b = subprocess.Popen(
            [sys.executable, "-m", "delm.demo.run_multihost_demo",
             "node", tmpdir, "B", "CONSTRAINT-B: el nodo B publica su gist."],
        )
        a.wait(); b.wait()
        ra = json.load(open(os.path.join(tmpdir, "A.result")))
        rb = json.load(open(os.path.join(tmpdir, "B.result")))
        # Verifica la convergencia: ambos nodos tienen los mismos 2 gists.
        assert ra["gists"] == rb["gists"], (
            f"no converge: A={ra['gists']} B={rb['gists']}")
        assert len(ra["gists"]) == 2, f"esperaba 2 gists, {ra['gists']}"
        print("=== SMCP multi-host demo (2 nodos, procesos distintos, Nostr) ===")
        print(f"relay puerto      : {_read_port(os.path.join(tmpdir, 'port'))}")
        print(f"nodo A pubkey     : {ra['pubkey'][:16]}…")
        print(f"nodo B pubkey     : {rb['pubkey'][:16]}…")
        print(f"gists A           : {ra['gists']}")
        print(f"gists B           : {rb['gists']}")
        print("convergencia      : A == B (mismo conjunto de gists)")
        print("=== demo OK ===")
    finally:
        relay.terminate()
        relay.wait()


def main() -> None:
    if len(sys.argv) < 2:
        _main_orchestrator()
        return
    role = sys.argv[1]
    if role == "relay":
        _run_relay(sys.argv[2])
    elif role == "node":
        # node <tmpdir> <name> <gist>
        _run_node(sys.argv[3], sys.argv[2], sys.argv[4])
    else:
        raise SystemExit(f"rol desconocido: {role!r}")


if __name__ == "__main__":
    main()
