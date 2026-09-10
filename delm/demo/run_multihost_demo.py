"""Demo multi-host: 2 nodos en procesos distintos, convergen al mismo conjunto de gists.

El **default** corre sobre **QUIC** (el despliegue real): los 2 nodos se
conectan entre sí por QUIC (uno servidor, otro cliente) y convergen. El modo
**Nostr** (el anterior, con un relay) sigue disponible con ``--nostr``.

El punto de entrada arranca los procesos y verifica la convergencia:

* **QUIC** (default): 2 nodos, ``B`` es servidor (escucha) y ``A`` es cliente
  (se conecta a ``B``). Cada nodo publica un gist y drena hasta recibir el
  del otro; al final ambos tienen los 2 gists.
* **Nostr** (``--nostr``): un relay ``NostrRelayServer`` + 2 nodos que
  intercambian gossip/heartbeat/gists por Nostr y convergen.

Uso::

    python -m delm.demo.run_multihost_demo            # QUIC (default)
    python -m delm.demo.run_multihost_demo --nostr   # modo Nostr (relay)
    # (los subprocesos se invocan como:)
    python -m delm.demo.run_multihost_demo quic-node <tmpdir> <name> <gist>
    python -m delm.demo.run_multihost_demo node <tmpdir> <name> <gist>
    python -m delm.demo.run_multihost_demo relay <tmpdir>
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from typing import cast

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
def _main_orchestrator(transport: str = "quic") -> None:
    """Arranca los procesos y verifica la convergencia.

    ``transport`` es ``"quic"`` (el default: los nodos se conectan entre sí
    por QUIC, el despliegue real) o ``"nostr"`` (el modo anterior, relay Nostr).
    """
    if transport == "quic":
        _main_orchestrator_quic()
        return
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


def _gossip_quic_until_other(mesh, other_name, timeout: float = 20.0) -> str:
    """Gossip QUIC: envía el anuncio a ``other_name`` hasta que ``mesh`` lo
    conozca como vecino.

    A diferencia del modo Nostr (no hay relay, el anuncio se envía al
    ``peer_id`` concreto del otro nodo). ``other_name`` es el ``peer_id``
    del otro nodo (el del ``portmap``).
    """
    t0 = time.time()
    while time.time() - t0 < timeout:
        mesh.send_announce(other_name)
        mesh.run_tick()
        if other_name in mesh._neighbors:
            return other_name
        time.sleep(0.05)
    raise TimeoutError("timeout en gossip (no recibió el anuncio del otro)")


def _run_quic_node(name: str, tmpdir: str, gist_text: str) -> None:
    """Un nodo de la malla sobre **QUIC** (entre procesos).

    Lee el ``portmap`` del tmpdir (lo escribe el orquestador) para saber su
    rol (``serve``/``connect``), su puerto y el par (el otro nodo). Construye
    un :class:`QuicHostNode` con ese par, lo envuelve en un
    :class:`QuicHostTransport` (el contrato ``MeshTransport``) y corre la
    misma lógica de convergencia que :func:`_run_node` (Nostr): gossip,
    publica un gist, drena hasta recibir el del otro.
    """
    from delm.core.quic_host import QuicHostNode, QuicHostTransport
    from delm.core.mesh_node import MeshNode, MeshTransport
    from delm.core.secure_context import SecureSharedContext
    from delm.core.requirements import MeshRequirements
    from delm.core.provenance import KeyPair
    from delm.core.gist import Gist, GistKind

    # El orquestador ya escribió el portmap (un JSON por nodo).
    with open(os.path.join(tmpdir, "portmap")) as f:
        portmap = json.load(f)
    me = portmap[name]
    role, port = me["role"], me["port"]
    # El par: el otro nodo (role/host/port). Para "serve", escucho en mi
    # puerto; para "connect", me conecto al puerto del otro.
    other_name = me["peer"]
    other = portmap[other_name]
    if role == "serve":
        # Escucho en mi puerto; el par (el otro) se conecta a mí.
        peer_spec = (role, "127.0.0.1", port)
    else:
        # Me conecto al puerto del otro (el servidor).
        peer_spec = (role, "127.0.0.1", other["port"])
    node = QuicHostNode(name, "127.0.0.1", {other_name: peer_spec})
    node.start()
    transport = QuicHostTransport(node)

    # Nodo de malla (firma gists con una KeyPair ed25519).
    # QuicHostTransport implementa el contrato MeshTransport (send/poll);
    # el cast silencia el falso positivo de Pyright (test_quic_host.py lo
    # demuestra en runtime).
    ctx = SecureSharedContext()
    req = MeshRequirements(mesh_id="mesh-demo", version_floor=(1, 0))
    mesh = MeshNode(
        peer_id=name, version=(1, 0), capabilities=(),
        transport=cast("MeshTransport", transport), ctx=ctx, key=KeyPair.new(name), req=req,
    )

    # 1. Gossip: recibe el anuncio del otro nodo (aprende su peer_id).
    other_peer = _gossip_quic_until_other(mesh, other_name)

    # 2. Publica su gist: lo firma, lo admite en su ctx y lo envía al otro.
    g = Gist(label=f"{name}-gist", gist=gist_text, kind=GistKind.FACT)
    raw = mesh.publish_gist(g)
    ctx.admit(g)
    transport.send(other_peer, raw)

    # 3. Drena hasta recibir el gist del otro (convergencia).
    _drain_until(mesh, min_gists=2)

    # 4. Escribe el resultado (el orquestador lo lee).
    result = {"name": name, "gists": sorted(ctx.labels())}
    with open(os.path.join(tmpdir, f"{name}.result"), "w") as f:
        json.dump(result, f)
    node.close()


def _main_orchestrator_quic() -> None:
    """Arranca 2 nodos sobre **QUIC** (procesos distintos) y verifica la
    convergencia.

    No hay relay: el nodo de mayor índice (``B``) es **servidor** (escucha en
    su puerto) y el de menor (``A``) es **cliente** (se conecta a ``B``). El
    orquestador escribe el ``portmap`` (rol/puerto/par por nodo) y arranca
    los 2 procesos; al final, ambos deben tener los mismos 2 gists.
    """
    import socket

    def _free_port() -> int:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    tmpdir = tempfile.mkdtemp(prefix="smcp_multihost_quic_")
    port_b = _free_port()
    portmap = {
        # A es cliente (se conecta a B); B es servidor (escucha en port_b).
        "A": {"role": "connect", "port": port_b, "peer": "B"},
        "B": {"role": "serve", "port": port_b, "peer": "A"},
    }
    with open(os.path.join(tmpdir, "portmap"), "w") as f:
        json.dump(portmap, f)
    procs = {}
    try:
        for nm, gist in (("A", "CONSTRAINT-A: el nodo A publica su gist."),
                        ("B", "CONSTRAINT-B: el nodo B publica su gist.")):
            # stderr a devnull: al cerrar la conexión QUIC, aioquic emite un
            # traceback benigno (RuntimeError: Event loop is closed) que no
            # afecta la convergencia (el orquestador la verifica por los
            # archivos de resultado).
            procs[nm] = subprocess.Popen(
                [sys.executable, "-m", "delm.demo.run_multihost_demo",
                 "quic-node", tmpdir, nm, gist],
                stderr=subprocess.DEVNULL,
            )
        for nm in procs:
            procs[nm].wait()
            if procs[nm].returncode != 0:
                raise SystemExit(
                    f"el nodo {nm} salió con código {procs[nm].returncode}"
                )
        ra = json.load(open(os.path.join(tmpdir, "A.result")))
        rb = json.load(open(os.path.join(tmpdir, "B.result")))
        # Verifica la convergencia: ambos nodos tienen los mismos 2 gists.
        assert ra["gists"] == rb["gists"], (
            f"no converge: A={ra['gists']} B={rb['gists']}")
        assert len(ra["gists"]) == 2, f"esperaba 2 gists, {ra['gists']}"
        print("=== SMCP multi-host demo (2 nodos, procesos distintos, QUIC) ===")
        print(f"puerto B (serve)  : {port_b}")
        print(f"gists A           : {ra['gists']}")
        print(f"gists B           : {rb['gists']}")
        print("convergencia      : A == B (mismo conjunto de gists)")
        print("=== demo OK ===")
    finally:
        for p in procs.values():
            p.terminate()


def main() -> None:
    argv = sys.argv[1:]
    # La flag --nostr fuerza el modo relay Nostr (el default es QUIC).
    if "--nostr" in argv:
        _main_orchestrator("nostr")
        return
    if not argv:
        _main_orchestrator()  # QUIC (default)
        return
    role = argv[0]
    if role == "relay":
        _run_relay(argv[1])
    elif role == "node":
        # node <tmpdir> <name> <gist>
        _run_node(argv[2], argv[1], argv[3])
    elif role == "quic-node":
        # quic-node <tmpdir> <name> <gist>  (firma: name, tmpdir, gist)
        _run_quic_node(argv[2], argv[1], argv[3])
    else:
        raise SystemExit(f"rol desconocido: {role!r}")


if __name__ == "__main__":
    main()
