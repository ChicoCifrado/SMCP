"""Transporte QUIC entre hosts (capa 3) — despliegue multi-nodo real.

El :class:`~delm.core.transport.QuicSwarm` corre en **loopback** (sin
sockets): el datagrama de ``a -> b`` se entrega directamente a ``b``.
Sirve para probar el handshake + el transporte de punta a punta en un
proceso. Para el **despliegue real** (nodos en hosts distintos), cada nodo
corre sobre un socket UDP y el datagrama viaja por la red.

Este módulo implementa :class:`QuicHostNode` y :class:`QuicHostSwarm`:

* :class:`QuicHostNode` — un nodo de la malla sobre QUIC real. Corre
  **un event loop asyncio en un hilo dedicado** y expone el contrato sync
  ``send``/``poll``/``pump`` (mismo que :class:`QuicSwarm`).

* :class:`QuicHostSwarm` — el orquestador de la malla QUIC entre hosts
  (equivalente a :class:`QuicSwarm`). Crea N :class:`QuicHostNode` (uno
  por par) y asigna los puertos.

**Modelo** (el de alto nivel de aioquic, ``aioquic.asyncio``):

Para cada par ``(a, b)`` con ``a < b``:

* ``a`` es **cliente**: ``connect()`` al puerto de ``b`` (para ese par).
* ``b`` es **servidor**: ``serve()`` en un puerto **dedicado** para ese par.

El **un puerto por par** es clave: cada ``serve()`` es de un par, así el
mapeo stream→par es directo (el stream que llega al ``serve()`` de ``b``
para ``a`` es de ``a``). Un nodo que es servidor de varios pares tiene un
``serve()`` (y un puerto) por par.

El **framing** es length-prefix (mismo que :class:`QuicSwarm`): el stream
QUIC es un byte-stream continuo, así que se parten los datagramas por
longitud al reconstruirlos en :meth:`poll`.

La **identidad** de un nodo es su ``peer_id`` (un string). Para el
handshake TLS, se genera un cert auto-firmado ECDSA P-256 (el mismo que
:class:`QuicSwarm`). El cliente **no** verifica el cert del servidor
(``verify_mode=0``): es un despliegue de confianza mutua.
"""
from __future__ import annotations

import asyncio
import queue
import struct
import threading
from typing import Any


# ---------------------------------------------------------------------------
# Framing (length-prefix) — mismo que QuicSwarm
# ---------------------------------------------------------------------------
def _frame(payload: bytes) -> bytes:
    """Prefijo de longitud (4 bytes BE) + payload."""
    return len(payload).to_bytes(4, "big") + payload


def _deframe(buf: bytes) -> tuple[list[bytes], bytes]:
    """Parte los datagramas de ``buf`` por longitud.

    Devuelve ``(datagramas, resto)``: los datagramas completos y el resto
    (bytes sueltos que esperan el resto del datagrama).
    """
    out: list[bytes] = []
    off = 0
    while len(buf) - off >= 4:
        (n,) = struct.unpack("!I", buf[off:off + 4])
        if len(buf) - off < 4 + n:
            break
        out.append(buf[off + 4:off + 4 + n])
        off += 4 + n
    return out, buf[off:]


# ---------------------------------------------------------------------------
# Cert auto-firmado ECDSA P-256 — mismo que QuicSwarm
# ---------------------------------------------------------------------------
def _make_cert() -> tuple[Any, Any, bytes]:
    """Cert ECDSA P-256 auto-firmado.

    Devuelve ``(cert, key, cert_pem)``: el objeto :class:`x509.Certificate`
    (para ``configuration.certificate``), la key privada (para
    ``configuration.private_key``) y el PEM (para ``cadata`` del cliente).
    """
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "smcp")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert, key, cert_pem


# ---------------------------------------------------------------------------
# Nodo QUIC entre hosts (M conexiones, un puerto por par)
# ---------------------------------------------------------------------------
class QuicHostNode:
    """Un nodo de la malla QUIC entre hosts.

    Un :class:`QuicHostNode` es un nodo de la malla sobre QUIC real
    (socket UDP). Corre **un event loop asyncio en un hilo dedicado** y
    expone el contrato sync :meth:`send`/ :meth:`poll`/ :meth:`pump`
    (mismo que :class:`~delm.core.transport.QuicSwarm`).

    El nodo maneja **M conexiones** (una por cada par). Para cada par, el
    nodo es **cliente** (``connect()`` al puerto del par para ese par) o
    **servidor** (``serve()`` en un puerto dedicado para ese par). El
    **un puerto por par** hace que el mapeo stream→par sea directo.

    ``peers`` es un dict ``{par: (role, peer_host, port)}`` donde ``role``
    es ``"connect"`` (el nodo se conecta a ``peer_host:port``) o ``"serve"``
    (el nodo escucha en ``port`` para ese par). ``host`` es el host propio
    del nodo (para los ``serve``).

    El **contrato**:

    * :meth:`send(to, payload)`: encola en la cola de salidas de ``to``.
    * :meth:`poll()`: drena ``_in_queue`` (los datagramas entrantes).
    * :meth:`pump()`: devuelve el nº de datagramas en salidas (no-op: el
      event loop corre continuamente).
    """

    def __init__(self, peer_id: str, host: str,
                 peers: dict[str, tuple[str, str, int]]) -> None:
        self.peer_id = peer_id
        self.host = host
        # Los pares: {par: (role, peer_host, port)}.
        self.peers = dict(peers)
        # Colas thread-safe (el event loop corre en un hilo dedicado).
        # _out[par] = cola de salidas hacia ``par``.
        self._out: dict[str, "queue.Queue[bytes]"] = {
            p: queue.Queue() for p in self.peers
        }
        # _in_queue = cola de recibidos (tupla (par, payload)).
        self._in_queue: "queue.Queue[tuple[str, bytes]]" = queue.Queue()
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._stop = threading.Event()
        # Los servers (para cerrarlos).
        self._servers: list[Any] = []

    # -- API pública (sync, thread-safe) ---------------------------------
    def start(self) -> None:
        """Arranca el event loop asyncio en un hilo dedicado."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=20)

    def send(self, to: str, payload: bytes) -> None:
        """Encola el datagrama en la cola de salidas de ``to``."""
        if to in self._out:
            self._out[to].put(payload)

    def poll(self) -> list[tuple[str, bytes]]:
        """Drena ``_in_queue`` (los datagramas entrantes)."""
        out: list[tuple[str, bytes]] = []
        while True:
            try:
                out.append(self._in_queue.get_nowait())
            except queue.Empty:
                break
        return out

    def pump(self) -> int:
        """Devuelve el nº de datagramas en salidas (no-op).

        El event loop corre continuamente; esto es solo para el contrato
        de :meth:`MeshNetwork.drain` (que espera un int).
        """
        total = 0
        for q in self._out.values():
            total += q.qsize()
        return total

    def close(self) -> None:
        """Para el event loop."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    # -- Event loop asyncio (hilo dedicado) ----------------------------
    def _run(self) -> None:
        """Corre el event loop asyncio en este hilo."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._serve_all())
        finally:
            loop.close()

    async def _serve_all(self) -> None:
        """Gestiona todas las conexiones del nodo (una por par).

        Para cada par: si es ``"connect"``, ``connect()`` al par; si es
        ``"serve"``, ``serve()`` en el puerto del par.
        """
        tasks: list[asyncio.Task] = []
        for par, (role, peer_host, port) in self.peers.items():
            if role == "connect":
                tasks.append(asyncio.create_task(
                    self._client(par, peer_host, port)))
            else:  # "serve"
                tasks.append(asyncio.create_task(self._server(par, port)))
        self._ready.set()
        if tasks:
            await asyncio.gather(*tasks)

    async def _client(self, par: str, peer_host: str, port: int) -> None:
        """La conexión cliente: ``connect()`` a ``peer_host:port``.

        Abre un stream bidireccional y corre ``_read``/``_write``.
        """
        from aioquic.asyncio import connect
        from aioquic.quic.configuration import QuicConfiguration

        _, _, cert_pem = _make_cert()
        cfg = QuicConfiguration(
            is_client=True, alpn_protocols=["smcp/1"],
            cadata=cert_pem, verify_mode=0,
        )
        async with connect(peer_host, port, configuration=cfg) as protocol:
            reader, writer = await protocol.create_stream()
            try:
                await asyncio.gather(
                    self._write(par, writer),
                    self._read(par, reader),
                )
            finally:
                writer.close()

    async def _server(self, par: str, port: int) -> None:
        """La conexión servidor: ``serve()`` en ``port`` (dedicado a par).

        El ``stream_handler`` (sync) genera una tarea que corre
        ``_read``/``_write`` para ``par``.
        """
        from aioquic.asyncio import serve
        from aioquic.quic.configuration import QuicConfiguration

        cert, key, _ = _make_cert()
        cfg = QuicConfiguration(
            is_client=False, alpn_protocols=["smcp/1"],
            certificate=cert, private_key=key,
        )
        srv = await serve(self.host, port, configuration=cfg,
                          stream_handler=self._make_handler(par))
        self._servers.append(srv)
        try:
            while not self._stop.is_set():
                await asyncio.sleep(0.05)
        finally:
            try:
                srv.close()
            except Exception:  # noqa: BLE001 - cierre tolerante
                pass

    def _make_handler(self, par: str):
        """Genera el ``stream_handler`` (sync) para ``par``.

        El handler (lo llama aioquic al recibir un stream) genera una tarea
        que corre ``_read``/``_write`` para ``par``.
        """
        def handler(reader, writer) -> None:
            loop = asyncio.get_running_loop()
            loop.create_task(self._stream(par, reader, writer))
        return handler

    async def _stream(self, par: str, reader, writer) -> None:
        """La tarea del stream de ``par``: ``_read``/``_write``."""
        try:
            await asyncio.gather(
                self._write(par, writer),
                self._read(par, reader),
            )
        finally:
            writer.close()

    # -- Tareas de I/O (escribir de _out[par], leer a _in_queue) --------
    async def _write(self, par: str, writer) -> None:
        """Escribe de ``_out[par]`` al stream (con framing).

        Bloquea en ``_out[par].get()`` hasta que haya un datagrama; lo
        escribe al stream con framing length-prefix.
        """
        loop = asyncio.get_running_loop()
        while not self._stop.is_set():
            payload = await loop.run_in_executor(None, self._out[par].get)
            writer.write(_frame(payload))

    async def _read(self, par: str, reader) -> None:
        """Lee del stream a ``_in_queue`` (con framing).

        Acumula en ``buf`` y parte los datagramas por longitud; los mete en
        ``_in_queue`` con ``par`` como origen.
        """
        buf = b""
        while not self._stop.is_set():
            data = await reader.read(65535)
            if not data:
                break  # fin de stream
            buf += data
            msgs, buf = _deframe(buf)
            for m in msgs:
                self._in_queue.put((par, m))


# ---------------------------------------------------------------------------
# Orquestador de la malla QUIC entre hosts
# ---------------------------------------------------------------------------
class QuicHostSwarm:
    """Orquestador de la malla QUIC entre hosts.

    Equivalente a :class:`~delm.core.transport.QuicSwarm`, pero con
    **red real** (sockets UDP). Crea N :class:`QuicHostNode` (uno por par)
    y asigna los puertos: para cada par ``(a, b)`` con ``a < b``, ``b`` es
    servidor y escucha en un puerto dedicado (asignado por el swarm);
    ``a`` es cliente y se conecta a ese puerto.

    El **un puerto por par** hace que el mapeo stream→par sea directo.

    * ``add_peer(peer_id, host)``: añade un par a la malla.
    * ``transport_for(peer_id)``: la :class:`QuicHostTransport` de
      ``peer_id``.
    * ``start()``: arranca todos los nodos.
    * ``close()``: cierra todos los nodos.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, QuicHostNode] = {}
        # Los pares: {peer_id: host}.
        self._hosts: dict[str, str] = {}
        # El puerto por par: {par: port}.
        self._ports: dict[str, int] = {}
        self._next_port = 44000
        self._started = False

    # -- API pública ---------------------------------------------------
    @property
    def peers(self) -> dict[str, QuicHostNode]:
        return self._nodes

    def add_peer(self, peer_id: str, host: str = "127.0.0.1") -> None:
        """Añade un par a la malla.

        ``peer_id`` es el identificador del par. ``host`` es su host
        (donde escucha). Para cada par ya en la malla, se asigna un puerto
        (el par de mayor índice es servidor y escucha; el de menor, cliente
        y se conecta).
        """
        if peer_id in self._hosts:
            return
        self._hosts[peer_id] = host
        # Asigna puertos para los pares nuevos (peer_id con cada par ya en
        # la malla).
        for other in self._hosts:
            if other == peer_id:
                continue
            lo, hi = (other, peer_id) if other < peer_id else (peer_id, other)
            # El par de mayor índice (hi) es servidor; asigna un puerto.
            key = f"{lo}->{hi}"
            if key not in self._ports:
                self._ports[key] = self._next_port
                self._next_port += 1
        self._rebuild()

    def transport_for(self, peer_id: str) -> "QuicHostTransport":
        """La :class:`QuicHostTransport` de ``peer_id`` (lo que un
        :class:`~delm.core.mesh_node.MeshNode` usa como transporte)."""
        return QuicHostTransport(self._nodes[peer_id])

    def pump(self) -> int:
        """No-op: el event loop corre continuamente. Devuelve 0."""
        return 0

    def start(self) -> None:
        """Arranca todos los nodos (el event loop de cada uno)."""
        if self._started:
            return
        for node in self._nodes.values():
            node.start()
        self._started = True

    def close(self) -> None:
        """Cierra todos los nodos."""
        for node in self._nodes.values():
            node.close()

    # -- Interno --------------------------------------------------------
    def _rebuild(self) -> None:
        """Recrea los nodos (con sus pares y puertos)."""
        # Cierra los nodos viejos (si había).
        for node in self._nodes.values():
            node.close()
        # Crea los nodos nuevos.
        self._nodes = {
            pid: self._make_node(pid)
            for pid in self._hosts
        }

    def _make_node(self, peer_id: str) -> QuicHostNode:
        """Crea el :class:`QuicHostNode` de ``peer_id`` (con sus pares)."""
        peers: dict[str, tuple[str, str, int]] = {}
        for other in self._hosts:
            if other == peer_id:
                continue
            lo, hi = (other, peer_id) if other < peer_id else (peer_id, other)
            key = f"{lo}->{hi}"
            port = self._ports[key]
            if peer_id == hi:
                # Es servidor: escucha en ``port``.
                peers[other] = ("serve", self._hosts[other], port)
            else:
                # Es cliente: se conecta a ``self._hosts[hi]:port``.
                peers[other] = ("connect", self._hosts[hi], port)
        return QuicHostNode(peer_id, self._hosts[peer_id], peers)


# ---------------------------------------------------------------------------
# Vista por nodo (implementa MeshTransport)
# ---------------------------------------------------------------------------
class QuicHostTransport:
    """Vista por nodo de un :class:`QuicHostSwarm` — implementa
    :class:`~delm.core.transport.MeshTransport`.

    ``node`` es el :class:`QuicHostNode` del par. ``send(to, payload)``
    delega en ``node.send(to, payload)``; ``poll()`` delega en
    ``node.poll()``. Es lo que un :class:`~delm.core.mesh_node.MeshNode`
    usa como transporte.
    """

    def __init__(self, node: QuicHostNode) -> None:
        self._node = node

    @property
    def peer_id(self) -> str:
        return self._node.peer_id

    def send(self, to: str, payload: bytes) -> None:
        self._node.send(to, payload)

    def poll(self) -> list[tuple[str, bytes]]:
        return self._node.poll()

    def pump(self) -> int:
        """No-op: el event loop corre continuamente. Devuelve 0."""
        return self._node.pump()

    def close(self) -> None:
        self._node.close()
