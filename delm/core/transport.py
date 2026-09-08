"""Transporte de malla (capa 3) — datagramas entre pares.

Dos implementaciones:

* **``InMemoryTransport``** — bus determinista sin red. Cada par tiene una
  cola entrante; ``send`` encola en la cola del destino; ``poll`` devuelve
  los pendientes. Determinista y sin latencia: es el camino por defecto del
  pipeline in-proceso.

* **``QuicSwarm``** — transporte **real** sobre QUIC (aioquic). Orquesta N
  pares: por cada par de pares hay una conexión punto a punto (un extremo
  cliente, el otro servidor). Handshake ECDSA P-256, ALPN ``smcp/1``.
  Enrutamiento **loopback** (sin sockets): el datagrama de ``a -> b`` se
  entrega directamente a ``b``. Mismo contrato: ``send`` / ``poll`` /
  ``pump``. Requiere ``aioquic`` + ``cryptography``; si faltan,
  ``QuicSwarm`` lanza ``ImportError`` (el resto corre con
  ``InMemoryTransport``).

  **``QuicTransport``** es la vista por nodo de un :class:`QuicSwarm`:
  implementa :class:`MeshTransport` (``send``/``poll``/``close``) para un
  par concreto, delegando en el swarm. Es lo que un :class:`MeshNode` usa.

El transporte es **opaco al contenido**: mueve bytes. La semántica (gossip,
gist, heartbeat) la interpreta el :class:`~delm.core.mesh_node.MeshNode`.
"""
from __future__ import annotations

import struct
import time
from typing import Any


# ---------------------------------------------------------------------------
# Contrato
# ---------------------------------------------------------------------------
class MeshTransport:
    """Contrato de transporte de malla.

    Un par envía datagramas a otros pares y los recibe de su cola entrante.
    ``send`` no entrega directamente: encola en la cola del destino, que se
    drena en ``poll`` (o en el siguiente tick del receptor).
    """

    def send(self, to: str, payload: bytes) -> None:
        raise NotImplementedError

    def poll(self) -> list[tuple[str, bytes]]:
        """Devuelve ``[(from_id, payload), ...]`` y limpia la cola entrante."""
        raise NotImplementedError

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Bus in-memory determinista
# ---------------------------------------------------------------------------
class _Bus:
    """Cola entrante compartida por todos los pares de una malla."""

    def __init__(self) -> None:
        self._queues: dict[str, list[tuple[str, bytes]]] = {}

    def queue(self, peer_id: str) -> list[tuple[str, bytes]]:
        return self._queues.setdefault(peer_id, [])

    def push(self, peer_id: str, from_id: str, payload: bytes) -> None:
        self.queue(peer_id).append((from_id, payload))


class InMemoryTransport(MeshTransport):
    """Transporte in-memory determinista.

    ``mesh`` es el :class:`_Bus` compartido. ``peer_id`` es el identificador
    de este par. ``send`` encola en la cola del destino; ``poll`` drena la
    cola de este par.
    """

    def __init__(self, mesh: _Bus, peer_id: str) -> None:
        self._bus = mesh
        self._peer_id = peer_id
        mesh.queue(peer_id)  # asegura la cola

    @property
    def peer_id(self) -> str:
        return self._peer_id

    def send(self, to: str, payload: bytes) -> None:
        self._bus.push(to, self._peer_id, payload)

    def pump(self) -> int:
        """No-op: el bus in-memory no necesita bombeo (los datagramas ya
        están en las colas). Devuelve 0."""
        return 0

    def poll(self) -> list[tuple[str, bytes]]:
        q = self._bus.queue(self._peer_id)
        out = list(q)
        q.clear()
        return out

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Transporte QUIC (aioquic) — despliegue multi-nodo real
# ---------------------------------------------------------------------------
def _quic_imports() -> dict:
    """Importa los símbolos de aioquic que ``QuicSwarm`` necesita.

    Lanza ``ImportError`` con un mensaje claro si falta ``aioquic`` o
    ``cryptography`` (el resto de la capa funciona con
    ``InMemoryTransport``).
    """
    try:
        from aioquic.quic.connection import QuicConnection
        from aioquic.quic.configuration import QuicConfiguration
        from cryptography import x509  # noqa: F401  (necesario para certs)
    except ImportError as e:  # pragma: no cover - depende del env
        raise ImportError(
            "QuicSwarm requiere 'aioquic' y 'cryptography'. "
            "Instálalos o usa InMemoryTransport."
        ) from e
    return {"QuicConnection": QuicConnection, "QuicConfiguration": QuicConfiguration}


def _make_cert():
    """Cert ECDSA P-256 auto-firmado (CA) para el extremo servidor.

    ECDSA P-256 porque es la única firma que aioquic negocia sin fricción
    (negocia a ``ECDSA_SECP256R1_SHA256``); una key RSA/otra curva produce
    ``No supported signature algorithm``. Devuelve ``(cert, key, cert_pem)``.
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


class _QuicPeer:
    """Estado QUIC de un par: una :class:`QuicConnection` por vecino.

    ``conns[remote_id]`` es la conexión de *este* par hacia ``remote_id``.
    El par no sabe si es cliente o servidor de cada conexión: lo decide
    :class:`QuicSwarm`. Aquí solo se guarda el extremo local.
    """

    def __init__(self, peer_id: str) -> None:
        self.peer_id = peer_id
        self.conns: dict[str, Any] = {}

    def conn(self, remote_id: str) -> Any:
        return self.conns[remote_id]


class QuicSwarm:
    """Orquesta N pares sobre QUIC (aioquic) — el transporte de malla real.

    Modelo punto a punto: por cada par de pares hay **una** conexión, con un
    extremo cliente y otro servidor. Regla de roles determinista: para el par
    ``(a, b)`` con ``a < b``, ``a`` es **cliente** y ``b`` es **servidor**.
    Así cada par es cliente de los de menor índice y servidor de los de mayor.

    **Loopback (sin sockets)**: el datagrama de ``a -> b`` se entrega
    directamente a ``b`` (``receive_datagram``). No hay red: sirve para
    probar el handshake + el transporte de punta a punta en un proceso.
    Para despliegue real, ``QuicSwarm`` expone el mismo ``send``/``poll``/
    ``pump`` sobre un transporte de red.

    Streams: el par ``(a, b)`` con ``a < b`` usa el stream ``0`` para
    ``a -> b`` (cliente-initiated) y el stream ``1`` para ``b -> a``
    (servidor-initiated). Cada dirección usa su stream de iniciación.
    """

    def __init__(self, peer_ids=(), alpn: str = "smcp/1") -> None:
        self._q = _quic_imports()
        self._alpn = alpn
        self._peers: dict[str, _QuicPeer] = {}
        self._cert, self._key, self._cert_pem = _make_cert()
        self._now = time.monotonic()
        self._client_conns: dict[tuple[str, str], Any] = {}
        self._connected: set[tuple[str, str]] = set()
        # Buffers de framing por (src, dst): el stream QUIC es un byte-stream
        # continuo, así que parto los datagramas por longitud (length-prefix).
        self._bufs: dict[tuple[str, str], bytes] = {}
        for p in peer_ids:
            self.add_peer(p)

    # -- API pública -------------------------------------------------------
    @property
    def peers(self) -> dict[str, _QuicPeer]:
        return self._peers

    def add_peer(self, peer_id: str) -> None:
        """Añade un par y crea sus conexiones con los pares ya existentes.

        Para cada par ``p`` ya en la malla, ``peer_id`` y ``p`` forman un par:
        el de menor índice es **cliente** y el de mayor, **servidor**. Así el
        nuevo par se conecta a todos los anteriores al vuelo.
        """
        if peer_id in self._peers:
            return
        self._peers[peer_id] = _QuicPeer(peer_id)
        for p in self._peers:
            if p == peer_id:
                continue
            lo, hi = (p, peer_id) if p < peer_id else (peer_id, p)
            self._mk_client(lo, hi)
            self._mk_server(lo, hi)

    def connect(self) -> None:
        """Asegura que todos los pares están conectados (idempotente).

        Las conexiones se crean al vuelo en :meth:`add_peer`; esto es un
        no-op si ya están todas. Se mantiene para compatibilidad con el
        contrato de malla (``MeshNetwork`` lo llama tras añadir nodos).
        """
        pass

    def _mk_client(self, a: str, b: str) -> None:
        """Crea el extremo cliente de ``a -> b`` (a es cliente)."""
        QuicConfiguration = self._q["QuicConfiguration"]
        cfg = QuicConfiguration(
            is_client=True, alpn_protocols=[self._alpn], cadata=self._cert_pem)
        c = self._q["QuicConnection"](configuration=cfg)
        self._peers[a].conns[b] = c
        self._client_conns[(a, b)] = c

    def _mk_server(self, a: str, b: str) -> None:
        """Crea el extremo servidor de ``a -> b`` (b es servidor).

        Coge el OD CID del cliente (``a``) para que el Initial del servidor
        lo porte (si no, ``original_destination_connection_id does not
        match``).
        """
        QuicConfiguration = self._q["QuicConfiguration"]
        client_conn = self._client_conns[(a, b)]
        cfg = QuicConfiguration(
            is_client=False, alpn_protocols=[self._alpn],
            certificate=self._cert, private_key=self._key)
        s = self._q["QuicConnection"](
            configuration=cfg,
            original_destination_connection_id=
            client_conn.original_destination_connection_id,
        )
        self._peers[b].conns[a] = s

    # -- framing (length-prefix) -------------------------------------------
    def _frame(self, payload: bytes) -> bytes:
        """Prefijo de longitud (4 bytes BE) + payload.

        El stream QUIC es un byte-stream continuo: dos ``send`` en el mismo
        stream se coalescen en un solo ``StreamDataReceived``. El framing por
        longitud permite partir los datagramas al reconstruirlos en ``poll``.
        """
        return len(payload).to_bytes(4, "big") + payload

    def _deframe(self, key: tuple[str, str], data: bytes) -> list[bytes]:
        """Acumula ``data`` en el buffer de ``key`` y parte los datagramas.

        Devuelve los datagramas completos (los bytes sueltos quedan en el
        buffer hasta que llegue el resto).
        """
        buf = self._bufs.setdefault(key, b"") + data
        out: list[bytes] = []
        off = 0
        while len(buf) - off >= 4:
            (n,) = struct.unpack("!I", buf[off:off + 4])
            if len(buf) - off < 4 + n:
                break  # datagrama parcial: queda en el buffer
            out.append(buf[off + 4:off + 4 + n])
            off += 4 + n
        self._bufs[key] = buf[off:]
        return out

    def send(self, src: str, dst: str, payload: bytes) -> None:
        """Envía ``payload`` de ``src`` a ``dst`` por su conexión.

        Stream de iniciación: si ``src < dst`` (src es cliente), stream ``0``;
        si ``src > dst`` (src es servidor), stream ``1``. El payload se envía
        con framing de longitud (el stream es un byte-stream continuo).
        """
        self._now = time.monotonic()
        c = self._peers[src].conns[dst]
        stream = 0 if src < dst else 1
        c.send_stream_data(stream, self._frame(payload), end_stream=False)

    def poll(self, peer_id: str) -> list[tuple[str, bytes]]:
        """Drena ``next_event`` de las conexiones de ``peer_id``.

        Devuelve ``[(from_id, payload), ...]`` con los datagramas ya partos
        por el framing de longitud.
        """
        out: list[tuple[str, bytes]] = []
        for r, c in self._peers[peer_id].conns.items():
            while True:
                ev = c.next_event()
                if ev is None:
                    break
                if type(ev).__name__ == "StreamDataReceived":
                    for d in self._deframe((r, peer_id), ev.data):
                        out.append((r, d))
        return out

    def pump(self) -> int:
        """Bombea datagramas: drena ``datagrams_to_send`` y los entrega.

        En loopback, el datagrama de ``a -> b`` va a ``b``. Devuelve el nº de
        datagramas entregados (para detectar convergencia).

        Antes de bombear, las conexiones **cliente** sin conectar llaman a
        ``connect(addr, now)`` (aioquic 1.3.0): sin ese paso,
        ``datagrams_to_send`` lanza ``IndexError`` (``_network_paths`` vacío).
        """
        self._now = time.monotonic()
        # Conecta los clientes pendientes (un solo connect por conexión).
        for key, c in self._client_conns.items():
            if key not in self._connected:
                c.connect(("127.0.0.1", 443), self._now)
                self._connected.add(key)
        delivered = 0
        for a in sorted(self._peers):
            for b, c in self._peers[a].conns.items():
                for data, _addr in c.datagrams_to_send(self._now):
                    self._peers[b].conns[a].receive_datagram(data, None, self._now)
                    delivered += 1
        return delivered

    def close(self) -> None:
        for p in self._peers.values():
            for c in p.conns.values():
                try:
                    c.close()
                except Exception:  # noqa: BLE001 - cierre tolerante
                    pass


# ---------------------------------------------------------------------------
# Vista por nodo (implementa MeshTransport)
# ---------------------------------------------------------------------------
class QuicTransport(MeshTransport):
    """Vista por nodo de un :class:`QuicSwarm` — implementa
    :class:`MeshTransport`.

    ``swarm`` es el orquestador compartido. ``peer_id`` es el identificador
    de este par. ``send(to, payload)`` delega en ``swarm.send(peer_id, to,
    payload)``; ``poll()`` delega en ``swarm.poll(peer_id)``. Es lo que un
    :class:`~delm.core.mesh_node.MeshNode` usa como transporte.
    """

    def __init__(self, swarm: QuicSwarm, peer_id: str) -> None:
        self._swarm = swarm
        self._peer_id = peer_id

    @property
    def peer_id(self) -> str:
        return self._peer_id

    def send(self, to: str, payload: bytes) -> None:
        self._swarm.send(self._peer_id, to, payload)

    def pump(self) -> int:
        """Bombea datagramas (handshake + datos) en todo el swarm.

        Lo llama :meth:`MeshNetwork.drain` en cada tick para mover el
        handshake QUIC y los datagramas. Devuelve el nº entregado.
        """
        return self._swarm.pump()

    def poll(self) -> list[tuple[str, bytes]]:
        return self._swarm.poll(self._peer_id)

    def close(self) -> None:
        pass
