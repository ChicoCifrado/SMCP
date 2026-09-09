"""Nostr — BIP340 (Schnorr secp256k1, x-only) + eventos Nostr.

BIP340 es el esquema de firma de Nostr. Se implementa **fiel a la referencia
oficial** (``bitcoin/bips`` ``bip-0340/reference.py``): misma aritmética de
punto, ``lift_x``, ``schnorr_sign`` y ``schnorr_verify``. Es **verificable
contra los vectores oficiales** (``bip-0340/test-vectors.csv``, 19 vectores).

No depende de ``cryptography``: la aritmética de secp256k1 se hace aquí
(pure Python, ``hashlib`` para los ``tagged_hash``).

Constantes (BIP340 / secp256k1):

* ``p`` — el módulo del campo (las coordenadas).
* ``n`` — el orden del grupo (el escalar).
* ``G`` — el punto base.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import threading
from typing import TYPE_CHECKING, Optional

from delm.core.transport import MeshTransport

if TYPE_CHECKING:
    # Evita un import circular en runtime: NostrDiscoveryTransport tipa
    # Announcement (de deployment) solo para el type checker.
    from delm.core.deployment import Announcement

# ---------------------------------------------------------------------------
# Constantes secp256k1 (fiel a la referencia BIP340)
# ---------------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

Point = tuple  # (x, y); None = punto en el infinito


# ---------------------------------------------------------------------------
# Aritmética de punto (fiel a la referencia)
# ---------------------------------------------------------------------------
def _tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def _point_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if (P1[0] == P2[0]) and (P1[1] != P2[1]):
        return None
    if P1 == P2:
        lam = (3 * P1[0] * P1[0] * pow(2 * P1[1], P - 2, P)) % P
    else:
        lam = ((P2[1] - P1[1]) * pow(P2[0] - P1[0], P - 2, P)) % P
    x3 = (lam * lam - P1[0] - P2[0]) % P
    return (x3, (lam * (P1[0] - x3) - P1[1]) % P)


def _point_mul(Pt, n):
    R = None
    for i in range(256):
        if (n >> i) & 1:
            R = _point_add(R, Pt)
        Pt = _point_add(Pt, Pt)
    return R


def _bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, "big")


def _int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _bytes_from_point(Pt) -> bytes:
    return _bytes_from_int(Pt[0])


def _has_even_y(Pt) -> bool:
    return Pt[1] % 2 == 0


def _lift_x(x: int):
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if (y & 1) == 0 else P - y)


# ---------------------------------------------------------------------------
# BIP340 (fiel a la referencia)
# ---------------------------------------------------------------------------
def pubkey_gen(seckey: bytes) -> bytes:
    """La x-only pubkey (32 bytes) de una private key (32 bytes)."""
    d0 = _int_from_bytes(seckey)
    if not (1 <= d0 <= N - 1):
        raise ValueError("seckey fuera de rango 1..n-1")
    Pt = _point_mul(G, d0)
    assert Pt is not None
    return _bytes_from_point(Pt)


def schnorr_sign(msg: bytes, seckey: bytes, aux_rand: bytes) -> bytes:
    """Firma BIP340: ``sig = R || s`` (64 bytes)."""
    d0 = _int_from_bytes(seckey)
    if not (1 <= d0 <= N - 1):
        raise ValueError("seckey fuera de rango 1..n-1")
    if len(aux_rand) != 32:
        raise ValueError(f"aux_rand debe ser 32 bytes, no {len(aux_rand)}")
    Pt = _point_mul(G, d0)
    assert Pt is not None
    d = d0 if _has_even_y(Pt) else N - d0
    t = bytes(a ^ b for a, b in zip(_bytes_from_int(d), _tagged_hash("BIP0340/aux", aux_rand)))
    k0 = _int_from_bytes(_tagged_hash("BIP0340/nonce", t + _bytes_from_point(Pt) + msg)) % N
    if k0 == 0:
        raise RuntimeError("k0 == 0 (probabilidad despreciable)")
    R = _point_mul(G, k0)
    assert R is not None
    k = N - k0 if not _has_even_y(R) else k0
    e = _int_from_bytes(_tagged_hash("BIP0340/challenge", _bytes_from_point(R) + _bytes_from_point(Pt) + msg)) % N
    return _bytes_from_point(R) + _bytes_from_int((k + e * d) % N)


def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    """Verifica una firma BIP340 (``sig = R || s``, 64 bytes)."""
    if len(pubkey) != 32:
        return False
    if len(sig) != 64:
        return False
    Pt = _lift_x(_int_from_bytes(pubkey))
    r = _int_from_bytes(sig[0:32])
    s = _int_from_bytes(sig[32:64])
    if (Pt is None) or (r >= P) or (s >= N):
        return False
    e = _int_from_bytes(_tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % N
    R = _point_add(_point_mul(G, s), _point_mul(Pt, N - e))
    if (R is None) or (not _has_even_y(R)) or (R[0] != r):
        return False
    return True


# ---------------------------------------------------------------------------
# API cómoda (bytes de 32)
# ---------------------------------------------------------------------------
def x_only_pubkey(seckey: bytes) -> bytes:
    """Alias de :func:`pubkey_gen` (la x-only pubkey, 32 bytes)."""
    return pubkey_gen(seckey)


def sign(msg: bytes, seckey: bytes, aux_rand: bytes) -> bytes:
    """Alias de :func:`schnorr_sign`."""
    return schnorr_sign(msg, seckey, aux_rand)


def verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    """Alias de :func:`schnorr_verify`."""
    return schnorr_verify(msg, pubkey, sig)


# ---------------------------------------------------------------------------
# Claves de Nostr (x-only, BIP340)
# ---------------------------------------------------------------------------
class NostrKey:
    """Clave x-only de Nostr (BIP340): un ``seckey`` (32 bytes) y su ``pubkey``.

    La ``pubkey`` es la **x-only** (32 bytes) derivada de la ``seckey``
    (``pubkey_gen``). ``sign`` firma con BIP340 (``schnorr_sign``).
    """

    def __init__(self, seckey: bytes) -> None:
        self.seckey = seckey

    @classmethod
    def new(cls) -> "NostrKey":
        """Genera una clave aleatoria (32 bytes de entropía)."""
        return cls(os.urandom(32))

    @property
    def pubkey(self) -> bytes:
        """La x-only pubkey (32 bytes)."""
        return pubkey_gen(self.seckey)

    def sign(self, msg: bytes, aux_rand: bytes = b"\x00" * 32) -> bytes:
        """Firma ``msg`` con BIP340.

        ``aux_rand`` por defecto es 32 bytes cero (determinista): el ``aux_rand``
        no se guarda en el evento y no afecta la verificabilidad (cualquier
        valor de 32 bytes produce una firma válida), así se usa uno fijo.
        """
        return schnorr_sign(msg, self.seckey, aux_rand)


# ---------------------------------------------------------------------------
# Evento de Nostr (NIP-01)
# ---------------------------------------------------------------------------
class NostrEvent:
    """Un evento de Nostr (NIP-01): ``pubkey``, ``created_at``, ``kind``,
    ``tags``, ``content`` y su firma BIP340 sobre el ``id``.

    El ``id`` es el ``sha256`` de la serialización canónica de la lista
    ``[0, pubkey, created_at, kind, tags, content]`` (JSON sin espacios,
    UTF-8). La firma ``sig`` es BIP340 sobre los 32 bytes del ``id``.
    """

    def __init__(
        self,
        pubkey: bytes,
        created_at: int,
        kind: int,
        tags: list,
        content: str,
        sig: bytes,
    ) -> None:
        self.pubkey = pubkey
        self.created_at = created_at
        self.kind = kind
        self.tags = tags
        self.content = content
        self.sig = sig

    def _canonical(self) -> bytes:
        """La serialización canónica (NIP-01) sobre la que se hace el ``id``.

        ``[0, <pubkey hex>, <created_at>, <kind>, <tags>, <content>]``
        serializada a JSON sin espacios (``separators=(",", ":")``), UTF-8.
        """
        arr = [
            0,
            self.pubkey.hex(),
            int(self.created_at),
            self.kind,
            self.tags,
            self.content,
        ]
        return json.dumps(arr, separators=(",", ":")).encode("utf-8")

    def event_id(self) -> bytes:
        """El ``id`` del evento: ``sha256`` de la serialización canónica."""
        return hashlib.sha256(self._canonical()).digest()

    def verify(self) -> bool:
        """Verifica la firma BIP340 del evento (``sig`` sobre el ``id``)."""
        return schnorr_verify(self.event_id(), self.pubkey, self.sig)

    def to_dict(self) -> dict:
        """El evento como ``dict`` JSON (para el transporte)."""
        return {
            "pubkey": self.pubkey.hex(),
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "sig": self.sig.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "NostrEvent":
        return cls(
            pubkey=bytes.fromhex(d["pubkey"]),
            created_at=int(d["created_at"]),
            kind=int(d["kind"]),
            tags=d.get("tags", []),
            content=d.get("content", ""),
            sig=bytes.fromhex(d["sig"]),
        )

    @classmethod
    def signed(
        cls,
        key: "NostrKey",
        created_at: int,
        kind: int,
        tags: list,
        content: str,
    ) -> "NostrEvent":
        """Crea un evento **firmado**: firma su ``id`` (BIP340) con ``key``.

        El ``id`` no depende de la firma (se computa de ``pubkey``,
        ``created_at``, ``kind``, ``tags`` y ``content``), así se firma el
        ``id`` una vez computado.
        """
        ev = cls(
            pubkey=key.pubkey,
            created_at=created_at,
            kind=kind,
            tags=tags,
            content=content,
            sig=b"",  # se firma tras computar el id
        )
        ev.sig = key.sign(ev.event_id())
        return ev


# ---------------------------------------------------------------------------
# Relay de Nostr (in-memory, swappable)
# ---------------------------------------------------------------------------
class NostrRelay:
    """Relay de Nostr in-memory (swappable por un relay real vía WebSocket).

    Un ``NostrRelay`` es el *medio* por el que los nodos publican y reciben
    eventos. ``publish`` **verifica la firma BIP340** de cada evento antes de
    aceptarlo (anti-MITM): un evento cuya firma no verifica contra su
    ``pubkey`` se descarta. ``events`` devuelve los aceptados.

    El adaptador real (un relay de red, p. ej. ``wss://``) implementa el mismo
    papel; este in-memory sirve para test y loopback.
    """

    def __init__(self) -> None:
        self._events: list[NostrEvent] = []
        self._dropped: list[NostrEvent] = []

    def publish(self, ev: NostrEvent) -> bool:
        """Publica ``ev``: lo acepta si su firma BIP340 verifica, si no lo
        descarta. Devuelve ``True`` si se aceptó."""
        if ev.verify():
            self._events.append(ev)
            return True
        self._dropped.append(ev)
        return False

    def events(self) -> list[NostrEvent]:
        """Los eventos aceptados (en orden)."""
        return list(self._events)

    def dropped(self) -> list[NostrEvent]:
        """Los eventos descartados (firma no verificable)."""
        return list(self._dropped)


# ---------------------------------------------------------------------------
# Transporte de descubrimiento Nostr (swappable con DiscoveryBus)
# ---------------------------------------------------------------------------
class NostrDiscoveryTransport:
    """Transporte de descubrimiento Nostr (swappable con ``DiscoveryBus``).

    Implementa el **mismo contrato** que ``delm.core.deployment.DiscoveryBus``
    (``register`` / ``publish`` / ``deliver`` / ``nodes``), así que
    ``DeploymentNode`` lo usa sin cambiar: ``self.bus = NostrDiscoveryTransport(...)``.

    ``publish(node, ann)`` emite el anuncio de ``node`` como un **evento Nostr**
    (``kind=10000``, ``content`` = el ``Announcement.to_dict()`` en base64,
    ``sig`` = la firma BIP340 de su ``id``) a través del :class:`NostrRelay`.
    El relay **verifica la firma BIP340** antes de aceptar el evento. Si se
    acepta, el anuncio se entrega a las bandejas de los demás nodos (como en
    ``DiscoveryBus``); ``DeploymentNode.poll()`` lo recibe y verifica la firma
    del owner (ed25519) como siempre.

    El *adaptador real* (un relay de red, p. ej. ``wss://``) implementa el
    mismo papel que :class:`NostrRelay`; este in-memory sirve para test y
    loopback.
    """

    def __init__(self, relay, key: "NostrKey") -> None:
        self.relay = relay
        self.key = key
        self._nodes: set[str] = set()
        self._inboxes: dict[str, list["Announcement"]] = {}

    def _is_network(self) -> bool:
        """``True`` si el relay es un :class:`NostrRelayClient` de red.

        El relay de red (``NostrRelayClient``) ya hace el fan-out a los demás
        clientes (el relay emite a todos menos al remitente), así que el
        transporte no hace fan-out local: ``deliver`` lee de la bandeja
        entrante del cliente. El relay in-memory (``NostrRelay``) no hace
        fan-out, así que el transporte sí lo hace (``_inboxes``).
        """
        return hasattr(self.relay, "uri")

    def register(self, node: str) -> None:
        """Registra un nodo (su bandeja existe y recibe los broadcasts)."""
        self._nodes.add(node)
        self._inboxes.setdefault(node, [])

    def publish(self, node: str, ann: "Announcement") -> None:
        """Emite el anuncio de ``node`` como un evento Nostr (``kind=10000``).

        El anuncio se serializa (``to_dict()`` en base64) y se firma (BIP340)
        su ``id``. El relay lo acepta si la firma verifica.

        * In-memory: el transporte hace el fan-out a las bandejas de los demás
          nodos (el relay no lo hace).
        * De red: el relay ya emite a los demás clientes (menos al remitente),
          así que el transporte no hace fan-out local.
        """
        content = base64.b64encode(
            json.dumps(ann.to_dict(), separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        ev = NostrEvent.signed(self.key, 0, 10000, [["d", node]], content)
        if self.relay.publish(ev) and not self._is_network():
            for other in self._nodes:
                if other != node:
                    self._inboxes.setdefault(other, []).append(ann)

    def deliver(self, node: str) -> list["Announcement"]:
        """Los anuncios que ``node`` recibe de los demás (FIFO).

        * In-memory: lee la bandeja local (``_inboxes``).
        * De red: lee la bandeja entrante del cliente (``relay.events()``) y
          decodifica cada evento (``content`` = base64 del ``to_dict``).
        """
        if self._is_network():
            from delm.core.deployment import Announcement

            out: list["Announcement"] = []
            for ev in self.relay.events():
                try:
                    raw = base64.b64decode(ev.content).decode("utf-8")
                    ann = Announcement.from_dict(json.loads(raw))
                except Exception:
                    continue
                if ann.node_id != node:
                    out.append(ann)
            return out
        box = self._inboxes.setdefault(node, [])
        out = list(box)
        self._inboxes[node] = []
        return out

    def nodes(self) -> list[str]:
        """Nodos registrados."""
        return sorted(self._nodes)


# ---------------------------------------------------------------------------
# Relay de red Nostr (WebSocket): servidor + cliente
# ---------------------------------------------------------------------------
# El relay de red es la pieza que cierra el objetivo: un relay Nostr real
# (``wss://``) por WebSocket, swappable con :class:`NostrRelay` (in-memory).
#
# * :class:`NostrRelayServer` — el relay (coro async, se corre en un thread).
#   Acepta conexiones, verifica la firma BIP340 de cada ``EVENT`` y lo emite
#   a los suscriptores (broadcast).
# * :class:`NostrRelayClient` — el cliente (API **síncrona**, encapsula el loop
#   en un thread). Expone el **mismo contrato** que :class:`NostrRelay`
#   (``publish``/``events``/``dropped``), así :class:`NostrDiscoveryTransport`
#   lo usa sin cambios.
#
# Protocolo (JSON por WebSocket, uno por mensaje):
#   cliente -> relay:  {"op": "req",  "filters": [...]}     (suscripción)
#   cliente -> relay:  {"op": "event","event": <NostrEvent>} (publicación)
#   cliente -> relay:  {"op": "close"}                    (cierra)
#   relay -> cliente:  {"op": "event","event": <NostrEvent>} (emisión)
#   relay -> cliente:  {"op": "ok",   "id": <id>}         (aceptado)
#   relay -> cliente:  {"op": "bad",  "id": <id>, "why": "..."} (rechazado)
#
# La verificación de la firma BIP340 la hace el **relay** (autoridad): un
# ``EVENT`` cuya firma no verifica contra su ``pubkey`` se rechaza (``bad``).


class NostrRelayServer:
    """Relay Nostr de red (coro async; se corre en un thread).

    Acepta conexiones WebSocket, verifica la firma BIP340 de cada ``EVENT``
    y la emite a los suscriptores. ``start()`` lanza el servidor en un thread
    (``port=0`` -> el SO asigna el puerto; ``port`` lo expone tras ``start``).
    ``stop()`` lo cierra.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.port = port
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._server = None  # asyncio.Server (el de websockets)
        self._ready = threading.Event()
        self._bound_port: Optional[int] = None
        self._conns: set = set()  # conexiones activas (ws)

    # -- ciclo de vida -------------------------------------------------------
    def start(self) -> None:
        """Lanza el servidor en un thread y espera a que esté listo."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait()

    def stop(self) -> None:
        """Cierra el servidor y el thread."""
        if self._thread is None:
            return
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._shutdown)
        self._thread.join(timeout=5)
        self._thread = None
        self._loop = None
        self._server = None

    # -- interno -------------------------------------------------------------
    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())

    async def _serve(self) -> None:
        import websockets.asyncio.server as ws_server

        async def handler(ws):
            self._conns.add(ws)
            try:
                async for raw in ws:
                    await self._on_message(ws, raw)
            finally:
                self._conns.discard(ws)

        self._server = await ws_server.serve(handler, self.host, self.port)
        # El puerto real (port=0 -> el SO lo asigna).
        sock = self._server.sockets[0]
        self._bound_port = sock.getsockname()[1]
        self.port = self._bound_port
        self._ready.set()
        await self._server.wait_closed()

    def _shutdown(self) -> None:
        if self._server is not None:
            for ws in list(self._conns):
                self._loop.call_soon_threadsafe(
                    lambda w=ws: self._close_ws(w)
                )
            self._server.close()

    def _close_ws(self, ws) -> None:
        try:
            ws.close()
        except Exception:
            pass

    async def _on_message(self, ws, raw: bytes) -> None:
        import json as _json

        try:
            msg = _json.loads(raw)
        except Exception:
            return
        op = msg.get("op")
        if op == "event":
            ev = NostrEvent.from_dict(msg["event"])
            if ev.verify():
                # Aceptado: emite a los demás (no al que lo envía).
                await self._broadcast(ws, ev)
                await self._send(ws, {"op": "ok", "id": ev.event_id().hex()})
            else:
                # Rechazado: el relay devuelve "rejected" **con el "event"
                # completo**, para que el remitente lo guarde en
                # ``dropped()``. "rejected" es la respuesta a un publish
                # (va **solo al remitente**; los otros no lo reciben).
                await self._send(
                    ws,
                    {
                        "op": "rejected",
                        "id": ev.event_id().hex(),
                        "why": "firma no verificable",
                        "event": ev.to_dict(),
                    },
                )
        # "req" / "close": el transporte gestiona la suscripción a su nivel;
        # el relay solo emite (broadcast) y verifica.

    async def _broadcast(self, sender, ev) -> None:
        import json as _json

        payload = _json.dumps({"op": "event", "event": ev.to_dict()})
        for ws in list(self._conns):
            if ws is sender:
                continue
            try:
                await ws.send(payload)
            except Exception:
                self._conns.discard(ws)

    async def _send(self, ws, obj) -> None:
        import json as _json

        try:
            await ws.send(_json.dumps(obj))
        except Exception:
            self._conns.discard(ws)


class NostrRelayClient:
    """Cliente de red Nostr (API **síncrona**; encapsula el loop en un thread).

    Mismo contrato que :class:`NostrRelay` (in-memory): ``publish(ev)`` /
    ``events()`` / ``dropped()``. Conecta a un :class:`NostrRelayServer` por
    WebSocket y:

    * ``publish(ev)``: envía ``EVENT`` al relay; el relay verifica la firma
      BIP340 y la emite a los demás. Devuelve ``True`` si el relay la aceptó
      (``ok``), ``False`` si la rechazó (``bad``).
    * ``events()``: los eventos recibidos de los demás (el relay se los emite).
    * ``dropped()``: los eventos que el relay rechazó (``bad``).

    Uso::

        server = NostrRelayServer().start()
        client = NostrRelayClient(f"ws://127.0.0.1:{server.port}")
        client.connect()
        client.publish(ev)
        evs = client.events()
        client.close()
    """

    def __init__(self, uri: str) -> None:
        self.uri = uri
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._ws = None
        self._connected = threading.Event()
        self._inbound: list = []      # eventos recibidos de los demás
        self._dropped: list = []      # eventos rechazados por el relay
        self._lock = threading.Lock()
        self._ok_wait = None          # (threading.Event, dict) por publish

    # -- ciclo de vida -------------------------------------------------------
    def connect(self) -> None:
        """Conecta al relay (lanza el loop en un thread)."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._connected.wait()

    def close(self) -> None:
        """Cierra la conexión y el thread."""
        if self._thread is None:
            return
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._do_close)
        self._thread.join(timeout=5)
        self._thread = None
        self._loop = None
        self._ws = None

    # -- API pública (mismo contrato que NostrRelay) -------------------------
    def publish(self, ev) -> bool:
        """Envía ``ev`` al relay; el relay verifica la firma y la emite.

        Devuelve ``True`` si el relay la aceptó (``ok``), ``False`` si la
        rechazó (``bad``).
        """
        import json as _json

        ready = threading.Event()
        result: dict = {}
        self._ok_wait = (ready, result)
        self._loop.call_soon_threadsafe(
            self._do_send, _json.dumps({"op": "event", "event": ev.to_dict()})
        )
        ready.wait()
        self._ok_wait = None
        return result.get("ok", False)

    def events(self) -> list:
        """Los eventos recibidos de los demás (el relay se los emite)."""
        with self._lock:
            out = list(self._inbound)
            self._inbound.clear()
            return out

    def dropped(self) -> list:
        """Los eventos que el relay rechazó (``bad``)."""
        with self._lock:
            out = list(self._dropped)
            self._dropped.clear()
            return out

    # -- interno -------------------------------------------------------------
    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._connect_and_loop())

    async def _connect_and_loop(self) -> None:
        import websockets.asyncio.client as ws_client

        self._ws = await ws_client.connect(self.uri)
        self._connected.set()
        try:
            async for raw in self._ws:
                self._on_inbound(raw)
        finally:
            self._connected.clear()

    def _on_inbound(self, raw: bytes) -> None:
        import json as _json

        try:
            msg = _json.loads(raw)
        except Exception:
            return
        op = msg.get("op")
        if op == "event":
            ev = NostrEvent.from_dict(msg["event"])
            with self._lock:
                self._inbound.append(ev)
        elif op == "rejected":
            # El relay rechazó un publish (el nuestro). El ``rejected`` va
            # **solo al remitente** y lleva el ``event`` completo, para que
            # lo guarde en ``dropped()`` (mismo contrato que el relay
            # in-memory). Si no lo lleva, se resuelve igualmente.
            if "event" in msg:
                ev = NostrEvent.from_dict(msg["event"])
                with self._lock:
                    self._dropped.append(ev)
            # Resuelve el ``ok_wait`` con ``ok=False`` (para que ``publish``
            # no se bloquee).
            if self._ok_wait is not None:
                ready, result = self._ok_wait
                result["ok"] = False
                ready.set()
        elif op == "ok":
            # Responde a un publish: el relay aceptó el evento.
            if self._ok_wait is not None:
                ready, result = self._ok_wait
                result["ok"] = True
                ready.set()

    def _do_send(self, payload: str) -> None:
        # ``_do_send`` corre en el loop (vía ``call_soon_threadsafe``), así
        # ``ensure_future`` se agenda directamente (sin anidar).
        if self._ws is not None:
            asyncio.ensure_future(self._ws.send(payload))

    def _do_close(self) -> None:
        # ``close`` es una coroutine en websockets 15.x: hay que agendarla
        # (``ensure_future``), no solo llamarla (sería un no-op).
        if self._ws is not None:
            asyncio.ensure_future(self._ws.close())


# ---------------------------------------------------------------------------
# Transporte de malla Nostr (capa 3 sobre red)
# ---------------------------------------------------------------------------
class NostrTransport(MeshTransport):
    """Transporte de malla Nostr: lleva la malla (capa 3) **a red**.

    Implementa :class:`~delm.core.transport.MeshTransport` (``send`` /
    ``poll`` / ``close``) sobre un :class:`NostrRelayClient` de red, así un
    :class:`~delm.core.mesh_node.MeshNode` puede correr **sobre la red**
    (no solo in-proceso). Es swappable con
    :class:`~delm.core.transport.InMemoryTransport` /
    :class:`~delm.core.transport.QuicTransport`.

    * **Identidad**: el ``peer_id`` de un nodo es su ``pubkey`` x-only
      (BIP340, hex de 64). El ``send`` firma un ``NostrEvent`` (``kind=10001``)
      con la :class:`NostrKey` del nodo; el ``poll`` deriva el ``from_id`` del
      ``pubkey`` del evento recibido.
    * **``send(to, payload)``**: firma ``NostrEvent`` (``content =
      base64(payload)``, ``tags = [["d", to]]``) y lo publica vía el
      :class:`NostrRelayClient`. El relay **verifica la firma BIP340** y la
      emite a los demás (**excluye al remitente**).
    * **``poll()``**: drena ``client.events()`` (destructivo), filtra los
      ``kind=10001`` y devuelve ``[(from_id, payload), ...]`` (el contrato
      :class:`~delm.core.transport.MeshTransport`).

    El relay ya hace el *fan-out* (emite a todos menos al remitente), así el
    transporte no hace broadcast: solo adapta. ``to`` / ``from_id`` son
    ``pubkey`` hex (el espacio de identidad de la malla Nostr).
    """

    KIND = 10001  # datagrama de malla (gossip / gist / heartbeat)

    def __init__(self, client: "NostrRelayClient", key: "NostrKey") -> None:
        self.client = client
        self.key = key

    @property
    def peer_id(self) -> str:
        """El ``peer_id`` de este nodo: su ``pubkey`` x-only (hex de 64)."""
        return self.key.pubkey.hex()

    # -- MeshTransport -------------------------------------------------------
    def send(self, to: str, payload: bytes) -> None:
        """Envía ``payload`` a ``to``: firma un ``NostrEvent`` y lo publica.

        ``to`` es el ``pubkey`` hex del destino. El relay verifica la firma
        BIP340 y la emite a los demás (excluye al remitente).
        """
        ev = NostrEvent.signed(
            self.key, 0, self.KIND, [["d", to]],
            base64.b64encode(payload).decode("ascii"),
        )
        self.client.publish(ev)

    def poll(self) -> list:
        """Drena ``client.events()``: devuelve ``[(from_id, payload), ...]``.

        ``from_id`` es el ``pubkey`` hex del remitente (derivado del ``pubkey``
        del evento). Solo los ``kind=10001`` (los datagramas de malla).
        """
        out: list = []
        for ev in self.client.events():
            if ev.kind != self.KIND:
                continue
            out.append((ev.pubkey.hex(), base64.b64decode(ev.content)))
        return out

    def close(self) -> None:
        """Cierra el cliente de red."""
        self.client.close()
