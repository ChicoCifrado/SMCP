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

import base64
import hashlib
import json
import os
from typing import TYPE_CHECKING

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

    def __init__(self, relay: NostrRelay, key: NostrKey) -> None:
        self.relay = relay
        self.key = key
        self._nodes: set[str] = set()
        self._inboxes: dict[str, list["Announcement"]] = {}

    def register(self, node: str) -> None:
        """Registra un nodo (su bandeja existe y recibe los broadcasts)."""
        self._nodes.add(node)
        self._inboxes.setdefault(node, [])

    def publish(self, node: str, ann: "Announcement") -> None:
        """Emite el anuncio de ``node`` como evento Nostr y lo entrega.

        El anuncio se serializa (``to_dict()`` en base64) y se firma (BIP340)
        su ``id``. El relay lo acepta si la firma verifica; entonces el
        anuncio se entrega a las bandejas de los demás nodos.
        """
        content = base64.b64encode(
            json.dumps(ann.to_dict(), separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        ev = NostrEvent.signed(self.key, 0, 10000, [["d", node]], content)
        if self.relay.publish(ev):
            for other in self._nodes:
                if other != node:
                    self._inboxes.setdefault(other, []).append(ann)

    def deliver(self, node: str) -> list["Announcement"]:
        """Los anuncios que ``node`` recibe de los demás (FIFO)."""
        box = self._inboxes.setdefault(node, [])
        out = list(box)
        self._inboxes[node] = []
        return out

    def nodes(self) -> list[str]:
        """Nodos registrados."""
        return sorted(self._nodes)
