"""SPV wallet — la identidad del nodo: maestro, derivación y dirección (BRC-42/43/75).

Por qué este módulo existe
--------------------------
:class:`~smcp.core.bsv_keys.Secp256k1KeyPair` firma bien, pero no es una
identidad: ``new()`` genera una clave suelta cada vez. Eso rompe la
pseudonymía — si el nodo firma con una clave distinta en cada llamada, sus
firmas no se atribuyen a un mismo nodo, y un reinicio produce otra identidad.
La identidad en Bitcoin es **pseudónima pero no anónima**, y eso se construye
con un maestro y derivación, no con claves sueltas.

Tres specs, tres piezas
-----------------------
* **BRC-75** — el maestro se respalda con un mnemonic BIP39. La clave es
  ``sha256(seed)`` con ``seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048)``.
  Verificable: mnemonic -> la misma clave, siempre.
* **BRC-42 (BKDS)** — la derivación. A diferencia de BIP32, que deriva hijos
  del maestro con un chain code y por tanto deja que cualquiera con la pubkey
  maestra y un índice vea *todas* las hijas, BKDS usa el **secreto compartido
  ECDH**: el mismo índice da una clave distinta para cada contraparte. Sin el
  límite de 4·10⁹ de hijos de BIP32.
* **BRC-43** — el ``keyId`` da forma a los universos:
  ``<securityLevel>-<protocolID>-<keyID>``.

La asimetría de BRC-42 (y el bug que costó encontrar)
---------------------------------------------------
La spec define dos lados distintos, y no son intercambiables:

* **receptor** — ``child_priv = (own_priv + scalar) mod n``
* **emisor** — ``child_pub = G*scalar + other_pub``  ← suma **de puntos**

Sumar escalares en el emisor produce otra clave, y las dos partes nunca
coinciden. Por eso son dos funciones, :func:`derive_private_shared` y
:func:`derive_child_public`, y no una con un flag. Lo fija
``test_both_sides_derive_the_same_child``.

Qué resuelve para SMCP
----------------------
**Atribución.** Un ancla lleva el ``keyId`` con el que firmó, y ese keyId
deriva del maestro. La **dirección** (``pubkey -> hash160 -> base58check``) es
lo que hace la atribución verificable por terceros: extraen la pubkey de un
input, derivan la dirección y comparan. El reloj no da atribución; la clave sí.

**Un maestro, varias claves.** Firmar anclas, firmar admisiones y la de pagos
son claves distintas del mismo maestro. Comprometer una no compromete la
identidad, y un observador ve tres claves sin poder enlazarlas (es
autoderivación, no ECDH con contraparte).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from smcp.core._bip39_words import BIP39_WORDS
from smcp.core.bsv_keys import HAVE_ECDSA, Secp256k1KeyPair

_LOG = logging.getLogger(__name__)

#: Iteraciones PBKDF2 de BIP39.
PBKDF2_ROUNDS = 2048

#: Protocolo por defecto del exchange de SMCP. Otro protocolo -> otro universo
#: de claves, por construcción.
SMCP_PROTOCOL = "smcp"

#: Orden de la curva secp256k1 (para la clave privada derivada: mod n).
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

#: Primo del campo (para los inversos modulares de la aritmética de curva).
#: **No** es `_N`. Sumar puntos con `pow(..., _N-2, _N)` produce puntos que no
#: satisfacen y² = x³ + 7, y `cryptography` lo rechaza con "Point is not on
#: the curve specified" — sin más detalle. Lo fija
#: ``test_derived_point_is_on_the_curve``.
_P_FIELD = 2**256 - 2**32 - 977

#: El punto generador real de secp256k1. El emisor suma sobre *este*; con otro
#: punto, las claves derivadas no coinciden con las del receptor.
_GEN_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GEN_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

#: Version byte de una dirección P2PKH en BSV mainnet (sale "1...").
_MAINNET_VERSION = 0x00


# --------------------------------------------------------------------------- base58
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    """Base58 con el alfabeto Bitcoin (direcciones y WIF)."""
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = 0
    for b in data:
        if b:
            break
        pad += 1
    return "1" * pad + out


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        idx = _B58.find(ch)
        if idx < 0:
            raise ValueError(f"carácter base58 inválido: {ch!r}")
        n = n * 58 + idx
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in text:
        if ch != "1":
            break
        pad += 1
    return b"\x00" * pad + body


def _b58check(payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)


def _b58check_decode(addr: str) -> bytes:
    raw = b58decode(addr)
    if len(raw) < 5:
        raise ValueError("dirección demasiado corta")
    payload, chk = raw[:-4], raw[-4:]
    want = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if chk != want:
        raise ValueError("checksum de la dirección no válido")
    return payload


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(x)) — el paso de la clave pública a la dirección."""
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


# --------------------------------------------------------------------------- dirección
def pubkey_to_address(public_key: bytes) -> str:
    """``pubkey (33 o 65 bytes) -> hash160 -> base58check``."""
    if len(public_key) not in (33, 65):
        raise ValueError(f"pubkey de {len(public_key)} bytes; se esperan 33 o 65")
    return _b58check(bytes([_MAINNET_VERSION]) + hash160(public_key))


def address_to_hash160(address: str) -> bytes:
    """La inversa, comprobando red y checksum."""
    payload = _b58check_decode(address)
    if len(payload) != 21:
        raise ValueError("dirección de longitud inesperada")
    if payload[0] != _MAINNET_VERSION:
        raise ValueError(f"dirección de otra red (version byte {payload[0]})")
    return payload[1:]


def address_matches_public_key(address: str, public_key: bytes) -> bool:
    """La atribución, comprobada: la dirección sale de *esta* clave.

    Lo que un tercero hace con una transacción ancla. Si es ``False``, la
    firma puede ser criptográficamente válida y aun así no ser de quien dice
    firmarla — por eso la dirección, y no solo el keyId.
    """
    try:
        return hash160(public_key) == address_to_hash160(address)
    except ValueError:
        return False


# --------------------------------------------------------------------------- BRC-75
def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP39: ``PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048)``.

    NFKD es obligatorio: normalizar de otro modo produce otro seed, y quien
    escriba su frase con otra normalización recuperaría otra clave sin que
    nada lo indique.
    """
    m = unicodedata.normalize("NFKD", " ".join(mnemonic.split()))
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", m.encode("utf-8"),
                               salt.encode("utf-8"), PBKDF2_ROUNDS)


def mnemonic_to_private(mnemonic: str, passphrase: str = "") -> bytes:
    """BRC-75: la clave privada del maestro es ``sha256(seed)``."""
    return hashlib.sha256(mnemonic_to_seed(mnemonic, passphrase)).digest()


def generate_mnemonic(entropy_bytes: int = 16) -> str:
    """Mnemonic BIP39: 12, 15, 18, 21 o 24 palabras.

    Solo se aceptan los tamaños que hacen ``ENT + ENT/32`` múltiplo de 11
    (16, 20, 24, 28 y 32 bytes). Admitir otros produciría una frase que no es
    un mnemonic BIP39 — pareciéndolo lo suficiente como para que alguien la
    respaldara sin poder recuperarla.

    Vector: con entropía cero da ``abandon x11 + about``. Lo fija
    ``test_entropy_zero_matches_the_bip39_vector``.
    """
    import secrets
    if entropy_bytes not in (16, 20, 24, 28, 32):
        raise ValueError(
            "entropía BIP39: 16, 20, 24, 28 o 32 bytes "
            "(12, 15, 18, 21 o 24 palabras)")
    n = entropy_bytes * 8
    ent = secrets.token_bytes(entropy_bytes)
    bits = "".join(f"{b:08b}" for b in ent) + \
        "".join(f"{b:08b}" for b in hashlib.sha256(ent).digest())[:n // 32]
    return " ".join(BIP39_WORDS[int(bits[i:i + 11], 2)]
                    for i in range(0, len(bits), 11))


def mnemonic_is_valid(mnemonic: str) -> bool:
    """Comprueba el checksum BIP39. ``False`` en vez de excepción: una frase
    tecleada mal es un caso normal, y quien teclea quiere un "no"."""
    words = mnemonic.split()
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    try:
        bits = "".join(f"{BIP39_WORDS.index(w):011b}" for w in words)
    except ValueError:
        return False
    cs = len(bits) // 33
    ent, chk = bits[:len(bits) - cs], bits[len(bits) - cs:]
    ent_bytes = bytes(int(ent[i:i + 8], 2) for i in range(0, len(ent), 8))
    want = "".join(f"{b:08b}" for b in hashlib.sha256(ent_bytes).digest())[:cs]
    return chk == want


# --------------------------------------------------------------------------- BRC-43
#: Niveles de seguridad de un keyId. 0 sin permisos, 1 todos los keyId de ese
#: protocolo, 2 solo una contraparte.
SECURITY_LEVELS = (0, 1, 2)


def format_key_id(security_level: int, protocol_id: str, key_id: str) -> str:
    """``<securityLevel>-<protocolID>-<keyID>``.

    El formato *es* la frontera de permisos: cambiar el ``protocolID`` cambia
    el universo, así que dos protocolos nunca comparten derivadas.
    """
    if security_level not in SECURITY_LEVELS:
        raise ValueError(f"nivel {security_level} fuera de {SECURITY_LEVELS}")
    if "-" in protocol_id or "-" in key_id:
        raise ValueError("protocolID y keyID no pueden contener guiones")
    return f"{security_level}-{protocol_id}-{key_id}"


def parse_key_id(key_id: str) -> tuple[int, str, str]:
    """La inversa de :func:`format_key_id`."""
    parts = key_id.split("-")
    if len(parts) != 3:
        raise ValueError(f"keyId {key_id!r}: se esperaba <nivel>-<protocolo>-<id>")
    try:
        level = int(parts[0])
    except ValueError as exc:
        raise ValueError(f"keyId {key_id!r}: nivel no numérico") from exc
    if level not in SECURITY_LEVELS:
        raise ValueError(f"keyId {key_id!r}: nivel {level} fuera de rango")
    return level, parts[1], parts[2]


# --------------------------------------------------------------------------- curva
def _curve() -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.SECP256K1()


def _numbers(x: int, y: int) -> Any:
    """Reconstruye un punto. El orden real es ``(x, y, curve)``.

    Importante porque la firma de `__init__` es posicional-oculta
    (``*args, **kwargs``): pasar ``(y, curve, x)`` no da un error de sintaxis
    ni un aviso de Pyright fiable, revienta con ``TypeError: 'SECP256K1'
    object is not an instance of 'int'`` en la primera llamada.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1())


def _generator() -> Any:
    return _numbers(_GEN_X, _GEN_Y)


def _derive_key(scalar: int) -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.derive_private_key(scalar, ec.SECP256K1())


def _pub_key(public_key: bytes) -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(),
                                                        public_key)


def _compress(numbers: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return _numbers(numbers.x, numbers.y).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def _pt_add(p: Any, q: Any) -> Any:
    """Suma de dos puntos. ``None`` si son inversos (punto en el infinito).

    Todos los inversos modulares van con ``_P_FIELD`` (primo del campo), nunca
    con ``_N``: con el orden del grupo el punto resultante no cae en la curva
    y el error que sale no señala la causa.
    """
    if p is None:
        return q
    if q is None:
        return p
    if p.x == q.x and (p.y + q.y) % _P_FIELD == 0:
        return None
    if p.x == q.x and p.y == q.y:
        lam = (3 * p.x * p.x) * pow(2 * p.y, _P_FIELD - 2, _P_FIELD) % _P_FIELD
    else:
        lam = (q.y - p.y) * pow(q.x - p.x, _P_FIELD - 2, _P_FIELD) % _P_FIELD
    x = (lam * lam - p.x - q.x) % _P_FIELD
    return _numbers(x, (lam * (p.x - x) - p.y) % _P_FIELD)


def _mul_point(point: Any, scalar: int) -> Any:
    """Multiplicación escalar (double-and-add)."""
    result = None
    acc, k = point, scalar % _N
    while k:
        if k & 1:
            result = _pt_add(result, acc)
        acc = _pt_add(acc, acc)
        k >>= 1
    return result


def _shared_scalar(own_priv: bytes, other_pub: bytes,
                   invoice: str) -> tuple[bytes, int]:
    """``(secreto_compartido, escalar)`` — el núcleo común de los dos lados.

    ``ECDH.exchange`` devuelve la coordenada x del punto producto, que es lo
    que usa la spec. (No se puede multiplicar un punto arbitrario con la API
    de `cryptography`; por eso esta vía.)
    """
    if not HAVE_ECDSA:  # pragma: no cover
        raise RuntimeError("BRC-42 requiere 'cryptography'")
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = _derive_key(int.from_bytes(own_priv, "big"))
    secret = priv.exchange(ec.ECDH(), _pub_key(other_pub))
    mac = hmac.new(secret, invoice.encode("utf-8"), hashlib.sha256).digest()
    return secret, int.from_bytes(mac, "big")


# --------------------------------------------------------------------------- BRC-42
def derive_private_shared(own_priv: bytes, other_pub: bytes,
                          invoice: str) -> tuple[bytes, bytes]:
    """BRC-42, lado **receptor**: ``child_priv = (own_priv + scalar) mod n``.

    **Autoderivación** (BRC-43, una sola parte): con ``other_pub`` igual a la
    propia pubkey, la clave depende solo de uno mismo. Es el caso de la
    identidad de un nodo, y por eso sus claves de propósito no se pueden
    enlazar entre sí.
    """
    _secret, scalar = _shared_scalar(own_priv, other_pub, invoice)
    child = (scalar + int.from_bytes(own_priv, "big")) % _N
    return child.to_bytes(32, "big"), _compress(_mul_point(_generator(), child))


def derive_child_public(own_priv: bytes, other_pub: bytes,
                        invoice: str) -> bytes:
    """BRC-42, lado **emisor**: ``child_pub = G*scalar + other_pub``.

    Aquí la suma es **de puntos**, no de escalares: sumar escalares es el paso
    del receptor y produce otra clave, con la que las dos partes nunca
    coinciden. Quien deriva así obtiene una clave pública que el otro sí
    puede firmar.
    """
    _secret, scalar = _shared_scalar(own_priv, other_pub, invoice)
    return _compress(_pt_add(_mul_point(_generator(), scalar),
                              _pub_key(other_pub).public_numbers()))


# --------------------------------------------------------------------------- wallet
@dataclass
class SpvWallet:
    """La identidad del nodo: un maestro, y claves derivadas por propósito.

    El ``mnemonic`` es la raíz de todo y se guarda porque un maestro del que
    no se puede hacer backup es un maestro que se pierde. No se imprime ni se
    expone en el ``repr``: el backup es una llamada explícita del operador.
    """

    master: Secp256k1KeyPair
    protocol: str = SMCP_PROTOCOL
    mnemonic: str = field(default="", repr=False)
    passphrase: str = field(default="", repr=False)
    _derived: dict[str, Secp256k1KeyPair] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------ create
    @classmethod
    def create(cls, mnemonic: str = "", passphrase: str = "",
               author_id: str = "", protocol: str = SMCP_PROTOCOL,
               ) -> "SpvWallet":
        """Crea o restaura una wallet desde un mnemonic.

        Sin mnemonic genera uno (12 palabras) y lo deja en :attr:`mnemonic`
        para que el operador lo respalde. Con mnemonic, es exactamente la
        misma wallet siempre: la identidad sobrevive al reinicio, que es lo
        que una clave suelta no hacía.
        """
        if not HAVE_ECDSA:  # pragma: no cover
            raise RuntimeError("SPV wallet requiere 'cryptography'")
        if not mnemonic:
            mnemonic = generate_mnemonic()
        elif not mnemonic_is_valid(mnemonic):
            # Falla claro: una frase con el checksum mal es la forma más
            # fácil de que un operador respalde algo que no recupera nada.
            raise ValueError(
                "mnemonic inválido (palabra desconocida, longitud incorrecta o "
                "checksum que no cuadra). Sin esto el nodo creería tener un "
                "backup y perdería la identidad al restaurar.")
        priv = mnemonic_to_private(mnemonic, passphrase)
        master = Secp256k1KeyPair.from_private_bytes(author_id or "spv-node", priv)
        return cls(master=master, protocol=protocol, mnemonic=mnemonic,
                   passphrase=passphrase)

    # ----------------------------------------------------------------- address
    def master_address(self) -> str:
        """La dirección del maestro: la identidad estable del nodo.

        Determinista y verificable por terceros sin preguntar a nadie.
        """
        return pubkey_to_address(self.master.public_key)

    # ------------------------------------------------------------------ derive
    def derive(self, key_id: str) -> Secp256k1KeyPair:
        """La clave derivada de un ``keyId`` de este protocolo."""
        _level, protocol, _kid = parse_key_id(key_id)
        if protocol != self.protocol:
            raise ValueError(
                f"keyId de protocolo {protocol!r} != {self.protocol!r}: son "
                "universos de claves distintos (BRC-43)")
        if key_id not in self._derived:
            master_priv = self.master._priv.private_numbers().private_value
            child_priv, _pub = derive_private_shared(
                master_priv.to_bytes(32, "big"), self.master.public_key, key_id)
            self._derived[key_id] = Secp256k1KeyPair.from_private_bytes(
                self.master.author_id, child_priv)
        return self._derived[key_id]

    def derive_for(self, purpose: str) -> Secp256k1KeyPair:
        """La clave de un propósito, con nivel 0.

        ``derive_for("anchor")`` -> ``0-smcp-anchor``. Firmar anclas y firmar
        admisiones son claves distintas del mismo maestro: comprometer una no
        compromete la identidad ni revela la otra.
        """
        return self.derive(format_key_id(0, self.protocol, purpose))

    def sign_for(self, purpose: str, digest: str) -> tuple[str, str, bytes]:
        """Firma con la clave de un propósito.

        Devuelve ``(key_id, pubkey_hex, signature)``. El keyId y la pubkey son
        la atribución, y viajan al ancla para que un tercero compruebe *qué*
        firmó, no solo *que* hay una firma.
        """
        key = self.derive_for(purpose)
        return (format_key_id(0, self.protocol, purpose),
                key.public_key.hex(), key.sign(digest))

    def address_for(self, purpose: str) -> str:
        """La dirección derivada de un propósito (la que ancla al nodo)."""
        return pubkey_to_address(self.derive_for(purpose).public_key)

    # ------------------------------------------------------------- persistence
    def save(self, path: str) -> str:
        """Guarda mnemonic y maestro en *path*, modo 0600.

        Un mnemonic es tan secreto como la clave privada y más expuesto: 12
        palabras sobreviven a más veces que 32 bytes en hex.
        """
        blob = {
            "protocol": "spv-wallet",
            "version": 1,
            "protocol_id": self.protocol,
            "author_id": self.master.author_id,
            "mnemonic": self.mnemonic,
            "master_public_key": self.master.public_key.hex(),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(blob, fh, indent=2, sort_keys=True)
            fh.write("\n")
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - platform-dependent
            _LOG.warning("no se pudo fijar 0600 en %s", path)
        return path

    @classmethod
    def load(cls, path: str) -> "SpvWallet":
        """Restaura una wallet desde su fichero."""
        with open(path, encoding="utf-8") as fh:
            blob = json.load(fh)
        if blob.get("protocol") != "spv-wallet":
            raise ValueError(f"fichero {blob.get('protocol')!r} != 'spv-wallet'")
        return cls.create(mnemonic=str(blob["mnemonic"]),
                          author_id=str(blob.get("author_id", "spv-node")),
                          protocol=str(blob.get("protocol_id", SMCP_PROTOCOL)))


__all__ = [
    "SpvWallet", "generate_mnemonic", "mnemonic_is_valid", "mnemonic_to_seed",
    "mnemonic_to_private", "format_key_id", "parse_key_id", "SECURITY_LEVELS",
    "SMCP_PROTOCOL", "pubkey_to_address", "address_to_hash160",
    "address_matches_public_key", "hash160", "b58encode", "b58decode",
    "derive_private_shared", "derive_child_public",
]
