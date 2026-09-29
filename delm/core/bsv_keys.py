"""ECDSA-secp256k1 keypairs — the identity that anchors to BSV (Fase 1).

Por qué un módulo nuevo y no cambiar ``provenance.py`` directamente: la
firma que el exchange ancla tiene que ser **la misma** que la que un tercero
verifica en la cadena. BRC-220 define ECDSA-secp256k1, no Ed25519 — Bitcoin
no tiene Ed25519 nativo. Anclar Ed25519 sería un protocolo propietario, sin
interoperabilidad.

Este módulo **no reemplaza** a :mod:`delm.core.provenance` todavía. Ese sigue
siendo el que firma las admisiones en memoria, y ``sig_kind`` es un string
que viaja por la serialización de :mod:`delm.core.contrib`: cambiar su
valor por defecto rompería entradas ya emitidas. Aquí la clave secp256k1
existe con su propio tipo, convive con ed25519, y se elige explícitamente
quien la use. La migración de las admisiones es un paso aparte.

Formato de firma: ``r || s``, 64 bytes big-endian, no DER.

BRC-220 lo explica y el motivo es concreto: un lector trata 64 bytes como
``r||s`` y cualquier otra longitud como DER, y un DER puede medir *exactamente*
64 bytes cuando ``r`` y ``s`` son inusualmente cortos — en cuyo caso se lee
como ``r||s`` y **no verifica**. ``cryptography`` emite DER de 69-72 bytes
(comprobado: 400 firmas, ninguna de 64), así que la ambigüedad no nos puede
afectar, pero emitir el formato compacto elimina la rama ambigua entera. Es
lo que la spec recomienda para un firmante con DER en la mano.

Determinismo: ECDSA es aleatorio. La firma no es reproducible bit a bit; lo
que sí se reproduce son ``digest``, ``public_key`` y la verificación. Eso es
suficiente para el ancla, que compromete un hash firmado, no una firma
determinista.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

try:  # pragma: no cover - exercised only when installed
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import utils as _asym_utils
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
    _HAVE_ECDSA = True
except Exception:  # noqa: BLE001 - degrade to HMAC
    _HAVE_ECDSA = False

#: True when real ECDSA-secp256k1 signatures are available.
HAVE_ECDSA = _HAVE_ECDSA

#: ``kind`` value for this backend, and what travels in ``sig_kind``.
SIG_KIND = "ecdsa-secp256k1"

#: Longitud de la clave publica comprimida (secp256k1: 33 bytes).
PUBKEY_LEN = 33

#: Longitud de la firma en formato compacto ``r || s``.
SIG_LEN = 64

#: Longitud de una clave privada en bytes.
PRIVKEY_LEN = 32


class KeyError_(RuntimeError):
    """``cryptography`` no esta disponible (no se puede firmar secp256k1)."""


@dataclass
class Secp256k1KeyPair:
    """A secp256k1 signing key: the identity that anchors to BSV.

    ``public_key`` is the 33-byte compressed point (BRC-220 accepts either
    encoding; compressed is the interoperable one). ``sign()`` returns
    ``r || s``, 64 bytes.
    """

    author_id: str
    kind: str
    _priv: Any
    public_key: bytes

    # ------------------------------------------------------------------ new
    @classmethod
    def new(cls, author_id: str) -> "Secp256k1KeyPair":
        """Generate a fresh secp256k1 key.

        Raises if ``cryptography`` is unavailable: this backend is exactly the
        public-asymmetric case, and degrading to a pre-shared key would
        silently turn the anchor's signer into the trust anchor itself.
        """
        if not HAVE_ECDSA:
            raise KeyError_(
                "ECDSA-secp256k1 no disponible (falta 'cryptography'). "
                "Este backend es precisamente la verificacion publica "
                "asimétrica: sin el, el firmante seria el ancla de confianza."
            )
        priv = _ec.generate_private_key(_ec.SECP256K1())  # type: ignore[possibly-unbound]
        return cls(author_id, SIG_KIND, priv, _compress(priv))

    @classmethod
    def from_private_bytes(cls, author_id: str, raw: bytes) -> "Secp256k1KeyPair":
        """Rebuild a key from 32 raw private bytes (persistence)."""
        if not HAVE_ECDSA:
            raise KeyError_("ECDSA-secp256k1 no disponible (falta 'cryptography')")
        if len(raw) != PRIVKEY_LEN:
            raise ValueError(
                f"clave privada secp256k1 de {len(raw)} bytes; se esperan {PRIVKEY_LEN}"
            )
        priv = _ec.derive_private_key(int.from_bytes(raw, "big"), _ec.SECP256K1())  # type: ignore[possibly-unbound]
        return cls(author_id, SIG_KIND, priv, _compress(priv))

    # ------------------------------------------------------------- sign/verify
    def sign(self, digest: str) -> bytes:
        """Sign the hex ``digest``, returning ``r || s`` (64 bytes).

        The digest is the message *digest*, per SEC 1 §4.1.3: it is read as a
        big-endian integer and **not** hashed again. That is what BRC-220
        requires, and it is a real footgun — a library that hashes its input
        by default produces a signature over a different value, and a
        conformant verifier rejects it.
        """
        msg = _digest_bytes(digest)
        der = self._priv.sign(msg, _ec.ECDSA(_asym_utils.Prehashed(_hashes.SHA256())))  # type: ignore[possibly-unbound]
        r, s = _asym_utils.decode_dss_signature(der)  # type: ignore[possibly-unbound]
        # `s` in the low-S form so the encoding is canonical (BIP62 / BIP340),
        # otherwise the same key signing the same digest yields two valid
        # encodings of the same signature.
        if s > _HALF_CURVE_ORDER:
            s = _N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def verify(self, digest: str, signature: bytes) -> bool:
        """Verify ``signature`` (r||s) over the hex ``digest``."""
        return verify_public(self.public_key, digest, signature)

    # ------------------------------------------------------------ persistence
    def save(self, path: str) -> str:
        """Persist the private key (0600). A signing key is a secret."""
        import json
        import os
        raw = self._priv.private_numbers().private_value.to_bytes(32, "big")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "author_id": self.author_id,
                "kind": self.kind,
                "private_key": raw.hex(),
                "public_key": self.public_key.hex(),
            }, fh, indent=2, sort_keys=True)
            fh.write("\n")
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - platform-dependent
            pass
        return path

    @classmethod
    def load(cls, path: str) -> "Secp256k1KeyPair":
        """Load a key written by :meth:`save`."""
        import json
        with open(path, encoding="utf-8") as fh:
            blob = json.load(fh)
        if blob.get("kind") != SIG_KIND:
            raise ValueError(f"kind persistido {blob.get('kind')!r} != {SIG_KIND!r}")
        return cls.from_private_bytes(str(blob.get("author_id", "")),
                                     bytes.fromhex(blob["private_key"]))


#: The secp256k1 curve order n.
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

#: n/2 — the low-S boundary (BIP62).
_HALF_CURVE_ORDER = _N // 2


def _digest_bytes(digest: str) -> bytes:
    """A hex digest as the 32 bytes ECDSA signs over."""
    raw = bytes.fromhex(digest)
    if len(raw) != 32:
        raise ValueError(
            f"digest de {len(raw)} bytes; ECDSA-secp256k1 firma exactamente 32 "
            "(SEC 1 §4.1.3). Si tu hash no es SHA-256, cambialo — no lo "
            "re-hashees aqui."
        )
    if digest != digest.lower():
        raise ValueError("digest en hexadecimal mayusculas: canonico en minusculas")
    return raw


def _compress(priv: Any) -> bytes:
    """The 33-byte compressed public key of ``priv``."""
    from cryptography.hazmat.primitives import serialization
    return priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )


def verify_public(public_key: bytes, digest: str, signature: bytes) -> bool:
    """Verify an ``r||s`` signature over the hex ``digest``.

    Signature-independent of the signer object: a peer holding only the
    public key can check an anchor without trusting whoever published it.
    """
    if not HAVE_ECDSA:
        return False
    if len(signature) != SIG_LEN:
        # BRC-220: a reader reads 64 bytes as r||s and any other length as
        # DER. We only ever emit the compact form, so anything else is
        # malformed rather than "a DER signature we could also read".
        return False
    if len(public_key) != PUBKEY_LEN:
        return False
    try:
        msg = _digest_bytes(digest)
    except ValueError:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import utils
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key)
        der = utils.encode_dss_signature(r, s)
        pub.verify(der, msg, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except _InvalidSignature:  # type: ignore[misc]
        return False
    except Exception:  # noqa: BLE001 - malformed key/sig
        return False


__all__ = [
    "Secp256k1KeyPair",
    "verify_public",
    "HAVE_ECDSA",
    "SIG_KIND",
    "PUBKEY_LEN",
    "SIG_LEN",
    "PRIVKEY_LEN",
    "KeyError_",
]
