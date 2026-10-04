"""Provenance — canonical digests and signatures for admitted gists.

This is the cryptographic core of the DELM security layer (Capas 1+2):

* **Canonical digest** — a stable SHA-256 over the *content* of a
  :class:`~smcp.core.gist.Gist`, independent of dict ordering or the
  signature fields themselves. The digest is the "identity" of what an
  agent admits: two gists with the same content have the same digest.

* **Signature** — a per-agent key signs ``(digest, author_id)`` so a peer can
  verify *who* admitted *what* without trusting the channel.

Two key backends are supported:

* **ed25519** (preferred, real asymmetric crypto) — used automatically when the
  ``cryptography`` package is importable.
* **HMAC-SHA256** (fallback) — a pre-shared-key scheme used when ``cryptography``
  is unavailable. It is *not* public-verify in the asymmetric sense: the
  verifier must already hold the author's key (the "trust anchor"). It exists
  so the framework runs with zero third-party deps; production should install
  ``cryptography`` and use ed25519.

The module is deliberately dependency-light: it imports ``cryptography``
lazily and degrades gracefully.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any

# --- backend detection (lazy, optional) -------------------------------------
# Los tres imports de abajo solo se ligan DENTRO del `try`. Pyright no
# propaga `HAVE_ED25519` (derivado del exito del try) hasta ellos, y reporta
# "possibly unbound" en cada uso — 6 falsos positivos: el unico camino que
# llega a `KeyPair.new(kind="ed25519")` pasa antes por
# `if not HAVE_ED25519: raise`, de modo que `_ed25519`/`_Encoding`/
# `_PublicFormat` estan ligadas ahi sin excepcion. Se silencia en el punto de
# uso (ver abajo) y no aqui: ponerlos a None en el except cambia "posiblemente
# no ligado" por "miembro de None", que es el mismo falso positivo con otro
# nombre, y deja un None alcanzable en una ruta de criptografia.
try:  # pragma: no cover - exercised only when installed
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _Encoding,
        PublicFormat as _PublicFormat,
    )
    _HAVE_Cryptography = True
except Exception:  # noqa: BLE001 - degrade to HMAC
    _HAVE_Cryptography = False

#: True when real ed25519 signatures are available.
HAVE_ED25519 = _HAVE_Cryptography

#: Modo estricto (default): el pipeline real NO degrada silenciosamente a
#: HMAC si ``cryptography`` no está disponible. En modo estricto,
#: ``KeyPair.new()`` (kind=None) lanza si no hay ed25519, en vez de
#: degradar a HMAC (pre-shared key). El modo no-estricto (``STRICT_MODE=False``)
#: o ``allow_hmac_fallback=True`` permiten el fallback (con warning) para el
#: modo de test/zero-deps.
#:
#: Rationale: un despliegue sin ``cryptography`` que firma con el fallback
#: HMAC sin que nadie lo note deja de ser verificación pública asimétrica
#: (la clave pre-compartida ES el trust anchor). El modo estricto hace que
#: ese despliegue *falle claro* en vez de degradar silenciosamente.
STRICT_MODE = True


# --------------------------------------------------------------------------
# Canonical digest
# --------------------------------------------------------------------------
def _refs_blob(gist: Any) -> list[tuple[str, str, int]]:
    out = []
    for r in getattr(gist, "refs", None) or []:
        out.append((r.head, r.tail, int(getattr(r, "n_words", 5))))
    return out


def _summary_blob(summary: Any) -> dict | None:
    if summary is None:
        return None
    claims = []
    for b in getattr(summary, "claims", None) or []:
        ref = b.get("ref")
        claims.append({
            "claim": b.get("claim", ""),
            "ref": (ref.head, ref.tail) if ref is not None else None,
        })
    return {"claims": claims, "raw_unit": getattr(summary, "raw_unit", "")}


def canonical_payload(gist: Any) -> dict:
    """The *content* of a gist, in a canonical (order-independent) form.

    Excludes the provenance fields (``author_id``/``digest``/``signature``)
    so the digest is not self-referential.
    """
    kind = getattr(gist, "kind", None)
    return {
        "label": gist.label,
        "gist": gist.gist,
        "kind": getattr(kind, "value", str(kind)),
        "refs": _refs_blob(gist),
        "summary": _summary_blob(getattr(gist, "summary", None)),
        "raw": getattr(gist, "raw", None),
    }


def digest_of(gist: Any) -> str:
    """Return the canonical SHA-256 hex digest of ``gist``'s content."""
    payload = canonical_payload(gist)
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# --------------------------------------------------------------------------
# Signing
# --------------------------------------------------------------------------
@dataclass
class KeyPair:
    """A per-agent signing key.

    ``kind`` is ``"ed25519"`` (asymmetric, real) or ``"hmac"`` (pre-shared
    fallback). ``public_key`` is the bytes a peer needs to verify (for
    ed25519 the raw 32-byte public key; for hmac the 32-byte pre-shared key).
    """

    author_id: str
    kind: str
    _priv: Any
    public_key: bytes

    @classmethod
    def new(cls, author_id: str, kind: str | None = None,
            *, allow_hmac_fallback: bool = False) -> "KeyPair":
        """Create a fresh key. ``kind=None`` picks ed25519 if available.

        En **modo estricto** (``STRICT_MODE=True``, el default), ``kind=None``
        lanza ``RuntimeError`` si no hay ed25519 disponible, en vez de
        degradar silenciosamente a HMAC (pre-shared key). El modo estricto
        hace que un despliegue sin ``cryptography`` *falle claro* en vez de
        firmar con el fallback sin que nadie lo note.

        Para el modo de test/zero-deps, se puede:

        * ``STRICT_MODE = False`` (módulo-level), o
        * ``allow_hmac_fallback=True`` (por llamada) — en cuyo caso se degrada
          a HMAC **con warning** visible (el fallback ya no es silencioso).
        """
        if kind is None:
            if HAVE_ED25519:
                kind = "ed25519"
            elif STRICT_MODE and not allow_hmac_fallback:
                raise RuntimeError(
                    "ed25519 no disponible (falta 'cryptography') y el modo "
                    "estricto está activo: no se degrada silenciosamente a "
                    "HMAC (pre-shared key). Instala 'cryptography' para "
                    "ed25519, o usa allow_hmac_fallback=True / STRICT_MODE=False "
                    "para el modo de test/zero-deps."
                )
            else:
                # Modo no-estricto: fallback a HMAC con warning visible.
                import warnings
                warnings.warn(
                    "Falling back to HMAC (pre-shared key) because "
                    "'cryptography' is not available. This is NOT public "
                    "verification (asymmetric); the shared key is the trust "
                    "anchor. Install 'cryptography' for real ed25519.",
                    RuntimeWarning,
                    stacklevel=2,
                )
                kind = "hmac"
        if kind == "ed25519":
            if not HAVE_ED25519:
                raise RuntimeError("ed25519 requested but 'cryptography' is not installed")
            # `HAVE_ED25519` True implica que el `try` de arriba termino bien y
            # que estas tres quedaron ligadas; el `raise` de la linea anterior
            # es la garantia. Pyright no rastrea esa implication.
            priv = _ed25519.Ed25519PrivateKey.generate()  # type: ignore[possibly-unbound]
            pub = priv.public_key().public_bytes(
                _Encoding.Raw, _PublicFormat.Raw  # type: ignore[possibly-unbound]
            )
            return cls(author_id, "ed25519", priv, pub)
        if kind == "hmac":
            # Pre-shared key: the "public key" IS the shared secret, so both
            # sides hold the same bytes (the trust anchor of the fallback).
            shared = os.urandom(32)
            return cls(author_id, "hmac", shared, shared)
        raise ValueError(f"unknown key kind {kind!r}")

    # -- sign / verify -----------------------------------------------------
    def sign(self, digest: str) -> bytes:
        """Sign the hex ``digest`` (the canonical content digest)."""
        msg = digest.encode("utf-8")
        if self.kind == "ed25519":
            return self._priv.sign(msg)
        return hmac.new(self._priv, msg, hashlib.sha256).digest()

    def verify(self, digest: str, signature: bytes) -> bool:
        return verify_public(self.kind, self.public_key, digest, signature)

    # -- persistence -------------------------------------------------------
    def save(self, path: str) -> str:
        """Persist this key to *path* so the identity survives a restart.

        Needed as soon as an identity has to be *re-attested* later: a mesh node
        that regenerated its key on every invocation would present a new public
        key each time, and nothing downstream could attribute anything to a
        stable peer.

        ed25519 only, and on purpose: an HMAC key's "private" half **is** the
        shared secret, so persisting one would write the trust anchor to disk
        and hand the verifier's own secret to whoever reads the file. Refusing
        here is the honest behaviour; a zero-dep deployment can still run the
        in-memory gists, it just cannot hold a persistent mesh identity.
        """
        if self.kind != "ed25519":
            raise ValueError(
                f"refusing to persist a {self.kind!r} key: its private half is "
                f"the shared secret (the verifier's trust anchor). Install "
                f"'cryptography' for an ed25519 identity."
            )
        priv_bytes = self._priv.private_bytes_raw()
        blob = {
            "author_id": self.author_id,
            "kind": self.kind,
            "private_key": priv_bytes.hex(),
            "public_key": self.public_key.hex(),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(blob, fh, indent=2, sort_keys=True)
            fh.write("\n")
        try:
            os.chmod(path, 0o600)   # best effort: a signing key is a secret
        except OSError:  # pragma: no cover - platform-dependent
            pass
        return path

    @classmethod
    def load(cls, path: str) -> "KeyPair":
        """Load a key written by :meth:`save` (ed25519)."""
        with open(path, encoding="utf-8") as fh:
            blob = json.load(fh)
        if blob.get("kind") != "ed25519":
            raise ValueError(f"unsupported persisted key kind: {blob.get('kind')!r}")
        # Misma garantia que en `KeyPair.new`: sin `cryptography` no se puede
        # haber escrito un blob de kind "ed25519", y sin las clases no habria
        # ni forma de generarlo. Pyright no ve esa dependencia entre archivos.
        priv = _ed25519.Ed25519PrivateKey.from_private_bytes(  # type: ignore[possibly-unbound]
            bytes.fromhex(blob["private_key"]))
        pub = priv.public_key().public_bytes(
            _Encoding.Raw,  # type: ignore[possibly-unbound]
            _PublicFormat.Raw,  # type: ignore[possibly-unbound]
        )
        return cls(str(blob.get("author_id", "")), "ed25519", priv, pub)



def verify_public(kind: str, public_key: bytes, digest: str, signature: bytes) -> bool:
    """Verify ``signature`` over ``digest`` using a peer's ``public_key``.

    ``kind`` must match the scheme the signer used. For ``ed25519`` this is a
    real asymmetric check; for ``hmac`` it requires the pre-shared key to be
    present (the "trust anchor"), which is exactly the limit of the fallback.

    ``ecdsa-secp256k1`` (the BSV anchor identity, :mod:`smcp.core.bsv_keys`)
    is dispatched to that module. A peer that only holds a public key and the
    ``sig_kind`` string can verify an anchor without importing the anchor
    module itself — which is the point: the third party checking a chain
    record must not need this repo's internals.
    """
    if kind == "ecdsa-secp256k1":
        from smcp.core.bsv_keys import verify_public as _v
        return _v(public_key, digest, signature)
    msg = digest.encode("utf-8")
    if kind == "ed25519":
        if not HAVE_ED25519:
            return False
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.exceptions import InvalidSignature
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            pub.verify(signature, msg)
            return True
        except InvalidSignature:
            return False
        except Exception:  # noqa: BLE001 - malformed key/sig
            return False
    if kind == "hmac":
        expected = hmac.new(public_key, msg, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)
    return False
