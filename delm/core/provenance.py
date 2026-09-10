"""Provenance — canonical digests and signatures for admitted gists.

This is the cryptographic core of the DELM security layer (Capas 1+2):

* **Canonical digest** — a stable SHA-256 over the *content* of a
  :class:`~delm.core.gist.Gist`, independent of dict ordering or the
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
            priv = _ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key().public_bytes(
                _Encoding.Raw, _PublicFormat.Raw
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


def verify_public(kind: str, public_key: bytes, digest: str, signature: bytes) -> bool:
    """Verify ``signature`` over ``digest`` using a peer's ``public_key``.

    ``kind`` must match the scheme the signer used. For ``ed25519`` this is a
    real asymmetric check; for ``hmac`` it requires the pre-shared key to be
    present (the "trust anchor"), which is exactly the limit of the fallback.
    """
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
