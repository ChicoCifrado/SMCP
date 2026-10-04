"""Canonical bytes for the ledger — the root every anchor rests on.

The ledger's ``entry_hash`` is what a BSV anchor commits to. If those bytes
are not reproducible by a party that has never seen this repo, the anchor is
a claim instead of evidence.

**What v1 actually got wrong** (measured, not assumed)
----------------------------------------------------
v1 computes ``sha256(json.dumps(to_dict, sort_keys=True, separators=(",",":")))
+ "|" + prev_hash)``. Two demonstrated problems, one of them a coin flip:

1. ``ensure_ascii`` is unspecified. The same entry with ``reason="rechazado"``
   hashes to ``73f89d11...`` with ``ensure_ascii=True`` and ``162fa7a6...``
   with ``ensure_ascii=False``. Python defaults to ``True``; most other
   languages emit raw UTF-8. **A verifier in another language gets a
   different digest about half the time and rejects a valid entry.**
2. ``ts`` is a float. ``json.dumps(1.0)`` is ``"1.0"``; a Go or Rust
   implementation may legitimately write ``"1"``. Same problem, different
   field.

Neither is a *collision* — ``prev_hash`` is a named field inside the JSON,
so the ``"|"`` separator is redundant rather than ambiguous (an earlier
version of this note claimed otherwise; it was wrong). The real defect is
that **there is no specification of which bytes feed the digest**. Every
implementation decides for itself.

**The v2 rule**
--------------
BRC-220 says it directly: the integrity root is a fixed length-prefixed
binary encoding, *never* JSON, "which is not stable across implementations"::

    lp(x)     = u32be(len(x)) || x
    u64be(n)  = 8 bytes, big-endian, unsigned

Every field is length-prefixed, so field boundaries are unambiguous whatever
the content — a ``label`` or ``reason`` containing ``|``, NUL, newlines or
anything else cannot shift a boundary. Floats are committed as IEEE-754
bytes, which have exactly one representation. Integers, strings and bytes
have one representation each.

The domain separator names the format, so a v2 digest can never collide with
a v1 digest even over identical fields — the two chains stay separable and
:func:`canonical_bytes` output is self-describing.

Versioning
----------
v1 keeps hashing exactly as before, byte for byte, so existing ledgers still
verify. v2 is opt-in at construction. :func:`digest_of_entry` dispatches on
the ledger's version, and a reader accepts either from the ``v`` field on
disk. Both paths are fixed by tests.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Any

#: Version of the canonical byte encoding.
CANON_VERSION = 2

#: Domain separator. Part of the hashed bytes, so it is also a guard against
#: a v1 digest ever being read as a v2 one over the same fields.
CANON_DOMAIN = b"SMCP/ledger/2"

#: Tag for each field, in the order they are committed. The tags make the
#: encoding self-describing: a verifier knows what each lp() is for without
#: reading this module's source.
F_SEQ = b"\x01"
F_TS = b"\x02"
F_AUTHOR = b"\x03"
F_LABEL = b"\x04"
F_DIGEST = b"\x05"
F_SIG = b"\x06"
F_SIG_KIND = b"\x07"
F_ACCEPTED = b"\x08"
F_REASON = b"\x09"
F_PREV = b"\x0a"

#: v1 separador, exactamente como era, para que los hashes sigan cuadrando.
V1_SEP = "|"


def lp(x: bytes) -> bytes:
    """Length-prefix: ``u32be(len(x)) || x`` (BRC-220)."""
    return struct.pack(">I", len(x)) + x


def u64be(n: int) -> bytes:
    """Unsigned 64-bit big-endian."""
    return struct.pack(">Q", n)


def u8(n: int) -> bytes:
    """Unsigned 8-bit."""
    return struct.pack(">B", n)


def _f64be(x: float) -> bytes:
    """IEEE-754 double, big-endian. One representation, unlike ``"1.0"``."""
    return struct.pack(">d", x)


def _lp_str(tag: bytes, value: str) -> bytes:
    """UTF-8 bytes of ``value``, length-prefixed, after its tag.

    UTF-8 and not escaped JSON: the bytes are the canonical form, so a
    verifier in any language reproduces them without deciding an escaping
    policy. A string with NUL, newlines or ``|`` inside cannot shift a
    boundary, which is the entire point of the length prefix.
    """
    return tag + lp(value.encode("utf-8"))


def _check_hex(name: str, value: str, nbytes: int | None = None) -> str:
    """Reject anything that is not canonical lower-case hex.

    ``digest``, ``sig`` and ``prev_hash`` are encoded as bytes, not as the
    text they happen to be. A verifier that received ``"AB"`` and ``"ab"``
    would otherwise have to guess whether they are the same bytes; making
    the encoder refuse anything but lower-case removes the guess. The round
    trip is lossless because the bytes come back from :func:`decode_and_verify`
    re-encoded lower-case.
    """
    if len(value) % 2 != 0:
        raise ValueError(f"{name}: hex de longitud impar ({len(value)})")
    if nbytes is not None and len(value) != nbytes * 2:
        raise ValueError(
            f"{name}: se esperaban {nbytes} bytes, hay {len(value) // 2}")
    if any(c not in "0123456789abcdef" for c in value):
        # Reject, do not normalise. Lower-casing here would quietly change the
        # bytes being committed to, which is the one thing a canonical form
        # must never do: the caller would get a digest for input it did not
        # supply.
        raise ValueError(
            f"{name}: hex no canónico (solo minúsculas, 0-9a-f)")
    return value


def _check_text(name: str, value: str, limit: int) -> str:
    if len(value) > limit:
        raise ValueError(
            f"{name}: {len(value)} caracteres, el máximo es {limit}")
    return value


def canonical_bytes(to_dict: dict[str, Any]) -> bytes:
    """The v2 pre-image of a ledger entry.

    ``prev_hash`` is included **once**, tagged. v1 included it twice (inside
    the JSON *and* appended after the ``"|"``), which was harmless but
    redundant; v2 commits to it exactly once.

    Every field is validated and every *unexpected* field is rejected. That
    strictness is not pedantry: if ``kind`` were silently ignored, an
    admission and an observation would prehash identically and a batch could
    be relabelled without invalidating its digest. A canonical form that
    tolerates unknown fields is not canonical.
    """
    expected = {"seq", "ts", "author", "label", "digest", "sig", "sig_kind",
                "accepted", "reason", "prev_hash"}
    got = set(to_dict)
    if got != expected:
        extra, missing = got - expected, expected - got
        raise ValueError(
            f"campos no canónicos: sobran {sorted(extra)}, "
            f"faltan {sorted(missing)}")

    accepted = to_dict["accepted"]
    if not isinstance(accepted, bool):
        # 0/1 would encode to the same byte; accepting it would let two
        # different Python objects claim one digest.
        raise ValueError("accepted debe ser bool")

    out = [CANON_DOMAIN]
    out.append(u8(CANON_VERSION))
    out.append(u64be(int(to_dict["seq"])))
    out.append(_f64be(float(to_dict["ts"])))
    out.append(_lp_str(F_AUTHOR, _check_text("author", str(to_dict["author"]), 256)))
    out.append(_lp_str(F_LABEL, _check_text("label", str(to_dict["label"]), 512)))
    out.append(_lp_str(F_DIGEST, _check_hex("digest", str(to_dict["digest"]), 32)))
    out.append(_lp_str(F_SIG, _check_hex("sig", str(to_dict["sig"]))))
    out.append(_lp_str(F_SIG_KIND, _check_text("sig_kind", str(to_dict["sig_kind"]), 64)))
    out.append(F_ACCEPTED)
    out.append(u8(1 if accepted else 0))
    out.append(_lp_str(F_REASON, _check_text("reason", str(to_dict["reason"]), 1024)))
    out.append(_lp_str(F_PREV, _check_hex("prev_hash", str(to_dict["prev_hash"]), 32)))
    return b"".join(out)


def digest_of(to_dict: dict[str, Any]) -> str:
    """The v2 ``entry_hash``: ``sha256(canonical_bytes(to_dict))``."""
    return hashlib.sha256(canonical_bytes(to_dict)).hexdigest()


def v1_digest(to_dict: dict[str, Any]) -> str:
    """The v1 hash, byte for byte as it was computed before.

    Kept because existing ledgers on disk carry these values: recomputing them
    the "clean" way would change every hash and invalidate the audit trail.
    That is the whole reason v1 and v2 coexist.
    """
    import json
    blob = json.dumps(to_dict, sort_keys=True, separators=(",", ":"))
    # v1 operaba sobre str: blob y prev_hash son texto y el separador es "|".
    # Se concatenan como texto y solo después se codifica, que es lo que hace
    # que esta función no pueda reutilizarse tal cual para v2.
    text = blob + V1_SEP + to_dict["prev_hash"]
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_for_version(to_dict: dict[str, Any], version: int) -> str:
    """Dispatch: the digest of ``to_dict`` under ledger format ``version``."""
    if version == 1:
        return v1_digest(to_dict)
    if version == 2:
        return digest_of(to_dict)
    raise ValueError(
        f"formato de ledger {version} no implementado (solo 1 y 2): un "
        "digest desconocido no se puede verificar, y asumir el mas nuevo "
        "aceptaria una cadena con otro formato sin avisar.")


def decode_and_verify(raw: bytes, declared_hash: str) -> dict[str, Any]:
    """Parse and check one canonical pre-image (BRC-220 style, for anchors).

    Not needed to *produce* an anchor — the ledger writes canonical bytes and
    hashes them. It exists because the other direction matters: a peer that
    receives a ``proofHash`` over the wire has to be able to check it landed
    on the chain intact, and to read which fields it commits to. Returns the
    field map, raises on any mismatch.

    Refuses a wrong length or a trailing byte rather than ignoring it: bytes
    after the last field are exactly what an attacker appends to make two
    different pre-images hash the same under a lax parser.
    """
    if len(raw) < len(CANON_DOMAIN) + 1:
        raise ValueError("pre-imagen demasiado corta")
    if raw[:len(CANON_DOMAIN)] != CANON_DOMAIN:
        raise ValueError(
            f"separador de dominio incorrecto: {raw[:len(CANON_DOMAIN)]!r} "
            f"!= {CANON_DOMAIN!r}")
    off = len(CANON_DOMAIN)
    version = raw[off]
    if version != CANON_VERSION:
        raise ValueError(f"versión {version} != {CANON_VERSION}")
    off += 1

    def take(n: int) -> bytes:
        nonlocal off
        if off + n > len(raw):
            raise ValueError("pre-imagen truncada")
        chunk = raw[off:off + n]
        off += n
        return chunk

    def take_lp() -> bytes:
        n = struct.unpack(">I", take(4))[0]
        return take(n)

    fields: dict[str, Any] = {}
    fields["seq"] = struct.unpack(">Q", take(8))[0]
    fields["ts"] = struct.unpack(">d", take(8))[0]
    for tag, name in ((F_AUTHOR, "author"), (F_LABEL, "label"),
                      (F_DIGEST, "digest"), (F_SIG, "sig"),
                      (F_SIG_KIND, "sig_kind")):
        if take(1) != tag:
            raise ValueError(f"tag inesperado esperando {name}")
        fields[name] = take_lp().decode("utf-8")
    if take(1) != F_ACCEPTED:
        raise ValueError("tag inesperado esperando accepted")
    fields["accepted"] = take(1)[0] == 1
    if take(1) != F_REASON:
        raise ValueError("tag inesperado esperando reason")
    fields["reason"] = take_lp().decode("utf-8")
    if take(1) != F_PREV:
        raise ValueError("tag inesperado esperando prev_hash")
    fields["prev_hash"] = take_lp().decode("utf-8")

    if off != len(raw):
        raise ValueError(
            f"{len(raw) - off} bytes de sobra al final: bytes despues del "
            "ultimo campo son justo lo que un atacante anade para colar dos "
            "pre-imagenes distintas con el mismo hash")
    if hashlib.sha256(raw).hexdigest() != declared_hash:
        raise ValueError("el digest no corresponde a estos bytes")
    return fields


__all__ = [
    "CANON_VERSION", "CANON_DOMAIN", "lp", "u64be", "u8",
    "canonical_bytes", "digest_of", "v1_digest", "digest_for_version",
    "decode_and_verify",
]
