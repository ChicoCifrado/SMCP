"""Tests de BIP340 (Schnorr secp256k1, x-only) — verificación contra vectores oficiales.

El esquema de firma de Nostr es **BIP340**. ``delm.core.nostr`` lo implementa
fiel a la referencia oficial (``bitcoin/bips`` ``bip-0340/reference.py``) y se
**verifica contra los vectores oficiales** (``bip-0340/test-vectors.csv``), que
viven en ``tests/data/bip340_vectors.csv``.

Estos tests son la *prueba de honestidad*: si la implementación se desvía de
la referencia (un bug en la aritmética de punto, en ``lift_x``, en el
``tagged_hash`` o en la firma), alguno de los 19 vectores falla.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path

import pytest

from delm.core.nostr import (
    pubkey_gen,
    schnorr_sign,
    schnorr_verify,
)

_VECTORS_CSV = Path(__file__).parent / "data" / "bip340_vectors.csv"


def _rows() -> list[list[str]]:
    """Carga los 19 vectores oficiales (índices 0-18)."""
    assert _VECTORS_CSV.exists(), f"faltan los vectores: {_VECTORS_CSV}"
    with open(_VECTORS_CSV, newline="") as f:
        reader = csv.reader(f)
        next(reader)  # header
        return [row for row in reader if row]


# -- Verificación contra todos los vectores ------------------------------------
def test_all_vectors_verify():
    """``schnorr_verify`` reproduce el ``verification result`` de cada vector.

    Los 19 vectores cubren: firmas válidas (TRUE) y casos que deben rechazar
    (FALSE) — clave no en la curva, ``has_even_y(R)`` falso, mensaje negado,
    ``s`` negado, ``sG - eP`` infinito, ``sig[0:32]`` no en la curva, ``sig``
    fuera de rango, pubkey fuera de rango, mensaje de tamaño 0/1/17/100.
    """
    rows = _rows()
    assert len(rows) == 19, f"se esperaban 19 vectores, hay {len(rows)}"
    for (idx, _seckey, pubkey_hex, _aux, msg_hex, sig_hex, result, _comment) in rows:
        msg = bytes.fromhex(msg_hex)
        sig = bytes.fromhex(sig_hex)
        expected = result == "TRUE"
        got = schnorr_verify(msg, bytes.fromhex(pubkey_hex), sig)
        assert got == expected, (
            f"vector {idx}: schnorr_verify={got}, esperado {expected} "
            f"({_comment})"
        )


# -- Generación de pubkey contra los vectores ---------------------------------
def test_all_vectors_pubkey_gen():
    """``pubkey_gen`` reproduce la ``public key`` de cada vector con seckey.

    Solo los vectores con ``secret key`` (0-3 y 15-18) tienen seckey; los de
    solo verificación (4-14) no.
    """
    rows = _rows()
    checked = 0
    for (idx, seckey_hex, pubkey_hex, _aux, _msg, _sig, _result, _comment) in rows:
        if not seckey_hex:
            continue
        got = pubkey_gen(bytes.fromhex(seckey_hex))
        expected = bytes.fromhex(pubkey_hex)
        assert got == expected, f"vector {idx}: pubkey_gen no coincide"
        checked += 1
    # 8 vectores con seckey (0,1,2,3 y 15,16,17,18).
    assert checked == 8, f"se verificaban 8 pubkey_gen, hay {checked}"


# -- Firma determinista contra los vectores -----------------------------------
def test_all_vectors_sign():
    """``schnorr_sign`` reproduce la ``signature`` exacta de cada vector.

    BIP340 es *determinista* (el nonce es una función de la clave, el mensaje
    y el ``aux_rand``), así que la firma debe ser *byte a byte* la del vector.
    Esto es el chequeo más fuerte: si la firma no coincide, la aritmética o
    el ``tagged_hash`` están mal.
    """
    rows = _rows()
    checked = 0
    for (idx, seckey_hex, _pub, aux_hex, msg_hex, sig_hex, _result, _comment) in rows:
        if not seckey_hex:
            continue
        sig = schnorr_sign(
            bytes.fromhex(msg_hex),
            bytes.fromhex(seckey_hex),
            bytes.fromhex(aux_hex),
        )
        expected = bytes.fromhex(sig_hex)
        assert sig == expected, (
            f"vector {idx}: schnorr_sign no coincide "
            f"({_comment})"
        )
        checked += 1
    assert checked == 8


# -- Round-trip (firma -> verificación) ---------------------------------------
def test_sign_verify_roundtrip():
    """Una firma BIP340 verifica contra su pubkey (y el mensaje original)."""
    seckey = bytes.fromhex(
        "0340034003400340034003400340034003400340034003400340034003400340"
    )
    aux = bytes.fromhex("00" * 32)
    msg = b"delm nostr round-trip"
    sig = schnorr_sign(msg, seckey, aux)
    pubkey = pubkey_gen(seckey)
    assert len(sig) == 64
    assert len(pubkey) == 32
    assert schnorr_verify(msg, pubkey, sig)


def test_verify_rejects_wrong_message():
    """La misma firma + pubkey *no* verifica con un mensaje distinto."""
    seckey = bytes.fromhex(
        "0340034003400340034003400340034003400340034003400340034003400340"
    )
    sig = schnorr_sign(b"uno", seckey, bytes.fromhex("00" * 32))
    pubkey = pubkey_gen(seckey)
    assert not schnorr_verify(b"dos", pubkey, sig)


def test_verify_rejects_wrong_key():
    """La firma *no* verifica contra un pubkey distinto."""
    seckey_a = bytes.fromhex(
        "0340034003400340034003400340034003400340034003400340034003400340"
    )
    seckey_b = bytes.fromhex(
        "0340034003400340034003400340034003400340034003400340034003400341"
    )
    sig = schnorr_sign(b"msg", seckey_a, bytes.fromhex("00" * 32))
    pubkey_b = pubkey_gen(seckey_b)
    assert not schnorr_verify(b"msg", pubkey_b, sig)


# -- Guardas de rango / longitud --------------------------------------------
def test_verify_rejects_short_pubkey():
    assert not schnorr_verify(b"m", b"short", b"x" * 64)


def test_verify_rejects_short_sig():
    assert not schnorr_verify(b"m", b"0" * 32, b"x" * 60)


def test_sign_rejects_short_aux_rand():
    with pytest.raises(ValueError):
        schnorr_sign(b"m", bytes.fromhex("03" * 32), b"short")


def test_sign_rejects_zero_seckey():
    with pytest.raises(ValueError):
        schnorr_sign(b"m", b"\x00" * 32, b"\x00" * 32)


def test_pubkey_gen_rejects_zero_seckey():
    with pytest.raises(ValueError):
        pubkey_gen(b"\x00" * 32)
