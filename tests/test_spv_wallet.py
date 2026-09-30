"""La wallet SPV: identidad del nodo con maestro, derivación y dirección.

Tres cosas que un test de "firma bien" no encuentra, y que_costaron dos bugs
reales al implementar BRC-42:

1. **La asimetría emisor/receptor.** La spec define dos pasos distintos y no
   intercambiables. Sumar escalares en el emisor da una clave distinta, y las
   dos partes nunca coinciden — sin error, sin excepción: dos claves
   distintas que parecen correctas.
2. **El primo del campo ≠ el orden del grupo.** Con ``pow(..., n-2, n)`` en
   las inversas de la suma de puntos, el resultado no cae en la curva y
   ``cryptography`` responde "Point is not on the curve specified", que no
   señala la causa.
3. **El mnemonic es el backup.** Si ``create()`` aceptara una frase inválida
   sin decir nada, el operador respaldaría algo que no recupera nada.
"""
from __future__ import annotations

import hashlib
import os

import pytest

from delm.core.bsv_keys import HAVE_ECDSA, verify_public
from delm.core.spv import (
    SECURITY_LEVELS,
    SpvWallet,
    address_matches_public_key,
    address_to_hash160,
    b58decode,
    b58encode,
    derive_child_public,
    derive_private_shared,
    format_key_id,
    generate_mnemonic,
    hash160,
    mnemonic_is_valid,
    mnemonic_to_private,
    parse_key_id,
    pubkey_to_address,
)

pytestmark = pytest.mark.skipif(
    not HAVE_ECDSA, reason="requiere 'cryptography' para secp256k1")

#: Frase de entropía cero del vector de prueba de BIP39.
ZERO_MNEMONIC = ("abandon " * 11) + "about"


def _priv(w: SpvWallet) -> bytes:
    return w.master._priv.private_numbers().private_value.to_bytes(32, "big")


# ============================================================ mnemonic (BRC-75)
def test_entropy_zero_matches_the_bip39_vector():
    """Si la palabra/entropía->índice->palabra está mal, el mnemonic no es
    un mnemonic: parece uno y no lo es. El vector es la única referencia."""
    from delm.core._bip39_words import BIP39_WORDS
    assert len(BIP39_WORDS) == 2048
    ent = b"\x00" * 16
    bits = "".join(f"{b:08b}" for b in ent) + \
        "".join(f"{b:08b}" for b in hashlib.sha256(ent).digest())[:128 // 32]
    phrase = " ".join(BIP39_WORDS[int(bits[i:i + 11], 2)]
                      for i in range(0, len(bits), 11))
    assert phrase == ZERO_MNEMONIC
    assert mnemonic_is_valid(phrase) is True


def test_generated_mnemonic_is_valid_and_the_right_length():
    """Los tamaños válidos son los que hacen ``ENT + ENT/32`` múltiplo de 11:
    12, 15, 18, 21 y 24 palabras. Más allá de 24 palabras ninguna wallet
    BIP39 lo reconoce, así que el generador lo rechaza en vez de producir
    una frase que parecería un backup y no lo sería."""
    for n_bytes, n_words in ((16, 12), (20, 15), (24, 18), (28, 21), (32, 24)):
        m = generate_mnemonic(n_bytes)
        assert len(m.split()) == n_words, f"{n_bytes} bytes -> {n_words} palabras"
        assert mnemonic_is_valid(m) is True
    with pytest.raises(ValueError, match="entropía BIP39"):
        generate_mnemonic(12)
    with pytest.raises(ValueError, match="entropía BIP39"):
        generate_mnemonic(33)


def test_an_invalid_mnemonic_is_refused_with_an_explanation():
    """El fallo más caro de una wallet es un backup que no recupera nada."""
    with pytest.raises(ValueError, match="mnemonic inválido"):
        SpvWallet.create(mnemonic="abandon " * 12)          # checksum mal
    with pytest.raises(ValueError, match="mnemonic inválido"):
        SpvWallet.create(mnemonic="esta frase no existe")   # palabras inventadas
    with pytest.raises(ValueError, match="mnemonic inválido"):
        SpvWallet.create(mnemonic="abandon about")          # longitud


def test_the_same_mnemonic_is_always_the_same_node():
    """La identidad sobrevive al reinicio — lo que una clave suelta no hacía."""
    a = SpvWallet.create(mnemonic=ZERO_MNEMONIC, author_id="n1")
    b = SpvWallet.create(mnemonic=ZERO_MNEMONIC, author_id="n1")
    assert a.master_address() == b.master_address()
    assert a.master.public_key == b.master.public_key
    # y distinta de otra wallet
    assert SpvWallet.create().master_address() != a.master_address()


# ================================================================= keyId (BRC-43)
def test_key_id_roundtrip():
    for level in SECURITY_LEVELS:
        kid = format_key_id(level, "smcp", "anchor")
        assert parse_key_id(kid) == (level, "smcp", "anchor")


def test_key_id_is_validated():
    with pytest.raises(ValueError, match="fuera de"):
        format_key_id(3, "smcp", "x")
    with pytest.raises(ValueError, match="guiones"):
        format_key_id(0, "sm-cp", "x")
    with pytest.raises(ValueError, match="se esperaba"):
        parse_key_id("0-smcp")


def test_a_different_protocol_is_a_different_key_universe():
    """El formato *es* la frontera: dos protocolos no comparten derivadas."""
    w = SpvWallet.create(mnemonic=ZERO_MNEMONIC)
    with pytest.raises(ValueError, match="universos de claves distintos"):
        w.derive(format_key_id(0, "otro", "anchor"))


# ============================================================== derivación (BRC-42)
def test_both_sides_derive_the_same_child():
    """La propiedad que define BRC-42, y la que mi primera versión rompía.

    El **receptor** suma escalares; el **emisor** suma puntos
    (``G*scalar + other_pub``). Con la misma fórmula en los dos lados, cada
    uno llega a una clave válida y distinta, y nada falla: dos identidades
    que no se reconocen sin que ningún error lo delate.
    """
    a, b = SpvWallet.create(), SpvWallet.create()
    invoice = format_key_id(0, "smcp", "compartida")

    pub_from_emisor = derive_child_public(_priv(a), b.master.public_key, invoice)
    _priv_receptor, pub_from_receptor = derive_private_shared(
        _priv(b), a.master.public_key, invoice)

    assert pub_from_emisor == pub_from_receptor, (
        "el emisor y el receptor deben derivar la MISMA clave; si no, la "
        "derivación no es BRC-42 y el intercambio entre dos pares no funciona")


def test_the_same_invoice_for_a_different_counterparty_gives_a_different_key():
    """Lo que BIP32 no puede: con un chain code, el índice basta para derivar
    y ver *todas* las hijas. Con ECDH, cada contraparte vive en su universo."""
    a = SpvWallet.create()
    b, c = SpvWallet.create(), SpvWallet.create()
    invoice = format_key_id(0, "smcp", "x")
    ab = derive_child_public(_priv(a), b.master.public_key, invoice)
    ac = derive_child_public(_priv(a), c.master.public_key, invoice)
    assert ab != ac


def test_derived_point_is_on_the_curve():
    """Los inversos de la suma de puntos usan el primo del *campo*, no el
    orden del grupo. Con el orden, el punto sale de la curva y
    ``cryptography`` dice "Point is not on the curve specified"."""
    w = SpvWallet.create()
    kid = w.derive_for("anchor")
    # cryptography reconstruye la clave: si el punto no estuviera en la
    # curva, from_private_bytes ya habria lanzado.
    x = int.from_bytes(kid.public_key[1:], "big")
    assert 1 <= x < _N_OF_CURVE()
    # y la pubkey compressed tiene forma 02/03 + 32 bytes
    assert len(kid.public_key) == 33
    assert kid.public_key[0] in (0x02, 0x03)


def _N_OF_CURVE() -> int:
    from delm.core.spv import _N
    return _N


# ================================================================== derivación local
def test_purposes_are_separate_keys_of_the_same_master():
    """Comprometer la clave de firma de un ancla no compromete la identidad
    ni revela la clave de admisiones: son hijas distintas del mismo maestro."""
    w = SpvWallet.create(mnemonic=ZERO_MNEMONIC)
    anchor = w.derive_for("anchor")
    admission = w.derive_for("admission")
    assert anchor.public_key != admission.public_key
    # ...pero ambas salen del mismo maestro, así que la identidad es una
    assert w.derive_for("anchor").public_key == anchor.public_key
    assert len({w.derive_for(p).public_key
                for p in ("anchor", "admission", "pago")}) == 3


def test_security_level_changes_the_universe():
    w = SpvWallet.create(mnemonic=ZERO_MNEMONIC)
    assert (w.derive(format_key_id(0, "smcp", "a")).public_key !=
            w.derive(format_key_id(2, "smcp", "a")).public_key)


# ==================================================================== dirección
def test_address_is_derived_deterministically_from_the_public_key():
    """La atribución verificable por terceros: extraen la pubkey, derivan la
    dirección y comparan. Sin consultar a nadie."""
    w = SpvWallet.create(mnemonic=ZERO_MNEMONIC)
    pub = w.derive_for("anchor").public_key
    addr = pubkey_to_address(pub)
    assert addr == pubkey_to_address(pub)          # determinista
    assert addr.startswith("1")                    # mainnet P2PKH
    assert address_to_hash160(addr) == hash160(pub)
    assert address_matches_public_key(addr, pub) is True


def test_a_valid_signature_from_the_wrong_key_is_not_attribution():
    """El caso que un "la firma verifica" no pilla: la firma es válida y la
    dirección no sale de esa clave."""
    a, b = SpvWallet.create(), SpvWallet.create()
    d = hashlib.sha256(b"ancla").hexdigest()
    kid, pub_hex, sig = a.sign_for("anchor", d)
    assert verify_public(bytes.fromhex(pub_hex), d, sig) is True
    # pero la dirección de B no corresponde a la clave que firmó
    assert address_matches_public_key(b.address_for("anchor"),
                                      bytes.fromhex(pub_hex)) is False
    assert parse_key_id(kid) == (0, "smcp", "anchor")


def test_base58_roundtrip_and_leading_zeros():
    """Los ceros iniciales se codifican como '1' cada uno: sin eso,
    hash160 y el resto de la carga se perderían al decodificar."""
    assert b58decode(b58encode(b"\x00\x00\x01\x02")) == b"\x00\x00\x01\x02"
    assert b58encode(b"\x00\x00\x01") == "112"
    assert b58encode(b"\x00") == "1"
    with pytest.raises(ValueError, match="base58"):
        b58decode("0OIl")     # fuera del alfabeto Bitcoin


def test_a_corrupted_address_is_rejected_not_guessed():
    w = SpvWallet.create()
    addr = w.address_for("anchor")
    bad = addr[:-1] + ("X" if addr[-1] != "X" else "Y")
    assert address_matches_public_key(bad, w.derive_for("anchor").public_key) is False


# ==================================================================== persistencia
def test_save_load_keeps_the_identity(tmp_path):
    """Un maestro del que no se puede hacer backup es un maestro que se
    pierde: la identidad del nodo no debería depender del disco."""
    p = str(tmp_path / "wallet.json")
    w = SpvWallet.create(author_id="nodo-1")
    w.save(p)

    back = SpvWallet.load(p)
    assert back.master_address() == w.master_address()
    assert back.master.author_id == "nodo-1"
    # y la clave derivada sigue siendo la misma
    assert back.derive_for("anchor").public_key == w.derive_for("anchor").public_key
    assert oct(os.stat(p).st_mode)[-3:] == "600"


def test_the_mnemonic_is_not_in_the_repr():
    """El mnemonic es un secreto: no debe colarse en un log ni en un traceback."""
    w = SpvWallet.create()
    assert w.mnemonic not in repr(w)
    assert "mnemonic=" not in repr(w)
