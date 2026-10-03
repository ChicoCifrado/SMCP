"""test_txbuild: el serializador, contra los vectores de Bitcoin Core.

Los vectores de ``sighash.json`` (Bitcoin Core v22.0) son la
prueba de que la serialización y el preimage del sighash son
los de la red, y no los de una implementación que se valida
a sí misma: seis casos con scripts vacíos y no vacíos, índices
en medio de la lista de inputs, y hashTypes positivos y
negativos (el bit alto de un hashType negativo es
SIGHASH_ANYONECANPAY, así que ambos caminos del preimage
quedan cubiertos).
"""
from __future__ import annotations

import hashlib

import pytest

from delm.core.bsv_keys import (
    HAVE_ECDSA,
    Secp256k1KeyPair,
    verify_public,
)
from delm.core.spv import hash160
from delm.core.txbuild import (
    SIGHASH_ALL,
    Transaction,
    TxIn,
    TxOut,
    der_encode,
    p2pkh_lock,
    push_data,
    varint,
)

# (tx_hex, script_hex, input_index, hash_type, expected_sighash_hex)
SIGHASH_VECTORS = [
    (
        "907c2bc503ade11cc3b04eb2918b6f547b0630ab569273824748c87ea14b0696"
        "526c66ba740200000004ab65ababfd1f9bdd4ef073c7afc4ae00da8a66f429c9"
        "17a0081ad1e1dabce28d373eab81d8628de802000000096aab5253ab52000052"
        "ad042b5f25efb33beec9f3364e8a9139e8439d9d7e26529c3c30b6c3fd89f868"
        "4cfd68ea0200000009ab53526500636a52ab599ac2fe02a526ed040000000008"
        "535300516352515164370e010000000003006300ab2ec229",
        '',
        2,
        1864164639,
        "31af167a6cf3f9d5f6875caa4d31704ceb0eba078d132b78dab52c3b8997317e",
    ),
    (
        "a0aa3126041621a6dea5b800141aa696daf28408959dfb2df96095db9fa425ad"
        "3f427f2f6103000000015360290e9c6063fa26912c2e7fb6a0ad80f1c5fea177"
        "1d42f12976092e7a85a4229fdb6e890000000001abc109f6e47688ac0e468298"
        "8785744602b8c87228fcef0695085edf19088af1a9db126e9300000000066551"
        "6aac536affffffff8fe53e0806e12dfd05d67ac68f4768fdbe23fc48ace22a5a"
        "a8ba04c96d58e2750300000009ac51abac63ab5153650524aa680455ce7b0000"
        "00000000499e50030000000008636a00ac526563ac5051ee030000000003abac"
        "abd2b6fe000000000003516563910fb6b5",
        '65',
        0,
        -1391424484,
        "48d6a1bd2cd9eec54eb866fc71209418a950402b5d7e52363bfb75c98e141175",
    ),
    (
        "6e7e9d4b04ce17afa1e8546b627bb8d89a6a7fefd9d892ec8a192d79c2ceafc0"
        "1694a6a7e7030000000953ac6a51006353636a33bced1544f797f08ceed02f10"
        "8da22cd24c9e7809a446c61eb3895914508ac91f07053a01000000055163ab51"
        "6affffffff11dc54eee8f9e4ff0bcf6b1a1a35b1cd10d63389571375501af744"
        "4073bcec3c02000000046aab53514a821f0ce3956e235f71e4c69d91abe1e93f"
        "b703bd33039ac567249ed339bf0ba0883ef300000000090063ab65000065ac65"
        "4bec3cc504bcf499020000000005ab6a52abac64eb060100000000076a6a5351"
        "650053bbbc130100000000056a6aab53abd6e1380100000000026a51c4e509b8",
        'acab655151',
        0,
        479279909,
        "2a3d95b09237b72034b23f2d2bb29fa32a58ab5c6aa72f6aafdfa178ab1dd01c",
    ),
    (
        "73107cbd025c22ebc8c3e0a47b2a760739216a528de8d4dab5d45cbeb3051ceb"
        "ae73b01ca10200000007ab6353656a636affffffffe26816dffc670841e6a6c8"
        "c61c586da401df1261a330a6c6b3dd9f9a0789bc9e000000000800ac6552ac6a"
        "ac51ffffffff0174a8f0010000000004ac52515100000000",
        '5163ac63635151ac',
        1,
        1190874345,
        "06e328de263a87b09beabe222a21627a6ea5c7f560030da31610c4611f4a46bc",
    ),
    (
        "e93bbf6902be872933cb987fc26ba0f914fcfc2f6ce555258554dd9939d12032"
        "a8536c8802030000000453ac5353eabb6451e074e6fef9de211347d6a45900ea"
        "5aaf2636ef7967f565dce66fa451805c5cd10000000003525253ffffffff047d"
        "c3e6020000000007516565ac656aabec9eea010000000001633e46e600000000"
        "000015080a030000000001ab00000000",
        '5300ac6a53ab6a',
        1,
        -886562767,
        "f03aa4fc5f97e826323d0daa03343ebf8a34ed67a1ce18631f8b88e5c992e798",
    ),
    (
        "50818f4c01b464538b1e7e7f5ae4ed96ad23c68c830e78da9a845bc19b5c3b0b"
        "20bb82e5e9030000000763526a63655352ffffffff023b3f9c04000000000863"
        "0051516a6a5163a83caf01000000000553ab65510000000000",
        '6aac',
        0,
        946795545,
        "746306f322de2b4b58ffe7faae83f6a72433c22f88062cdde881d4dd8a5a4e2d",
    ),
]


def test_varint_boundaries() -> None:
    assert varint(0) == b"\x00"
    assert varint(0xFC) == b"\xfc"
    assert varint(0xFD) == b"\xfd\xfd\x00"
    assert varint(0xFFFF) == b"\xfd\xff\xff"
    assert varint(0x1_0000) == b"\xfe\x00\x00\x01\x00"
    assert varint(0xFFFFFFFF) == b"\xfe\xff\xff\xff\xff"
    assert varint(0x1_0000_0000) == (
        b"\xff\x00\x00\x00\x00\x01\x00\x00\x00"
    )
    with pytest.raises(ValueError):
        varint(-1)


def test_push_data_framing() -> None:
    assert push_data(b"") == b"\x00"
    assert push_data(b"x" * 75) == b"\x4b" + b"x" * 75
    assert push_data(b"x" * 76) == b"\x4c\x4c" + b"x" * 76
    assert push_data(b"x" * 255) == b"\x4c\xff" + b"x" * 255
    assert push_data(b"x" * 256) == b"\x4d\x00\x01" + b"x" * 256


def test_p2pkh_lock_is_the_canonical_script() -> None:
    h160 = bytes(range(20))
    assert p2pkh_lock(h160) == (
        bytes([0x76, 0xA9, 0x14]) + h160 + bytes([0x88, 0xAC])
    )
    with pytest.raises(ValueError):
        p2pkh_lock(b"corto")


@pytest.mark.parametrize(
    "tx_hex,script_hex,index,hash_type,expected",
    SIGHASH_VECTORS,
)
def test_sighash_against_core_vectors(
    tx_hex: str, script_hex: str, index: int,
    hash_type: int, expected: str,
) -> None:
    """El preimage del sighash, contra la referencia de la red."""
    tx = Transaction.parse(bytes.fromhex(tx_hex))
    assert tx.sighash_hex(
        index, bytes.fromhex(script_hex), hash_type
    ) == expected


def test_sighash_ignores_other_inputs_scriptsigs() -> None:
    """Firmar el input 0 no depende del scriptSig del input 1."""
    requester = Secp256k1KeyPair.new("A")
    script_code = p2pkh_lock(hash160(requester.public_key))
    clean = Transaction(
        inputs=[TxIn("ab" * 32, 0), TxIn("cd" * 32, 1)],
        outputs=[TxOut(99, script_code)],
    )
    dirty = Transaction(
        inputs=[
            TxIn("ab" * 32, 0, script_sig=b"basura"),
            TxIn("cd" * 32, 1, script_sig=b"mas basura"),
        ],
        outputs=[TxOut(99, script_code)],
    )
    assert dirty.sighash(0, script_code) == clean.sighash(
        0, script_code
    )


def test_sighash_changes_with_the_signed_script() -> None:
    """El scriptCode del input firmado SÍ cambia el sighash."""
    alice = Secp256k1KeyPair.new("alice")
    bob = Secp256k1KeyPair.new("bob")
    tx = Transaction(
        inputs=[TxIn("ab" * 32, 0)],
        outputs=[TxOut(99, p2pkh_lock(hash160(bob.public_key)))],
    )
    alice_code = p2pkh_lock(hash160(alice.public_key))
    bob_code = p2pkh_lock(hash160(bob.public_key))
    assert tx.sighash(0, alice_code) != tx.sighash(0, bob_code)


def test_serialize_parse_round_trip() -> None:
    tx = Transaction(
        version=2,
        inputs=[
            TxIn("ab" * 32, 7, script_sig=b"\x01\x02",
                 sequence=0xFFFFFFFE),
        ],
        outputs=[TxOut(100, b"\xac"), TxOut(0, b"")],
        locktime=12345,
    )
    raw = tx.serialize()
    parsed = Transaction.parse(raw)
    assert parsed == tx
    assert parsed.serialize() == raw
    with pytest.raises(ValueError):
        Transaction.parse(raw + b"\x00")


def test_txid_is_the_reversed_double_sha256() -> None:
    tx = Transaction(inputs=[TxIn("00" * 32, 0)],
                     outputs=[TxOut(0, b"")])
    wire = tx.serialize()
    want = hashlib.sha256(
        hashlib.sha256(wire).digest()
    ).digest()[::-1].hex()
    assert tx.txid() == want


def test_der_encode_known_values() -> None:
    one = (1).to_bytes(32, "big")
    assert der_encode(one + one) == bytes.fromhex("3006020101020101")
    # r con el bit alto encendido lleva un cero adelante
    # (enteros con signo en DER).
    high = bytes([0xFF]) + bytes(31)
    der = der_encode(high + one)
    assert der[:4] == b"\x30\x26\x02\x21"
    assert der[4] == 0x00


@pytest.mark.skipif(
    not HAVE_ECDSA, reason="requiere 'cryptography' para secp256k1"
)
def test_sign_input_round_trip() -> None:
    """Firmar produce un scriptSig que gasta el P2PKH del firmante."""
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
    )

    alice = Secp256k1KeyPair.new("alice")
    script_code = p2pkh_lock(hash160(alice.public_key))
    tx = Transaction(
        inputs=[TxIn("ab" * 32, 0)],
        outputs=[TxOut(99, script_code)],
    )
    tx.sign_input(0, alice, script_code)
    script_sig = tx.inputs[0].script_sig
    # <push <DER + byte sighash>> <push <pubkey>>
    assert script_sig[-33:] == alice.public_key
    sig_push = script_sig[:-34]
    # El push de la firma puede ser directo (<=75 bytes) o
    # PUSHDATA1; los dos se leen igual.
    der = sig_push[2:] if sig_push[0] == 0x4C else sig_push[1:]
    assert der[0] == 0x30
    assert der[-1] == SIGHASH_ALL
    r, s = decode_dss_signature(der[:-1])
    compact = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert verify_public(
        alice.public_key, tx.sighash(0, script_code).hex(), compact
    )
