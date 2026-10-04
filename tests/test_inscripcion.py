"""test_inscripcion: el template SMCP3, todo offline.

Aquí no hay red ni broadcast: todo es construcción y
verificación local. La inclusión se fabrica con un árbol de
Merkle de una sola hoja (la propia tx), que es una prueba
válida contra su propia raíz — lo que importa es que el
verificador la acepta cuando es correcta y rechaza todo lo
demás.

Lo que sujetan estos tests, en orden de importancia:

1. el hash ``H`` compromete (mesh_id, solicitante) con el
   prefijo de longitud, y nada más;
2. el envelope BRC-160 rueda (construir -> parsear) y el
   body es el último campo;
3. el flujo DPP completo construye una tx que verifica;
4. cada manipulación (hash, firma, fondeo, cerradura,
   inclusión) se rechaza con su motivo.
"""
from __future__ import annotations

import hashlib
import struct

import pytest

from smcp.core.bsv_keys import (
    HAVE_ECDSA,
    Secp256k1KeyPair,
    verify_public,
)
from smcp.core.inscripcion import (
    INSCRIPTION_VERSION,
    ORDINAL_SATOSHIS,
    InscriptionRequest,
    build_inscription,
    build_payment_terms,
    envelope_script,
    extract_inscription,
    inference_hash,
    parse_envelope,
    server_signature,
    sign_requester_input,
    verify_inscription,
    verify_payment_terms,
)
from smcp.core.membership import (
    BlockHeader,
    InclusionProof,
    ProtocolError,
    merkle_root,
)
from smcp.core.spv import hash160
from smcp.core.tiers import PER_INFERENCE_SATOSHIS
from smcp.core.txbuild import (
    OP_0,
    OP_1,
    OP_2,
    OP_3,
    OP_4,
    OP_5,
    OP_ENDIF,
    Transaction,
    TxIn,
    TxOut,
    p2pkh_lock,
)

pytestmark = pytest.mark.skipif(
    not HAVE_ECDSA, reason="requiere 'cryptography' para secp256k1"
)

MESH_ID = "mesh-de-prueba"


def _proof_for(tx: Transaction) -> tuple[InclusionProof, BlockHeader]:
    """Una prueba de inclusión válida: árbol de una sola hoja."""
    root = merkle_root([bytes.fromhex(tx.txid())[::-1]])[::-1].hex()
    return (
        InclusionProof(
            txid=tx.txid(), index=0, path=[],
            merkle_root=root, height=1,
        ),
        BlockHeader(merkle_root=root, height=1),
    )


def _build(alice: Secp256k1KeyPair, bob: Secp256k1KeyPair,
           fee_sats: int = 10, funding: TxIn | None = None,
           mesh_id: str = MESH_ID) -> Transaction:
    return build_inscription(
        mesh_id=mesh_id,
        requester_key=alice,
        server_key=bob,
        funding=funding or TxIn("ab" * 32, 0),
        funding_sats=PER_INFERENCE_SATOSHIS,
        fee_sats=fee_sats,
    )


def test_inference_hash_is_the_documented_formula() -> None:
    pub = bytes(range(33))
    mesh = MESH_ID.encode("utf-8")
    preimage = len(mesh).to_bytes(2, "big") + mesh + pub
    assert inference_hash(MESH_ID, pub) == (
        hashlib.sha256(preimage).hexdigest()
    )


def test_inference_hash_distinguishes_mesh_and_requester() -> None:
    pub = bytes(range(33))
    other = bytes([0x02]) + bytes(range(32))
    assert inference_hash("a", pub) != inference_hash("b", pub)
    assert inference_hash("a", pub) != inference_hash("a", other)


def test_inference_hash_rejects_wrong_key_length() -> None:
    with pytest.raises(ProtocolError):
        inference_hash(MESH_ID, b"corto")
    with pytest.raises(ProtocolError):
        inference_hash("", bytes(range(33)))


def test_request_rejects_wrong_key_lengths() -> None:
    pub = bytes(range(33))
    with pytest.raises(ProtocolError):
        InscriptionRequest("m", b"corto", pub)
    with pytest.raises(ProtocolError):
        InscriptionRequest("m", pub, pub[:32])
    with pytest.raises(ProtocolError):
        InscriptionRequest("", pub, pub)


def test_envelope_round_trip() -> None:
    sig = bytes(range(64))
    script = envelope_script(
        server_pubkey=bytes(range(33)),
        parent_txid="ab" * 32,
        parent_vout=7,
        signature=sig,
        hash_hex="cd" * 32,
    )
    fields = parse_envelope(script)
    assert fields[OP_1] == b"text/plain"
    assert fields[OP_2] == bytes(range(33))
    # El parent viaja como en el cable: txid interno + vout LE.
    assert fields[OP_3] == (
        bytes.fromhex("ab" * 32)[::-1] + struct.pack("<I", 7)
    )
    assert fields[OP_4] == b"\x03"
    assert fields[OP_5] == sig
    # El body es el último campo, antes de OP_ENDIF.
    assert fields[OP_0] == b"cd" * 32
    assert script[-1] == OP_ENDIF


def test_envelope_rejects_bad_values() -> None:
    with pytest.raises(ProtocolError):
        envelope_script(
            server_pubkey=b"corto", parent_txid="ab" * 32,
            parent_vout=0, signature=bytes(64), hash_hex="cd" * 32,
        )
    with pytest.raises(ProtocolError):
        envelope_script(
            server_pubkey=bytes(33), parent_txid="ab" * 32,
            parent_vout=0, signature=bytes(63), hash_hex="cd" * 32,
        )
    with pytest.raises(ProtocolError):
        envelope_script(
            server_pubkey=bytes(33), parent_txid="ab" * 32,
            parent_vout=0, signature=bytes(64), hash_hex="CD" * 32,
        )
    with pytest.raises(ProtocolError):
        parse_envelope(b"\x00\x63\x03ord")  # sin OP_ENDIF


def test_build_and_verify_full_flow() -> None:
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    tx = _build(alice, bob)
    proof, header = _proof_for(tx)
    ok, reason = verify_inscription(
        tx,
        mesh_id=MESH_ID,
        requester_pubkey=alice.public_key,
        funding_sats=PER_INFERENCE_SATOSHIS,
        inclusion=proof,
        header=header,
    )
    assert ok, reason


def test_verify_payment_terms_before_broadcast() -> None:
    """Alice verifica antes de firmar: sin inclusión todavía."""
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    tx = _build(alice, bob)
    ok, reason = verify_payment_terms(
        tx,
        mesh_id=MESH_ID,
        requester_pubkey=alice.public_key,
        funding_sats=PER_INFERENCE_SATOSHIS,
    )
    assert ok, reason


def test_inscription_survives_the_wire() -> None:
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    tx = _build(alice, bob)
    parsed = Transaction.parse(tx.serialize())
    proof, header = _proof_for(parsed)
    ok, reason = verify_inscription(
        parsed,
        mesh_id=MESH_ID,
        requester_pubkey=alice.public_key,
        funding_sats=PER_INFERENCE_SATOSHIS,
        inclusion=proof,
        header=header,
    )
    assert ok, reason


def test_ordinal_output_is_locked_to_the_requester() -> None:
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    tx = _build(alice, bob)
    assert tx.outputs[0].satoshis == ORDINAL_SATOSHIS
    assert tx.outputs[0].script.endswith(
        p2pkh_lock(hash160(alice.public_key))
    )


def test_parent_ties_to_the_paying_input() -> None:
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    tx = _build(alice, bob, funding=TxIn("ab" * 32, 5))
    receipt = extract_inscription(tx)
    assert receipt.parent == (
        bytes.fromhex("ab" * 32)[::-1] + struct.pack("<I", 5)
    )
    assert receipt.parent_outpoint == f"{'ab' * 32}:5"


def test_fee_arithmetic() -> None:
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    for fee in (0, 10, 98):
        tx = _build(alice, bob, fee_sats=fee)
        assert tx.outputs[1].satoshis == (
            PER_INFERENCE_SATOSHIS - ORDINAL_SATOSHIS - fee
        )
    with pytest.raises(ProtocolError):
        _build(alice, bob, fee_sats=99)


def test_tampered_hash_rejected() -> None:
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    tx = _build(alice, bob)
    receipt = extract_inscription(tx)
    # Un byte distinto en el body: el hash inscrito ya no
    # compromete (mesh_id, solicitante), aunque la firma
    # (sobre el H verdadero) siga siendo de Bob.
    bad = ("0" if receipt.hash_hex[0] != "0" else "1")
    bad_hex = bad + receipt.hash_hex[1:]
    funding = tx.inputs[0]
    ordinal = TxOut(
        ORDINAL_SATOSHIS,
        envelope_script(
            server_pubkey=receipt.server_pubkey,
            parent_txid=funding.prev_txid,
            parent_vout=funding.vout,
            signature=receipt.signature,
            hash_hex=bad_hex,
        )
        + p2pkh_lock(hash160(alice.public_key)),
    )
    server = TxOut(
        receipt.server_satoshis,
        p2pkh_lock(hash160(receipt.server_pubkey)),
    )
    tampered = Transaction(inputs=[funding], outputs=[ordinal, server])
    ok, reason = verify_payment_terms(
        tampered,
        mesh_id=MESH_ID,
        requester_pubkey=alice.public_key,
        funding_sats=PER_INFERENCE_SATOSHIS,
    )
    assert not ok
    assert "hash" in reason


def test_wrong_signature_rejected() -> None:
    """Una firma de otra clave: el verificador la rechaza aunque
    alguien la haya metido en el envelope a mano (la construcción
    la habría rechazado antes; aquí se prueba el verificador)."""
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    eve = Secp256k1KeyPair.new("eve")
    h = inference_hash(MESH_ID, alice.public_key)
    sig = eve.sign(h)
    funding = TxIn("ab" * 32, 0)
    ordinal = TxOut(
        ORDINAL_SATOSHIS,
        envelope_script(
            server_pubkey=bob.public_key,
            parent_txid=funding.prev_txid,
            parent_vout=funding.vout,
            signature=sig,
            hash_hex=h,
        )
        + p2pkh_lock(hash160(alice.public_key)),
    )
    server = TxOut(
        PER_INFERENCE_SATOSHIS - ORDINAL_SATOSHIS - 10,
        p2pkh_lock(hash160(bob.public_key)),
    )
    tx = Transaction(inputs=[funding], outputs=[ordinal, server])
    ok, reason = verify_payment_terms(
        tx,
        mesh_id=MESH_ID,
        requester_pubkey=alice.public_key,
        funding_sats=PER_INFERENCE_SATOSHIS,
    )
    assert not ok
    assert "firma" in reason


def test_wrong_funding_rejected() -> None:
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    tx = _build(alice, bob)
    ok, reason = verify_payment_terms(
        tx,
        mesh_id=MESH_ID,
        requester_pubkey=alice.public_key,
        funding_sats=PER_INFERENCE_SATOSHIS - 1,
    )
    assert not ok
    assert "fondeo" in reason


def test_wrong_requester_rejected() -> None:
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    eve = Secp256k1KeyPair.new("eve")
    tx = _build(alice, bob)
    ok, reason = verify_payment_terms(
        tx,
        mesh_id=MESH_ID,
        requester_pubkey=eve.public_key,
        funding_sats=PER_INFERENCE_SATOSHIS,
    )
    assert not ok
    assert "hash" in reason


def test_wrong_server_lock_rejected() -> None:
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    eve = Secp256k1KeyPair.new("eve")
    tx = _build(alice, bob)
    tx.outputs[1].script = p2pkh_lock(hash160(eve.public_key))
    ok, reason = verify_payment_terms(
        tx,
        mesh_id=MESH_ID,
        requester_pubkey=alice.public_key,
        funding_sats=PER_INFERENCE_SATOSHIS,
    )
    assert not ok
    assert "pago" in reason


def test_wrong_inclusion_rejected() -> None:
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    tx = _build(alice, bob)
    proof, header = _proof_for(tx)
    other = InclusionProof(
        txid="00" * 32, index=0, path=[],
        merkle_root=proof.merkle_root, height=1,
    )
    ok, reason = verify_inscription(
        tx,
        mesh_id=MESH_ID,
        requester_pubkey=alice.public_key,
        funding_sats=PER_INFERENCE_SATOSHIS,
        inclusion=other,
        header=header,
    )
    assert not ok
    assert "otra transacción" in reason


def test_each_build_is_a_fresh_txid() -> None:
    """Una inferencia = una tx = un txid: ECDSA es aleatorio, así
    que cada construcción es una inscripción distinta, y el txid
    (la clave de ``record_inference``) lo dice."""
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    tx1 = _build(alice, bob)
    tx2 = _build(alice, bob)
    assert tx1.txid() != tx2.txid()
    # Otro UTXO de fondeo: otro parent, otra inscripción.
    tx3 = _build(alice, bob, funding=TxIn("cd" * 32, 0))
    assert tx3.txid() != tx1.txid()


def test_extract_rejects_plain_transaction() -> None:
    tx = Transaction(inputs=[TxIn("ab" * 32, 0)],
                     outputs=[TxOut(100, b"")])
    with pytest.raises(ProtocolError):
        extract_inscription(tx)


def test_extract_rejects_wrong_shape() -> None:
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    tx = _build(alice, bob)
    tx.outputs.append(TxOut(1, p2pkh_lock(hash160(alice.public_key))))
    with pytest.raises(ProtocolError):
        extract_inscription(tx)
    tx.outputs.pop()
    tx.inputs.append(TxIn("cd" * 32, 0))
    with pytest.raises(ProtocolError):
        extract_inscription(tx)


def test_server_signature_is_brc220_r_s() -> None:
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    sig = server_signature(
        mesh_id=MESH_ID,
        requester_pubkey=alice.public_key,
        server_key=bob,
    )
    assert len(sig) == 64
    h = inference_hash(MESH_ID, alice.public_key)
    assert verify_public(bob.public_key, h, sig)


def test_sign_requester_input_rejects_wrong_key_kind() -> None:
    alice, bob = Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new(
        "bob"
    )
    tx = _build(alice, bob)
    # Una clave que no sea secp256k1 no puede firmar el input.
    with pytest.raises(ProtocolError):
        sign_requester_input(tx, 0, _FakeKey())


class _FakeKey:
    """Una "clave" de otro tipo, para probar el guardia."""

    kind = "ed25519"
    public_key = bytes(33)
