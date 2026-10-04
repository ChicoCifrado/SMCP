"""Tests del smart contract BSV y protocolo permissionless."""

import hashlib

import pytest

from smcp.core.bsv_keys import Secp256k1KeyPair
from smcp.core.contract import (
    InferenceBounty,
    build_claim_tx,
    p2pkh_lock,
)
from smcp.core.txbuild import Transaction


def _key() -> Secp256k1KeyPair:
    return Secp256k1KeyPair.new("nodo-test")


def _bounty(key: Secp256k1KeyPair,
            satoshis: int = 1000) -> InferenceBounty:
    return InferenceBounty(
        gist_digest="a" * 64,
        node_pubkey=key.public_key.hex(),
        verifier_pubkey="b" * 66,
        satoshis=satoshis,
        task_digest="c" * 64,
    )


def test_p2pkh_lock_es_hash160() -> None:
    """El locking script lleva el hash160 de la clave."""
    key = _key()
    script = p2pkh_lock(key.public_key.hex())
    # OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    assert script[0] == 0x76  # OP_DUP
    assert script[1] == 0xA9  # OP_HASH160
    assert script[2] == 0x14  # push 20
    assert len(script) == 25
    # el hash es hash160(pubkey)
    sha = hashlib.sha256(key.public_key).digest()
    rip = hashlib.new("ripemd160", sha).digest()
    assert script[3:23] == rip


def test_build_claim_tx_firma_y_serializa() -> None:
    """La tx de claim se firma (P2PKH) y serializa."""
    key = _key()
    bounty = _bounty(key)
    tx, registro = build_claim_tx(
        bounty, key,
        prev_txid="d" * 64, prev_vout=0, prev_satoshis=5000,
        change_address_pubkey=key.public_key,
        fee_satoshis=500,
    )
    # txid de 64 hex
    assert len(registro["txid"]) == 64
    # outpoint de atribucion = txid:0 (el output del nodo)
    assert registro["outpoint"] == f"{registro['txid']}:0"
    # la tx parsea
    parsed = Transaction.parse(bytes.fromhex(registro["raw_hex"]))
    assert len(parsed.inputs) == 1
    assert len(parsed.outputs) == 2  # bounty + cambio
    # el script_sig lleva firma + pubkey
    assert len(parsed.inputs[0].script_sig) > 70


def test_claim_tx_paga_al_nodo() -> None:
    """El output 0 paga el bounty al nodo (P2PKH del nodo)."""
    key = _key()
    bounty = _bounty(key, satoshis=1000)
    tx, _ = build_claim_tx(
        bounty, key,
        prev_txid="d" * 64, prev_vout=0, prev_satoshis=5000,
        change_address_pubkey=key.public_key,
        fee_satoshis=500,
    )
    # output 0: 1000 sats, P2PKH del nodo
    assert tx.outputs[0].satoshis == 1000
    # el script de bloqueo es P2PKH del nodo (hash160)
    sha = hashlib.sha256(key.public_key).digest()
    rip = hashlib.new("ripemd160", sha).digest()
    assert tx.outputs[0].script[3:23] == rip


def test_claim_tx_cambio_vuelve_al_nodo() -> None:
    """Lo que sobra del UTXO (cambio) vuelve al nodo."""
    key = _key()
    bounty = _bounty(key, satoshis=1000)
    tx, _ = build_claim_tx(
        bounty, key,
        prev_txid="d" * 64, prev_vout=0, prev_satoshis=5000,
        change_address_pubkey=key.public_key,
        fee_satoshis=500,
    )
    # UTXO 5000 - bounty 1000 - fee 500 = 3500 cambio
    assert tx.outputs[1].satoshis == 3500


def test_claim_tx_rechaza_utxo_insuficiente() -> None:
    """UTXO menor que bounty + fee es error."""
    key = _key()
    bounty = _bounty(key, satoshis=1000)
    with pytest.raises(ValueError, match="no cubre"):
        build_claim_tx(
            bounty, key,
            prev_txid="d" * 64, prev_vout=0, prev_satoshis=1000,
            change_address_pubkey=key.public_key,
            fee_satoshis=500,
        )


def test_claim_tx_sin_cambio_si_utxo_justo() -> None:
    """UTXO exacto (bounty + fee): sin output de cambio."""
    key = _key()
    bounty = _bounty(key, satoshis=1000)
    tx, _ = build_claim_tx(
        bounty, key,
        prev_txid="d" * 64, prev_vout=0, prev_satoshis=1500,
        change_address_pubkey=key.public_key,
        fee_satoshis=500,
    )
    assert len(tx.outputs) == 1
    assert tx.outputs[0].satoshis == 1000


def test_inferencia_bounty_valida_digests() -> None:
    """El bounty valida la longitud de los digests."""
    key = _key()
    with pytest.raises(ValueError, match="gist_digest"):
        InferenceBounty(
            gist_digest="corto", node_pubkey=key.public_key.hex(),
            verifier_pubkey="b" * 66, satoshis=1000,
        )


def test_inferencia_bounty_rechaza_satoshis_negativos() -> None:
    """Satoshis negativos son error."""
    key = _key()
    with pytest.raises(ValueError, match="negativos"):
        InferenceBounty(
            gist_digest="a" * 64, node_pubkey=key.public_key.hex(),
            verifier_pubkey="b" * 66, satoshis=-1,
        )


def test_inferencia_bounty_dict_roundtrip() -> None:
    """El bounty serializa a dict y vuelve."""
    key = _key()
    bounty = _bounty(key, satoshis=1234)
    d = bounty.to_dict()
    assert d["satoshis"] == 1234
    assert d["gist_digest"] == "a" * 64
    # roundtrip
    again = InferenceBounty.from_dict(d)
    assert again == bounty
