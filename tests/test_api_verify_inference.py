"""test_api_verify_inference: verificar una inferencia ajena por SPV.

El endpoint POST /api/inferences/{txid}/verify reutiliza
``verify_inscription`` (inclusion + terminos de pago). El
verificador aporta SU cadena de cabeceras: la inclusion se
comprueba contra la raiz que *el* eligio, no contra la que
manda el contraparte (SPV puro).

Lo que sujetan estos tests, en orden de importancia:

1. prueba valida (arbol de una hoja) -> verificada;
2. inclusion invalidada (raiz distinta) -> rechazada;
3. header con raiz distinta a la de la prueba -> rechazada;
4. tx que no coincide con el txid -> 400;
5. tx invalida (hex corto) -> 400;
6. endianness invertida (la trampa clasica) -> rechazada;
7. read-only: no crea transacciones ni toca el libro.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from smcp.core.bsv_keys import HAVE_ECDSA, Secp256k1KeyPair
from smcp.core.inscripcion import build_inscription
from smcp.core.membership import (
    BlockHeader,
    InclusionProof,
    merkle_root,
)
from smcp.core.tiers import PER_INFERENCE_SATOSHIS
from smcp.core.txbuild import Transaction, TxIn
from smcp.web.app import app

pytestmark = pytest.mark.skipif(
    not HAVE_ECDSA, reason="requiere 'cryptography' para secp256k1"
)

MESH_ID = "mesh-de-prueba"


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def _keys() -> tuple[Secp256k1KeyPair, Secp256k1KeyPair]:
    return Secp256k1KeyPair.new("alice"), Secp256k1KeyPair.new("bob")


def _proof_for(tx: Transaction) -> tuple[InclusionProof, BlockHeader]:
    """Una prueba de inclusion valida: arbol de una sola hoja."""
    root = merkle_root([bytes.fromhex(tx.txid())[::-1]])[::-1].hex()
    return (
        InclusionProof(
            txid=tx.txid(), index=0, path=[],
            merkle_root=root, height=1,
        ),
        BlockHeader(merkle_root=root, height=1),
    )


def _build_tx(alice: Secp256k1KeyPair,
              bob: Secp256k1KeyPair) -> Transaction:
    return build_inscription(
        mesh_id=MESH_ID,
        requester_key=alice,
        server_key=bob,
        funding=TxIn("ab" * 32, 0),
        funding_sats=PER_INFERENCE_SATOSHIS,
        fee_sats=10,
    )


def _payload(tx: Transaction, inclusion: InclusionProof,
             header: BlockHeader, *,
             txid_override: str = "",
             requester_pubkey: str = "",
             funding_sats: int = PER_INFERENCE_SATOSHIS,
             ) -> dict:
    return {
        "mesh_id": MESH_ID,
        "requester_pubkey": requester_pubkey,
        "funding_sats": funding_sats,
        "tx_hex": tx.serialize().hex(),
        "inclusion": {
            "txid": txid_override or inclusion.txid,
            "index": inclusion.index,
            "path": list(inclusion.path),
            "merkle_root": inclusion.merkle_root,
            "height": inclusion.height,
        },
        "header": {
            "merkle_root": header.merkle_root,
            "height": header.height,
            "raw": header.raw.hex(),
        },
    }


def test_verify_valid_inference(client: TestClient) -> None:
    alice, bob = _keys()
    tx = _build_tx(alice, bob)
    inclusion, header = _proof_for(tx)
    r = client.post(
        f"/api/inferences/{tx.txid()}/verify",
        json=_payload(tx, inclusion, header,
                      requester_pubkey=alice.public_key.hex()),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["verified"] is True
    assert body["inclusion"] is True
    assert body["txid"] == tx.txid()
    # El server_pubkey sale de la tx (no del request).
    assert body["server_pubkey"] == bob.public_key.hex()
    assert body["inference_id"] is not None
    assert body["header"]["height"] == 1


def test_verify_rejects_wrong_merkle_root(client: TestClient) -> None:
    """La prueba es de otra raiz -> inclusion invalida."""
    alice, bob = _keys()
    tx = _build_tx(alice, bob)
    inclusion, header = _proof_for(tx)
    # Forjar una prueba con raiz distinta (no coincide con la tx).
    forged = InclusionProof(
        txid=tx.txid(), index=0, path=[],
        merkle_root="cd" * 32, height=1,
    )
    r = client.post(
        f"/api/inferences/{tx.txid()}/verify",
        json=_payload(tx, forged, header,
                      requester_pubkey=alice.public_key.hex()),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert body["inclusion"] is False
    assert "inclusión" in body["reason"]


def test_verify_rejects_header_with_distinct_root(client: TestClient) -> None:
    """La cabecera que el verificador elige tiene otra raiz
    (no la de la prueba) -> la inclusion no cuadra."""
    alice, bob = _keys()
    tx = _build_tx(alice, bob)
    inclusion, _header = _proof_for(tx)
    # El verificador elige una cabecera con raiz distinta.
    hostile = BlockHeader(merkle_root="ef" * 32, height=1)
    r = client.post(
        f"/api/inferences/{tx.txid()}/verify",
        json=_payload(tx, inclusion, hostile,
                      requester_pubkey=alice.public_key.hex()),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert body["inclusion"] is False


def test_verify_rejects_txid_mismatch(client: TestClient) -> None:
    """La tx no coincide con el txid de la URL -> 400."""
    alice, bob = _keys()
    tx = _build_tx(alice, bob)
    inclusion, header = _proof_for(tx)
    r = client.post(
        "/api/inferences/" + "00" * 32 + "/verify",
        json=_payload(tx, inclusion, header,
                      requester_pubkey=alice.public_key.hex()),
    )
    assert r.status_code == 400
    assert "no coincide" in r.json()["detail"]


def test_verify_rejects_invalid_tx_hex(client: TestClient) -> None:
    """Hex de tx corto -> 400."""
    alice, bob = _keys()
    tx = _build_tx(alice, bob)
    inclusion, header = _proof_for(tx)
    payload = _payload(tx, inclusion, header,
                       requester_pubkey=alice.public_key.hex())
    payload["tx_hex"] = "0102"
    r = client.post(
        f"/api/inferences/{tx.txid()}/verify",
        json=payload,
    )
    assert r.status_code == 400
    assert "tx invalida" in r.json()["detail"]


def test_verify_rejects_endianness_swap(client: TestClient) -> None:
    """La trampa clasica: presentar el txid en orden interno
    (volteado) produce una raiz distinta y se rechaza."""
    alice, bob = _keys()
    tx = _build_tx(alice, bob)
    inclusion, header = _proof_for(tx)
    # Voltear el txid (orden interno en vez de presentacion).
    swapped = bytes.fromhex(tx.txid())[::-1].hex()
    r = client.post(
        f"/api/inferences/{swapped}/verify",
        json=_payload(tx, inclusion, header,
                      txid_override=swapped,
                      requester_pubkey=alice.public_key.hex()),
    )
    # La tx parsea, pero su txid no coincide con el volteado.
    assert r.status_code == 400


def test_verify_is_read_only(client: TestClient) -> None:
    """No crea transacciones: el endpoint solo verifica pruebas."""
    alice, bob = _keys()
    tx = _build_tx(alice, bob)
    inclusion, header = _proof_for(tx)
    r = client.post(
        f"/api/inferences/{tx.txid()}/verify",
        json=_payload(tx, inclusion, header,
                      requester_pubkey=alice.public_key.hex()),
    )
    assert r.status_code == 200
    body = r.json()
    # No hay campo que indique broadcast ni tx nueva.
    assert "broadcast" not in body
    assert "txid_nueva" not in body
    # La tx original se preserva intacta.
    assert body["txid"] == tx.txid()
