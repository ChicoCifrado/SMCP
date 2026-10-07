"""test_mensajeria: la secuencia v3 de punta a punta, por el transporte.

El mismo flujo que ``test_intercambio`` — pide, sirve,
verifica, firma, emite, cuenta— pero con los mensajes
**por el transporte**: dos pares sobre un bus in-memory,
cada uno en su hilo, como un despliegue real en
miniatura (el QUIC real ya lo sujetan
``tests/test_quic_host.py``).

Lo que sujetan los tests, en orden de importancia:

1. la secuencia completa por el transporte: respuesta,
   términos, pago firmado, emisión y cobro;
2. el formato de los mensajes (ida y vuelta de la
   codificación, los cuatro tipos);
3. que un pago sin petición cierra;
4. que los mensajes malformados se dicen, no se
   ignoran.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest

from smcp.core.arc import ACCEPTED_BY_NETWORK, ArcTxStatus
from smcp.core.bsv_keys import Secp256k1KeyPair
from smcp.core.contrib import CapacityReport, ContributionLedger
from smcp.core.inscripcion import ORDINAL_SATOSHIS
from smcp.core.intercambio import DEFAULT_FEE_SATOSHIS, InferenceServer
from smcp.core.llm import FakeLLMClient
from smcp.core.membership import ProtocolError
from smcp.core.mensajeria import (
    KIND_INFERENCE_REQUEST,
    KIND_INFERENCE_RESPONSE,
    KIND_PAYMENT_TERMS,
    KIND_SIGNED_PAYMENT,
    InferenceResponder,
    InferenceRequester,
    decode_inference_request,
    decode_inference_response,
    decode_payment_terms,
    decode_signed_payment,
    encode_inference_request,
    encode_inference_response,
    encode_payment_terms,
    encode_signed_payment,
    new_request_id,
)
from smcp.core.mesh_node import decode_msg
from smcp.core.provenance import KeyPair
from smcp.core.registro import InferenceRegistry
from smcp.core.tiers import PER_INFERENCE_SATOSHIS
from smcp.core.transport import InMemoryTransport, _Bus
from smcp.core.txbuild import Transaction, TxIn

MESH = "malla-v3"
NOW = 1_000.0


class _FakeArc:
    """Un ARC en proceso: acepta todo y deriva el txid de verdad.

    El txid lo calcula de la tx serializada — lo que un ARC
    de verdad hace — para que el chequeo de identidad de
    ``broadcast_transaction`` sea real, no trivial.
    """

    def __init__(self) -> None:
        self.broadcasts: list[str] = []

    async def broadcast(self, tx_hex: str, **kwargs) -> ArcTxStatus:
        self.broadcasts.append(tx_hex)
        return ArcTxStatus(
            txid=Transaction.parse(bytes.fromhex(tx_hex)).txid(),
            tx_status=ACCEPTED_BY_NETWORK,
        )


def _admit(led: ContributionLedger, peer: str,
           vram: float) -> KeyPair:
    """Publica VRAM firmado (el anuncio de capacidad, que v3 hereda)."""
    identity = KeyPair.new(peer)
    ch = led.issue_challenge(peer, now=NOW)
    rep = CapacityReport(
        mesh_id=MESH, peer_id=peer, vram_gb=vram,
        vram_advertised_gb=vram, ram_gb=32.0, cpu_cores=8,
        nonce=ch.nonce, issued_at=NOW, expires_at=NOW + 3600,
    ).sign(identity)
    ok, why = led.admit(rep, now=NOW)
    assert ok, why
    led.observe(peer, NOW, dt_s=60)
    return identity


def _mesh() -> tuple[InMemoryTransport, InMemoryTransport]:
    """Dos pares sobre un bus in-memory compartido."""
    bus = _Bus()
    return InMemoryTransport(bus, "alice"), InMemoryTransport(bus, "bob")


def test_the_wire_format_round_trips() -> None:
    """Los cuatro mensajes se codifican y se decodifican iguales."""
    alice = Secp256k1KeyPair.new("alice")
    rid = new_request_id()
    funding = TxIn("ab" * 32, 0)

    # petición (0x04)
    payload = encode_inference_request(
        rid, prompt="hola", mesh_id=MESH,
        requester_pubkey=alice.public_key, funding=funding,
    )
    kind, body = decode_msg(payload)
    assert kind == KIND_INFERENCE_REQUEST
    rid2, req = decode_inference_request(body)
    assert rid2 == rid
    assert req.prompt == "hola"
    assert req.mesh_id == MESH
    assert req.requester_pubkey == alice.public_key
    assert req.funding.prev_txid == funding.prev_txid
    assert req.funding.vout == funding.vout
    assert req.funding_sats == PER_INFERENCE_SATOSHIS

    # respuesta (0x07)
    payload = encode_inference_response(rid, "OK")
    kind, body = decode_msg(payload)
    assert kind == KIND_INFERENCE_RESPONSE
    rid2, response = decode_inference_response(body)
    assert (rid2, response) == (rid, "OK")

    # términos (0x05) y pago firmado (0x06): el mismo
    # formato, distinto tipo.
    server = InferenceServer(
        server_key=Secp256k1KeyPair.new("bob"),
        llm=FakeLLMClient(), arc=_FakeArc(),
    )
    _, tx = asyncio.run(server.serve(req))
    for encode, decode, kind_expected in (
        (encode_payment_terms, decode_payment_terms, KIND_PAYMENT_TERMS),
        (encode_signed_payment, decode_signed_payment, KIND_SIGNED_PAYMENT),
    ):
        payload = encode(rid, tx)
        kind, body = decode_msg(payload)
        assert kind == kind_expected
        rid2, tx2 = decode(body)
        assert rid2 == rid
        assert tx2.txid() == tx.txid()


def test_the_whole_chain_over_the_transport() -> None:
    """Pide, sirve, verifica, firma, emite y cuenta — por el transporte."""
    led = ContributionLedger(MESH)
    _admit(led, "bob", 8.0)
    alice = Secp256k1KeyPair.new("alice")
    bob = Secp256k1KeyPair.new("bob-members")
    arc = _FakeArc()
    registry = InferenceRegistry()
    server = InferenceServer(
        server_key=bob, llm=FakeLLMClient(), arc=arc,
        ledger=led, peer_id="bob", registry=registry,
    )
    alice_t, bob_t = _mesh()
    responder = InferenceResponder(transport=bob_t, server=server)
    requester = InferenceRequester(transport=alice_t, key=alice)

    # Bob sirve en su hilo, como un nodo desplegado.
    stop = threading.Event()
    hilo = threading.Thread(
        target=responder.serve_while, args=(stop.is_set,),
        daemon=True,
    )
    hilo.start()
    try:
        response, tx = requester.request(
            to="bob", prompt="hola", mesh_id=MESH,
            funding=TxIn("ab" * 32, 0),
        )
        # La respuesta viaja fuera de cadena: llegó
        # por el transporte.
        assert response == "OK"
        # La tx firmada es el recibo de Alice: su
        # input firmado.
        assert tx.inputs[0].script_sig
        # El pago viaja y Bob lo cobra: un tick de
        # su hilo (el servidor sigue vivo mientras
        # esperamos).
        deadline = time.monotonic() + 5.0
        while not led.peers["bob"].inferences_served:
            if time.monotonic() >= deadline:
                raise AssertionError("el servidor no cobró a tiempo")
            time.sleep(0.01)
    finally:
        stop.set()
        hilo.join(timeout=5)

    # ... y el libro tiene la inferencia, con el txid
    # de la tx que Alice firmó.
    rec = registry.by_txid(tx.txid())
    assert rec is not None
    assert rec.mesh_id == MESH
    assert rec.requester_pubkey == alice.public_key.hex()
    assert rec.server_pubkey == bob.public_key.hex()
    assert rec.completed_at > 0
    # Bob cobró y el ledger lo cuenta.
    assert len(arc.broadcasts) == 1
    assert led.peers["bob"].inferences_served == 1
    assert led.peers["bob"].satoshis_earned == (
        PER_INFERENCE_SATOSHIS - ORDINAL_SATOSHIS
        - DEFAULT_FEE_SATOSHIS
    )


def test_a_payment_without_a_request_is_rejected() -> None:
    """Un pago firmado para un ``request_id`` desconocido cierra."""
    alice_t, bob_t = _mesh()
    server = InferenceServer(
        server_key=Secp256k1KeyPair.new("bob"),
        llm=FakeLLMClient(), arc=_FakeArc(),
    )
    responder = InferenceResponder(transport=bob_t, server=server)
    alice = Secp256k1KeyPair.new("alice")

    # Una petición atendida a mano (sin hilos): queda
    # pendiente en el servidor.
    rid = new_request_id()
    alice_t.send("bob", encode_inference_request(
        rid, prompt="hola", mesh_id=MESH,
        requester_pubkey=alice.public_key, funding=TxIn("ab" * 32, 0),
    ))
    assert responder.serve_next() == rid

    # Los términos llegaron a Alice.
    terms = None
    for _, payload in alice_t.poll():
        kind, body = decode_msg(payload)
        if kind == KIND_PAYMENT_TERMS:
            terms = decode_payment_terms(body)[1]
    assert terms is not None

    # Un pago firmado para un request_id que no existe.
    alice_t.send("bob", encode_signed_payment(new_request_id(), terms))
    with pytest.raises(ProtocolError, match="sin petición"):
        responder.serve_next()


def test_malformed_messages_are_said_not_ignored() -> None:
    """Un mensaje malformado es un error, no un mensaje vacío."""
    rid = new_request_id()

    # JSON válido, campos no.
    with pytest.raises(ProtocolError):
        decode_inference_request(b'{"request_id": "x"}')
    # no es JSON.
    with pytest.raises(ProtocolError):
        decode_inference_request(b"no es json")
    # la clave pública no es hex.
    with pytest.raises(ProtocolError):
        decode_inference_request(json.dumps({
            "request_id": rid, "prompt": "p", "mesh_id": MESH,
            "requester_pubkey": "zzz", "funding_txid": "a" * 64,
            "funding_vout": 0, "funding_sats": PER_INFERENCE_SATOSHIS,
        }).encode("utf-8"))
    # la tx no es hex.
    with pytest.raises(ProtocolError):
        decode_payment_terms(json.dumps(
            {"request_id": rid, "tx_hex": "zzz"},
        ).encode("utf-8"))
    with pytest.raises(ProtocolError):
        decode_signed_payment(b"no es json")
    # la respuesta no tiene texto.
    with pytest.raises(ProtocolError):
        decode_inference_response(b'{"request_id": "x"}')
