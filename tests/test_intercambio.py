"""test_intercambio: la secuencia v3 de punta a punta, offline.

El mismo patrón que ``test_exchange_thesis.py`` (la tesis del
intercambio de v2), con las piezas de v3:

    un nodo publica VRAM (firmado)  ->  otro nodo pide una
    inferencia  ->  el servidor la sirve y construye los
    PaymentTerms  ->  el solicitante verifica y firma su
    input (Payment)  ->  el servidor emite por ARC y espera
    el PaymentACK  ->  y solo entonces el historial sube
    y el ranking lo muestra

No toca red: la inferencia es ``FakeLLMClient`` y ARC es un
doble en proceso (el contrato de wire de ARC ya lo sujetan
``tests/test_arc.py``).

Lo que sujetan los tests, en orden de importancia:

1. la secuencia completa, del pedido al ranking;
2. que el mismo txid no cuenta dos veces;
3. que el solicitante no firma términos alterados;
4. que el servidor no emite una Payment sin firmar;
5. que un servidor sin ledger ack pero no cuenta;
6. la aritmética de la fee.
"""
from __future__ import annotations

import asyncio

import pytest

from smcp.core.arc import ACCEPTED_BY_NETWORK, ArcTxStatus
from smcp.core.bsv_keys import Secp256k1KeyPair
from smcp.core.contrib import CapacityReport, ContributionLedger
from smcp.core.inscripcion import ORDINAL_SATOSHIS
from smcp.core.intercambio import (
    DEFAULT_FEE_SATOSHIS,
    InferenceRequest,
    InferenceServer,
    sign_payment,
)
from smcp.core.llm import FakeLLMClient
from smcp.core.membership import ProtocolError
from smcp.core.registro import (
    InferenceRegistry,
    PAY_BSV,
    PAY_DELM,
)
from smcp.core.placement import ModelSpec, plan_placement
from smcp.core.provenance import KeyPair
from smcp.core.reputation import board_from_counters
from smcp.core.tiers import PER_INFERENCE_SATOSHIS
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


def _request(alice: Secp256k1KeyPair,
             prompt: str = "hola") -> InferenceRequest:
    """Lo que Alice pide: su prompt, su clave y su UTXO de fondeo."""
    return InferenceRequest(
        prompt=prompt, mesh_id=MESH,
        requester_pubkey=alice.public_key,
        funding=TxIn("ab" * 32, 0),
    )


def test_the_whole_chain_from_request_to_ranking():
    async def go():
        led = ContributionLedger(MESH)
        # 1. el nodo publica VRAM (firmado): es proveedor,
        #    y la malla le coloca carga.
        _admit(led, "bob", 8.0)
        plan = plan_placement(
            ModelSpec(name="m", memory_required_gb=4.0), led,
        )
        assert plan.ok and plan.peers == ("bob",)

        # 2. Alice pide; Bob sirve y construye los términos.
        alice = Secp256k1KeyPair.new("alice")
        bob = Secp256k1KeyPair.new("bob-members")
        arc = _FakeArc()
        server = InferenceServer(
            server_key=bob, llm=FakeLLMClient(), arc=arc,
            ledger=led, peer_id="bob",
        )
        req = _request(alice)
        response, tx = await server.serve(req)
        # La respuesta viaja fuera de cadena: no se ancla,
        # no se publica, solo se entrega.
        assert response == "OK"

        # 3. Alice verifica y firma (Payment).
        sign_payment(tx, requester_key=alice, mesh_id=MESH)
        assert tx.inputs[0].script_sig

        # 4. Bob emite, espera el PaymentACK, y solo entonces
        #    cuenta: el historial sube con el txid de la tx.
        ack = await server.settle(tx, req)
        assert ack.status.accepted
        assert ack.txid == tx.txid()
        assert len(arc.broadcasts) == 1
        assert led.peers["bob"].inferences_served == 1
        # 250 sats de fondeo: 1 de ordinal a Alice,
        # 249 menos la fee por defecto (la fee media
        # de relay) a Bob.
        assert led.peers["bob"].satoshis_earned == (
            PER_INFERENCE_SATOSHIS - ORDINAL_SATOSHIS
            - DEFAULT_FEE_SATOSHIS
        )

        # 5. y el ranking lo muestra.
        assert board_from_counters(led).get("bob").inferences_served == 1

    asyncio.run(go())


def test_the_same_txid_is_not_counted_twice():
    async def go():
        led = ContributionLedger(MESH)
        _admit(led, "bob", 8.0)
        alice = Secp256k1KeyPair.new("alice")
        arc = _FakeArc()
        server = InferenceServer(
            server_key=Secp256k1KeyPair.new("bob"),
            llm=FakeLLMClient(), arc=arc,
            ledger=led, peer_id="bob",
        )
        req = _request(alice)
        _, tx = await server.serve(req)
        sign_payment(tx, requester_key=alice, mesh_id=MESH)
        assert (await server.settle(tx, req)).txid == tx.txid()
        # La cadena prohíbe gastar el mismo txid dos veces;
        # el historial también. La segunda vuelta falla al
        # contar, y se dice en vez de contar silenciosamente.
        with pytest.raises(ProtocolError):
            await server.settle(tx, req)
        assert led.peers["bob"].inferences_served == 1

    asyncio.run(go())


def test_the_requester_refuses_to_sign_tampered_terms():
    async def go():
        led = ContributionLedger(MESH)
        _admit(led, "bob", 8.0)
        alice = Secp256k1KeyPair.new("alice")
        server = InferenceServer(
            server_key=Secp256k1KeyPair.new("bob"),
            llm=FakeLLMClient(), arc=_FakeArc(),
        )
        req = _request(alice)
        _, tx = await server.serve(req)
        # Alterar el ordinal (2 sats en vez de 1) rompe la
        # plantilla: Alice no firma lo que no verifica.
        tx.outputs[0].satoshis = 2
        with pytest.raises(ProtocolError):
            sign_payment(tx, requester_key=alice, mesh_id=MESH)
        assert not tx.inputs[0].script_sig

    asyncio.run(go())


def test_the_server_refuses_to_settle_an_unsigned_payment():
    async def go():
        led = ContributionLedger(MESH)
        _admit(led, "bob", 8.0)
        alice = Secp256k1KeyPair.new("alice")
        arc = _FakeArc()
        server = InferenceServer(
            server_key=Secp256k1KeyPair.new("bob"),
            llm=FakeLLMClient(), arc=arc,
            ledger=led, peer_id="bob",
        )
        req = _request(alice)
        # Alice nunca firmó: emitir sería tirar la tx a la
        # red para que el minero la rechace (input sin gastar).
        _, tx = await server.serve(req)
        with pytest.raises(ProtocolError):
            await server.settle(tx, req)
        assert not arc.broadcasts
        assert led.peers["bob"].inferences_served == 0

    asyncio.run(go())


def test_a_server_without_ledger_acks_but_does_not_count():
    async def go():
        alice = Secp256k1KeyPair.new("alice")
        server = InferenceServer(
            server_key=Secp256k1KeyPair.new("bob"),
            llm=FakeLLMClient(), arc=_FakeArc(),
        )
        req = _request(alice)
        _, tx = await server.serve(req)
        sign_payment(tx, requester_key=alice, mesh_id=MESH)
        # Sin ledger no hay historial que contar: el
        # intercambio se verifica y se emite, nada más.
        ack = await server.settle(tx, req)
        assert ack.status.accepted
        assert ack.txid == tx.txid()

    asyncio.run(go())


def test_the_fee_comes_out_of_the_server_share():
    async def go():
        led = ContributionLedger(MESH)
        _admit(led, "bob", 8.0)
        alice = Secp256k1KeyPair.new("alice")
        server = InferenceServer(
            server_key=Secp256k1KeyPair.new("bob"),
            llm=FakeLLMClient(), arc=_FakeArc(),
            ledger=led, peer_id="bob", fee_sats=10,
        )
        req = _request(alice)
        _, tx = await server.serve(req)
        sign_payment(tx, requester_key=alice, mesh_id=MESH)
        await server.settle(tx, req)
        # 250 - 1 (ordinal) - 10 (fee) = 239 para el servidor.
        assert led.peers["bob"].satoshis_earned == (
            PER_INFERENCE_SATOSHIS - ORDINAL_SATOSHIS - 10
        )
        # Una fee que se come el pago del servidor no cierra.
        with pytest.raises(ProtocolError):
            InferenceServer(
                server_key=Secp256k1KeyPair.new("bob2"),
                llm=FakeLLMClient(), arc=_FakeArc(),
                fee_sats=PER_INFERENCE_SATOSHIS,
            )

    asyncio.run(go())


# ---------------------------------------------------------------------------
# Union de piezas: completion (status 200) -> timestamp -> registro -> cobro
# ---------------------------------------------------------------------------
def test_completion_registered_with_timestamp_and_payment():
    """La inferencia completada (status 200) queda en el libro.

    Une el flujo de intercambio (Alice pide, Bob sirve y cobra)
    con el libro de inferencias: la completion produce un
    registro con txid, timestamp, identidades y el cobro.
    """
    async def go():
        led = ContributionLedger(MESH)
        _admit(led, "bob", 8.0)
        alice = Secp256k1KeyPair.new("alice")
        bob = Secp256k1KeyPair.new("bob-members")
        arc = _FakeArc()
        registry = InferenceRegistry()
        server = InferenceServer(
            server_key=bob, llm=FakeLLMClient(), arc=arc,
            ledger=led, peer_id="bob", registry=registry,
            pay_method=PAY_BSV,
        )
        req = _request(alice)
        _, tx = await server.serve(req)
        sign_payment(tx, requester_key=alice, mesh_id=MESH)
        await server.settle(tx, req)

        # El libro tiene la inferencia, con el txid de la tx.
        assert len(registry.records) == 1
        rec = registry.by_txid(tx.txid())
        assert rec is not None
        assert rec.completed_at > 0  # timestamp de la completion
        assert rec.mesh_id == MESH
        assert rec.server_pubkey == bob.public_key.hex()
        assert rec.requester_pubkey == alice.public_key.hex()
        assert rec.pay_method == PAY_BSV
        assert rec.satoshis == (
            PER_INFERENCE_SATOSHIS - ORDINAL_SATOSHIS
            - DEFAULT_FEE_SATOSHIS
        )
        assert rec.delm_amount == 0
        # el inference_id es consultable
        assert registry.by_inference_id(rec.inference_id) is rec
        # el historial del servidor
        assert len(registry.by_server(bob.public_key.hex())) == 1

    asyncio.run(go())


def test_completion_paid_in_delm():
    """El nodo puede cobrar la inferencia en DELM (capa F).

    En modo DELM el pago es el token: el servidor no cobra
    los sats del output, sino unidades DELM. El libro lo
    registra como metodo de pago `delm`.
    """
    async def go():
        alice = Secp256k1KeyPair.new("alice")
        bob = Secp256k1KeyPair.new("bob-delm")
        registry = InferenceRegistry()
        server = InferenceServer(
            server_key=bob, llm=FakeLLMClient(), arc=_FakeArc(),
            registry=registry,
            pay_method=PAY_DELM,
            delm_token_id="8d7f4834..._0",
        )
        req = _request(alice)
        _, tx = await server.serve(req)
        sign_payment(tx, requester_key=alice, mesh_id=MESH)
        await server.settle(tx, req)

        rec = registry.by_txid(tx.txid())
        assert rec is not None
        assert rec.pay_method == PAY_DELM
        assert rec.satoshis == 0  # no cobra sats
        assert rec.delm_amount == (
            PER_INFERENCE_SATOSHIS - ORDINAL_SATOSHIS
            - DEFAULT_FEE_SATOSHIS
        )
        assert rec.delm_token_id == "8d7f4834..._0"

    asyncio.run(go())
