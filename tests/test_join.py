"""test_join: el join v3 — gratis, off-chain, en el roster.

El mismo patrón de los tests de v3 (secuencia de punta a
punta, offline), con las piezas del roster
(:mod:`delm.core.roster`) y el intercambio
(:mod:`delm.core.intercambio`):

    cada nodo funda su roster  ->  se intercambian
    claves  ->  cada uno avala al otro  ->
    intercambian rosters y reconcilian  ->  y cada
    uno ve al otro como verificado

No toca red ni cadena: no hay nada que tocar — el join
no gasta sats, no firma una tx, no llama a ARC. Eso es
lo que lo separa del join de v2 (la membresía de 1
satoshi en cadena, :mod:`delm.core.membership`).

Lo que sujetan los tests, en orden de importancia:

1. el join completo, con confianza mutua verificada;
2. que el join y el intercambio componen el flujo v3
   (la misma identidad, el roster como puerta, el
   trabajo como lo que sube el ranking);
3. que un cluster ajeno no se empareja;
4. que un emparejamiento unilateral deja a un lado sin
   confianza verificada;
5. que el keyring es la autoridad (una clave wrong no
   verifica, aunque el aval esté firmado).
"""
from __future__ import annotations

import asyncio

from delm.core.bsv_keys import Secp256k1KeyPair
from delm.core.contrib import CapacityReport, ContributionLedger
from delm.core.intercambio import (
    InferenceRequest,
    InferenceServer,
    sign_payment,
)
from delm.core.join import found, pair
from delm.core.llm import FakeLLMClient
from delm.core.provenance import KeyPair
from delm.core.roster import cert_fingerprint
from delm.core.tiers import PER_INFERENCE_SATOSHIS
from delm.core.txbuild import Transaction, TxIn

CLUSTER = "malla-v3"
NOW = 1_000.0


class _FakeArc:
    """Un ARC en proceso: acepta todo y deriva el txid."""

    def __init__(self) -> None:
        self.broadcasts: list[str] = []

    async def broadcast(self, tx_hex: str, **kwargs):
        from delm.core.arc import ACCEPTED_BY_NETWORK, ArcTxStatus

        self.broadcasts.append(tx_hex)
        return ArcTxStatus(
            txid=Transaction.parse(bytes.fromhex(tx_hex)).txid(),
            tx_status=ACCEPTED_BY_NETWORK,
        )


def _two_nodes(cluster: str = CLUSTER
               ) -> tuple[KeyPair, KeyPair, dict[str, bytes],
                          dict[str, bytes]]:
    """Dos nodos, cada uno con su roster fundado y su keyring."""
    akey, bkey = KeyPair.new("A"), KeyPair.new("B")
    _, a_keyring = found(cluster, "A", akey, now=NOW)
    _, b_keyring = found(cluster, "B", bkey, now=NOW)
    return akey, bkey, a_keyring, b_keyring


def test_two_nodes_pair_off_chain_without_spending_anything():
    akey, bkey, a_keyring, b_keyring = _two_nodes()
    a_roster, _ = found(CLUSTER, "A", akey, now=NOW)
    b_roster, _ = found(CLUSTER, "B", bkey, now=NOW)

    res = pair(a_roster=a_roster, a_key=akey, a_keyring=a_keyring,
               b_roster=b_roster, b_key=bkey, b_keyring=b_keyring,
               now=NOW)

    # La propiedad del join: confianza mutua verificada —
    # alguien en quien ya confiaban avaló la admisión.
    assert res.a_trusts_b and res.b_trusts_a
    assert res.mutual
    # Y cada roster conoce al par, con el aval del otro
    # dentro (el propio y el del par, tras reconciliar).
    assert a_roster.is_member("B") and b_roster.is_member("A")
    assert res.pinned_a >= 1 and res.pinned_b >= 1
    # El intercambio de claves dejó las del par en cada
    # keyring: contra ellas se verifican los avales.
    assert a_keyring["B"] == bkey.public_key
    assert b_keyring["A"] == akey.public_key


def test_join_and_exchange_compose_the_v3_flow():
    async def go():
        # La mitad de la identidad: el join en el
        # roster (claves ed25519 de provenance). Bob
        # es un par verificado de Alice — puede
        # servir en su malla.
        bob_key = KeyPair.new("bob")
        alice_key = KeyPair.new("alice")
        bob_roster, bob_keyring = found(
            CLUSTER, "bob", bob_key, now=NOW)
        alice_roster, alice_keyring = found(
            CLUSTER, "alice", alice_key, now=NOW)
        res = pair(a_roster=bob_roster, a_key=bob_key,
                   a_keyring=bob_keyring,
                   b_roster=alice_roster, b_key=alice_key,
                   b_keyring=alice_keyring, now=NOW)
        assert res.mutual
        assert alice_roster.is_verified_trusted(
            "bob", alice_keyring)

        # La mitad del trabajo: el intercambio (claves
        # secp256k1 de la inscripción, la misma
        # identidad por peer_id). Bob publica VRAM,
        # sirve, y el historial lo cuenta — el ranking
        # sube por el trabajo, no por la entrada (que
        # fue gratis).
        led = ContributionLedger(CLUSTER)
        identity = KeyPair.new("bob")
        ch = led.issue_challenge("bob", now=NOW)
        rep = CapacityReport(
            mesh_id=CLUSTER, peer_id="bob", vram_gb=8.0,
            vram_advertised_gb=8.0, ram_gb=32.0,
            cpu_cores=8, nonce=ch.nonce, issued_at=NOW,
            expires_at=NOW + 3600,
        ).sign(identity)
        ok, why = led.admit(rep, now=NOW)
        assert ok, why
        led.observe("bob", NOW, dt_s=60)

        alice = Secp256k1KeyPair.new("alice")
        server = InferenceServer(
            server_key=Secp256k1KeyPair.new("bob"),
            llm=FakeLLMClient(), arc=_FakeArc(),
            ledger=led, peer_id="bob",
        )
        req = InferenceRequest(
            prompt="hola", mesh_id=CLUSTER,
            requester_pubkey=alice.public_key,
            funding=TxIn("ab" * 32, 0),
        )
        _, tx = await server.serve(req)
        sign_payment(tx, requester_key=alice, mesh_id=CLUSTER)
        await server.settle(tx, req)
        assert led.peers["bob"].inferences_served == 1
        assert led.peers["bob"].satoshis_earned == (
            PER_INFERENCE_SATOSHIS - 1  # 1 sat de ordinal
        )

    asyncio.run(go())


def test_a_foreign_cluster_does_not_pair():
    akey, bkey, a_keyring, b_keyring = _two_nodes()
    a_roster, _ = found(CLUSTER, "A", akey, now=NOW)
    b_roster, _ = found("otra-malla", "B", bkey, now=NOW)

    res = pair(a_roster=a_roster, a_key=akey, a_keyring=a_keyring,
               b_roster=b_roster, b_key=bkey, b_keyring=b_keyring,
               now=NOW)

    # Un roster es de un cluster: no se intenta el
    # emparejamiento (ni claves, ni avales, ni pinneo).
    assert res.pinned_a == 0 and res.pinned_b == 0
    assert not res.mutual
    assert not a_roster.is_member("B")
    assert not b_roster.is_member("A")
    assert "B" not in a_keyring and "A" not in b_keyring


def test_a_one_sided_pairing_leaves_one_side_unverified():
    akey, bkey, a_keyring, b_keyring = _two_nodes()
    a_roster, _ = found(CLUSTER, "A", akey, now=NOW)
    b_roster, _ = found(CLUSTER, "B", bkey, now=NOW)

    # La secuencia a mano, con un solo aval: A avala a
    # B, y B no avala a A. La decisión de emparejar no
    # fue mutua, y la confianza no lo es tampoco.
    a_keyring["B"] = bkey.public_key
    b_keyring["A"] = akey.public_key
    a_roster.endorse(
        akey, "B", cert_fingerprint(bkey.public_key),
        epoch=b_roster.self_epoch, now=NOW,
    )
    a_roster.reconcile(b_roster, a_keyring)
    b_roster.reconcile(a_roster, b_keyring)

    # A ve a B como verificado (A lo avaló), y B es
    # miembro del roster de A...
    assert a_roster.is_member("B")
    assert a_roster.is_verified_trusted("B", a_keyring)
    # ...pero A nunca llegó al roster de B: nadie en
    # quien B confía avaló a A. La confianza no es
    # mutua, y no lo será sin el segundo aval.
    assert not b_roster.is_member("A")
    assert not b_roster.is_verified_trusted("A", b_keyring)


def test_the_keyring_is_the_authority():
    akey, bkey, a_keyring, b_keyring = _two_nodes()
    a_roster, _ = found(CLUSTER, "A", akey, now=NOW)
    b_roster, _ = found(CLUSTER, "B", bkey, now=NOW)
    pair(a_roster=a_roster, a_key=akey, a_keyring=a_keyring,
         b_roster=b_roster, b_key=bkey, b_keyring=b_keyring,
         now=NOW)
    assert a_roster.is_verified_trusted("B", a_keyring)

    # Un intruso trata de hacerse pasar por B: funda
    # su propio roster con el id de B y SU clave, y
    # lo ofrece a A. La verificación es contra el
    # keyring — la clave que A ya tiene de B —, nunca
    # contra una clave que viaja con el mensaje: el
    # fingerprint no cuadra (re-key, que no es merge)
    # y la firma no verifica contra la clave real.
    intruso = KeyPair.new("C")
    falso, _ = found(CLUSTER, "B", intruso, now=NOW)
    pinned, _ = a_roster.reconcile(falso, a_keyring)
    assert pinned == 0
    # B sigue siendo B: el certificado que A tiene
    # es el de la clave real, y sigue verificando.
    assert a_roster.known_cert("B") == \
        cert_fingerprint(bkey.public_key)
    assert a_roster.is_verified_trusted("B", a_keyring)
