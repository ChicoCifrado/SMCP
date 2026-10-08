"""test_join_wire: el join v3 por el transporte.

El mismo flujo que ``test_join`` — fundar,
handshake BRC-103, avales mutuos, reconciliar—
pero con los mensajes **por el transporte**:
dos nodos sobre un bus in-memory, cada mensaje
atendido a mano (sin hilos: la secuencia es
determinista paso a paso).

Lo que sujetan los tests, en orden de importancia:

1. el join completo por el transporte: handshake
   en los dos sentidos, rosters, confianza mutua
   verificada;
2. que una clave sustituida (MITM) falla cerrado:
   la prueba falsificada "verifica" (es
   consistente), pero el roster del par no cuadra
   con la clave que probó — nada se pinnea;
3. que una prueba de otra sesión (replay) no
   verifica: el nonce del par no casa;
4. el formato de los mensajes (ida y vuelta de la
   codificación) y que los malformados se dicen.
"""
from __future__ import annotations

import json

import pytest

from smcp.core.identidad import new_nonce, sign_handshake
from smcp.core.join import found
from smcp.core.mensajeria import (
    KIND_HANDSHAKE,
    KIND_ROSTER,
    JoinWire,
    decode_handshake_init,
    decode_handshake_proof,
    decode_roster,
    encode_handshake_init,
    encode_handshake_proof,
    encode_roster,
)
from smcp.core.membership import ProtocolError
from smcp.core.mesh_node import decode_msg
from smcp.core.provenance import KeyPair
from smcp.core.roster import Roster
from smcp.core.transport import InMemoryTransport, _Bus

CLUSTER = "malla-v3"
NOW = 1_000.0


def _two_wire_nodes() -> tuple[
        JoinWire, JoinWire, Roster, Roster,
        dict[str, bytes], dict[str, bytes],
        InMemoryTransport, InMemoryTransport]:
    """Dos nodos, cada uno con su roster fundado,
    sobre un bus in-memory compartido."""
    akey, bkey = KeyPair.new("A"), KeyPair.new("B")
    a_roster, a_keyring = found(CLUSTER, "A", akey, now=NOW)
    b_roster, b_keyring = found(CLUSTER, "B", bkey, now=NOW)
    bus = _Bus()
    a_t = InMemoryTransport(bus, "A")
    b_t = InMemoryTransport(bus, "B")
    a = JoinWire(transport=a_t, roster=a_roster,
                 key=akey, keyring=a_keyring)
    b = JoinWire(transport=b_t, roster=b_roster,
                 key=bkey, keyring=b_keyring)
    return (a, b, a_roster, b_roster, a_keyring,
            b_keyring, a_t, b_t)


def test_the_whole_join_over_the_transport():
    """El join completo, mensaje a mensaje."""
    (a, b, a_roster, b_roster, a_keyring,
     b_keyring, _, _) = _two_wire_nodes()

    # La secuencia, paso a paso: cada pump()
    # atiende lo que llegó y puede enviar.
    a.start("B")                  # INIT viaja a B
    assert b.pump() is None       # B genera su nonce, firma y envía su PROOF
    assert a.pump() is None       # A verifica, firma, y envía PROOF + ROSTER (crudo)
    assert b.pump() is None       # B verifica, envía ROSTER (crudo), avala a A y
                                  # envía ROSTER (avalado) — aún sin cerrar
    res_a = a.pump()              # A avala a B y cierra: el roster de B
                                  # trae su aval a A
    assert res_a is not None
    assert res_a.mutual
    assert res_a.authenticated is True
    res_b = b.pump()              # B cierra: el roster de A trae su aval a B
    assert res_b is not None
    assert res_b.mutual
    assert res_b.authenticated is True

    # La propiedad del join: cada nodo ve al otro
    # como verificado (alguien en quien ya confía
    # avaló esa admisión), con la clave del par
    # en su keyring y al par en su roster.
    assert a_keyring["B"] == b._key.public_key
    assert b_keyring["A"] == a._key.public_key
    assert a_roster.is_member("B") and b_roster.is_member("A")
    assert a_roster.is_verified_trusted("B", a_keyring)
    assert b_roster.is_verified_trusted("A", b_keyring)
    assert res_a.pinned_a >= 1 and res_b.pinned_a >= 1


def test_a_substituted_key_fails_closed():
    """Un MITM que firma con su propia clave no
    pinnea nada: el roster del par no cuadra con
    la clave que probó."""
    (a, b, a_roster, b_roster, a_keyring,
     b_keyring, a_t, b_t) = _two_wire_nodes()
    mitm = KeyPair.new("MITM")

    a.start("B")
    assert b.pump() is None       # B firma bien: su PROOF viaja a A
    # El MITM intercepta la prueba de B y la
    # sustituye por una firmada con su propia
    # clave (conoce los nonces: viajan en claro).
    proof_b = decode_handshake_proof(
        decode_msg(a_t.poll()[0][1])[1])
    forged = sign_handshake(
        mitm, peer_nonce=proof_b.peer_nonce,
        own_nonce=proof_b.nonce,
    )
    b_t.send("A", encode_handshake_proof(forged))
    # La prueba falsificada es consistente (verifica
    # contra la clave del MITM): A completa su
    # mitad y envía su PROOF y su ROSTER.
    assert a.pump() is None
    # B empareja con A de verdad (la prueba de A
    # es genuina): avala a A y envía su roster
    # avalado — pero su cierre aún no vuelve.
    assert b.pump() is None
    # ... pero A recibe el roster de B, y el
    # certificado que declara no es el de la
    # clave que probó: sustitución. El join falla
    # cerrado — no se avaló nada, no se pinneó
    # nada, no hay confianza.
    res_a = a.pump()
    assert res_a is not None
    assert not res_a.mutual
    assert res_a.authenticated is False
    assert not a_roster.is_member("B")
    assert "B" not in a_keyring
    # B sí cerró con A: la prueba de A era
    # genuina, y A firmó con su propia clave.
    assert b_roster.is_verified_trusted("A", b_keyring)


def test_a_replayed_proof_does_not_verify():
    """Una prueba de otra sesión no cuadra: el
    nonce del par no es el de esta."""
    a, _, _, _, _, _, _, b_t = _two_wire_nodes()

    a.start("B")
    # En lugar de la prueba de B, una prueba
    # firmada pero sobre nonces de otra sesión:
    # la firma verifica, el nonce no casa.
    other = sign_handshake(
        KeyPair.new("otra"), peer_nonce=new_nonce(),
        own_nonce=new_nonce(),
    )
    b_t.send("A", encode_handshake_proof(other))
    with pytest.raises(ProtocolError, match="no verifica"):
        a.pump()


def test_the_wire_format_round_trips():
    """Los mensajes de join se codifican y se
    decodifican iguales."""
    akey = KeyPair.new("A")
    nonce = new_nonce()

    # INIT (0x03, fase init)
    payload = encode_handshake_init(akey.public_key, nonce)
    kind, body = decode_msg(payload)
    assert kind == KIND_HANDSHAKE
    identity_key, nonce2 = decode_handshake_init(body)
    assert identity_key == akey.public_key
    assert nonce2 == nonce

    # PROOF (0x03, fase proof)
    proof = sign_handshake(
        akey, peer_nonce=new_nonce(), own_nonce=new_nonce(),
    )
    payload = encode_handshake_proof(proof)
    kind, body = decode_msg(payload)
    assert kind == KIND_HANDSHAKE
    assert decode_handshake_proof(body) == proof

    # ROSTER (0x08): el roster y el keyring.
    roster, keyring = found(CLUSTER, "A", akey, now=NOW)
    payload = encode_roster(roster, keyring)
    kind, body = decode_msg(payload)
    assert kind == KIND_ROSTER
    roster2, keyring2 = decode_roster(body)
    assert roster2.cluster_id == roster.cluster_id
    assert roster2.self_id == roster.self_id
    assert roster2.member_ids() == roster.member_ids()
    assert keyring2 == keyring


def test_malformed_messages_are_said_not_ignored():
    """Un mensaje de join malformado es un error,
    no un mensaje vacío."""
    # Un init que no es un init.
    with pytest.raises(ProtocolError):
        decode_handshake_init(
            json.dumps({"phase": "proof"}).encode("utf-8"))
    # No es JSON.
    with pytest.raises(ProtocolError):
        decode_handshake_init(b"no es json")
    # Una prueba cuya clave no es hex.
    with pytest.raises(ProtocolError):
        decode_handshake_proof(json.dumps({
            "phase": "proof", "identity_key": "zzz",
            "sig_kind": "ed25519", "nonce": "ab" * 32,
            "peer_nonce": "cd" * 32,
            "signature": "ef" * 64,
        }).encode("utf-8"))
    # Un roster cuya forma no es la del roster.
    with pytest.raises(ProtocolError):
        decode_roster(json.dumps(
            {"roster": ["no"], "keyring": {}},
        ).encode("utf-8"))
    # Un roster sin keyring.
    with pytest.raises(ProtocolError):
        decode_roster(json.dumps({"roster": {}}).encode("utf-8"))
