"""Identidad — el handshake BRC-103 que prueba el join.

El intercambio de claves del join **afirma** la clave
del par; el handshake prueba que el par la controla.
Aquí se verifica la prueba en sus dos direcciones y
se atacan las dos vías del MITM: sustituir la clave
(y la firma no verifica contra ella) y repetir la
prueba de otra sesión (y el nonce del par no casa).
"""
from __future__ import annotations

from smcp.core.identidad import (
    NONCE_BYTES,
    HandshakeProof,
    Session,
    handshake,
    new_nonce,
    sign_handshake,
    verify_handshake,
)
from smcp.core.join import found, pair
from smcp.core.provenance import KeyPair


def _keys() -> tuple[KeyPair, KeyPair]:
    return KeyPair.new("a"), KeyPair.new("b")


def test_el_nonce_es_fresco() -> None:
    n = new_nonce()
    assert len(n) == NONCE_BYTES == 32
    assert new_nonce() != new_nonce()


def test_el_handshake_se_verifica_en_ambos_sentidos() -> None:
    a, b = _keys()
    s = handshake(a_key=a, b_key=b)
    # cada prueba viaja con la clave que la firmó
    assert s.a_proof.identity_key == a.public_key
    assert s.b_proof.identity_key == b.public_key
    assert s.verified(a_key=a, b_key=b) is True
    # y quien verifica puede hacerlo solo con su nonce:
    # B verifica la prueba de A con el nonce de B.
    assert verify_handshake(s.a_proof, my_nonce=s.b_nonce) is True
    assert verify_handshake(s.b_proof, my_nonce=s.a_nonce) is True


def test_una_clave_sustituida_no_verifica() -> None:
    # MITM: la prueba de B (su firma, sus nonces) viaja
    # con la clave del atacante. La firma no verifica
    # contra ella.
    a, b = _keys()
    eva = KeyPair.new("eva")
    s = handshake(a_key=a, b_key=b)
    mitt = Session(
        a_nonce=s.a_nonce, b_nonce=s.b_nonce,
        a_proof=s.a_proof,
        b_proof=HandshakeProof(
            identity_key=eva.public_key,
            sig_kind=s.b_proof.sig_kind,
            nonce=s.b_proof.nonce,
            peer_nonce=s.b_proof.peer_nonce,
            signature=s.b_proof.signature,
        ),
    )
    assert mitt.verified(a_key=a, b_key=b) is False


def test_un_replay_de_otra_sesion_no_cuadra() -> None:
    # Las pruebas son de otra sesión: los nonces de
    # esta no casan con los que las pruebas firman.
    a, b = _keys()
    s1 = handshake(a_key=a, b_key=b)
    s2 = handshake(a_key=a, b_key=b)
    replay = Session(
        a_nonce=s2.a_nonce, b_nonce=s2.b_nonce,
        a_proof=s1.a_proof, b_proof=s1.b_proof,
    )
    assert replay.verified(a_key=a, b_key=b) is False


def test_verify_handshake_rechaza_nonces_malformados() -> None:
    a, b = _keys()
    s = handshake(a_key=a, b_key=b)
    # nonce propio de longitud rara
    assert verify_handshake(s.b_proof, my_nonce=b"\x00" * 31) is False
    # nonce propio que no es el de la sesión
    assert verify_handshake(s.b_proof, my_nonce=new_nonce()) is False
    # firmar con nonces mal formados lanza
    try:
        sign_handshake(a, peer_nonce=b"\x00", own_nonce=s.a_nonce)
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("nonces cortos deben lanzar")


def test_pair_con_sesion_cierra_autenticado() -> None:
    a, b = _keys()
    ra, ka = found("c", "a", a)
    rb, kb = found("c", "b", b)
    s = handshake(a_key=a, b_key=b)
    r = pair(a_roster=ra, a_key=a, a_keyring=ka,
             b_roster=rb, b_key=b, b_keyring=kb, session=s)
    assert r.mutual is True
    assert r.authenticated is True


def test_pair_falla_cerrado_con_sesion_tampeada() -> None:
    # MITM en el cable: la prueba de B viaja con la
    # clave del atacante. El join no sigue — no hay
    # intercambio de claves, no hay avales, no hay nada.
    a, b = _keys()
    eva = KeyPair.new("eva")
    ra, ka = found("c", "a", a)
    rb, kb = found("c", "b", b)
    s = handshake(a_key=a, b_key=b)
    mitt = Session(
        a_nonce=s.a_nonce, b_nonce=s.b_nonce,
        a_proof=s.a_proof,
        b_proof=HandshakeProof(
            identity_key=eva.public_key,
            sig_kind=s.b_proof.sig_kind,
            nonce=s.b_proof.nonce,
            peer_nonce=s.b_proof.peer_nonce,
            signature=s.b_proof.signature,
        ),
    )
    r = pair(a_roster=ra, a_key=a, a_keyring=ka,
             b_roster=rb, b_key=b, b_keyring=kb, session=mitt)
    assert r.authenticated is False
    assert r.mutual is False
    assert r.pinned_a == 0 and r.pinned_b == 0
    # nada se intercambió: el keyring sigue sin la clave
    # del par, y el roster sigue sin avales nuevos.
    assert "b" not in ka and "a" not in kb
    assert len(ra.members) == 1 and len(rb.members) == 1


def test_pair_sin_sesion_sigue_siendo_el_intercambio_simple() -> None:
    # Sin sesión, el join es el de hoy: la clave del par
    # se afirma sin probar su control, y el resultado lo
    # dice (authenticated=None) en vez de ocultarlo.
    a, b = _keys()
    ra, ka = found("c", "a", a)
    rb, kb = found("c", "b", b)
    r = pair(a_roster=ra, a_key=a, a_keyring=ka,
             b_roster=rb, b_key=b, b_keyring=kb)
    assert r.mutual is True
    assert r.authenticated is None
    assert "b" in ka and "a" in kb
