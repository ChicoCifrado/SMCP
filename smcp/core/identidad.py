"""Identidad — auth mutua (BRC-103) para el join.

Qué resuelve este módulo
------------------------
El join v3 (:mod:`smcp.core.join`) intercambia claves
públicas off-chain, pero el intercambio **afirma** la
clave del par sin probar que la controla: un MITM activo
puede sustituir la clave en el cable, y el aval acaba
firmado contra la clave del atacante. La confianza del
roster es transitiva, pero solo sobre claves que nadie
probó que son de quien dicen ser.

BRC-103 cierra eso con un handshake: cada lado genera un
nonce fresco (32 bytes, CSPRNG) y **firma
(nonce_del_par ‖ nonce_propio)** con su clave de
identidad — la misma :class:`smcp.core.provenance.KeyPair`
que avala el roster. Quien verifica la prueba contra la
clave que le llega tiene prueba de control **vivo** de
esa clave, ligada a esta sesión por los nonces: un
replay de otra sesión no cuadra (el nonce del par no
casa) y una sustitución no cuadra (la firma no verifica
contra la clave sustituida).

Variante simétrica
------------------
BRC-103 en su forma más simple autentica solo al
respondedor (su respuesta firma ambos nonces). El join
es simétrico — ningún nodo es el iniciador —, así que
aquí **los dos lados firman** (nonce_del_par ‖
nonce_propio): la misma prueba en ambos sentidos, y el
resultado es auth mutua, no solo de un lado.

Desviación documentada
----------------------
BRC-103 firma con derivación BRC-100 (protocolID /
keyID / counterparty, BRC-42/43). SMCP firma con la
clave de identidad directamente — la misma clave que
avala el roster —, porque la malla no tiene derivación
de claves. La propiedad que importa (prueba de control
de la clave que el roster avala) se preserva, y el
preimage es de formato fijo, como en el resto de la v3.

Lo que este módulo NO hace
--------------------------
* No es BRC-52: los certificados de identidad (campos
  firmados por un certificador, revelación selectiva,
  revocación por outpoint) necesitan una política de
  certificadores — una decisión de diseño, no código.
  El handshake es la capa de auth mutua; los
  certificados se añadirían *sobre* él (BRC-103 los
  lleva en los mensajes).
* No es transporte: los mensajes son llamadas, como en
  el resto de la v3.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Protocol

from smcp.core.provenance import KeyPair, verify_public

__all__ = [
    "NONCE_BYTES",
    "HandshakeProof",
    "PublicKeyed",
    "Session",
    "handshake",
    "new_nonce",
    "sign_handshake",
    "verify_handshake",
]


class PublicKeyed(Protocol):
    """Lo que la verificación de sesión necesita de
    una clave: su parte pública.

    :class:`~smcp.core.provenance.KeyPair` lo cumple
    (la clave completa, en proceso) y
    :class:`~smcp.core.join.PeerIdentity` también
    (la identidad de un par que llegó por el cable —
    su clave privada nunca viaja).
    """

    public_key: bytes


#: Longitud de un nonce de sesión (BRC-103 §6.2: 256
#: bits, generador criptográficamente seguro).
NONCE_BYTES = 32


def new_nonce() -> bytes:
    """Un nonce de sesión: 32 bytes de CSPRNG."""
    return secrets.token_bytes(NONCE_BYTES)


def handshake_digest(peer_nonce: bytes, own_nonce: bytes) -> str:
    """El preimage firmado: ``SHA-256(peer ‖ own)`` en hex."""
    return hashlib.sha256(peer_nonce + own_nonce).hexdigest()


@dataclass(frozen=True)
class HandshakeProof:
    """La prueba de un lado: su nonce, el del par y la firma.

    La firma es sobre :func:`handshake_digest`, hecha con
    la clave de identidad del que firma — y
    ``sig_kind`` + ``identity_key`` viajan con ella: la
    verificación es contra la clave que se intercambia,
    no contra una que el verificador suponga.
    """

    identity_key: bytes
    sig_kind: str
    nonce: bytes
    peer_nonce: bytes
    signature: bytes


def sign_handshake(key: KeyPair, *, peer_nonce: bytes,
                   own_nonce: bytes) -> HandshakeProof:
    """Firma el handshake por un lado (el respondedor, en BRC-103)."""
    if len(own_nonce) != NONCE_BYTES or len(peer_nonce) != NONCE_BYTES:
        raise ValueError(
            "nonces de "
            f"{len(own_nonce)}/{len(peer_nonce)} bytes; el handshake "
            f"firma exactamente {NONCE_BYTES} por lado"
        )
    return HandshakeProof(
        identity_key=key.public_key,
        sig_kind=key.kind,
        nonce=own_nonce,
        peer_nonce=peer_nonce,
        signature=key.sign(handshake_digest(peer_nonce, own_nonce)),
    )


def verify_handshake(proof: HandshakeProof, *, my_nonce: bytes) -> bool:
    """¿La prueba autentica a su firmante, en *esta* sesión?

    Las dos comprobaciones son las del MITM: el nonce del
    par debe ser **el propio** (liga la prueba a esta
    sesión — un replay de otra sesión no casa), y la firma
    debe verificar contra la clave de identidad que la
    prueba trae (una clave sustituida no verifica).
    """
    if len(my_nonce) != NONCE_BYTES:
        return False
    if proof.peer_nonce != my_nonce:
        return False
    if len(proof.nonce) != NONCE_BYTES:
        return False
    return verify_public(
        proof.sig_kind,
        proof.identity_key,
        handshake_digest(proof.peer_nonce, proof.nonce),
        proof.signature,
    )


@dataclass(frozen=True)
class Session:
    """Una sesión de handshake: los dos nonces y las dos pruebas.

    ``a_proof`` es la firma de A (sobre ``b_nonce ‖ a_nonce``)
    y ``b_proof`` la de B (sobre ``a_nonce ‖ b_nonce``) —
    cada uno firma (nonce_del_par ‖ nonce_propio).
    """

    a_nonce: bytes
    b_nonce: bytes
    a_proof: HandshakeProof
    b_proof: HandshakeProof

    def verified(self, *, a_key: PublicKeyed,
                 b_key: PublicKeyed) -> bool:
        """¿Ambas pruebas casan con las claves que se intercambian?"""
        return (
            self.a_proof.identity_key == a_key.public_key
            and self.b_proof.identity_key == b_key.public_key
            and verify_handshake(self.a_proof, my_nonce=self.b_nonce)
            and verify_handshake(self.b_proof, my_nonce=self.a_nonce)
        )


def handshake(*, a_key: KeyPair, b_key: KeyPair) -> Session:
    """El handshake BRC-103 entre dos nodos, offline.

    Simétrico: cada lado genera su nonce y firma
    (nonce_del_par ‖ nonce_propio). En el cable serían
    dos idas y vueltas (A envía su nonce; B responde con
    el suyo y su firma; A completa con la suya); aquí,
    como en :func:`smcp.core.join.pair`, los dos papeles
    son llamadas.
    """
    a_nonce, b_nonce = new_nonce(), new_nonce()
    a_proof = sign_handshake(
        a_key, peer_nonce=b_nonce, own_nonce=a_nonce)
    b_proof = sign_handshake(
        b_key, peer_nonce=a_nonce, own_nonce=b_nonce)
    return Session(
        a_nonce=a_nonce, b_nonce=b_nonce,
        a_proof=a_proof, b_proof=b_proof,
    )
