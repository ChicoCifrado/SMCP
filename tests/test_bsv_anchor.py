"""ECDSA-secp256k1 (la identidad que ancla a BSV) y el reloj del nodo.

Dos cosas que no existen en ningun otro test del repo:

1. Que una firma secp256k1 sea verificable por un tercero que solo tiene la
   clave publica — la propiedad de la que depende todo el ancla.
2. Que el nodo **retransmita** lo suyo mientras no este confirmado, que es lo
   que hace que "minada a las 12:00" signifique algo y no "minada, o
   reemplazada en silencio tres minutos despues".
"""
from __future__ import annotations

import hashlib
import os

import pytest

from delm.core import provenance
from delm.core.bsv_keys import (
    HAVE_ECDSA,
    PRIVKEY_LEN,
    PUBKEY_LEN,
    SIG_KIND,
    SIG_LEN,
    Secp256k1KeyPair,
    verify_public,
)
from delm.core.timechain import AnchorRecord, Timechain

pytestmark = pytest.mark.skipif(
    not HAVE_ECDSA, reason="requiere 'cryptography' para secp256k1")


def _d(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


# ====================================================================== claves
def test_public_key_is_33_bytes_compressed():
    """BRC-220 acepta pubkey de 33 (comprimida) o 65 bytes; la comprimida es
    la interoperable. Lo que no vale es una codificacion intermediaria."""
    k = Secp256k1KeyPair.new("n1")
    assert len(k.public_key) == PUBKEY_LEN == 33
    assert k.public_key[0] in (0x02, 0x03), "prefijo de punto comprimido"


def test_signature_is_64_bytes_r_s_not_der():
    """El formato compacto `r||s`, no DER.

    BRC-220: un lector trata 64 bytes como r||s y cualquier otra longitud como
    DER — y un DER *puede* medir 64 bytes cuando r y s son inusualmente
    cortos, en cuyo caso se lee como r||s y no verifica. `cryptography`
    emite DER de 69-72 bytes (medido), asi que la ambiguedad no nos alcanza,
    pero emitir compacto elimina la rama entera.
    """
    k = Secp256k1KeyPair.new("n1")
    sig = k.sign(_d(b"contenido"))
    assert len(sig) == SIG_LEN == 64


def test_a_third_party_with_only_the_public_key_can_verify():
    """La propiedad de la que depende todo: un verificador que NO tiene la
    clave privada, ni el objeto KeyPair, ni confianza en quien publico —
    solo la pubkey y la firma — dice que es valido."""
    k = Secp256k1KeyPair.new("nodo-emisor")
    digest = _d(b"el hash anclado")
    sig = k.sign(digest)

    # el verificador solo recibe bytes, como lo haria leyendo la cadena
    assert verify_public(k.public_key, digest, sig) is True


def test_verification_fails_for_the_three_ways_that_matter():
    """Firma alterada, digest distinto, y firma de otra clave."""
    k = Secp256k1KeyPair.new("nodo")
    digest = _d(b"d")
    sig = k.sign(digest)

    altered = bytearray(sig)
    altered[0] ^= 0xFF
    assert verify_public(k.public_key, digest, bytes(altered)) is False
    assert verify_public(k.public_key, _d(b"otro"), sig) is False
    assert verify_public(k.public_key, digest,
                         Secp256k1KeyPair.new("atacante").sign(digest)) is False


def test_provenance_dispatches_the_bsv_kind():
    """Quien recibe el ancla solo tiene `sig_kind` como string. Si tiene que
    importar el modulo del ancla para verificarlo, la interoperabilidad es
    ficticia: un verificador de fuera no tiene estos internos."""
    k = Secp256k1KeyPair.new("n")
    digest = _d(b"x")
    assert provenance.verify_public(SIG_KIND, k.public_key, digest,
                                    k.sign(digest)) is True
    # y no acepta una firma secp etiquetada como ed25519
    assert provenance.verify_public("ed25519", k.public_key, digest,
                                    k.sign(digest)) is False


def test_signature_is_low_s_canonical():
    """s <= n/2 (BIP62). Sin esto la misma clave firmando el mismo digest
    produce dos codificaciones validas de la misma firma, y el certificado
    deja de comprometer a los bytes exactos que el firmante produjo."""
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    k = Secp256k1KeyPair.new("n")
    for payload in (b"a", b"b", b"c", b"d", b"e"):
        s = int.from_bytes(k.sign(_d(payload))[32:], "big")
        assert s <= n // 2, "s no esta en forma low-S"


def test_malformed_inputs_are_rejected_not_accepted():
    """Un digest de 32 bytes es lo que SEC 1 §4.1.3 exige. Other -> error, no
    un hash inventado: re-hashear aqui seria firmar sobre otro valor."""
    k = Secp256k1KeyPair.new("n")
    with pytest.raises(ValueError, match="32"):
        k.sign(hashlib.sha256(b"x").hexdigest()[:62])
    with pytest.raises(ValueError, match="mayusculas"):
        k.sign(hashlib.sha256(b"x").hexdigest().upper())
    # firma DER de 71 bytes: no es nuestro formato, se rechaza
    assert verify_public(k.public_key, _d(b"x"), b"\x30" + b"\x00" * 70) is False
    # pubkey de 65 bytes (no comprimida): no es lo que emitimos
    assert verify_public(b"\x04" + b"\x00" * 64, _d(b"x"), b"\x00" * 64) is False


def test_persistence_roundtrip_keeps_the_identity(tmp_path):
    """Un nodo que regenera su clave en cada invocacion no puede atribuir nada
    a un par estable — y sin identidad estable no hay ancla que valga."""
    p = str(tmp_path / "k.json")
    k = Secp256k1KeyPair.new("nodo-estable")
    k.save(p)
    back = Secp256k1KeyPair.load(p)

    assert back.public_key == k.public_key
    assert back.author_id == "nodo-estable"
    # y la clave recuperada firma algo que la original verifica
    digest = _d(b"tras reiniciar")
    assert k.verify(digest, back.sign(digest)) is True
    # el fichero es secreto: 0600
    assert oct(os.stat(p).st_mode)[-3:] == "600"


def test_private_bytes_roundtrip():
    k = Secp256k1KeyPair.new("n")
    raw = k._priv.private_numbers().private_value.to_bytes(PRIVKEY_LEN, "big")
    assert Secp256k1KeyPair.from_private_bytes("n", raw).public_key == k.public_key
    with pytest.raises(ValueError, match="32"):
        Secp256k1KeyPair.from_private_bytes("n", b"\x00" * 31)


# ==================================================================== timechain
def _rec(txid: str) -> AnchorRecord:
    return AnchorRecord(txid=txid, certificate={"rawTx": f"raw-{txid}",
                                                 "txid": txid})


def test_node_persists_what_it_published(tmp_path):
    """Cada nodo guarda sus transacciones: un nodo que olvida lo que publico
    no puede defender que lo publico a esa hora."""
    path = str(tmp_path / "anchors.jsonl")
    chain = Timechain(path=path)
    chain.add(_rec("tx-a"))
    chain.add(_rec("tx-b"))

    back = Timechain.load(path)
    assert [r.txid for r in back.records] == ["tx-a", "tx-b"]
    assert back.records[0].certificate["rawTx"] == "raw-tx-a"
    assert all(r.first_broadcast > 0 for r in back.records)


def test_restart_forgets_the_proof_but_keeps_the_claim(tmp_path):
    """Al reiniciar, `proven` vuelve a False: este nodo no ha comprobado
    nada en esta ejecucion. Dejar True de una corrida anterior seria una
    afirmacion que ya no puede respaldar."""
    path = str(tmp_path / "a.jsonl")
    chain = Timechain(path=path)
    chain.add(_rec("tx"))
    chain.records[0].proven = True
    chain.records[0].block_height = 900000
    chain._flush()

    back = Timechain.load(path)
    assert back.records[0].block_height == 900000   # la claim se conserva
    assert back.records[0].proven is False          # la prueba, no


def test_unconfirmed_transactions_are_rebroadcast_every_time():
    """El bucle del reloj. Una transaccion no confirmada sigue siendo
    reemplazable: quien la tenga en mempool puede meter otra con el mismo
    input. Si el nodo solo reenvia una vez, la ventana sigue abierta."""
    sent: list[str] = []

    def sender(txid, payload):
        sent.append(txid)
        return True

    chain = Timechain()
    chain.add(_rec("tx-1"))
    chain.add(_rec("tx-2"))

    assert chain.rebroadcast(sender) == ["tx-1", "tx-2"]
    assert chain.rebroadcast(sender) == ["tx-1", "tx-2"]   # otra vez
    assert chain.rebroadcast(sender) == ["tx-1", "tx-2"]   # y otra
    assert len(sent) == 6
    assert all(r.rebroadcasts == 3 for r in chain.records)


def test_a_freshly_published_transaction_is_never_left_out():
    """Reenviar solo "las que tienen mas de N segundos" dejaria una ventana
    sin proteccion justo despues de publicar — que es la ventana del
    ataque. Por eso se reenvia todo lo no confirmado, siempre."""
    chain = Timechain()
    for i in range(5):
        chain.add(_rec(f"tx-{i}"))
    # todas son recien publicadas, ninguna tiene "edad"
    assert len(chain.pending()) == 5
    assert len(chain.rebroadcast(lambda t, p: True)) == 5


def test_confirmed_transactions_stop_being_rebroadcast():
    """Una vez en un bloque, la ventana de reemplazo se cierra: seguir
    reenviando es ruido."""
    sent: list[str] = []
    chain = Timechain()
    chain.add(_rec("tx-1"))
    chain.add(_rec("tx-2"))
    chain.mark_mined("tx-1", 900001, 1767225600)

    got = chain.rebroadcast(lambda t, p: sent.append(t) or True)
    assert got == ["tx-2"]
    assert "tx-1" not in sent


def test_a_dead_relay_does_not_stop_the_others():
    """Si un relé falla, los reintentos de los demás no se pierden: cada
    transaccion no confirmada necesita su propio reenvio, y una excepcion en
    uno no puede tragarse al resto."""
    def sender(txid, payload):
        if txid == "tx-1":
            raise ConnectionError("relay caido")
        return True

    chain = Timechain()
    chain.add(_rec("tx-1"))
    chain.add(_rec("tx-2"))
    got = chain.rebroadcast(sender)
    assert got == ["tx-2"], "el fallo de uno no debe tragarse al resto"
    assert chain.records[0].rebroadcasts == 0
    assert chain.records[1].rebroadcasts == 1


def test_status_does_not_claim_the_timestamps_are_proven():
    """`mark_mined` registra lo que la cadena dijo, no que alguien comprobó
    la inclusion. El estado distingue las dos cosas a proposito."""
    chain = Timechain()
    chain.add(_rec("tx-1"))
    chain.add(_rec("tx-2"))
    chain.mark_mined("tx-1", 900001, 1767225600)

    st = chain.status()
    assert st["node_records"] == 2
    assert st["unconfirmed"] == 1
    assert st["reported_by_chain"] == 1
    assert st["proven"] == 0, "nadie ha verificado una prueba SPV todavia"
    assert st["spv_verified"] is False, "la Fase 2 todavia no existe"
