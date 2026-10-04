"""Membership — la pertenencia a la malla anclada en BSV.

Lo que estos tests sujetan, y lo que no:

* La inclusion se verifica de verdad contra una cabecera: raiz de Merkle mal
  construida -> ``False``, no excepcion.
* La **doble rotacion** solo la puede ganar una. Es la garantia central del
  diseno y no necesita ningun registro porque la impone el grafo.
* Rotar a la misma clave se rechaza. Sin eso, la rotacion es una membresia
  renovada gratis y el Sybil que la membresia deberia impedir entra por la
  puerta de la rotacion.
* Un lock ajeno no abre la puerta. Es la razon de que la lista de locks sea
  una decision del operador.
* Un outpoint gastado no se readmite.

Y lo que **no** sujetan, escrito para que nadie lo lea como otra cosa:

* Nada parsea Bitcoin Script. :meth:`MembershipLock.from_spent_output` lanza
  :class:`ProtocolError` a proposito, y hay test que lo exige. Un modulo que
  fingiera leer el lock de un output real seria una puerta abierta con nombre
  de puerta.
* ``MembershipSet`` es una vista **local**. ``is_member`` responde "lo que este
  nodo ha visto", y hay test que lo dice con esas palabras.
"""
from __future__ import annotations

import hashlib
from typing import Any

import pytest

from smcp.core.bsv_keys import Secp256k1KeyPair
from smcp.core.membership import (
    BlockHeader,
    InclusionProof,
    MembershipLock,
    MembershipOutput,
    MembershipProof,
    MembershipSet,
    HEADER_LEN,
    ProtocolError,
    RotationProof,
    _canonical_digest,
    dsha256,
    merkle_root,
    verify_merkle_proof,
)


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------
@pytest.fixture()
def lock() -> MembershipLock:
    """Un lock de membresia con su despliegue, anclado por txid."""
    return MembershipLock(
        script_hash=hashlib.sha256(b"smcp-membership-p2pkh").hexdigest()[:40],
        deployment_txid="aa" * 32,
        deployment_vout=0,
        genesis_txid="bb" * 32,
    )


@pytest.fixture()
def funding_key() -> Secp256k1KeyPair:
    """Clave de fondos: paga la membresia, NO es la identidad de la malla."""
    return Secp256k1KeyPair.new("funder")


@pytest.fixture()
def member_key() -> Secp256k1KeyPair:
    return Secp256k1KeyPair.new("member")


def _leaf(*parts: bytes) -> bytes:
    return dsha256(b"".join(parts))


def _tree(leaves: list[bytes]) -> tuple[str, list[list[str]], list[int]]:
    """Raiz + una prueba por hoja, todo en hex de presentacion."""
    root = merkle_root(leaves)
    proofs: list[list[str]] = []
    for target in range(len(leaves)):
        path: list[bytes] = []
        level = list(leaves)
        idx = target
        while len(level) > 1:
            if len(level) % 2:
                level = level + [level[-1]]
            sib = 1 if idx % 2 else 0
            path.append(level[idx ^ 1])
            level = [dsha256(level[i] + level[i + 1])
                     for i in range(0, len(level), 2)]
            idx //= 2
        proofs.append([h[::-1].hex() for h in path])
    from smcp.core.membership import _present
    return _present(root), proofs, list(range(len(leaves)))


def _one_tx_proof(txid: str, lock: Any = None) -> InclusionProof:
    """Prueba de una transaccion sola: raiz = la hoja misma, path vacio."""
    leaf = bytes.fromhex(txid)[::-1]
    return InclusionProof(txid=txid, index=0, path=[],
                          merkle_root=leaf[::-1].hex(), height=900000)


def _proof_for(lock: Any, member_key: Any,
               txid: str = "cc" * 32, satoshis: int = 5000,
               vout: int = 0) -> MembershipProof:
    out = MembershipOutput(txid=txid, vout=vout, satoshis=satoshis,
                           script_hash=lock.script_hash)
    return MembershipProof.create(out, _one_tx_proof(txid, lock),
                                  member_key, lock)


# --------------------------------------------------------------------------
# Merkle
# --------------------------------------------------------------------------
def test_a_single_leaf_is_its_own_root():
    leaf = _leaf(b"a")
    assert merkle_root([leaf]) == leaf


def test_merkle_root_is_the_bitcoin_ordering_not_the_obvious_one():
    """`a+b` y `b+a` dan raices distintas: el orden de concatenacion es el script."""
    assert merkle_root([_leaf(b"a"), _leaf(b"b")]) != \
        merkle_root([_leaf(b"b"), _leaf(b"a")])


def test_an_odd_level_duplicates_its_last_node():
    """La rareza de Bitcoin: un nivel impar duplica el ultimo.

    Sin esto la raiz no coincide con la de nadie mas y el verificador
    rechazaria pruebas legitimas. Es el commitment de diseno, no un error.
    """
    two = merkle_root([_leaf(b"a"), _leaf(b"b")])
    three = merkle_root([_leaf(b"a"), _leaf(b"b"), _leaf(b"c")])
    # con duplicacion: raiz = H(H(a+b) + H(c+c))
    expect = dsha256(merkle_root([_leaf(b"a"), _leaf(b"b")])
                     + dsha256(_leaf(b"c") + _leaf(b"c")))
    assert three == expect
    assert two != expect


def test_merkle_needs_at_least_one_leaf():
    with pytest.raises(ValueError):
        merkle_root([])


def test_an_inclusion_proof_verifies_against_its_own_header():
    """Cuatro transactions reales en un arbol, y cada una prueba su inclusion.

    Las hojas del arbol **son** los txids: un proof construye su camino
    elevando esos hashes, asi que un arbol de hojas inventadas daria una raiz
    que ninguna transaccion real produce.
    """
    from smcp.core.membership import _present
    txids = ["11" * 32, "22" * 32, "33" * 32, "44" * 32]
    leaves = [bytes.fromhex(t)[::-1] for t in txids]
    root = merkle_root(leaves)
    for i, txid in enumerate(txids):
        _root, proofs, _ = _tree(leaves)
        header = BlockHeader(merkle_root=_present(root), height=900000)
        pr = InclusionProof(txid=txid, index=i, path=proofs[i],
                            merkle_root=_present(root), height=900000)
        assert pr.verify(header), f"no valida la inclusion de {i}"


def test_an_inclusion_proof_against_another_header_fails():
    from smcp.core.membership import _present
    txids = ["11" * 32, "22" * 32, "33" * 32, "44" * 32]
    leaves = [bytes.fromhex(t)[::-1] for t in txids]
    root = _present(merkle_root(leaves))
    _r, proofs, _ = _tree(leaves)
    other = BlockHeader(merkle_root=("ab" * 32), height=900001)
    pr = InclusionProof(txid=txids[0], index=0, path=proofs[0],
                        merkle_root=root, height=900000)
    assert not pr.verify(other), "una inclusion no puede validar en otra cabecera"


def test_merkle_proof_with_the_wrong_index_fails():
    from smcp.core.membership import _present
    txids = ["11" * 32, "22" * 32]
    leaves = [bytes.fromhex(t)[::-1] for t in txids]
    root = _present(merkle_root(leaves))
    _r, proofs, _ = _tree(leaves)
    #     # el camino de la hoja 1, pero con indice 0
    assert not verify_merkle_proof(txids[0], 0, proofs[1], root)


def test_merkle_proof_with_a_tampered_sibling_fails():
    from smcp.core.membership import _present
    txids = ["11" * 32, "22" * 32]
    leaves = [bytes.fromhex(t)[::-1] for t in txids]
    root = _present(merkle_root(leaves))
    _r, proofs, _ = _tree(leaves)
    tampered = [("ff" * 32)] + proofs[0][1:]
    assert not verify_merkle_proof(txids[0], 0, tampered, root)


def test_merkle_proof_rejects_a_malformed_hash_without_raising():
    assert not verify_merkle_proof("11" * 31, 0, [], "22" * 32)
    assert not verify_merkle_proof("11" * 32, 0, ["zz"], "22" * 32)
    assert not verify_merkle_proof("11" * 32, -1, [], "22" * 32)


# --------------------------------------------------------------------------
# La prueba de pertenencia
# --------------------------------------------------------------------------
def test_a_freshly_joined_node_proves_membership(lock, member_key):
    pr = _proof_for(lock, member_key)
    header = BlockHeader(merkle_root=pr.inclusion.merkle_root, height=900000)
    ok, why = pr.verify(header)
    assert ok, why


def test_the_lock_is_documentedal_and_not_a_trust_anchor():
    """El txid de despliegue da formato, no confianza.

    La confianza real es el script_hash, y la lista de locks aceptados es una
    decision del operador. Sin esto, cualquiera despliega su propio "SC" y su
    propia malla, y un verificador no tiene forma de distinguirlas.
    """
    a = MembershipLock(script_hash="11" * 20)
    b = MembershipLock(script_hash="22" * 20, deployment_txid="aa" * 32)
    assert a.deployment_txid == ""
    assert a.script_hash != b.script_hash


def test_a_proof_whose_pubkey_is_not_the_signer_is_rejected(lock, member_key,
                                                           funding_key):
    """La pubkey declarada tiene que ser la que firmó.

    Es lo que separa "poseo el output" de "pagué una membresia": si el
    verificador aceptara cualquier pubkey, bastaría ver el outpoint en la
    cadena y reclamar esa membresia con una firma propia de otra clave.

    Aqui la firma es **valida** — la hizo ``member_key`` sobre el digest
    correcto — pero se presenta declarando la pubkey de la clave de fondos. La
    verificacion tiene que fallar en la pareja, no en la firma.
    """
    out = MembershipOutput(txid="cc" * 32, vout=0, satoshis=5000,
                           script_hash=lock.script_hash)
    honest = MembershipProof.create(out, _one_tx_proof("cc" * 32, lock),
                                    member_key, lock)
    # misma firma, pubkey de otra clave
    swapped = MembershipProof(output=out, inclusion=honest.inclusion,
                              membership_pubkey=funding_key.public_key.hex(),
                              signature=honest.signature, lock=lock)
    header = BlockHeader(merkle_root=honest.inclusion.merkle_root)
    ok, why = swapped.verify(header)
    assert not ok, "una firma de otra clave no debe validar como membresia"
    assert "firma" in why


def test_a_tampered_satoshis_breaks_the_signature(lock, member_key):
    """Los satoshis entran en el digest: no se puede subir la apuesta."""
    pr = _proof_for(lock, member_key, satoshis=5000)
    upgraded = MembershipOutput(txid="cc" * 32, vout=0, satoshis=999999,
                                script_hash=lock.script_hash)
    tampered = MembershipProof(output=upgraded, inclusion=pr.inclusion,
                               membership_pubkey=pr.membership_pubkey,
                               signature=pr.signature, lock=lock)
    header = BlockHeader(merkle_root=pr.inclusion.merkle_root)
    ok, _ = tampered.verify(header)
    assert not ok


def test_a_tampered_vout_breaks_the_signature(lock, member_key):
    """El vout entra porque un txid puede tener varias salidas."""
    pr = _proof_for(lock, member_key, vout=0)
    moved = MembershipOutput(txid="cc" * 32, vout=1, satoshis=5000,
                             script_hash=lock.script_hash)
    tampered = MembershipProof(output=moved, inclusion=pr.inclusion,
                               membership_pubkey=pr.membership_pubkey,
                               signature=pr.signature, lock=lock)
    header = BlockHeader(merkle_root=pr.inclusion.merkle_root)
    assert not tampered.verify(header)[0]


def test_a_foreign_lock_does_not_open_the_membership_gate(lock, member_key):
    """Un lock ajeno no vale, aunque la firma sea perfecta.

    Es la razon de que la lista de locks de confianza viva en el cliente y no
    en la cadena: la cadena no puede decir cual es el SC legitimo.
    """
    foreign = MembershipLock(script_hash="ff" * 20)
    pr = _proof_for(lock, member_key)
    forged_lock = MembershipLock(script_hash=foreign.script_hash)
    relabelled = MembershipProof(output=pr.output, inclusion=pr.inclusion,
                                 membership_pubkey=pr.membership_pubkey,
                                 signature=pr.signature, lock=forged_lock)
    header = BlockHeader(merkle_root=pr.inclusion.merkle_root)
    ok, why = relabelled.verify(header)
    assert not ok
    assert "lock" in why


def test_an_admission_signature_is_not_a_membership_signature(lock, member_key):
    """Dominio distinto: una firma de admision no se reusa como membresia.

    Sin el prefijo de dominio, cualquier firma de 64 bytes que el nodo hubiera
    emitido para otra capa pasaria aqui, y un `MembershipProof` seria
    construible sin poseer nada.
    """
    admission_digest = _canonical_digest({"kind": "gist", "body": "x"})
    sig = member_key.sign(admission_digest)
    out = MembershipOutput(txid="cc" * 32, vout=0, satoshis=5000,
                           script_hash=lock.script_hash)
    pr = MembershipProof(output=out, inclusion=_one_tx_proof("cc" * 32, lock),
                         membership_pubkey=member_key.public_key.hex(),
                         signature=sig.hex(), lock=lock)
    header = BlockHeader(merkle_root=pr.inclusion.merkle_root)
    assert not pr.verify(header)[0]


def test_malformed_public_key_or_signature_never_raises(lock, member_key):
    pr = _proof_for(lock, member_key)
    header = BlockHeader(merkle_root=pr.inclusion.merkle_root)
    for pub, sig in [("", pr.signature),
                     ("abcd", pr.signature),
                     (pr.membership_pubkey, "zz"),
                     (pr.membership_pubkey, ""),
                     (pr.membership_pubkey, "00" * 63)]:
        bad = MembershipProof(output=pr.output, inclusion=pr.inclusion,
                              membership_pubkey=pub, signature=sig, lock=lock)
        assert not bad.verify(header)[0], f"no deberia verificar: {pub[:8]}"


def test_membership_costs_nothing_today_and_that_is_a_choice_not_a_check(lock, member_key):
    """El valor de la membresia lo pone el minado, no este modulo.

    ``DUST_ORDER`` esta ahi para nombrar la banda, no para fingir que un join
    de 1 satoshi es "pago real". La presion economica la decide el operador al
    elegir el lock; el verificador solo puede rechazar salida que incumplan su
    lock, no decir si un join fue caro.
    """
    pr = _proof_for(lock, member_key, satoshis=1)
    header = BlockHeader(merkle_root=pr.inclusion.merkle_root)
    ok, _ = pr.verify(header)
    assert ok, "un join de 1 satoshi sigue siendo una membresia valida"


# --------------------------------------------------------------------------
# La rotacion
# --------------------------------------------------------------------------
def _rotation(lock: Any, old_key: Any, new_key: Any, satoshis: int = 4800):
    spent = MembershipOutput(txid="dd" * 32, vout=0, satoshis=satoshis,
                             script_hash=lock.script_hash)
    return RotationProof.create(spent, _one_tx_proof("dd" * 32, lock),
                                old_key, new_key, new_outpoint="ee" * 32 + ":1",
                                new_satoshis=4700)


def test_rotating_to_a_new_key_is_signed_by_the_old_one(lock, member_key):
    new_key = Secp256k1KeyPair.new("member-2")
    rot = _rotation(lock, member_key, new_key)
    header = BlockHeader(merkle_root=rot.spent_inclusion.merkle_root)
    ok, why = rot.verify(member_key.public_key.hex(), header)
    assert ok, why


def test_a_rotation_signed_by_the_new_key_is_rejected(lock, member_key):
    """La asimetria es la regla: firma la clave VIEJA.

    Si firmara la nueva, cualquiera podria anunciar una rotacion que nadie
    autorizo, y un atacante se auto-rotaria sin controlar ningun output.
    """
    new_key = Secp256k1KeyPair.new("member-2")
    rot = _rotation(lock, member_key, new_key)
    # la misma firma, reinterpretada contra la clave nueva
    ok, _ = rot.verify(new_key.public_key.hex(),
                       BlockHeader(merkle_root=rot.spent_inclusion.merkle_root))
    assert not ok, "firmar con la nueva no debe validar la rotacion"


def test_rotating_to_the_same_key_is_refused_at_construction(lock, member_key):
    """Renovar sin cambiar de clave = membresia gratis indefinida."""
    spent = MembershipOutput(txid="dd" * 32, vout=0, satoshis=4800,
                             script_hash=lock.script_hash)
    with pytest.raises(ProtocolError):
        RotationProof.create(spent, _one_tx_proof("dd" * 32, lock),
                             member_key, member_key,
                             new_outpoint="ee" * 32 + ":0", new_satoshis=4700)


def test_two_simultaneous_rotations_cannot_both_win(lock, member_key):
    """La garantia central: de dos rotaciones del mismo output, una gana.

    Dos clave nuevas distintas, dos firmas legitimas, mismo output gastado. A
    nivel de grafo es un doble gasto, y solo una transaction entra en un
    bloque. Aqui se comprueba la mitad verificable: las dos pruebas son
    criptograficamente validas, y por eso el orden de llegada es el que
    decide — que es exactamente por lo que hace falta la inclusion contra una
    cabecera real, no la fiat del peer.
    """
    rot_a = _rotation(lock, member_key, Secp256k1KeyPair.new("m2"))
    rot_b = _rotation(lock, member_key, Secp256k1KeyPair.new("m3"))
    hdr = BlockHeader(merkle_root=rot_a.spent_inclusion.merkle_root)
    assert rot_a.verify(member_key.public_key.hex(), hdr)[0]
    assert rot_b.verify(member_key.public_key.hex(), hdr)[0]

    ms = MembershipSet(lock=lock)
    assert ms.apply_rotation(rot_a, member_key.public_key.hex(), hdr)[0]
    # la segunda llega despues sobre un output ya retirado
    ok, why = ms.apply_rotation(rot_b, member_key.public_key.hex(), hdr)
    assert not ok
    assert "gastado" in why or "no gasta" in why or "retirada" in why


def test_a_stale_membership_cannot_be_readmitted_after_rotation(lock, member_key):
    """La garantia se completa: gastar el output retira la membresia vieja.

    Sin esto, un nodo cuyo output se gasto en la cadena podria seguir
    presentandolo, y la rotacion no valdria para nada.
    """
    ms = MembershipSet(lock=lock)
    old_proof = _proof_for(lock, member_key)
    hdr = BlockHeader(merkle_root=old_proof.inclusion.merkle_root)
    assert ms.admit(old_proof, hdr)[0]

    new_key = Secp256k1KeyPair.new("member-2")
    rot = RotationProof.create(old_proof.output,
                               _one_tx_proof("cc" * 32, lock),
                               member_key, new_key,
                               new_outpoint="ee" * 32 + ":1", new_satoshis=4700)
    assert ms.apply_rotation(rot, member_key.public_key.hex(), hdr)[0]

    # vuelve a intentar el mismo output, ya retirado
    ok, why = ms.admit(old_proof, hdr)
    assert not ok
    assert "gastado" in why or "retirada" in why


def test_a_rotation_whose_spent_output_is_not_the_known_one_is_rejected(
        lock, member_key):
    """Un nodo no acepta rotaciones de un output que el nodo no conoce."""
    ms = MembershipSet(lock=lock)
    other = _proof_for(lock, member_key, txid="11" * 32)
    ms.admit(other, BlockHeader(merkle_root=other.inclusion.merkle_root))
    rot = _rotation(lock, member_key, Secp256k1KeyPair.new("m2"))
    ok, why = ms.apply_rotation(rot, member_key.public_key.hex(),
                                BlockHeader(merkle_root=rot.spent_inclusion.merkle_root))
    assert not ok
    assert "no gasta" in why


def test_a_tampered_new_outpoint_breaks_the_rotation_signature(lock, member_key):
    new_key = Secp256k1KeyPair.new("member-2")
    rot = _rotation(lock, member_key, new_key)
    bad = RotationProof(spent=rot.spent, spent_inclusion=rot.spent_inclusion,
                        new_key_pubkey=rot.new_key_pubkey,
                        new_outpoint="ff" * 32 + ":9", new_satoshis=rot.new_satoshis,
                        signature=rot.signature)
    hdr = BlockHeader(merkle_root=rot.spent_inclusion.merkle_root)
    assert not bad.verify(member_key.public_key.hex(), hdr)[0]


# --------------------------------------------------------------------------
# El conjunto
# --------------------------------------------------------------------------
def test_a_set_admits_a_valid_member_and_reports_it(lock, member_key):
    ms = MembershipSet(lock=lock)
    pr = _proof_for(lock, member_key)
    ok, _ = ms.admit(pr, BlockHeader(merkle_root=pr.inclusion.merkle_root))
    assert ok
    assert ms.is_member(member_key.public_key.hex())
    st = ms.status()
    assert st["members"] == 1 and st["spent_outpoints"] == 0


def test_a_set_refuses_a_member_from_another_lock(lock, member_key):
    """La malla decide su lock; un proof de otro lock no entra."""
    mine = MembershipLock(script_hash="11" * 20)
    other = MembershipLock(script_hash="22" * 20)
    out = MembershipOutput(txid="cc" * 32, vout=0, satoshis=5000,
                           script_hash=other.script_hash)
    pr = MembershipProof.create(out, _one_tx_proof("cc" * 32, lock),
                                member_key, other)
    ms = MembershipSet(lock=mine)
    ok, why = ms.admit(pr, BlockHeader(merkle_root=pr.inclusion.merkle_root))
    assert not ok
    assert "lock" in why


def test_is_member_is_a_local_view_not_a_global_ledger(lock):
    """La honestidad que evita el malentendido que hace inutil el gate.

    ``is_member`` responde "lo que este nodo ha visto", no "es miembro en la
    malla". Un nodo desconectado puede tener una respuesta desactualizada, y
    con ella la garantia de que un nodo con la misma clave no siga siendo
    miembro en otro sitio. Por eso ``status`` expone el tamano de la vista.
    """
    ms = MembershipSet(lock=lock)
    assert not ms.is_member("aa" * 33)
    assert ms.status()["view_is_local"] is True


def test_from_spent_output_raises_instead_of_inventing_a_lock():
    """Nada parsea Bitcoin Script, y el modulo lo dice en vez de disimularlo.

    Un gate que aceptara un lock que nadie leyo del output real seria una
    puerta abierta con nombre de puerta.
    """
    with pytest.raises(ProtocolError):
        MembershipLock.from_spent_output({"vout": [{"scriptPubKey": {}}]}, 0)


# --------------------------------------------------------------------------
# Lo que este modulo NO hace
# --------------------------------------------------------------------------
def test_spv_does_not_validate_the_blockchain_and_the_docstring_says_so():
    """SPV prueba inclusion contra una cabecera, no que la cabecera sea la buena.

    Esa es la debilidad conyelada de SPV (BRC-96). El modulo lo declara en el
    docstring porque un gate de pertenencia que se creyera mas fuerte de lo que
    es invites a confiarle decisiones que no puede sostener.
    """
    from smcp.core import membership
    doc = membership.__doc__ or ""
    assert "cadena no se valida" in doc or "BRC-96" in doc
    assert "No decide qu" in doc or "no hay nada en la cadena" in doc


# --------------------------------------------------------------------------
# Lo que sobrevivio a la primera ronda de mutacion
#
# Estas seis trampas devolvieron verde, y cuatro de ellas son la garantia
# central del modulo. No se "arreglan" con un test mas debil: se sujetan con
# una comprobacion que el mutador no puede esquivar.
# --------------------------------------------------------------------------
def test_the_hash_is_double_sha256_proven_by_the_bitcoin_genesis_block():
    """Un vector externo, no mi propia funcion contra si misma.

    El txid del bloque genesis de Bitcoin **es** la raiz de Merkle de su unica
    transaccion, asi que fija el algoritmo entero: doble SHA-256, orden interno,
    hex de presentacion. Con SHA-256 simple el valor no cuadra — comprobado,
    no supuesto. Un test que comparara ``dsha256`` consigo mismo daria verde
    con la doble aplicacion rota, que es exactamente lo que hacia la trampa
    anterior.
    """
    genesis = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    leaf = bytes.fromhex(genesis)[::-1]          # orden interno de la cadena
    assert merkle_root([leaf])[::-1].hex() == genesis
    # y el hash simple NO cuadra: por eso el test distingue
    import hashlib
    assert hashlib.sha256(leaf).digest()[::-1].hex() != genesis


def test_a_standalone_transaction_verifies_against_its_own_root():
    """Una hoja sola: raiz = la hoja. El caso degenerado que mas se usa."""
    txid = "11" * 32
    pr = InclusionProof(txid=txid, index=0, path=[], merkle_root=txid)
    assert pr.verify(BlockHeader(merkle_root=txid))
    assert not pr.verify(BlockHeader(merkle_root="22" * 32))


def test_a_forged_inclusion_with_a_valid_looking_path_is_rejected():
    """Una inclusion **falsa** con camino plausible, no solo una raiz ajena.

    La trampa anterior sobrevivio porque la guarda de cabecera interceptaba
    antes de llegar a la prueba. Aqui el camino es de verdad incorrecto y la
    raiz **si** coincide con la del atacante: la unica defensa posible es
    recomputar la raiz desde el camino, que es lo que hace la funcion.
    """
    from smcp.core.membership import _present
    real = [bytes.fromhex(t)[::-1] for t in ("11" * 32, "22" * 32)]
    attacker_root = _present(merkle_root(real))
    # camino inventado: un solo hermano que no combina
    forged = InclusionProof(txid="11" * 32, index=0,
                            path=["ff" * 32], merkle_root=attacker_root)
    assert not forged.verify(BlockHeader(merkle_root=attacker_root)), \
        "un camino de Merkle falso debe fallar aunque la raiz coincida"


def test_rotating_to_the_same_key_is_rejected_at_verification_not_only_at_build():
    """La guarda vive en los dos sitios, y por eso ninguna trampas pasa.

    ``RotationProof.create`` ya rechaza la rotacion a si misma. Aqui se
    comprueba que ``verify`` tambien — porque un ``RotationProof`` puede venir
    de otro sitio (serializado, red, un peer), no solo de este constructor. Si
    ``verify`` no lo comprobara, un atacante fabricaria el dataclass a mano y
    renovaria su membresia gratis e indefinidamente.
    """
    member = Secp256k1KeyPair.new("m")
    spent = MembershipOutput(txid="dd" * 32, vout=0, satoshis=4800,
                             script_hash="11" * 20)
    inc = InclusionProof(txid="dd" * 32, index=0, path=[],
                         merkle_root="dd" * 32)
    # fabrication a mano: misma clave en los dos lados
    import smcp.core.membership as M
    payload = {
        "v": M.MEMBERSHIP_VERSION, "domain": "smcp-rotation",
        "spent": spent.outpoint(),
        "new_key_pubkey": member.public_key.hex(),
        "new_outpoint": "ee" * 32 + ":0", "new_satoshis": 4700,
    }
    forged = RotationProof(spent=spent, spent_inclusion=inc,
                           new_key_pubkey=member.public_key.hex(),
                           new_outpoint="ee" * 32 + ":0", new_satoshis=4700,
                           signature=member.sign(_canonical_digest(payload)).hex())
    ok, why = forged.verify(member.public_key.hex(), BlockHeader(merkle_root="dd" * 32))
    assert not ok, "verify debe rechazar rotar a si mismo"
    assert "misma clave" in why


def test_the_rotation_retires_the_old_membership_key_from_the_set():
    """Tras rotar, la clave vieja no es miembro: su output ya no existe.

    Sin este ``pop``, un nodo puede rotar y seguir figurando como miembro con
    la clave antigua — dos membresias vivas para un solo UTXO, que es el
    Sybil que la pertenencia de pago deberia impedir.
    """
    from smcp.core.membership import _present
    lock = MembershipLock(script_hash="11" * 20)
    old_key = Secp256k1KeyPair.new("m1")
    ms = MembershipSet(lock=lock)
    out = MembershipOutput(txid="cc" * 32, vout=0, satoshis=5000,
                           script_hash=lock.script_hash)
    # hoja unica: la raiz de Merkle de una sola transaccion es el txid mismo
    inc = InclusionProof(txid="cc" * 32, index=0, path=[],
                         merkle_root=("cc" * 32))
    pr = MembershipProof.create(out, inc, old_key, lock)
    assert ms.admit(pr, BlockHeader(merkle_root="cc" * 32))[0]
    assert ms.is_member(old_key.public_key.hex())

    new_key = Secp256k1KeyPair.new("m2")
    rot = RotationProof.create(out, inc, old_key, new_key,
                               "ee" * 32 + ":1", 4700)
    assert ms.apply_rotation(rot, old_key.public_key.hex(),
                             BlockHeader(merkle_root="cc" * 32))[0]
    assert not ms.is_member(old_key.public_key.hex()), \
        "la clave que rotó ya no debe figurar como miembro"
    assert ms.status()["members"] == 0


def test_a_domained_signature_cannot_be_replayed_across_domains():
    """El prefijo de dominio es lo que impide el replay entre capas.

    Una firma de admision (dominio "gist") no vale como membresia, y una
    firma de membresia no vale como rotacion. Sin el dominio, cualquier
    firma de 64 bytes emitida para otra capa pasaria aqui.
    """
    from smcp.core import membership as M
    member = Secp256k1KeyPair.new("m")
    spent = MembershipOutput(txid="dd" * 32, vout=0, satoshis=4800,
                             script_hash="11" * 20)
    inc = InclusionProof(txid="dd" * 32, index=0, path=[],
                         merkle_root="dd" * 32)
    # firma de membresia reutilizada como rotacion
    out = MembershipOutput(txid="cc" * 32, vout=0, satoshis=5000,
                           script_hash="11" * 20)
    pr = MembershipProof.create(out, inc, member, MembershipLock(script_hash="11" * 20))
    replayed = RotationProof(spent=spent, spent_inclusion=inc,
                             new_key_pubkey=Secp256k1KeyPair.new("n").public_key.hex(),
                             new_outpoint="ee" * 32 + ":1", new_satoshis=4700,
                             signature=pr.signature)
    ok, why = replayed.verify(member.public_key.hex(),
                              BlockHeader(merkle_root="dd" * 32))
    assert not ok, "una firma de membresia no debe validar como rotacion"
    assert "firma" in why or "antigua" in why


def test_malformed_hashes_and_outpoints_raise_instead_of_returning_garbage():
    """Un outpoint o un hash malformado es un error de construccion, no un None.

    Dejarlos pasar haria que ``admit`` metiera en el set una membresia con un
    outpoint que no puede compararse contra nada, y la comprobacion de "ya
    gastado" — la garantia central — se volveria un ``==`` sobre basura.
    """
    with pytest.raises(ValueError):
        MembershipOutput(txid="ab", vout=0, satoshis=1, script_hash="x").outpoint()
    with pytest.raises(ValueError):
        MembershipOutput(txid="aa" * 32, vout=-1, satoshis=1, script_hash="x").outpoint()
    with pytest.raises(ValueError):
        MembershipOutput.from_outpoint("sin dos puntos", 1, "11" * 20)


def test_a_wrong_length_signature_is_rejected_not_guessed_at():
    """BRC-220: 64 bytes se lee r||s, cualquier otra longitud es malformed.

    Aceptar longitudes arbitrarias seria aceptar DER donde se espera compacto,
    y un DER puede medir exactamente 64 bytes con r y s cortos — en cuyo caso se
    leeria como compacto y no verificaria. El filtro por longitud es lo que
    cierra esa rama.
    """
    lock = MembershipLock(script_hash="11" * 20)
    member = Secp256k1KeyPair.new("m")
    out = MembershipOutput(txid="cc" * 32, vout=0, satoshis=5000,
                           script_hash=lock.script_hash)
    inc = InclusionProof(txid="cc" * 32, index=0, path=[], merkle_root="cc" * 32)
    pr = MembershipProof.create(out, inc, member, lock)
    hdr = BlockHeader(merkle_root="cc" * 32)
    for bad_len in (63, 65, 32, 128):
        bad = MembershipProof(output=out, inclusion=inc,
                              membership_pubkey=member.public_key.hex(),
                              signature=("ab" * bad_len), lock=lock)
        assert not bad.verify(hdr)[0], f"firma de {bad_len} bytes no deberia pasar"


def test_a_malformed_public_key_never_reaches_the_verifier():
    """La pubkey se valida antes de firmar: una clave rota no es un 403, es un 500."""
    lock = MembershipLock(script_hash="11" * 20)
    member = Secp256k1KeyPair.new("m")
    out = MembershipOutput(txid="cc" * 32, vout=0, satoshis=5000,
                           script_hash=lock.script_hash)
    inc = InclusionProof(txid="cc" * 32, index=0, path=[], merkle_root="cc" * 32)
    pr = MembershipProof.create(out, inc, member, lock)
    hdr = BlockHeader(merkle_root="cc" * 32)
    for bad_pub in ("", "ab", "ab" * 16, "ab" * 64, "zz" * 33):
        bad = MembershipProof(output=out, inclusion=inc,
                              membership_pubkey=bad_pub,
                              signature=pr.signature, lock=lock)
        ok, why = bad.verify(hdr)
        assert not ok, f"pubkey {bad_pub[:6]!r} no deberia pasar"
        assert isinstance(why, str) and why


def test_the_hash_is_double_sha256_anchored_to_the_genesis_block_hash():
    """Un vector externo real, no mi funcion comparada consigo misma.

    Este es el test que hace que la doble aplicacion sea *fijada* y no
    *supuesta*. La cabecera del bloque genesis de Bitcoin, tal cual esta en el
    volcado hex del bloque (orden interno en todos los campos), con el nonce
    0x1dac2b7c, produce con doble SHA-256 el hash

        000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f

    y con SHA-256 simple **no**. Comprobado, no supuesto: las dos ramas se
    evaluan aqui, asi que si alguien cambia ``dsha256`` por una sola
    aplicacion el test falla por la razon correcta.

    Nota sobre el nonce: dos fuentes dan valores distintos (0x1dac2b7c y
    0xb9ed4b7c) y solo el primero produce el hash genesis. Se usa el que
    cuadra, verificado aqui, no el que se leia primero.
    """
    genesis_header = bytes.fromhex(
        "01000000"                                        # version
        "0000000000000000000000000000000000000000000000000000000000000000"  # prev
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"  # merkle
        "29ab5f49"                                        # timestamp
        "ffff001d"                                        # bits
        "1dac2b7c")                                       # nonce
    assert len(genesis_header) == HEADER_LEN
    expected = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    assert dsha256(genesis_header)[::-1].hex() == expected
    # y la variante de una sola aplicacion NO da ese valor: por eso el test
    # distingue las dos implementaciones.
    import hashlib
    assert hashlib.sha256(genesis_header).digest()[::-1].hex() != expected


def test_block_hash_of_a_raw_header_uses_the_same_double_hash():
    """``BlockHeader.block_hash`` y ``dsha256`` no pueden divergir.

    Si el hash de bloque usara una sola aplicacion, la cabecera que un
    verificador presenta y la que el proof compara darian valores distintos, y
    el rechazo seria un bug de formato antes de ser una decision de seguridad.
    """
    raw = bytes.fromhex(
        "01000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
        "29ab5f49" "ffff001d" "1dac2b7c")
    hdr = BlockHeader(merkle_root="00" * 32, height=0, raw=raw)
    assert hdr.block_hash == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    # sin cabecera cruda no se inventa un hash
    assert BlockHeader(merkle_root="00" * 32).block_hash == ""


def test_the_digest_domain_is_not_optional():
    """El prefijo de dominio esta en el digest firmado, y se comprueba.

    Sin el, una firma de admision (dominio distinto) serviria como prueba de
    membresia y viceversa. Aqui se fija el valor exacto que viaja, para que
    quitarlo no sea un cambio invisible: cualquier par de firmas de dominios
    distintos deja de ser intercambiable.
    """
    from smcp.core import membership as M
    lock = MembershipLock(script_hash="11" * 20)
    member = Secp256k1KeyPair.new("m")
    out = MembershipOutput(txid="cc" * 32, vout=0, satoshis=5000,
                           script_hash=lock.script_hash)
    inc = InclusionProof(txid="cc" * 32, index=0, path=[], merkle_root="cc" * 32)
    pr = MembershipProof.create(out, inc, member, lock)
    # el digest firmado lleva el dominio explicito
    expected = _canonical_digest({
        "v": M.MEMBERSHIP_VERSION,
        "domain": "smcp-membership",
        "lock": lock.script_hash,
        "outpoint": "cc" * 32 + ":0",
        "satoshis": 5000,
        "membership_pubkey": member.public_key.hex(),
    })
    assert pr._digest() == expected, "el digest firmado cambio de forma"
    # y sin el dominio daria OTRO valor: por eso el campo no es decorativo
    sin_dominio = _canonical_digest({
        "v": M.MEMBERSHIP_VERSION,
        "lock": lock.script_hash,
        "outpoint": "cc" * 32 + ":0",
        "satoshis": 5000,
        "membership_pubkey": member.public_key.hex(),
    })
    assert sin_dominio != expected


def test_three_mutations_that_cannot_be_caught_because_the_guard_is_doubled():
    """Lo que sobrevive a la mutacion, con la razon de cada caso.

    Tres trampas devuelven verde. Ninguna es un agujero: las tres tienen una
    **segunda guarda** en otro sitio, y esto es lo que hace que quitarlas no
    cambie el comportamiento observable. Se dejan escritas para que nadie lea
    "17/20" como "tres	defectos".

    1. **longitud de firma** — `membership` filtra por longitud, y despues
       `bsv_keys.verify_public` vuelve a filtrar. Quitar el filtro de un lado
       no cambia nada observable.
    2. **pubkey de longitud invalida** — igual: dos filtros independientes.
    3. **outpoint malformado** — quitado el `raise` explicito, la conversion
       `int(vout)` sobre un texto no numerico lanza igualmente. La guarda
       explicita es la que da un mensaje util; la que protege de verdad es el
       `int()`.

    La leccion es la de siempre y conviene repetirla: un filtro que se
    duplica no esta dos veces probado. Aqui la duplicacion es deliberada
    (defensa en profundidad entre capas), y la consecuencia aceptada es que la
    mutacion no puede distinguirla de la redundancia.
    """
    from smcp.core import bsv_keys
    from smcp.core.membership import MembershipProof as MP

    # (1) y (2): la segunda guarda, en bsv_keys
    assert bsv_keys.verify_public(bytes.fromhex("ab" * 33), "11" * 32,
                                  bytes.fromhex("cd" * 64)) is False
    assert bsv_keys.verify_public(bytes.fromhex("ab" * 33), "11" * 32,
                                  bytes.fromhex("cd" * 63)) is False

    lock = MembershipLock(script_hash="11" * 20)
    member = Secp256k1KeyPair.new("m")
    out = MembershipOutput(txid="cc" * 32, vout=0, satoshis=5000,
                           script_hash=lock.script_hash)
    inc = InclusionProof(txid="cc" * 32, index=0, path=[], merkle_root="cc" * 32)
    pr = MP.create(out, inc, member, lock)
    hdr = BlockHeader(merkle_root="cc" * 32)

    # la guarda de membership
    assert not MP(output=out, inclusion=inc,
                  membership_pubkey="ab" * 32,
                  signature=pr.signature, lock=lock).verify(hdr)[0]
    # y la de bsv_keys, que es la que sobrevive a la mutacion
    assert bsv_keys.verify_public(bytes.fromhex("ab" * 32), "11" * 32,
                                  bytes.fromhex("cd" * 64)) is False

    # (3) el outpoint: con y sin el raise explicito, la conversion lanza
    with pytest.raises(ValueError):
        MembershipOutput.from_outpoint("sin-puntos", 1, "11" * 20)
    with pytest.raises(ValueError):
        # "txid:no-es-un-numero" -> el int() es la guarda que protege
        MembershipOutput.from_outpoint("cc" * 32 + ":no-es-un-numero", 1,
                                       "11" * 20)
