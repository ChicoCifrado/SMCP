"""Anchor — una transaccion por inferencia, sin contenido hasheado.

Lo que estos tests sujetan:

* **El contenido no se publica, y no por convenience.** `content_sha256` no se
  puede ni rellenar: la decision de no publicar el contenido esta en la
  estructura, no en un comentario. Si alguien lo rellena, el constructor falla.
* **La atribucion.** El ancla se firma con la clave de membresia, y el output
  que paga es el de esa membresia. Firmar con la clave de identidad del
  handshake haria que una rotacion dejara el historico sin poder verificar.
* **No retroactividad.** Una inferencia anterior a la membresia se rechaza.
  Sin esto, un nodo puede presentar trabajo anterior a su propia entrada.
* **Inclusion y firma son dos preguntas.** La inclusion tiene que ser de la
  MISMA transaccion que la membresia declarada: dos cosas reales que no van
  juntas siguen siendo dos cosas reales.
* **BRC-96.** `chain_validated` sale False siempre, porque inclusion contra la
  cabecera que da el llamante no es validacion de cadena.

Y lo que el modulo **no** puede hacer, fijado con test para que no se lea como
resuelto: no puede demostrar *que* inferencia fue, solo que hubo una.
"""
from __future__ import annotations

import pytest

from delm.core.anchor import (
    ANCHOR_VERSION,
    ANCLAIM_AMOUNT_SATS,
    AnchorLedger,
    AnchorRecord,
)
from delm.core.bsv_keys import Secp256k1KeyPair
from delm.core.membership import (
    BlockHeader,
    InclusionProof,
    MembershipOutput,
    ProtocolError,
    merkle_root,
)

TXID = "aa" * 32


def _header(txid: str, height: int) -> BlockHeader:
    """Cabecera cuyo Merkle root es el txid. Una sola hoja -> raiz == hoja."""
    return BlockHeader(merkle_root=txid, height=height)


def _inclusion(txid: str, height: int) -> InclusionProof:
    """Inclusion de una transaccion unica: la raiz ES el txid.

    El txid de presentacion es big-endian y la raiz interna little-endian, asi
    que la hoja se invierte — igual que hace el resto del repo. Sin eso, la raiz
    seria distinta de la que computa cualquier otro y el test pasaria sin probar
    nada.
    """
    leaf = bytes.fromhex(txid)[::-1]
    return InclusionProof(txid=txid, index=0, path=[],
                          merkle_root=merkle_root([leaf]).hex(),
                          height=height)


REQUESTER = Secp256k1KeyPair.new('quien-pide')


def _record(key: Secp256k1KeyPair, *, vout: int = 0, satoshis: int = 1,
            occurred_at: int = 1_700_000_000,
            requester: Secp256k1KeyPair | None = None) -> AnchorRecord:
    """Un ancla de una peticion **de la red**: el solicitante es otro nodo.

    El default es un solicitante distinto a proposito: casi todo lo que se
    prueba aqui (firma, inclusion,DER) asume una peticion de otro. El caso
    auto-solicitado tiene sus propios tests.
    """
    return AnchorRecord(membership_txid=TXID, membership_vout=vout,
                        membership_pubkey=key.public_key.hex(),
                        requester_pubkey=(requester or REQUESTER).public_key.hex(),
                        satoshis=satoshis, occurred_at=occurred_at)


# ---------------------------------------------------------------------------
# La decision de no publicar el contenido
# ---------------------------------------------------------------------------
def test_the_content_hash_cannot_be_filled_and_that_is_the_point():
    """``content_sha256`` no es un campo: es una decision cerrada.

    El hash del contenido de una inferencia es tan identificador como el
    contenido. Si fuera un campo cualquiera, rellenarlo seria un cambio de una
    linea y nadie lo revisaria — y en ese momento cualquier observador de la
    cadena podria confirmar que alguien ejecuto esa conversacion. Falla al
    construir, con un motivo que explica por que.
    """
    key = Secp256k1KeyPair.new("n1")
    with pytest.raises(ProtocolError) as ei:
        AnchorRecord(membership_txid=TXID, membership_vout=0,
                     membership_pubkey=key.public_key.hex(),
                     requester_pubkey=REQUESTER.public_key.hex(), satoshis=1,
                     content_sha256="ab" * 32)
    assert "no publica el contenido" in str(ei.value)
    assert "identificador" in str(ei.value)


def test_a_ledger_that_published_content_would_say_so_and_it_never_does():
    """El resumen expone si publica contenido, y la respuesta es siempre no.

    ``publishes_content`` esta ahi para que sea una comprobacion y no una
    suposicion: si alguna vez se cumple, alguien que mire el estado lo ve sin
    tener que leer el codigo.
    """
    key = Secp256k1KeyPair.new("n1")
    out = MembershipOutput(txid=TXID, vout=0, satoshis=1, script_hash="bb" * 32)
    led = AnchorLedger(membership_outputs=[out])
    inc = _inclusion(TXID, height=100)
    rec = _record(key)
    ok, why = led.append(rec, inc, rec.sign(key))
    assert ok, why
    st = led.status()
    assert st["publishes_content"] is False
    assert st["anchors"] == 1


# ---------------------------------------------------------------------------
# Atribucion
# ---------------------------------------------------------------------------
def test_the_anchor_is_signed_with_the_membership_key_and_it_checks():
    """La firma tiene que ser de la clave que el output paga.

    Es lo que hace que la firma pruebe posesion y no declaracion, y es lo que
    ya hace que funcione la pertenencia. Si aqui se pudiera firmar con otra
    clave, un nodo podria atribuirse inferencias de otro.
    """
    key = Secp256k1KeyPair.new("n1")
    rec = _record(key)
    sig = rec.sign(key)
    inc = _inclusion(TXID, 100)
    ok, why = rec.verify(sig, inc, _header(TXID, 100))
    assert ok, why


def test_signing_with_a_key_other_than_the_declared_one_is_refused():
    """Firmar con una clave ajena a la declarada se rechaza al firmar.

    Sin esta comprobacion se produciria una firma valida — de la clave que
    firmó — sobre un registro que declara otra clave, y el fallo solo apareceria
    al verificar, en el lado del verificador.
    """
    key = Secp256k1KeyPair.new("n1")
    other = Secp256k1KeyPair.new("n2")
    rec = _record(key)
    with pytest.raises(ProtocolError) as ei:
        rec.sign(other)
    assert "no es la clave de membresia" in str(ei.value)


def test_a_signature_from_another_node_does_not_verify():
    """La firma de otro nodo no vale para este registro.

    Con la misma membresia declarada, cambiada la firma: es el caso de un nodo
    que copia el registro de otro y lo reenvia.
    """
    from delm.core.membership import _canonical_digest

    key = Secp256k1KeyPair.new("n1")
    atacante = Secp256k1KeyPair.new("atacante")
    rec = _record(key)
    # el atacante firma el payload IDENTICO al del registro, con SU clave
    sig_atacante = atacante.sign(_canonical_digest(rec.digest_payload())).hex()
    inc = _inclusion(TXID, 100)
    ok, why = rec.verify(sig_atacante, inc, _header(TXID, 100))
    assert not ok and "firma" in why


def test_the_membership_pubkey_is_part_of_the_signed_payload():
    """Cambiar la clave declarada invalida la firma.

    Si la pubkey no estuviera en el payload firmado, un atacante podria declarar
    la clave de otro nodo y su firma pasaria: la firma noatia a quien declara.
    """
    key = Secp256k1KeyPair.new("n1")
    victim = Secp256k1KeyPair.new("victima")
    rec = _record(key)
    sig = rec.sign(key)
    # mismo txid, mismo vout, pero clave declarada distinta
    spoofed = AnchorRecord(membership_txid=TXID, membership_vout=0,
                           membership_pubkey=victim.public_key.hex(),
                           requester_pubkey=REQUESTER.public_key.hex(),
                           satoshis=rec.satoshis, occurred_at=rec.occurred_at)
    inc = _inclusion(TXID, 100)
    ok, why = spoofed.verify(sig, inc, _header(TXID, 100))
    assert not ok and "firma" in why


def test_a_tampered_amount_invalidates_the_signature():
    """El importe esta firmado. Cambiarlo invalida el registro.

    El importe no es un precio (no se verifica contra nada), pero si esta
    firmado: si no, un nodo podria subir su propio importe para que el total de
    la cadena le favorezca.
    """
    key = Secp256k1KeyPair.new("n1")
    rec = _record(key, satoshis=1)
    sig = rec.sign(key)
    inflado = AnchorRecord(membership_txid=TXID, membership_vout=0,
                           membership_pubkey=key.public_key.hex(),
                           requester_pubkey=REQUESTER.public_key.hex(),
                           satoshis=1_000_000,
                           occurred_at=rec.occurred_at)
    ok, why = inflado.verify(sig, _inclusion(TXID, 100), _header(TXID, 100))
    assert not ok and "firma" in why


# ---------------------------------------------------------------------------
# Inclusion: dos preguntas separadas
# ---------------------------------------------------------------------------
def test_inclusion_from_another_transaction_is_refused():
    """La inclusion tiene que ser de la membresia declarada.

    Dos cosas reales que no van juntas siguen siendo dos cosas reales: un nodo
    podria presentar una membresia verdadera y la inclusion de una transaccion
    cualquiera, y las dos por separado pasan.
    """
    key = Secp256k1KeyPair.new("n1")
    rec = _record(key)
    sig = rec.sign(key)
    otra = "bb" * 32
    ok, why = rec.verify(sig, _inclusion(otra, 100), _header(otra, 100))
    assert not ok and "no es de la transaccion" in why


def test_inclusion_against_the_wrong_header_fails_and_says_so():
    """Contra otra cabecera no valida — y el motivo lo distingue."""
    key = Secp256k1KeyPair.new("n1")
    rec = _record(key)
    sig = rec.sign(key)
    otra = "cc" * 32
    ok, why = rec.verify(sig, _inclusion(TXID, 100), _header(otra, 100))
    assert not ok and "Merkle" in why


def test_inclusion_is_checked_before_the_signature():
    """Inclusion primero: si no esta en un bloque, no hay nada que firmar.

    Al reves se gasta trabajo de ECDSA en comprobar una firma de un atacante
    antes de haber comprobado lo barato. Aqui la firma es basura y la inclusion
    es de la membresia correcta, pero contra OTRA cabecera: si el orden fuera
    firma-primero, el motivo seria "firma invalida" y este test no lo notaria.
    """
    key = Secp256k1KeyPair.new("n1")
    rec = _record(key)
    otra_cabecera = "dd" * 32
    ok, why = rec.verify("00" * 64, _inclusion(TXID, 100),
                         _header(otra_cabecera, 100))
    assert not ok and "Merkle" in why, "la inclusion se comprueba antes"


# ---------------------------------------------------------------------------
# Forma
# ---------------------------------------------------------------------------
def test_a_malformed_pubkey_is_refused_at_construction_not_at_verification():
    """Longitudes raras se rechazan al construir. Barato.

    Una pubkey de 10 hex es un atacante, y rechazar por longitud cuesta una
    comparacion mientras que rechazar por firma cuesta una operacion ECDSA.
    """
    key = Secp256k1KeyPair.new("n1")
    with pytest.raises(ProtocolError) as ei:
        AnchorRecord(membership_txid=TXID, membership_vout=0,
                     membership_pubkey="ab" * 5,
                     requester_pubkey=REQUESTER.public_key.hex(), satoshis=1)
    assert "pubkey" in str(ei.value)


def test_negative_values_and_bad_method_are_refused():
    key = Secp256k1KeyPair.new("n1")
    pk = key.public_key.hex()
    with pytest.raises(ProtocolError):
        AnchorRecord(membership_txid=TXID, membership_vout=0,
                     membership_pubkey=pk, requester_pubkey=REQUESTER.public_key.hex(), satoshis=-1)
    with pytest.raises(ProtocolError):
        AnchorRecord(membership_txid=TXID, membership_vout=0,
                     membership_pubkey=pk, requester_pubkey=REQUESTER.public_key.hex(), satoshis=1, method="p2sh")
    with pytest.raises(ProtocolError):
        AnchorRecord(membership_txid=TXID, membership_vout=0,
                     membership_pubkey=pk, requester_pubkey=REQUESTER.public_key.hex(), satoshis=1, occurred_at=-1)


def test_an_unknown_format_version_is_refused():
    """El formato va a cambiar; sin version habria que adivinar por los campos."""
    key = Secp256k1KeyPair.new("n1")
    with pytest.raises(ProtocolError) as ei:
        AnchorRecord(membership_txid=TXID, membership_vout=0,
                     membership_pubkey=key.public_key.hex(), requester_pubkey=REQUESTER.public_key.hex(), satoshis=1,
                     ver=ANCHOR_VERSION + 1)
    assert "version" in str(ei.value)


def test_a_malformed_dict_is_a_protocol_error_not_a_key_error():
    """Entrada de red corrupta -> error controlado, no KeyError."""
    with pytest.raises(ProtocolError):
        AnchorRecord.from_dict({"membership_txid": TXID})
    with pytest.raises(ProtocolError):
        AnchorRecord.from_dict({})


# ---------------------------------------------------------------------------
# El ledger
# ---------------------------------------------------------------------------
def test_an_anchor_for_an_unknown_membership_is_refused():
    """Solo se ancla desde una salida de membresia que el gate conoce.

    Si el ledger aceptara cualquier clave, cualquiera podria llenarlo. La lista
    viene del MembershipSet, no se deduce aqui.
    """
    key = Secp256k1KeyPair.new("n1")
    led = AnchorLedger(membership_outputs=[])     # sin salidas conocidas
    rec = _record(key)
    ok, why = led.append(rec, _inclusion(TXID, 100), rec.sign(key))
    assert not ok and "no esta en las salidas conocidas" in why


def test_an_anchor_without_a_block_height_is_refused():
    """Sin altura no se puede comprobar que sea posterior a la membresia.

    Y no se acepta "por defecto": aceptar sin poder comprobar es como no
    comprobar. La razon lo dice, porque la tentacion de relajar esto es alta.
    """
    key = Secp256k1KeyPair.new("n1")
    out = MembershipOutput(txid=TXID, vout=0, satoshis=1, script_hash="bb" * 32)
    led = AnchorLedger(membership_outputs=[out])
    rec = _record(key)
    ok, why = led.append(rec, _inclusion(TXID, 0), rec.sign(key))
    assert not ok and "altura" in why


def test_the_ledger_verifies_everything_and_reports_the_first_failure():
    """Verifica todas, y devuelve el primer fallo con su indice.

    Un ledger con tres anclas y la tercera invalida no sirve para nada; saber
    "hay un problema" es lo que el llamante necesita, y el indice dice cual.
    """
    key = Secp256k1KeyPair.new("n1")
    out = MembershipOutput(txid=TXID, vout=0, satoshis=1, script_hash="bb" * 32)
    led = AnchorLedger(membership_outputs=[out])
    hdr = _header(TXID, 100)
    for i in range(3):
        rec = _record(key, occurred_at=1_700_000_000 + i)
        inc = _inclusion(TXID, 100 + i)
        sig = rec.sign(key)
        if i == 2:
            sig = "00" * 64          # la tercera falla
        ok, why = led.append(rec, inc, sig)
        assert ok, why
    ok, why = led.verify(hdr)
    assert not ok and why.startswith("ancla 2")
    assert "Merkle" not in why   # esta vez falla la firma, no la inclusion


def test_a_healthy_ledger_verifies_and_summarises():
    key = Secp256k1KeyPair.new("n1")
    out = MembershipOutput(txid=TXID, vout=0, satoshis=1, script_hash="bb" * 32)
    led = AnchorLedger(membership_outputs=[out])
    hdr = _header(TXID, 100)
    for i in range(3):
        rec = _record(key, vout=0, occurred_at=1_700_000_000 + i)
        ok, why = led.append(rec, _inclusion(TXID, 100 + i), rec.sign(key))
        assert ok, why
    ok, why = led.verify(hdr)
    assert ok and "3 anclas" in why
    st = led.status()
    assert st["anchors"] == 3
    assert st["unique_membership_outpoints"] == 1
    assert st["satoshis_anchored"] == 3 * ANCLAIM_AMOUNT_SATS
    assert st["earliest_block"] == 100


def test_chain_validated_is_always_false_because_spv_does_not_validate_the_chain():
    """BRC-96: inclusion contra la cabecera que da el llamante no es validacion.

    Dos cabeceras de un atacante se validan mutuamente. Por eso el estado dice
    False siempre, y no "False si no me diste cabecera": siempre.
    """
    key = Secp256k1KeyPair.new("n1")
    led = AnchorLedger(membership_outputs=[])
    assert led.status()["chain_validated"] is False
    out = MembershipOutput(txid=TXID, vout=0, satoshis=1, script_hash="bb" * 32)
    led = AnchorLedger(membership_outputs=[out])
    rec = _record(key)
    led.append(rec, _inclusion(TXID, 100), rec.sign(key))
    led.verify(_header(TXID, 100))
    assert led.status()["chain_validated"] is False


def test_the_amount_is_not_a_price_because_nothing_verifies_it():
    """El importe no se usa como precio, y hay test de que no se puede.

    El riesgo concreto: alguien usa `satoshis_anchored` para decidir si una
    inferencia esta pagada. Seria un campo que el nodo eligio libremente y que
    por tanto no significa nada economico. El estado no lo ofrece como
    "pagado" — ofrece un conteo, que es lo unico que el modulo sabe.
    """
    key = Secp256k1KeyPair.new("n1")
    out = MembershipOutput(txid=TXID, vout=0, satoshis=1, script_hash="bb" * 32)
    led = AnchorLedger(membership_outputs=[out])
    for i in range(2):
        rec = _record(key, satoshis=ANCLAIM_AMOUNT_SATS,
                      occurred_at=1_700_000_000 + i)
        assert led.append(rec, _inclusion(TXID, 100 + i), rec.sign(key))[0]
    st = led.status()
    # es un conteo, no un pago: no hay ningun campo que lo llame pagado
    assert st["satoshis_anchored"] == 2 * ANCLAIM_AMOUNT_SATS
    assert "paid" not in st and "paid_sats" not in st
    assert not any("paid" in k for k in st)
    # y el verificador no lo compara con ningun precio de la malla
    ok, why = led.verify(_header(TXID, 100))
    assert ok, why
    # y la verificacion no importa ningun precio de la malla: `anchor` no
    # depende de `tiers`, y eso es lo que hace que "satoshis" no sea un pago
    import delm.core.anchor as anchor_mod
    src = (anchor_mod.__doc__ or "") + (anchor_mod.AnchorRecord.__doc__ or "")
    assert "tiers" not in src, "anchor no debe hablar de precios de nivel"


# ---------------------------------------------------------------------------
# Las cuatro cosas que la primera ronda de mutacion dejo sin sujetar
# ---------------------------------------------------------------------------
def test_a_signature_of_the_wrong_length_is_refused_in_all_three_directions():
    """Corta, larga y vacia. Las tres se rechazan antes de gastar ECDSA.

    Sin esta comprobacion, una firma corta llega a ``_secp_verify``, que en una
    libreria que no valida la longitud puede leer fuera del buffer. Es la razon
    de que el motivo sea explicito y no un error generico de libreria.
    """
    key = Secp256k1KeyPair.new("n1")
    rec = _record(key)
    inc = _inclusion(TXID, 100)
    hdr = _header(TXID, 100)
    for bad, n in [("", 0), ("00" * 10, 10), ("00" * 100, 100),
                   ("00" * 63, 63), ("00" * 65, 65)]:
        ok, why = rec.verify(bad, inc, hdr)
        assert not ok, f"una firma de {n} bytes deberia rechazarse"
        assert "firma" in why and "64" in why


def test_a_txid_of_the_wrong_length_is_refused_at_construction():
    """El txid de la membresia es parte del payload firmado, asi que su longitud
    importa: uno de 10 bytes no identifica ninguna transaccion."""
    key = Secp256k1KeyPair.new("n1")
    pk = key.public_key.hex()
    with pytest.raises(ProtocolError) as ei:
        AnchorRecord(membership_txid="ab" * 10, membership_vout=0,
                     membership_pubkey=pk, requester_pubkey=REQUESTER.public_key.hex(), satoshis=1)
    assert "txid" in str(ei.value)
    with pytest.raises(ProtocolError):
        AnchorRecord(membership_txid=TXID + "ab", membership_vout=0,
                     membership_pubkey=pk, requester_pubkey=REQUESTER.public_key.hex(), satoshis=1)


def test_changing_occurred_at_invalidates_the_signature():
    """El timestamp esta firmado, aunque no sea de confianza.

    "No es confianza" no quiere decir "no importa": si no estuviera en el
    payload, un nodo podria mover la fecha de sus inferencias para que todas
    parecieran anteriores o posteriores a un corte. La confianza la da el height
    del bloque; la integridad del campo la da la firma.
    """
    key = Secp256k1KeyPair.new("n1")
    rec = _record(key, occurred_at=1_000)
    sig = rec.sign(key)
    movido = AnchorRecord(membership_txid=TXID, membership_vout=0,
                          membership_pubkey=key.public_key.hex(), requester_pubkey=REQUESTER.public_key.hex(), satoshis=1,
                          occurred_at=2_000_000)
    ok, why = movido.verify(sig, _inclusion(TXID, 100), _header(TXID, 100))
    assert not ok and "firma" in why


def test_the_ledger_never_accepts_an_unknown_membership_even_with_everything_else_right():
    """El caso completo: firma valida, inclusion valida, membresia desconocida.

    Es el ataque de verdad — un nodo que rellena el ledger de otro. Se separa
    del caso basico porque aqui todo lo demas pasa y solo esta comprobacion lo
    detiene. Sin ella, el ledger seria un documento que cualquiera puede
    firmar.
    """
    key = Secp256k1KeyPair.new("n1")
    rec = _record(key)
    sig = rec.sign(key)                      # firma perfecta
    inc = _inclusion(TXID, 100)               # inclusion perfecta
    # el ledger no tiene ninguna salida conocida
    led = AnchorLedger(membership_outputs=[])
    ok, why = led.append(rec, inc, sig)
    assert not ok and "no esta en las salidas conocidas" in why
    assert len(led.anchors) == 0, "no se anade nada"

    # y con una membresia DISTINTA a la declarada
    otra = MembershipOutput(txid="bb" * 32, vout=0, satoshis=1,
                            script_hash="cc" * 32)
    led2 = AnchorLedger(membership_outputs=[otra])
    ok2, why2 = led2.append(rec, inc, sig)
    assert not ok2 and "no esta en las salidas conocidas" in why2

    # con la membresia correcta si se acepta
    led3 = AnchorLedger(membership_outputs=[
        MembershipOutput(txid=TXID, vout=0, satoshis=1, script_hash="bb" * 32)])
    ok3, why3 = led3.append(rec, inc, sig)
    assert ok3, why3


# ---------------------------------------------------------------------------
# Las defensas del ledger: el estado corrupto y la inclusion ajena
# ---------------------------------------------------------------------------
def test_the_ledger_refuses_an_inclusion_from_another_transaction():
    """Registro declara una membresia, la inclusion trae otra transaccion.

    Las dos son reales y por separado pasan. Solo juntas son un ataque: un nodo
    podria presentar su membresia verdadera y la inclusion de una transaccion
    cualquiera, y quien verificara veria dos pruebas validas de cosas distintas.
    """
    key = Secp256k1KeyPair.new("n1")
    rec = _record(key)                       # declara TXID
    sig = rec.sign(key)
    otra = "bb" * 32
    led = AnchorLedger(membership_outputs=[
        MembershipOutput(txid=TXID, vout=0, satoshis=1, script_hash="bb" * 32)])
    ok, why = led.append(rec, _inclusion(otra, 100), sig)
    assert not ok and "no es de la transaccion" in why
    assert len(led.anchors) == 0


def test_a_corrupt_ledger_refuses_to_verify_and_says_it_is_corrupt():
    """Listas descuadradas -> no verifica, y el motivo lo dice.

    El estado de un ledger puede venir de disco, de una redaccion, de una
    fusion. Si el numero de anclas no cuadra con el de inclusiones, verificar la
    mitad que queda seria emitir un veredicto sobre un documento que nadie sabe
    que es. Se rechaza entero.
    """
    key = Secp256k1KeyPair.new("n1")
    rec = _record(key)
    led = AnchorLedger(membership_outputs=[
        MembershipOutput(txid=TXID, vout=0, satoshis=1, script_hash="bb" * 32)])
    assert led.append(rec, _inclusion(TXID, 100), rec.sign(key))[0]
    led.anchors.append(rec)                    # dos anclas, una inclusion
    ok, why = led.verify(_header(TXID, 100))
    assert not ok and "corrupto" in why


def test_a_corrupt_ledger_refuses_to_grow():
    """Append tambien comprueba la salud del registro.

    Anadir sobre un ledger ya descuadrado lo hace mas descuadrado, y el fallo se
    propaga en silencio hasta que alguien verifique. Comprobarlo aqui significa
    que el error aparece en el sitio donde se introduce.
    """
    key = Secp256k1KeyPair.new("n1")
    rec = _record(key)
    led = AnchorLedger(membership_outputs=[
        MembershipOutput(txid=TXID, vout=0, satoshis=1, script_hash="bb" * 32)])
    led.anchors.append(rec)                    # ya esta descuadrado
    ok, why = led.append(rec, _inclusion(TXID, 100), rec.sign(key))
    assert not ok and "corrupto" in why
    assert len(led.anchors) == 1, "no se anade nada sobre un registro roto"


# ============================================== la peticion viene de la red
# La regla que sostiene la reputacion: un nodo solo cuenta inferencias que
# ALGUIEN le pidio. Sin esto, ejecutar inferencia contra uno mismo —lo mas
# barato de hacer y lo mas facil de multiplicar— seria indistinguible de
# servir a la malla, y el ranking no significaria nada.

def test_an_anchor_without_a_requester_is_refused():
    """Sin solicitante no hay peticion de red que probar.

    Un ancla v1 (que no tenia el campo) llega con el solicitante vacio y se
    rechaza. La direccion del fallo importa: preferimos un registro que no
    cuenta antes que uno que cuenta sin poder distinguir local de red.
    """
    key = Secp256k1KeyPair.new("n1")
    with pytest.raises(ProtocolError) as ei:
        AnchorRecord(membership_txid=TXID, membership_vout=0,
                     membership_pubkey=key.public_key.hex(), satoshis=1,
                     requester_pubkey="")
    assert "solicitante" in str(ei.value)
    assert "red" in str(ei.value)


def test_a_self_requested_anchor_is_refused():
    """El nodo pidiendo a si mismo es autoacreditacion, y no se ancla."""
    key = Secp256k1KeyPair.new("n1")
    with pytest.raises(ProtocolError) as ei:
        AnchorRecord(membership_txid=TXID, membership_vout=0,
                     membership_pubkey=key.public_key.hex(),
                     requester_pubkey=key.public_key.hex(), satoshis=1)
    assert "auto-solicitada" in str(ei.value)


def test_a_requester_of_the_wrong_length_is_refused():
    key = Secp256k1KeyPair.new("n1")
    with pytest.raises(ProtocolError) as ei:
        AnchorRecord(membership_txid=TXID, membership_vout=0,
                     membership_pubkey=key.public_key.hex(),
                     requester_pubkey="ab" * 5, satoshis=1)
    assert "pubkey" in str(ei.value)


def test_the_requester_is_inside_the_signed_payload():
    """Cambiar el solicitante despues de firmar invalida la firma.

    Si el campo no estuviera en el payload firmado, un nodo podria anclar una
    peticion de otro y luego reescribir el solicitante por uno suyo para
    convertirla en local (o al reves, para atribuir a otro). Es la misma
    disciplina que el importe: firmado, aunque no sea de confianza.
    """
    key = Secp256k1KeyPair.new("n1")
    rec = _record(key)
    sig = rec.sign(key)
    otro = Secp256k1KeyPair.new("otro")
    cambiado = AnchorRecord(
        membership_txid=TXID, membership_vout=rec.membership_vout,
        membership_pubkey=key.public_key.hex(),
        requester_pubkey=otro.public_key.hex(),
        satoshis=rec.satoshis, occurred_at=rec.occurred_at)
    ok, why = cambiado.verify(sig, _inclusion(TXID, 100), _header(TXID, 100))
    assert not ok and "firma" in why


def test_a_v1_record_cannot_come_back_as_an_inference():
    """Un ancla v1 no tiene solicitante, y el formato v1 ya no se acepta.

    Subir la version es lo que hace esto barato: no hace falta migrar los
    registros viejos ni decidir que hacen, simplemente no vuelven a existir como
    inferencias contables. El que se lea con `ver: 1` falla al construirse, y
    por tanto tampoco verifica.
    """
    key = Secp256k1KeyPair.new("n1")
    rec = _record(key)
    sig = rec.sign(key)
    v1 = rec.to_dict()
    v1.pop("requester_pubkey")
    v1["ver"] = 1
    with pytest.raises(ProtocolError) as ei:
        AnchorRecord.from_dict(v1)
    assert "version" in str(ei.value)
