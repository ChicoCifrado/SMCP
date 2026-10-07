"""Inscripción — la transacción única de v3: paga e inscribe.

Qué resuelve este módulo
------------------------
La pregunta que v2 dejó abierta: **cuál es el template de la
transacción que paga y ancla una inferencia.** La respuesta (en
``docs/inscripcion-v3.md``) es una sola transacción: Alice paga
250 sats, Bob sirve la inferencia y ancla el hash por 1 satoshi —
un ordinal que viaja a Alice como comprobante — y cobra 249 sats
menos la fee, que paga Bob de su parte.

El flujo es DPP (BRC-27): Bob construye la tx
(:func:`build_payment_terms`), Alice verifica
(:func:`verify_payment_terms`), firma su input
(:func:`sign_requester_input`), y Bob emite. La verificación
post-minado (:func:`verify_inscription`) es offline: firma sobre
``H`` más inclusión contra una cabecera que el verificador confíe.

El hash
-------
``H = SHA-256(uint16be(len(mesh_id)) ‖ mesh_id ‖ pubkey[33])``

Deliberadamente **no** es el hash del resultado (ver la spec:
publicar el hash de un prompt es tan identificador como el
prompt). Lo que se ancla es *que* una inferencia verificada
ocurrió en este mesh, para este solicitante, servida por este
nodo.

El envelope
-----------
BRC-160: el envelope ``OP_FALSE OP_IF "ord" … OP_ENDIF`` va **en
el script de bloqueo del output de 1 sat**, no en un OP_RETURN.
El envelope es un no-op, así que el output se gasta normal con la
clave de Alice: quien posee el comprobante posee el registro. Los
campos de aplicación (2 servidor, 3 parent, 4 versión, 5 firma)
van antes del body (campo 0), que es el **último** campo — y el
orden de campos es parte del formato, como en BRC-220:
codificación fija, nunca "el que lea que interprete".

Orden de bytes
--------------
El *parent* (campo 3) es el outpoint del input que paga: el txid
en **orden interno** (como viaja en el cable) más el vout en
little-endian. Todo lo demás (txid de presentación, ``H``) es lo
de siempre: hex big-endian para mostrar.

Lo que este módulo NO hace
--------------------------
* No emite a la red (el ``PaymentACK`` de DPP es de la capa de
  transporte, no de aquí).
* No ejecuta ni verifica la inferencia — el modelo es de
  :mod:`smcp.core.llm`, y el hash del resultado es SMCP4.
* No cuenta la inferencia:
  :func:`smcp.core.contrib.record_inference` es el único camino
  del historial, y su clave es el **txid** de esta transacción.
* No es v2: ``anchor.py`` y ``membership.py`` siguen intactos;
  v3 es un formato nuevo, versionado (campo 4 = 3).
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from smcp.core.bsv_keys import (
    HAVE_ECDSA,
    PUBKEY_LEN,
    SIG_KIND,
    SIG_LEN,
    Secp256k1KeyPair,
    verify_public,
)
from smcp.core.membership import BlockHeader, InclusionProof, ProtocolError
from smcp.core.spv import hash160
from smcp.core.tiers import PER_INFERENCE_SATOSHIS
from smcp.core.txbuild import (
    OP_0,
    OP_1,
    OP_2,
    OP_3,
    OP_4,
    OP_5,
    OP_ENDIF,
    OP_FALSE,
    OP_IF,
    Transaction,
    TxIn,
    TxOut,
    p2pkh_lock,
    push_data,
)

#: Versión de formato de la inscripción (campo 4 del envelope).
INSCRIPTION_VERSION = 3

#: El ordinal es de 1 satoshi: el comprobante viaja dentro de él.
ORDINAL_SATOSHIS = 1

#: Longitud del body en caracteres hex (32 bytes de hash).
_HASH_HEX_LEN = 64

#: Longitud del parent en bytes (32 de txid + 4 de vout).
_PARENT_LEN = 36


# ---------------------------------------------------------------------------
# El hash que ancla la inferencia
# ---------------------------------------------------------------------------
def inference_hash(mesh_id: str, requester_pubkey: bytes) -> str:
    """``H``: lo que la cadena compromete, y nada más.

    El prefijo ``uint16be`` de longitud evita la ambigüedad de la
    concatenación (la misma lección de determinismo de BRC-220:
    codificación fija). Con él, ``("ab", pk)`` y ``("a", pk')``
    no pueden colisionar aunque sus concatenaciones sí.
    """
    if len(requester_pubkey) != PUBKEY_LEN:
        raise ProtocolError(
            f"pubkey de solicitante de {len(requester_pubkey)} bytes; "
            f"se esperan {PUBKEY_LEN}"
        )
    mesh = mesh_id.encode("utf-8")
    if not mesh:
        raise ProtocolError("mesh_id vacío: el hash no compromete nada")
    if len(mesh) > 0xFFFF:
        raise ProtocolError(
            f"mesh_id de {len(mesh)} bytes; el prefijo u16 llega a 65 535"
        )
    preimage = len(mesh).to_bytes(2, "big") + mesh + requester_pubkey
    return hashlib.sha256(preimage).hexdigest()


# ---------------------------------------------------------------------------
# La petición y la firma del servidor (BRC-220)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class InscriptionRequest:
    """Lo que Alice pide y Bob ancla: el contenido del compromiso.

    ``requester_pubkey`` es la clave de Alice — la que paga y la
    que recibe el ordinal. ``server_pubkey`` es la de Bob — la que
    firma ``H`` y la que cobra. Las dos viajan en la tx, en sitios
    distintos, con roles distintos.
    """

    mesh_id: str
    requester_pubkey: bytes
    server_pubkey: bytes

    def __post_init__(self) -> None:
        if len(self.requester_pubkey) != PUBKEY_LEN:
            raise ProtocolError(
                f"pubkey de solicitante de {len(self.requester_pubkey)} "
                f"bytes; se esperan {PUBKEY_LEN}"
            )
        if len(self.server_pubkey) != PUBKEY_LEN:
            raise ProtocolError(
                f"pubkey de servidor de {len(self.server_pubkey)} bytes; "
                f"se esperan {PUBKEY_LEN}"
            )
        if not self.mesh_id.encode("utf-8"):
            raise ProtocolError("mesh_id vacío")


def server_signature(*, mesh_id: str, requester_pubkey: bytes,
                     server_key: Secp256k1KeyPair) -> bytes:
    """Bob firma ``H`` con su clave (BRC-220: secp256k1, ``r‖s``).

    La firma es **local**: el servidor hashea y firma sin tocar la
    cadena, y la cadena lleva el hash y la firma — nunca el
    contenido. Que la firma sea sobre ``H`` y no sobre la tx es lo
    que permite a Alice verificar el *PaymentTerms* antes de firmar
    su input.
    """
    if server_key.kind != SIG_KIND:
        raise ProtocolError(
            f"la clave del servidor debe ser {SIG_KIND}, "
            f"no {server_key.kind!r}"
        )
    return server_key.sign(inference_hash(mesh_id, requester_pubkey))


# ---------------------------------------------------------------------------
# El envelope BRC-160
# ---------------------------------------------------------------------------
def envelope_script(*, server_pubkey: bytes, parent_txid: str,
                    parent_vout: int, signature: bytes,
                    hash_hex: str) -> bytes:
    """El envelope SMCP3: los campos 1, 2, 3, 4, 5 y el body (0).

    El body es el último campo, como manda BRC-160. El *parent*
    (campo 3) es el outpoint del input que paga: txid en orden
    interno más vout little-endian — la forma en que el outpoint
    viaja en el cable.
    """
    if len(server_pubkey) != PUBKEY_LEN:
        raise ProtocolError(
            f"pubkey de servidor de {len(server_pubkey)} bytes; "
            f"se esperan {PUBKEY_LEN}"
        )
    if len(signature) != SIG_LEN:
        raise ProtocolError(
            f"firma de {len(signature)} bytes; se esperan {SIG_LEN} (r‖s)"
        )
    if len(hash_hex) != _HASH_HEX_LEN:
        raise ProtocolError(
            f"body de {len(hash_hex)} caracteres; se esperan "
            f"{_HASH_HEX_LEN} hex"
        )
    if hash_hex != hash_hex.lower():
        raise ProtocolError("el body va en hex minúsculas (canónico)")
    try:
        bytes.fromhex(hash_hex)
        parent = bytes.fromhex(parent_txid)[::-1]
    except ValueError as exc:
        raise ProtocolError(
            f"parent o body no son hex válido: {exc}"
        ) from exc
    if len(parent) != 32:
        raise ProtocolError(
            f"txid de parent de {len(parent)} bytes; se esperan 32"
        )
    try:
        parent += struct.pack("<I", parent_vout)
    except struct.error as exc:
        raise ProtocolError(f"vout {parent_vout} fuera de u32") from exc
    return b"".join([
        bytes([OP_FALSE, OP_IF]),
        push_data(b"ord"),
        bytes([OP_1]) + push_data(b"text/plain"),
        bytes([OP_2]) + push_data(server_pubkey),
        bytes([OP_3]) + push_data(parent),
        bytes([OP_4]) + push_data(bytes([INSCRIPTION_VERSION])),
        bytes([OP_5]) + push_data(signature),
        bytes([OP_0]) + push_data(hash_hex.encode("ascii")),
        bytes([OP_ENDIF]),
    ])


def _read_push(script: bytes, pos: int) -> tuple[bytes, int]:
    """Lee el push de datos que empieza en ``pos``."""
    if pos >= len(script):
        raise ProtocolError("script cortado")
    op = script[pos]
    pos += 1
    if op <= 75:
        n = op
    elif op == 0x4C:  # OP_PUSHDATA1
        if pos >= len(script):
            raise ProtocolError("PUSHDATA1 sin longitud")
        n = script[pos]
        pos += 1
    elif op == 0x4D:  # OP_PUSHDATA2
        n = int.from_bytes(script[pos:pos + 2], "little")
        pos += 2
    elif op == 0x4E:  # OP_PUSHDATA4
        n = int.from_bytes(script[pos:pos + 4], "little")
        pos += 4
    else:
        raise ProtocolError(f"{op:#04x} no es un push de datos")
    if pos + n > len(script):
        raise ProtocolError("push fuera del script")
    return script[pos:pos + n], pos + n


#: Los tags de campo que SMCP3 define. Un tag desconocido es otro
#: formato (una versión futura), no un error de parseo silencioso.
_ENVELOPE_TAGS = frozenset({OP_0, OP_1, OP_2, OP_3, OP_4, OP_5})


def parse_envelope(script: bytes) -> dict[int, bytes]:
    """Los campos tag/valor de un envelope BRC-160.

    Lee hasta ``OP_ENDIF`` y deja el resto del script (el P2PKH que
    sigue al envelope) al que llama. Un tag que no es de SMCP3 lanza
    :class:`ProtocolError`: es otra versión del formato, y eso se
    dice, no se ignora.
    """
    if script[:2] != bytes([OP_FALSE, OP_IF]):
        raise ProtocolError("no empieza con OP_FALSE OP_IF")
    pos = 2
    word, pos = _read_push(script, pos)
    if word != b"ord":
        raise ProtocolError('no es un envelope "ord"')
    fields: dict[int, bytes] = {}
    while pos < len(script) and script[pos] != OP_ENDIF:
        tag = script[pos]
        if tag not in _ENVELOPE_TAGS:
            raise ProtocolError(f"tag de envelope desconocido: {tag:#04x}")
        pos += 1
        value, pos = _read_push(script, pos)
        if tag in fields:
            raise ProtocolError(f"tag de envelope repetido: {tag:#04x}")
        fields[tag] = value
    if pos >= len(script):
        raise ProtocolError("envelope sin OP_ENDIF")
    return fields


# ---------------------------------------------------------------------------
# Construcción DPP: Bob construye, Alice firma
# ---------------------------------------------------------------------------
def build_payment_terms(*, request: InscriptionRequest,
                        signature: bytes, funding: TxIn,
                        funding_sats: int, fee_sats: int) -> Transaction:
    """La tx sin firmar (DPP ``PaymentTerms``), construida por Bob.

    El fondeo es **exactamente** :data:`PER_INFERENCE_SATOSHIS`: la
    plantilla v3.0 no lleva cambio (Alice consolida un UTXO exacto,
    operación normal de wallet). La fee sale de los 249 sats del
    servidor, así que una fee de 249 o más no cierra — y la tx
    (~453 bytes) solo pasa relay por debajo de ~0.55 sat/vB, ver
    :func:`relay_budget`. El knob es
    :data:`PER_INFERENCE_SATOSHIS`.
    """
    if funding_sats != PER_INFERENCE_SATOSHIS:
        raise ProtocolError(
            f"fondeo de {funding_sats} sats; la plantilla son "
            f"{PER_INFERENCE_SATOSHIS} exactos (sin cambio en v3.0)"
        )
    if funding.script_sig:
        raise ProtocolError(
            "el input de fondeo ya está firmado: DPP construye la tx "
            "sin firmar y el cliente firma su input"
        )
    server_sats = PER_INFERENCE_SATOSHIS - ORDINAL_SATOSHIS - fee_sats
    if server_sats < 1:
        raise ProtocolError(
            f"fee de {fee_sats} sats: se come el pago del servidor "
            f"(le quedan {server_sats}); el knob es "
            f"PER_INFERENCE_SATOSHIS"
        )
    h = inference_hash(request.mesh_id, request.requester_pubkey)
    if not verify_public(request.server_pubkey, h, signature):
        raise ProtocolError("la firma del servidor no verifica sobre H")
    ordinal = TxOut(
        ORDINAL_SATOSHIS,
        envelope_script(
            server_pubkey=request.server_pubkey,
            parent_txid=funding.prev_txid,
            parent_vout=funding.vout,
            signature=signature,
            hash_hex=h,
        )
        + p2pkh_lock(hash160(request.requester_pubkey)),
    )
    server = TxOut(
        server_sats, p2pkh_lock(hash160(request.server_pubkey))
    )
    return Transaction(inputs=[funding], outputs=[ordinal, server])


def sign_requester_input(tx: Transaction, index: int,
                         requester_key: Secp256k1KeyPair) -> None:
    """Alice firma su input (DPP ``Payment``).

    El scriptCode que se firma es el P2PKH del UTXO de fondeo — la
    clave de Alice —, no el scriptSig (que todavía está vacío).
    """
    if requester_key.kind != SIG_KIND:
        raise ProtocolError(
            f"la clave del solicitante debe ser {SIG_KIND}, "
            f"no {requester_key.kind!r}"
        )
    script_code = p2pkh_lock(hash160(requester_key.public_key))
    tx.sign_input(index, requester_key, script_code)


def build_inscription(*, mesh_id: str, requester_key: Secp256k1KeyPair,
                      server_key: Secp256k1KeyPair, funding: TxIn,
                      funding_sats: int, fee_sats: int) -> Transaction:
    """El flujo DPP completo, offline: Bob construye, Alice firma.

    Lo que **no** incluye es la ejecución de la inferencia (es de
    :mod:`smcp.core.llm`) ni la emisión (es de la capa de
    transporte). Todo aquí es determinista salvo la firma ECDSA,
    que es aleatoria por diseño (ver :mod:`smcp.core.bsv_keys`).
    """
    request = InscriptionRequest(
        mesh_id, requester_key.public_key, server_key.public_key
    )
    signature = server_signature(
        mesh_id=mesh_id,
        requester_pubkey=requester_key.public_key,
        server_key=server_key,
    )
    tx = build_payment_terms(
        request=request, signature=signature, funding=funding,
        funding_sats=funding_sats, fee_sats=fee_sats,
    )
    sign_requester_input(tx, 0, requester_key)
    return tx


# ---------------------------------------------------------------------------
# Presupuesto de relay (abierto 3 de la spec, cerrado por medición)
# ---------------------------------------------------------------------------
#: Tarifa de relay que el **software** de nodo BSV aplica
#: por defecto (``minrelaytxfee`` = 0.00001 BSV/kB). Es el
#: techo del software, no del mercado: los pools de BSV
#: minan habitualmente por debajo de él.
BSV_RELAY_SOFTWARE_SAT_PER_BYTE = 1.0

#: Techo del rango que los pools de BSV aceptan de forma
#: común (0.05-0.25 sat/vB). Con el precio de 250 sats la
#: plantilla **cierra** en todo él (a 0.25 la fee son
#: ~113 sats).
BSV_RELAY_POOL_SAT_PER_BYTE = 0.25

#: Techo de la banda de relay objetivo de la v3: el precio
#: (250 sats, presupuesto de 249) cierra hasta ~0.55
#: sat/vB, que cubre 0.1-0.5 con margen.
BSV_RELAY_TARGET_SAT_PER_BYTE = 0.5


@dataclass(frozen=True)
class RelayBudget:
    """Lo que una tx de inscripción puede pagar de relay.

    Atributos:
        size_bytes: tamaño serializado de la tx. Varía un
            byte de una construcción a otra (la firma DER
            mide 71 u 72 bytes), así que cualquier decisión
            que dependa del tamaño mide la tx, no la
            estima.
        fee_sats: la fee que la tx paga (de los 249 sats
            del servidor).
    """

    size_bytes: int
    fee_sats: int

    @property
    def max_rate_sat_per_byte(self) -> float:
        """La mayor tarifa de relay a la que la tx cierra."""
        return self.fee_sats / self.size_bytes

    def cierra_a(self, rate_sat_per_byte: float) -> bool:
        """¿La tx paga su relay a esta tarifa (sat/vB)?"""
        return self.size_bytes * rate_sat_per_byte <= self.fee_sats


def relay_budget(tx: Transaction, fee_sats: int) -> RelayBudget:
    """Presupuesto de relay de una tx de inscripción construida.

    La medición que cierra el abierto 3 de la spec
    (``docs/inscripcion-v3.md``): la plantilla v3.0
    serializa **~453 bytes**, no los ~250 que la spec
    estimó — el envelope de BRC-160 viaja en el script de
    bloqueo del ordinal (campo 5 = firma de 64 B en hex,
    campo 0 = ``H`` de 64 B en hex). Con el precio de
    250 sats el presupuesto de fee son 249, y la tx
    cierra por debajo de ``249 / 453 ≈ 0.55 sat/vB``
    (techo; la fee máxima construible son 248, que dejan
    1 sat al servidor):

    * el default del software (1 sat/vB) **no cierra** —
      harían falta ~453 sats;
    * la banda objetivo de la v3 (0.1-0.5 sat/vB) **cierra
      entera**: a 0.1 bastan ~46 sats, a 0.5 ~227;
    * el rango común de los pools (0.05-0.25) cierra con
      margen: a 0.25 la fee son ~113 sats;
    * con la fee por defecto del intercambio (0 sats) la
      tx no paga relay alguno — solo la minan los pools
      que aceptan txs sin fee.

    El knob, si la tx no cierra donde se quiere minar, es
    :data:`smcp.core.tiers.PER_INFERENCE_SATOSHIS` (y el
    corte de :func:`smcp.core.tiers.tier_for_inferences`
    se mueve con él).
    """
    return RelayBudget(size_bytes=len(tx.serialize()),
                       fee_sats=fee_sats)


# ---------------------------------------------------------------------------
# Extracción y verificación del comprobante
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class InscriptionReceipt:
    """Lo que una tx de inscripción dice, sin verificar todavía.

    Lo que **no** está aquí es deliberado: ``mesh_id`` y la
    ``requester_pubkey`` no viajan en la tx (solo su compromiso
    ``H`` y el ``hash160`` de la clave), y el valor del fondeo no
    está en la tx (está en la tx previa). Los tres son datos
    fuera de cadena que el verificador aporta.
    """

    txid: str
    ordinal_vout: int
    ordinal_satoshis: int
    server_vout: int
    server_satoshis: int
    server_pubkey: bytes
    parent: bytes
    version: int
    signature: bytes
    hash_hex: str

    @property
    def ordinal_outpoint(self) -> str:
        """El outpoint del ordinal: el comprobante que Alice posee."""
        return f"{self.txid}:{self.ordinal_vout}"

    @property
    def parent_outpoint(self) -> str:
        """El outpoint del input que pagó la inscripción."""
        txid = self.parent[:32][::-1].hex()
        vout = int.from_bytes(self.parent[32:], "little")
        return f"{txid}:{vout}"


def _field(fields: dict[int, bytes], tag: int, length: int,
           name: str) -> bytes:
    if tag not in fields:
        raise ProtocolError(f"falta el campo {tag:#04x} ({name})")
    value = fields[tag]
    if len(value) != length:
        raise ProtocolError(
            f"campo {name} de {len(value)} bytes; se esperan {length}"
        )
    return value


def extract_inscription(tx: Transaction) -> InscriptionReceipt:
    """Extrae la inscripción de una tx. Lanza si no es SMCP3.

    El ordinal se identifica por **tener envelope**, no por su
    importe: un pago de 1 sat a P2PKH plano no es un ordinal. La
    plantilla es exactamente 1 input y 2 outputs (sin cambio en
    v3.0), y el body ha de ser hex canónico — todo eso es estructura
    del formato, y un fallo es :class:`ProtocolError` (otro formato
    o un bug), no un ``False`` de verificación.
    """
    if len(tx.inputs) != 1:
        raise ProtocolError(
            f"{len(tx.inputs)} inputs; la plantilla es exactamente 1"
        )
    if len(tx.outputs) != 2:
        raise ProtocolError(
            f"{len(tx.outputs)} outputs; la plantilla es exactamente 2 "
            "(sin cambio en v3.0)"
        )
    ordinal_vout = -1
    envelope_fields: dict[int, bytes] = {}
    for i, out in enumerate(tx.outputs):
        try:
            fields = parse_envelope(out.script)
        except ProtocolError:
            continue
        if ordinal_vout >= 0:
            raise ProtocolError("más de un output con envelope")
        ordinal_vout = i
        envelope_fields = fields
    if ordinal_vout < 0:
        raise ProtocolError("ningún output tiene envelope BRC-160")
    ordinal = tx.outputs[ordinal_vout]
    if ordinal.satoshis != ORDINAL_SATOSHIS:
        raise ProtocolError(
            f"el output con envelope es de {ordinal.satoshis} sats; "
            f"el ordinal es de {ORDINAL_SATOSHIS}"
        )
    server_vout = 1 - ordinal_vout
    server_pubkey = _field(
        envelope_fields, OP_2, PUBKEY_LEN, "pubkey del servidor"
    )
    parent = _field(envelope_fields, OP_3, _PARENT_LEN, "parent")
    version = _field(envelope_fields, OP_4, 1, "versión")[0]
    signature = _field(envelope_fields, OP_5, SIG_LEN, "firma")
    body = _field(envelope_fields, OP_0, _HASH_HEX_LEN, "body")
    try:
        hash_hex = body.decode("ascii")
        bytes.fromhex(hash_hex)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProtocolError(f"body no es hex ASCII: {exc}") from exc
    if hash_hex != hash_hex.lower():
        raise ProtocolError("el body no es hex canónico (minúsculas)")
    return InscriptionReceipt(
        txid=tx.txid(),
        ordinal_vout=ordinal_vout,
        ordinal_satoshis=ordinal.satoshis,
        server_vout=server_vout,
        server_satoshis=tx.outputs[server_vout].satoshis,
        server_pubkey=server_pubkey,
        parent=parent,
        version=version,
        signature=signature,
        hash_hex=hash_hex,
    )


def verify_payment_terms(tx: Transaction, *, mesh_id: str,
                        requester_pubkey: bytes,
                        funding_sats: int) -> tuple[bool, str]:
    """Verifica la tx **antes** de emitirla: lo que Alice comprueba.

    No necesita inclusión (la tx todavía no está en un bloque):
    comprueba el compromiso (``H``), la firma del servidor, el
    parent, las cerraduras y la aritmética de pagos. El orden de las
    comprobaciones es barato-primero, como en
    :meth:`smcp.core.membership.MembershipProof.verify`.
    """
    if not HAVE_ECDSA:  # pragma: no cover
        return False, "ecdsa-secp256k1 no disponible"
    if funding_sats != PER_INFERENCE_SATOSHIS:
        return False, (
            f"fondeo de {funding_sats} sats; la plantilla son "
            f"{PER_INFERENCE_SATOSHIS}"
        )
    try:
        receipt = extract_inscription(tx)
        # Reconstruir el envelope canónico: si el de la tx no es
        # canónico (otro orden de campos, otra codificación), la
        # reconstrucción no casa y la inscripción no es SMCP3.
        canonical = envelope_script(
            server_pubkey=receipt.server_pubkey,
            parent_txid=tx.inputs[0].prev_txid,
            parent_vout=tx.inputs[0].vout,
            signature=receipt.signature,
            hash_hex=receipt.hash_hex,
        )
    except ProtocolError as exc:
        return False, f"inscripción malformada: {exc}"
    if receipt.version != INSCRIPTION_VERSION:
        return False, (
            f"versión {receipt.version}: este verificador es "
            f"SMCP{INSCRIPTION_VERSION}"
        )
    h = inference_hash(mesh_id, requester_pubkey)
    if receipt.hash_hex != h:
        return False, "el hash inscrito no compromete (mesh_id, solicitante)"
    if not verify_public(receipt.server_pubkey, h, receipt.signature):
        return False, "la firma del servidor no verifica sobre H"
    paying = tx.inputs[0]
    parent = bytes.fromhex(paying.prev_txid)[::-1] + struct.pack(
        "<I", paying.vout
    )
    if receipt.parent != parent:
        return False, "el parent no es el outpoint del input que paga"
    ordinal_script = tx.outputs[receipt.ordinal_vout].script
    if ordinal_script != canonical + p2pkh_lock(
        hash160(requester_pubkey)
    ):
        return False, "el ordinal no es el envelope canónico a nombre del solicitante"
    if tx.outputs[receipt.server_vout].script != p2pkh_lock(
        hash160(receipt.server_pubkey)
    ):
        return False, "el pago no está a nombre de la pubkey inscrita"
    total_out = receipt.ordinal_satoshis + receipt.server_satoshis
    if total_out > funding_sats:
        return False, "la tx gasta más de lo que el fondeo cubre"
    if receipt.server_satoshis < 1:
        return False, "la fee se come el pago del servidor"
    return True, "ok"


def verify_inscription(tx: Transaction, *, mesh_id: str,
                       requester_pubkey: bytes, funding_sats: int,
                       inclusion: InclusionProof,
                       header: BlockHeader) -> tuple[bool, str]:
    """Verifica el comprobante completo: inclusión más el pago.

    La inclusión va primero, como en v2: si la transacción no está en
    un bloque no hay nada que firmar, y buscar la firma primero solo
    gasta trabajo de un atacante. Que la cabecera sea la correcta
    **no** se prueba aquí — esa es la decisión del verificador
    (SPV, BRC-96): la confianza está en la cadena de cabeceras que
    él elige, no en la prueba.
    """
    if inclusion.txid != tx.txid():
        return False, "inclusión: la prueba es de otra transacción"
    if not inclusion.verify(header):
        return False, "inclusión: prueba de Merkle no válida"
    return verify_payment_terms(
        tx, mesh_id=mesh_id, requester_pubkey=requester_pubkey,
        funding_sats=funding_sats,
    )


__all__ = [
    "InscriptionReceipt", "InscriptionRequest",
    "INSCRIPTION_VERSION", "ORDINAL_SATOSHIS",
    "inference_hash", "server_signature",
    "envelope_script", "parse_envelope",
    "build_payment_terms", "sign_requester_input", "build_inscription",
    "extract_inscription", "verify_payment_terms", "verify_inscription",
]
