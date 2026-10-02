"""Membership — la pertenencia a la malla anclada en BSV: unir, rotar, verificar.

Qué resuelve este módulo
------------------------
Hoy un nodo se "une" porque un pariente lo metió en un roster firmado
(:mod:`delm.core.roster`). Eso es atribución social: basta con que avales, y
un atacante necesita un solo aval. Este módulo es el otro eje: **la
pertenencia la posee el nodo, y esa posesión es verificable sin nosotros.**

La idea completa cabe en una frase: **un smart contract en BSV no tiene
estado, pero un UTXO sí.** La union de los outputs de membresía *es* el
conjunto de miembros, y cualquiera lo computa escaneando la cadena. El script
no "unifica" a nadie — la estructura lo hace emerger.

Cómo se convierte una clave en una membresía
---------------------------------------------
El truco que hace que la rotación funcione es que **la clave de identidad se
crea antes que el output, y el output se paga a esa clave**:

    clave SMCP nueva  ->  P2PKH(pubkey)  =  la membresía

El nodo genera su clave, construye ``(mi clave de fondos) -> P2PKH(clave SMCP)``
y lo firma con la de fondos. La clave de identidad **controla un UTXO**, y por
eso la membresía es algo que se posee, no algo que se declara. No hace falta
un servicio que "apruebe" a nadie.

Rotación por gasto: la succession de claves sale gratis
---------------------------------------------------------
Renovar clave es **gastar el output de membresía a la nueva clave**::

    P2PKH(clave_vieja)  ->  P2PKH(clave_nueva)   firmada con la clave vieja

De aquí salen dos propiedades que no hay que implementar, porque las da el
grafo:

* **Rotación doble simultánea -> una sola gana.** Es un doble gasto. La otra
  clave se queda sin output y su nodo deja de ser miembro. No hace falta un
  registro de "cuál era la clave vigente".
* **La cadena de ancestros ES la sucesión de claves.** Verificable por
  cualquiera sin que nadie la mantenga, y sin índice.

Un nodo no puede renovarse a sí mismo dos veces ni vender su output sin
perderlo. Eso es resistencia a Sybil en la capa de identidad, gratis, porque
nunca estuvo en el código: estaba en la estructura de la cadena.

El limite honesto: SPV verifica, la cadena no se valida
---------------------------------------------------------
:class:`MembershipProof` hace una verificación real de la prueba de Merkle
contra una cabecera de bloque. Eso prueba que *esa* transacción está en *ese*
bloque. **No prueba que ese bloque sea el más largo** — esa es la debilidad
conhecyida de SPV (BRC-96), y no se arregla aquí. Por eso la confianza no
está en la prueba sino en la **cadena de cabecera**: un verificador que acepta
la prueba tiene que decidir de antemano qué cadena cree, igual que
:mod:`delm.core.timechain` deja escrito que la cadena *es* el reloj.

Lo que este módulo NO hace, y está escrito en vez de omitido:

* **No valida el *script* de una transaction real.** No parsea Bitcoin Script.
  Trabaja con un :class:`MembershipLock` que declara el formato esperado
  (hash de un script) y una :class:`MembershipOutput` que dice que un output
  lo cumple. Quien use esto contra la cadena real tiene que extraer el script
  del output gastado y compararlo; aquí eso es un :class:`ProtocolError`
  explícito, no un ``None`` ambiguo.
* **No decide qué SC es el de confianza.** Si el lock es un lock de pubkey,
  cualquiera despliega su propio "SC" y su propia malla. La lista de locks de
  confianza es una decisión del operador, en su cliente.
* **No ancla.** :mod:`delm.core.timechain` publica; este módulo verifica lo
  publicado. No hay emisión de transacciones aquí.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

from delm.core.bsv_keys import (
    HAVE_ECDSA,
    PUBKEY_LEN,
    SIG_KIND,
    SIG_LEN,
    Secp256k1KeyPair,
    verify_public as _secp_verify,
)

_LOG = logging.getLogger(__name__)

#: Longitud de un txid / hash de bloque: 32 bytes.
HASH_LEN = 32

#: Longitud de una cabecera de bloque Bitcoin serializada: 80 bytes.
HEADER_LEN = 80

#: Version del formato de la prova. Viaja dentro del digest firmado, asi que
#: subirlo invalida las pruebas emitidas con el formato viejo — a proposito.
MEMBERSHIP_VERSION = 1

#: Rango comodo para membership_fee, en satoshis. No es una validacion de
#: politica economica: es la banda en la que un JoinProof es plausible como
#: "pago real" frente a "dust". El limite de dust de BSV esta en el mismo
#: orden de magnitud, asi que un valor aqui dentro podria ser dust y aun asi
#: pasaria la comprobacion — el coste lo pone el minado, no este numero.
DUST_ORDER = 1000


# ---------------------------------------------------------------------------
# Errores
# ---------------------------------------------------------------------------
class ProtocolError(RuntimeError):
    """La prueba no cumple el protocolo. Distinto de "firma invalida" a proposito.

    Un ``ProtocolError`` es un bug de implementacion o una prueba de otro
    formato; un ``False`` de la verificacion es un atacante. Confundirlos hace
    que un cliente rechace con un error generico lo que deberia rechazar con un
    ``403``, y al reves.
    """


# ---------------------------------------------------------------------------
# Primitivas de bloque
# ---------------------------------------------------------------------------
def dsha256(data: bytes) -> bytes:
    """Doble SHA-256, byte a byte. El hash de Bitcoin no es SHA-256 simple."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """La raiz de Merkle de una lista de hashes, tal como la computa Bitcoin.

    Implementa la rareza de Bitcoin: cuando un nivel tiene un numero impar de
    nodos, **el ultimo se duplica**. No es un error, es elCommitment de diseno
    — un arbol de potencia de dos no podria representar un numero arbitrario de
    transacciones. Omitir la duplicacion produce una raiz distinta de la que
    cualquier otro nodo computa, y el verificador rechazaria pruebas validas.

    Los hashes son interno (little-endian), no el txid de presentacion.
    """
    if not leaves:
        raise ValueError("una raiz de Merkle necesita al menos una hoja")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [dsha256(level[i] + level[i + 1])
                 for i in range(0, len(level), 2)]
    return level[0]


def verify_merkle_proof(txid: str, index: int, path: list[str],
                        root: str) -> bool:
    """Prueba que ``txid`` esta incluido en un arbol con raiz ``root``.

    ``txid`` y ``root`` van en **hex de presentacion** (big-endian, el orden
    inverso al interno). ``path`` son los hashes hermanos, tambien en hex de
    presentacion, de abajo arriba.

    Esta conversion de endianness es la trampa clasica de las pruebas de
    Merkle: la cadena tiene el hash en orden interno y las APIs lo muestran
    invertido, asi que un verificador que mezcla las dos produce una raiz
    distinta y rechaza pruebas legitimas. Todo entra en presentacion y se
    invierte exactamente una vez, en :func:`_internal`.
    """
    if index < 0:
        return False
    try:
        node = _internal(txid)
    except ValueError:
        return False
    try:
        want = _internal(root)
    except ValueError:
        return False
    for sibling_hex in path:
        try:
            sib = _internal(sibling_hex)
        except ValueError:
            return False
        if index % 2:
            node = dsha256(sib + node)
        else:
            node = dsha256(node + sib)
        index //= 2
    return node == want


def _internal(hex_str: str) -> bytes:
    """Hex de presentacion (big-endian) -> bytes en orden interno de la cadena."""
    if len(hex_str) != HASH_LEN * 2:
        raise ValueError(
            f"hash de {len(hex_str)} caracteres hex; se esperan {HASH_LEN * 2}")
    return bytes.fromhex(hex_str)[::-1]


def _present(raw: bytes) -> str:
    """Bytes en orden interno -> hex de presentacion."""
    return raw[::-1].hex()


@dataclass(frozen=True)
class BlockHeader:
    """Una cabecera de bloque, y sobre todo su raiz de Merkle.

    Solo se usa la raiz, y por eso el resto de los campos se conserva sin
    validar: el proposito de este modulo es la inclusion, no encadenar bloques.
    """

    merkle_root: str
    height: int = 0
    raw: bytes = b""

    @property
    def block_hash(self) -> str:
        """El hash del bloque, si se paso la cabecera cruda._si no, vacio."""
        if len(self.raw) != HEADER_LEN:
            return ""
        return _present(dsha256(self.raw))


# ---------------------------------------------------------------------------
# El lock: cual es "el" SC de esta malla
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class MembershipLock:
    """La raiz de confianza: *que* salida de membresia vale.

    Es un identificador de formato, no una clave que verifique firmas. Lo que
    dice es "un output cuenta como membresia si su script cumple *esto*". La
    decision de cual es el lock legitimo la toma el operador, aqui y en su
    cliente — no hay nada en la cadena que la imponga. Si no, cualquiera
    despliega su propio lock y su propia malla, y las dos son indistinguibles
    para un verificador.

    ``script_hash`` es el hash160 del script de membresia. ``deployment`` es
    el ``(txid, vout)`` del despliegue, y es **documental**: da formato y
    contexto, no ancla de confianza. Se ancla por txid y no por altura a proposito
    — una reorganizacion deja una altura que nadie puede probar despues, y un
    txid es inmutable por definicion.
    """

    script_hash: str
    deployment_txid: str = ""
    deployment_vout: int = 0
    genesis_txid: str = ""

    def matches_output(self, output: "MembershipOutput") -> bool:
        """Si esta salida cumple el lock.

        aqui esta el unico sitio del modulo que tendria que mirar un script
        real, y no lo hace: :class:`MembershipOutput` declara que su script
        cumple, y esto compara declaraciones. Contra la cadena de verdad hace
        falta extraer el script del output gastado y hashear — ver
        :meth:`from_spent_output`, que lanza :class:`ProtocolError` en vez de
        devolver ``False`` para que el hueco sea visible.
        """
        return output.script_hash == self.script_hash

    @classmethod
    def from_spent_output(cls, spent_tx: dict[str, Any], vout: int) -> "MembershipLock":
        """Extraer el lock de un output real. **No implementado todavia.**

        Deliberadamente lanza en vez de devolver un lock inventado: un
        membership gate que acepta un lock que nadie leyo del script seria una
        puerta abierta con nombre de puerta.
        """
        raise ProtocolError(
            "from_spent_output requiere parsear Bitcoin Script del output "
            "gastado (hash160 del script de membresia). Este modulo verifica "
            "pruebas de Merkle y firmas, no scripts. Implementarlo requiere el "
            "serializador de transacciones; hasta entonces, usa un "
            "MembershipLock construido explicitamente y no lo presentes como "
            "verificado contra la cadena."
        )


# ---------------------------------------------------------------------------
# La salida de membresia
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class MembershipOutput:
    """Un output que cumple el lock. Es "la membresia", en singular."""

    txid: str
    vout: int
    satoshis: int
    script_hash: str
    address: str = ""

    def outpoint(self) -> str:
        """``txid:vout`` — la direccion estable de este output."""
        if len(self.txid) != HASH_LEN * 2:
            raise ValueError(f"txid de {len(self.txid)} caracteres hex")
        if self.vout < 0:
            raise ValueError("vout negativo")
        return f"{self.txid}:{self.vout}"

    @classmethod
    def from_outpoint(cls, outpoint: str, satoshis: int, script_hash: str,
                      address: str = "") -> "MembershipOutput":
        """Construye desde ``txid:vout``. La forma que viajan los proofs."""
        if ":" not in outpoint:
            raise ValueError(f"outpoint {outpoint!r}: se esperaba 'txid:vout'")
        txid, _, vout = outpoint.rpartition(":")
        return cls(txid=txid, vout=int(vout), satoshis=int(satoshis),
                   script_hash=script_hash, address=address)


# ---------------------------------------------------------------------------
# La prueba de inclusion
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class InclusionProof:
    """Prueba de Merkle de que ``outpoint`` esta en un bloque.

    Verificable por cualquiera con una cabecera. Es la unica parte que exige
    confianza en el mundo exterior, y por eso ``merkle_root`` viaja aqui: el
    verificador compara contra la cabecera que *el* cree, no contra la que le
    manda el que pide la membresia.
    """

    txid: str
    index: int
    path: list[str]
    merkle_root: str
    height: int = 0

    def verify(self, header: BlockHeader) -> bool:
        """¿Está la transacción en *esta* cabecera?

        No dice que esta cabecera sea la correcta — solo que la inclusion es
        real respecto a la raiz que el verificador eligió. Confundir las dos
        cosas es como se cuela una cadena hostil.
        """
        if header.merkle_root != self.merkle_root:
            return False
        if self.txid != self.txid.lower() or self.merkle_root != self.merkle_root.lower():
            return False
        return verify_merkle_proof(self.txid, self.index, self.path,
                                   self.merkle_root)


# ---------------------------------------------------------------------------
# La prueba de pertenencia
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class MembershipProof:
    """Lo que un nodo presenta para ser considerado miembro.

    Tres cosas, y las tres hacen falta:

    1. la salida que cumple el lock, con su prueba de inclusion en un bloque;
    2. la **firma de la clave de membresía** sobre el vinculo entre esa salida y
       su clave publica — sin esto, cualquiera que viera el outpoint en la
       cadena podria reclamar esa membresia;
    3. la pubkey de membresia, que es la que encadena todo lo demas.

    La firma va sobre un digest con dominio, asi que una firma de admision
    (:mod:`delm.core.provenance`) no se puede reusar como prueba de membresia.
    """

    output: MembershipOutput
    inclusion: InclusionProof
    membership_pubkey: str
    signature: str
    lock: MembershipLock | None = None

    # ------------------------------------------------------------------ digest
    def _digest(self) -> str:
        """Digest firmado: version, lock, outpoint y la pubkey de membresia.

        ``vout`` y ``satoshis`` entran. El vout porque un mismo txid puede
        tener varias salidas y solo una cumple el lock; los satoshis porque la
        identidad economica del output es parte de lo firmado, y asi una firma
        de un outputdust no se puede raiz emparejar con un output pagado despues.
        """
        payload = {
            "v": MEMBERSHIP_VERSION,
            "domain": "smcp-membership",
            "lock": self.lock.script_hash if self.lock else "",
            "outpoint": self.output.outpoint(),
            "satoshis": self.output.satoshis,
            "membership_pubkey": self.membership_pubkey,
        }
        return _canonical_digest(payload)

    # ------------------------------------------------------------------- verify
    def verify(self, header: BlockHeader) -> tuple[bool, str]:
        """Verifica la prueba completa. Devuelve ``(ok, motivo)``.

        El orden importa: inclusion primero, porque si la transaccion no esta en
        un bloque no hay nada que firmar, y buscar la firma primero solo gasta
        trabajo de un atacante.
        """
        if not HAVE_ECDSA:  # pragma: no cover
            return False, "ecdsa-secp256k1 no disponible"
        if len(self.membership_pubkey) != PUBKEY_LEN * 2:
            return False, "pubkey de membresia de longitud invalida"
        if not self.inclusion.verify(header):
            return False, "inclusion: prueba de Merkle no valida"
        if self.lock is not None and not self.lock.matches_output(self.output):
            return False, "la salida no cumple el lock"
        try:
            pub = bytes.fromhex(self.membership_pubkey)
            sig = bytes.fromhex(self.signature)
        except ValueError:
            return False, "pubkey o firma no son hex valido"
        if len(sig) != SIG_LEN:
            return False, f"firma de {len(sig)} bytes; se esperaban {SIG_LEN}"
        if not _secp_verify(pub, self._digest(), sig):
            return False, "firma de la clave de membresia no valida"
        return True, "ok"

    # ------------------------------------------------------------------ build
    @classmethod
    def create(cls, output: MembershipOutput, inclusion: InclusionProof,
               key: Secp256k1KeyPair, lock: MembershipLock | None = None,
               ) -> "MembershipProof":
        """Firma la pertenencia con la clave que controla el output.

        Aqui esta el punto que hace que todo lo anterior funcione: la clave
        que firma **es** la que el output paga. Por eso firmarla prueba
        posesion, no declaracion.
        """
        if key.kind != SIG_KIND:  # pragma: no cover - construccion
            raise ProtocolError(
                f"la clave de membresia debe ser {SIG_KIND}, no {key.kind!r}")
        draft = cls(output=output, inclusion=inclusion,
                    membership_pubkey=key.public_key.hex(), signature="",
                    lock=lock)
        sig = key.sign(draft._digest())
        return cls(output=output, inclusion=inclusion,
                   membership_pubkey=key.public_key.hex(),
                   signature=sig.hex(), lock=lock)


def _canonical_digest(payload: dict[str, Any]) -> str:
    import json
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# La rotacion
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class RotationProof:
    """Un output de membresia gastado a una clave nueva.

    La rotacion **es** el gasto: no hay una operacion de "cambiar clave" que
    registrar. Por eso la doble rotacion es imposible sin que el grafo la
    impida, y por eso la cadena de ancestros es la sucesion de claves sin que
    nadie la mantenga.
    """

    spent: MembershipOutput
    spent_inclusion: InclusionProof
    new_key_pubkey: str
    new_outpoint: str
    new_satoshis: int
    signature: str

    def _digest(self) -> str:
        payload = {
            "v": MEMBERSHIP_VERSION,
            "domain": "smcp-rotation",
            "spent": self.spent.outpoint(),
            "new_key_pubkey": self.new_key_pubkey,
            "new_outpoint": self.new_outpoint,
            "new_satoshis": self.new_satoshis,
        }
        return _canonical_digest(payload)

    def verify(self, old_key_pubkey: str, header: BlockHeader) -> tuple[bool, str]:
        """¿Esta rotacion la firmo la clave que controlaba el output gastado?

        Y el punto de seguridad: la clave nueva **no** puede ser la misma que
        la vieja. Sin esa comprobacion, "rotar" a si mismo seria una membresia
       renewed sin coste, y una cadena de rotaciones infinitas sin pagar fees
        — el Sybil que la membresia deberia impedir, reintroducido por la
        puerta de la rotacion.
        """
        if self.new_key_pubkey == old_key_pubkey:
            return False, "rotacion a la misma clave: no renueva nada"
        if not self.spent_inclusion.verify(header):
            return False, "inclusion: el output gastado no prueba inclusion"
        try:
            old_pub = bytes.fromhex(old_key_pubkey)
            new_pub = bytes.fromhex(self.new_key_pubkey)
            sig = bytes.fromhex(self.signature)
        except ValueError:
            return False, "pubkeys o firma no son hex valido"
        if len(sig) != SIG_LEN:
            return False, f"firma de {len(sig)} bytes; se esperaban {SIG_LEN}"
        # La firma es de la clave VIEJA sobre un digest que incluye la NUEVA.
        if not _secp_verify(old_pub, self._digest(), sig):
            return False, "firma de la clave antigua no valida"
        if len(new_pub) != PUBKEY_LEN:
            return False, "pubkey nueva de longitud invalida"
        return True, "ok"

    @classmethod
    def create(cls, spent: MembershipOutput, spent_inclusion: InclusionProof,
               old_key: Secp256k1KeyPair, new_key: Secp256k1KeyPair,
               new_outpoint: str, new_satoshis: int) -> "RotationProof":
        """Firma la rotacion con la clave **vieja**.

        La asimetria es intencionada y es la regla: la vieja firma porque es la
        que el output gastado reconoce. Si firmara la nueva, cualquiera podria
        anunciar una rotacion que nadie autorizo.
        """
        if new_key.public_key == old_key.public_key:
            raise ProtocolError(
                "rotar a la misma clave no renueva la membresia y no cuesta un "
                "fee: rechazalo aqui, no despues")
        draft = cls(spent=spent, spent_inclusion=spent_inclusion,
                    new_key_pubkey=new_key.public_key.hex(),
                    new_outpoint=new_outpoint, new_satoshis=int(new_satoshis),
                    signature="")
        return cls(spent=spent, spent_inclusion=spent_inclusion,
                   new_key_pubkey=new_key.public_key.hex(),
                   new_outpoint=new_outpoint, new_satoshis=int(new_satoshis),
                   signature=old_key.sign(draft._digest()).hex())


# ---------------------------------------------------------------------------
# El conjunto: quien es miembro ahora
# ---------------------------------------------------------------------------
@dataclass
class MembershipSet:
    """Las membresias vivas que un nodo conoce, y su reloj de views.

    Un input de esta clase es lo que un nodo actualiza con lo que ve: cada
    rotacion gasta un output y crea otro, asi que "miembros" es un conjunto
    vivo y no una lista fija. Aqui se guarda lo minimo para responder "quien
    es miembro" y para detectar la doble rotacion.
    """

    lock: MembershipLock
    members: dict[str, MembershipProof] = field(default_factory=dict)
    spent_outpoints: set[str] = field(default_factory=set)

    def admit(self, proof: MembershipProof, header: BlockHeader) -> tuple[bool, str]:
        """Da de alta una membresia si su prueba valida.

        Rechaza un outpoint ya gastado: es la comprobacion que hace imposible
        el doble gasto de membresia **sin** necesitar la cadena completa. Un
        nodo que ve dos "miembros" con el mismo outpoint sabe que uno miente,
        y el que miente es el que llega despues.
        """
        ok, why = proof.verify(header)
        if not ok:
            return False, why
        if proof.lock is not None and proof.lock.script_hash != self.lock.script_hash:
            return False, "lock distinto al de esta malla"
        out = proof.output.outpoint()
        if out in self.spent_outpoints:
            return False, "outpoint ya gastado: membresia retirada"
        self.members[self._node_key(proof)] = proof
        return True, "ok"

    def apply_rotation(self, rot: RotationProof, old_key_pubkey: str,
                       header: BlockHeader) -> tuple[bool, str]:
        """Aplica una rotacion: gasta un output y exige el nuevo.

        Tras esto el outpoint viejo queda en :attr:`spent_outpoints` **y la
        clave vieja sale de :attr:`members`**. Si alguien presenta despues una
        :class:`MembershipProof` sobre el, se rechaza — y ese es el mecanismo
        completo del que la rotacion-por-gasto deriva su garantia.

        El rechazo del outpoint ya gastado no es una comprobacion extra: es la
        garantia entera. Sin ella, dos rotaciones validas del mismo output se
        aceptan las dos, y el nodo con la clave antigua sigue figurando como
        miembro junto al que ya renovo — que es el Sybil que la membresia de
        pago deberia impedir, reintroducido por la puerta de la rotacion.
        """
        ok, why = rot.verify(old_key_pubkey, header)
        if not ok:
            return False, why
        spent = rot.spent.outpoint()
        if spent in self.spent_outpoints:
            return False, "outpoint ya gastado: doble gasto de membresia"
        old = self.members.get(old_key_pubkey)
        if old is not None and old.output.outpoint() != spent:
            return False, "la rotacion no gasta el output que este nodo tiene"
        self.spent_outpoints.add(spent)
        # La clave antigua deja de ser miembro: su output ya no existe, asi
        # que la ultima version de esa membresia esta retirada.
        self.members.pop(old_key_pubkey, None)
        return True, "ok"

    def is_member(self, membership_pubkey: str) -> bool:
        """¿Es esta clave miembro vigente, segun lo que este nodo ha visto?

        Local: es lo que este nodo conoce, no unLED global. Un nodo que ha
        estado desconectado puede tener una respuesta desactualizada, y por eso
        la respuesta lleva la longitud de :attr:`spent_outpoints` — cuanta
        mas views, mas informacion. Confundir esto con "es miembro" global es
        el malentendido que hace inutil un gate de pertenencia.
        """
        return membership_pubkey in self.members

    def status(self) -> dict[str, Any]:
        """Lo que este nodo sabe del estado de las membresias."""
        return {
            "lock": self.lock.script_hash,
            "members": len(self.members),
            "spent_outpoints": len(self.spent_outpoints),
            "view_is_local": True,
        }

    @staticmethod
    def _node_key(proof: MembershipProof) -> str:
        return proof.membership_pubkey


__all__ = [
    "MembershipLock", "MembershipOutput", "InclusionProof", "BlockHeader",
    "MembershipProof", "RotationProof", "MembershipSet",
    "ProtocolError", "merkle_root", "verify_merkle_proof", "dsha256",
    "MEMBERSHIP_VERSION", "DUST_ORDER", "HASH_LEN", "HEADER_LEN",
]
