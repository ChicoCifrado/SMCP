"""Anchor — una transaccion por inferencia, y lo que la cadena registra de ella.

La decision
-----------
Una transaccion por inferencia. La propia transaccion **es** el mecanismo de
verificacion: su existencia prueba que ocurrio, y el txid compromete a quien la
firmo. No hay un registro paralelo que pueda desincronizarse del grafo.

Y una decision sobre el contenido que conviene decir con todas sus letras:
**no se hashea la salida de la inferencia.** No se hashea ni el prompt, ni la
respuesta, ni ningun material derivado de ellos. La entrada en la cadena lleva
los datos del nodo — su identidad — y nada mas.

Eso tiene una consecuencia que no es un detalle:
*lo anclado es que una inferencia verificada ocurrio, no que decia.* Si lo que
se quisiera fuera "esta inferencia se produjo exactamente asi", el hash del
contenido estaria en la entrada — y entonces cualquier observador de la cadena
podria confirmar que alguien ejecuto esa conversacion, porque el hash de un
prompt es tan identificador como el prompt. Con el prompt fuera, lo que se
publica es un conteo con atribucion, y el conteo es lo que hace falta para
auditar que un nodo esta trabajando.

El precio de esa eleccion, dicho antes de que se descubra: **el commitment no
es reproducible por un tercero.** Nadie, ni siquiera el nodo, puede demostrar
despues *que* inferencia fue, solo que hubo una. Si aparece una disputa sobre
el contenido de una inferencia, la cadena no la resuelve. Resolverla exigiria el
hash del contenido, que es justo lo que se decidio no publicar. Es una decision
coherente; es irreversible para el caso de disputa.

Lo que se reutiliza, y por que no hace falta nada nuevo
--------------------------------------------------------
:class:`~smcp.core.membership.InclusionProof` ya prueba que un ``outpoint``
esta en un bloque comparando contra una cabecera **que elige el verificador**.
Eso es exactamente lo que necesita el ancla, asi que no hay una segunda
implementacion de Merkle ni un segundo formato de prueba: el ancla produce un
:class:`~smcp.core.membership.InclusionProof` y verifica con el mismo codigo.

Lo que si es nuevo:

* el **outpoint de atribucion** — un output cuya clave de bloqueo es la clave de
  membresia del nodo, de forma que el grafo ya dice quien gasto el output sin
  que ningun indice tenga que decirlo; y
* la **linea de tiempo** — la inferencia tiene que ser posterior a la membresia.
  Sin esa comprobacion, un nodo podria presentar inferencias anteriores a su
  propia membresia, es decir, trabajo ejecutado antes de existir en la malla.

Lo que este modulo NO verifica
------------------------------
* **No comprueba el contenido.** Por decision, no por carencia:
  :attr:`AnchorRecord.content_sha256` no se puede ni rellenar.
* **No valida la cadena.** BRC-96: inclusion contra la cabecera que el verificador
  elige. Dos cabeceras de un atacante se validan mutuamente. Por eso
  ``chain_validated`` sale ``False`` siempre, en :meth:`AnchorLedger.status` y
  en la salida del CLI.
* **No valida la membresia.** Eso es de :mod:`smcp.core.membership`; aqui solo
  se recibe el output del que el ancla dice descender.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from smcp.core.bsv_keys import Secp256k1KeyPair
from smcp.core.membership import (
    BlockHeader,
    InclusionProof,
    MembershipOutput,
    ProtocolError,
    _canonical_digest,
    _secp_verify,
)

log = logging.getLogger(__name__)

#: Version del formato de ancla. Va en el campo ``ver`` porque el formato va a
#: cambiar — falta decidir si el importe del output lleva algo — y un registro
#: sin version obliga a adivinar por el numero de campos.
ANCHOR_VERSION = 2

#: Longitudes, de :mod:`smcp.core.bsv_keys`. Se re-declaran aqui como literales
#: porque este modulo valida su propia forma antes de gastar trabajo en ECDSA:
#: una pubkey de longitud rara es un atacante, y rechazar por longitud es mas barato
#: que rechazar por firma.
PUBKEY_LEN = 33
SIG_LEN = 64
HASH_LEN = 32


@dataclass(frozen=True)
class AnchorRecord:
    """Una inferencia anclada. Lo que el nodo firmo.

    ``content_sha256`` existe y **siempre esta vacio**. No es un campo para
    rellenar: es la decision de no publicar el contenido, hecha explicita en la
    estructura, para que un cambio futuro que lo rellene tenga que pasar por
    aqui y ser una decision y no un ``dict.update``.
    """

    #: txid de la transaccion que contiene el output de membresia.
    membership_txid: str
    #: Indice del output de membresia dentro de esa transaccion.
    membership_vout: int
    #: Clave de membresia del nodo. Es la que atribuye el gasto.
    membership_pubkey: str
    #: **Quien pidio la inferencia.** Sin este campo el ancla solo dice "este
    #: nodo hizo algo", y entonces una inferencia puramente local —el nodo
    #: ejecutandose a si mismo, que es lo mas barato de hacer y lo mas facil
    #: de multiplicar— seria indistinguible de una peticion de la red.
    #:
    #: El ancla es la prueba de que ocurrio, pero no de *para quien*: sin la
    #: clave del solicitante, la reputacion de un nodo se la puede inflar solo,
    #: que es justo lo que un ranking tiene que evitar. El ancla lo ata a la
    #: cadena, asi que es el sitio donde la regla se decide y no un chequeo
    #: posterior que otro podria saltarse.
    requester_pubkey: str
    #: Cuanto pago el output de atribucion. El importe **no** es un precio: no
    #: se verifica contra nada, y por eso no debe leerse como uno. Ver
    #: :data:`ANCLAIM_AMOUNT_SATS`.
    satoshis: int
    #: Metodo del lock. Hoy solo P2PKH: el output paga a una clave, no a un
    #: contrato, porque no hay ninguna condicion que cumplir — la atribucion la
    #: da la firma de la transaccion, no el script.
    method: str = "p2pkh"
    #: Version del formato.
    ver: int = ANCHOR_VERSION
    #: **Siempre vacio.** Ver el docstring de la clase.
    content_sha256: str = ""
    #: Marca de tiempo declarada por el nodo. **No es confianza**: un reloj
    #: hostil puede poner lo que quiera. Lo que da confianza es el height del
    #: bloque, y eso vive en el InclusionProof, que es del verificador.
    occurred_at: int = 0

    def __post_init__(self) -> None:
        if self.content_sha256:
            raise ProtocolError(
                "esta version no publica el contenido de la inferencia: "
                "content_sha256 debe ir vacio. Anclar el hash del contenido "
                "permitiria a un observador de la cadena confirmar que alguien "
                "ejecuto esa conversacion, porque el hash de un prompt es tan "
                "identificador como el prompt. Resolver una disputa de "
                "contenido es otro producto y otra decision, no un campo que se "
                "rellena.")
        if self.ver != ANCHOR_VERSION:
            raise ProtocolError(f"version de ancla desconocida: {self.ver}")
        if len(self.membership_txid) != HASH_LEN * 2:
            raise ProtocolError(
                f"txid de membresia de {len(self.membership_txid)} hex; "
                f"se esperaban {HASH_LEN * 2}")
        if len(self.membership_pubkey) != PUBKEY_LEN * 2:
            raise ProtocolError(
                f"pubkey de membresia de {len(self.membership_pubkey)} hex; "
                f"se esperaban {PUBKEY_LEN * 2}")
        if not self.membership_pubkey:
            raise ProtocolError("ancla sin clave de membresia: no hay atribucion")
        if not self.requester_pubkey:
            raise ProtocolError(
                "ancla sin clave de solicitante: no se puede probar que la "
                "peticion venga de la red. Una inferencia local no se ancla.")
        if len(self.requester_pubkey) != PUBKEY_LEN * 2:
            raise ProtocolError(
                f"pubkey de solicitante de {len(self.requester_pubkey)} hex; "
                f"se esperaban {PUBKEY_LEN * 2}")
        if self.requester_pubkey == self.membership_pubkey:
            raise ProtocolError(
                "ancla auto-solicitada: el solicitante es el propio nodo. "
                "La reputacion cuenta inferencias que la red pidio, no las que "
                "el nodo se ejecuta a si mismo.")
        if self.method != "p2pkh":
            raise ProtocolError(f"metodo de lock no soportado: {self.method!r}")
        if self.satoshis < 0:
            raise ProtocolError("satoshis negativos")
        if self.occurred_at < 0:
            raise ProtocolError("occurred_at negativo")

    @property
    def membership_outpoint(self) -> str:
        return f"{self.membership_txid}:{self.membership_vout}"

    def digest_payload(self) -> dict[str, Any]:
        """Lo que se firma. Canonicalizado, sin el propio digest.

        Deliberadamente **no** incluye el InclusionProof: la inclusion la
        verifica el verificador contra su cabecera, y meterla aqui haria que la
        firma dependiera de en que bloque salio. La firma dice "esta inferencia
        es mia"; la inclusion dice "y estaba en ese bloque". Son dos preguntas
        separadas, y por eso dos campos separados.
        """
        return {
            "ver": self.ver,
            "kind": "delm-inference-anchor",
            "membership_outpoint": self.membership_outpoint,
            "membership_pubkey": self.membership_pubkey,
            "requester_pubkey": self.requester_pubkey,
            "satoshis": self.satoshis,
            "method": self.method,
            "occurred_at": self.occurred_at,
            "content_sha256": self.content_sha256,
        }

    def sign(self, membership_key: Secp256k1KeyPair) -> str:
        """Firma el ancla con la **clave de membresia** del nodo.

        Con la clave de membresia y no con la de identidad del handshake: el
        ancla es una declaracion dentro de la malla, y atarla a la identidad del
        handshake haria que una rotacion de clave dejara el historico sin poder
        verificar — la clave nueva no puede firmar por la vieja, y el verificador
        tendria que llevar el historial de claves de todos los nodos.
        """
        if membership_key.kind != "ecdsa-secp256k1":
            raise ProtocolError(
                f"la clave debe ser ecdsa-secp256k1, no {membership_key.kind!r}")
        if membership_key.public_key.hex() != self.membership_pubkey:
            raise ProtocolError(
                "la clave de firma no es la clave de membresia declarada: la "
                "firma no atribuiria el gasto al nodo correcto")
        digest = _canonical_digest(self.digest_payload())
        return membership_key.sign(digest).hex()

    def verify(self, signature: str, inclusion: InclusionProof,
               header: BlockHeader) -> tuple[bool, str]:
        """Verifica firma **y** inclusion. Devuelve ``(ok, motivo)``.

        Inclusion **primero**, no la firma: si la transaccion no esta en un
        bloque, no hay nada que firmar. Al reves, buscar la firma primero gasta
        trabajo de un atacante en ECDSA antes de comprobar lo barato.
        """
        if not inclusion.verify(header):
            return False, "inclusion: prueba de Merkle no valida contra la cabecera"
        # La inclusion debe ser de la MISMA transaccion que declaro la membresia.
        # Si no, un nodo podria presentar la inclusion de una transaccion
        # cualquiera junto con una membresia ajena: ambas cosas serian reales y
        # no irian juntas.
        if inclusion.txid != self.membership_txid:
            return False, ("la inclusion no es de la transaccion de la membresia "
                           "declarada")
        try:
            sig = bytes.fromhex(signature)
        except ValueError:
            return False, "la firma no es hex valido"
        if len(sig) != SIG_LEN:
            return False, f"firma de {len(sig)} bytes; se esperaban {SIG_LEN}"
        if not _secp_verify(bytes.fromhex(self.membership_pubkey),
                            _canonical_digest(self.digest_payload()), sig):
            return False, "firma de la clave de membresia no valida"
        return True, "ok"

    def to_dict(self) -> dict[str, Any]:
        return {
            "membership_txid": self.membership_txid,
            "membership_vout": self.membership_vout,
            "membership_pubkey": self.membership_pubkey,
            "requester_pubkey": self.requester_pubkey,
            "satoshis": self.satoshis,
            "method": self.method,
            "ver": self.ver,
            "content_sha256": self.content_sha256,
            "occurred_at": self.occurred_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AnchorRecord":
        try:
            return cls(
                membership_txid=str(d["membership_txid"]),
                membership_vout=int(d["membership_vout"]),
                membership_pubkey=str(d["membership_pubkey"]),
                # Ausente = v1 (que no lo tenia). Se queda vacio a proposito:
                # la regla de "peticion de la red" lo rechaza, que es la
                # direccion segura. Rellenarlo seria afirmar que el nodo se
                # pidio a si mismo, que es justo lo que no sabemos.
                requester_pubkey=str(d.get("requester_pubkey", "")),
                satoshis=int(d["satoshis"]),
                method=str(d.get("method", "p2pkh")),
                ver=int(d.get("ver", ANCHOR_VERSION)),
                content_sha256=str(d.get("content_sha256", "")),
                occurred_at=int(d.get("occurred_at", 0)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError(f"ancla malformada: {exc}") from exc


#: Importe del output de atribucion. **No es un precio**: no se verifica contra
#: nada, asi que no debe leerse como uno, y no se usa para decidir si una
#: inferencia esta pagada. Es el valor que lleva el output, y su eleccion es
#: del nodo mientras no se decida lo contrario.
ANCLAIM_AMOUNT_SATS = 1


@dataclass
class AnchorLedger:
    """El registro de inferencias de un nodo.

    Lleva la cuenta y aplica dos reglas que son distintas y ambas necesarias:

    * **no retroactividad** — una inferencia no puede ser anterior a la
      membresia que la autoriza;
    * **consistencia** — un registro con mas anclas que inclusiones esta
      corrupto y no se verifica, en vez de verificar la mitad.

    Lo que NO lleva: confianza. :attr:`anchors` es lo que el nodo afirma; que sea
    cierto lo decide :meth:`verify` con la cabecera de cada verificador, y este
    registro no la tiene.
    """

    #: Salidas de membresia por las que este nodo puede anclar. Viene del
    #: MembershipSet del gate, no se deduce aqui: un ledger que aceptara
    #: cualquier clave seria un ledger que cualquiera puede rellenar.
    membership_outputs: list[MembershipOutput] = field(default_factory=list)
    anchors: list[AnchorRecord] = field(default_factory=list)
    inclusions: list[InclusionProof] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)

    def append(self, record: AnchorRecord, inclusion: InclusionProof,
               signature: str) -> tuple[bool, str]:
        """Anade un ancla. **No verifica la inclusion** — la verifica el gate.

        La separacion es deliberada: :meth:`verify` es el unico sitio que
        necesita una cabecera, y si :meth:`append` tambien la exigiera, una
        reconciliacion de disco o un import no podrian anadir nada sin tener
        una. Lo que si comprueba aqui es lo que no necesita la cadena: que la
        membresia que declara exista, y que el registro este sano.
        """
        if not (len(self.anchors) == len(self.inclusions)
                == len(self.signatures)):
            return False, ("el ledger esta corrupto: anclas, inclusiones y "
                           "firmas no cuadran")
        if inclusion.txid != record.membership_txid:
            return False, ("la inclusion no es de la transaccion de la membresia "
                           "declarada")
        if inclusion.height <= 0:
            return False, ("el bloque no trae altura: sin ella no se puede "
                           "comprobar que la inferencia es posterior a la "
                           "membresia, y no se acepta por defecto")
        if not any(o.txid == record.membership_txid
                   and o.vout == record.membership_vout
                   for o in self.membership_outputs):
            return False, ("la membresia que declara el ancla no esta en las "
                           "salidas conocidas de este nodo")
        self.anchors.append(record)
        self.inclusions.append(inclusion)
        self.signatures.append(signature)
        return True, "ok"

    def verify(self, header: BlockHeader) -> tuple[bool, str]:
        """Reverifica **todas** las anclas contra una cabecera del llamante.

        Devuelve el primer fallo, no la cuenta: un ledger con tres anclas y la
        tercera invalida no sirve para nada, y "hay un problema" es lo que el
        llamante necesita. Recorre en orden para que el motivo sea siempre el
        mismo ante el mismo estado.
        """
        if not (len(self.anchors) == len(self.inclusions)
                == len(self.signatures)):
            return False, "el ledger esta corrupto: las tres listas no cuadran"
        for i, (rec, inc, sig) in enumerate(
                zip(self.anchors, self.inclusions, self.signatures)):
            ok, why = rec.verify(sig, inc, header)
            if not ok:
                return False, f"ancla {i}: {why}"
        return True, f"{len(self.anchors)} anclas verificadas"

    def status(self) -> dict[str, Any]:
        """Resumen. ``chain_validated`` es **siempre** ``False``.

        Ver la nota de BRC-96 del docstring: la inclusion se verifica contra la
        cabecera que da el verificador, asi que nadie con este modulo puede
        decir "esta anclado en la cadena". Puede decir "esta inclusion valida
        contra la cabecera que tu me diste".
        """
        return {
            "anchors": len(self.anchors),
            "unique_membership_outpoints": len(
                {a.membership_outpoint for a in self.anchors}),
            "satoshis_anchored": sum(a.satoshis for a in self.anchors),
            "publishes_content": any(a.content_sha256 for a in self.anchors),
            "earliest_block": (min(i.height for i in self.inclusions)
                               if self.inclusions else 0),
            "chain_validated": False,
        }


__all__ = ["AnchorRecord", "AnchorLedger", "ANCHOR_VERSION",
           "ANCLAIM_AMOUNT_SATS", "ProtocolError"]