"""Mensajería v3 — la secuencia de punta a punta, por el transporte.

Qué resuelve este módulo
--------------------------
Los módulos de la v3 (:mod:`intercambio`,
:mod:`inscripcion`, :mod:`identidad`) son **llamadas
a funciones**: la secuencia existe, pero sus mensajes
no viajan. El transporte (:mod:`transport`) mueve
bytes opacos y :mod:`mesh_node` interpreta gossip y
gists (``0x01``/``0x02``). Este módulo es la pieza
que faltaba: **los mensajes de la v3, codificados y
transportados** — la secuencia que ``intercambio.py``
delega a la capa de transporte.

Los mensajes
--------------
Extienden el espacio de tipos de :mod:`mesh_node`:

===== =================== ====================================
tipo  mensaje            dirección
===== =================== ====================================
0x03  HANDSHAKE          cualquiera (identidad BRC-103)
0x04  INFERENCE_REQUEST  Alice -> Bob
0x05  PAYMENT_TERMS      Bob -> Alice (la tx sin firmar)
0x06  SIGNED_PAYMENT     Alice -> Bob (la tx firmada)
0x07  INFERENCE_RESPONSE Bob -> Alice (off-chain)
0x08  ROSTER             cualquiera (el join: roster +
                        keyring)
===== =================== ====================================

Todos llevan ``request_id`` (hex aleatorio) —
los de inferencia— para correlacionar la petición
con sus respuestas en un transporte de datagramas
sin estado, y se codifican en JSON — el mismo
formato que el anuncio de gossip
(:mod:`mesh_node`).

La secuencia de inferencia
----------------------------
::

    Alice pide (0x04)  ->  Bob sirve y devuelve la
    respuesta (0x07) y los términos (0x05)  ->
    Alice verifica y firma (0x06)  ->  Bob
    verifica, emite por ARC y cuenta.

El join (:class:`JoinWire`)
-----------------------------
El handshake BRC-103 (:mod:`smcp.core.identidad`)
es simétrico — ningún nodo es el iniciador —, pero
el cable necesita un primer mensaje, y cualquiera
puede darlo (:meth:`JoinWire.start`):

::

    A: INIT ----------------------> B
    B:      <---- PROOF (B) -------
    A:      ---- PROOF (A) ------->
    A:      ---- ROSTER (crudo) -->
    B:      ---- ROSTER (crudo) -->
    A:      ---- ROSTER (avalado) >
    B:      ---- ROSTER (avalado) >

Los rosters se cruzan dos veces: el *epoch*
que se avala es el que el roster del par
declara, así que el primer cruce es sin
avales — cada lado avala al par en **su**
roster (:func:`smcp.core.join.pair_local`:
la clave privada del par nunca viaja) y el
segundo cruce los lleva. El join completa
cuando el roster del par trae mi admisión:
su aval a mí.

Los actores
--------------
:class:`InferenceRequester` (Alice),
:class:`InferenceResponder` (Bob) y
:class:`JoinWire` corren sobre cualquier
:class:`~smcp.core.transport.MeshTransport`:
in-memory para pruebas, QUIC para despliegue. Son
**síncronos** — ``serve`` y ``settle`` son asíncronos,
y cada mensaje corre su propio ``asyncio.run`` (el
patrón del resto de la v3: el contrato es sync).

Lo que no hace
----------------
No es un transporte (mueve bytes por uno), no
garantiza la entrega (un datagrama perdido es una
petición que caduca — el ledger no cuenta un txid
dos veces, que es la guarda de la cadena) y no
agrupa peticiones (una inferencia = una tx, la
decisión de v3).
"""
from __future__ import annotations

import asyncio
import json
import secrets
import time
from typing import Callable

from smcp.core.bsv_keys import Secp256k1KeyPair
from smcp.core.identidad import (
    HandshakeProof,
    Session,
    new_nonce,
    sign_handshake,
    verify_handshake,
)
from smcp.core.intercambio import (
    InferenceRequest,
    InferenceServer,
    sign_payment,
)
from smcp.core.join import (
    JoinResult,
    PeerIdentity,
    pair_local,
)
from smcp.core.membership import ProtocolError
from smcp.core.mesh_node import decode_msg, encode_msg
from smcp.core.provenance import KeyPair
from smcp.core.roster import Roster
from smcp.core.tiers import PER_INFERENCE_SATOSHIS
from smcp.core.transport import MeshTransport
from smcp.core.txbuild import Transaction, TxIn

__all__ = [
    "KIND_HANDSHAKE",
    "KIND_INFERENCE_REQUEST",
    "KIND_INFERENCE_RESPONSE",
    "KIND_PAYMENT_TERMS",
    "KIND_ROSTER",
    "KIND_SIGNED_PAYMENT",
    "InferenceRequester",
    "InferenceResponder",
    "JoinWire",
    "decode_handshake_init",
    "decode_handshake_proof",
    "decode_inference_request",
    "decode_inference_response",
    "decode_payment_terms",
    "decode_roster",
    "decode_signed_payment",
    "encode_handshake_init",
    "encode_handshake_proof",
    "encode_inference_request",
    "encode_inference_response",
    "encode_payment_terms",
    "encode_roster",
    "encode_signed_payment",
    "new_request_id",
]

#: Handshake de identidad BRC-103, en dos
#: fases (en el cuerpo): ``init`` — la clave
#: y el nonce de un lado — y ``proof`` — su
#: nonce, el del par y la firma de ambos.
KIND_HANDSHAKE = 0x03
#: Alice -> Bob: el prompt, la malla, su clave y su UTXO.
KIND_INFERENCE_REQUEST = 0x04
#: Bob -> Alice: los términos (la tx sin firmar, DPP).
KIND_PAYMENT_TERMS = 0x05
#: Alice -> Bob: la tx con su input firmado (la Payment).
KIND_SIGNED_PAYMENT = 0x06
#: Bob -> Alice: la respuesta, fuera de cadena.
KIND_INFERENCE_RESPONSE = 0x07
#: El roster y el keyring de un nodo (el join).
KIND_ROSTER = 0x08


def new_request_id() -> str:
    """Identificador de petición: 16 bytes aleatorios, en hex."""
    return secrets.token_hex(16)


# ---------------------------------------------------------------------------
# Codificación (JSON, como el anuncio de gossip)
# ---------------------------------------------------------------------------
def encode_inference_request(
    request_id: str, *, prompt: str, mesh_id: str,
    requester_pubkey: bytes, funding: TxIn,
    funding_sats: int = PER_INFERENCE_SATOSHIS,
) -> bytes:
    """Codifica la petición (0x04).

    El fondeo viaja como outpoint (``txid:vout``): la
    identidad del UTXO, no sus campos de tx — el servidor
    construye su propio input con él.
    """
    body = {
        "request_id": request_id,
        "prompt": prompt,
        "mesh_id": mesh_id,
        "requester_pubkey": requester_pubkey.hex(),
        "funding_txid": funding.prev_txid,
        "funding_vout": funding.vout,
        "funding_sats": funding_sats,
    }
    return encode_msg(
        KIND_INFERENCE_REQUEST, json.dumps(body).encode("utf-8"),
    )


def decode_inference_request(payload: bytes) -> tuple[str, InferenceRequest]:
    """Decodifica la petición (0x04): ``(request_id, petición)``.

    Lanza :class:`ProtocolError` si el cuerpo no vale —
    un mensaje malformado se dice, no se ignora.
    """
    try:
        d = json.loads(payload.decode("utf-8"))
        return d["request_id"], InferenceRequest(
            prompt=d["prompt"],
            mesh_id=d["mesh_id"],
            requester_pubkey=bytes.fromhex(d["requester_pubkey"]),
            funding=TxIn(d["funding_txid"], d["funding_vout"]),
            funding_sats=d["funding_sats"],
        )
    except (KeyError, TypeError, ValueError) as e:
        raise ProtocolError(f"petición malformada: {e}") from e


def encode_inference_response(request_id: str, response: str) -> bytes:
    """Codifica la respuesta (0x07): el texto, fuera de cadena."""
    body = {"request_id": request_id, "response": response}
    return encode_msg(
        KIND_INFERENCE_RESPONSE, json.dumps(body).encode("utf-8"),
    )


def decode_inference_response(payload: bytes) -> tuple[str, str]:
    """Decodifica la respuesta (0x07): ``(request_id, texto)``."""
    try:
        d = json.loads(payload.decode("utf-8"))
        return d["request_id"], d["response"]
    except (KeyError, TypeError, ValueError) as e:
        raise ProtocolError(f"respuesta malformada: {e}") from e


def _encode_tx(kind: int, request_id: str, tx: Transaction) -> bytes:
    """Codifica una tx (términos o pago) como mensaje."""
    body = {"request_id": request_id, "tx_hex": tx.serialize().hex()}
    return encode_msg(kind, json.dumps(body).encode("utf-8"))


def _decode_tx(que: str, payload: bytes) -> tuple[str, Transaction]:
    """Decodifica una tx (términos o pago) de un mensaje."""
    try:
        d = json.loads(payload.decode("utf-8"))
        return d["request_id"], Transaction.parse(bytes.fromhex(d["tx_hex"]))
    except (KeyError, TypeError, ValueError) as e:
        raise ProtocolError(f"{que} malformado: {e}") from e


def encode_payment_terms(request_id: str, tx: Transaction) -> bytes:
    """Codifica los términos (0x05): la tx **sin firmar**."""
    return _encode_tx(KIND_PAYMENT_TERMS, request_id, tx)


def decode_payment_terms(payload: bytes) -> tuple[str, Transaction]:
    """Decodifica los términos (0x05): ``(request_id, tx)``."""
    return _decode_tx("términos", payload)


def encode_signed_payment(request_id: str, tx: Transaction) -> bytes:
    """Codifica el pago (0x06): la tx **con el input firmado**."""
    return _encode_tx(KIND_SIGNED_PAYMENT, request_id, tx)


def decode_signed_payment(payload: bytes) -> tuple[str, Transaction]:
    """Decodifica el pago (0x06): ``(request_id, tx)``."""
    return _decode_tx("pago", payload)


# ---------------------------------------------------------------------------
# Codificación del handshake (BRC-103) y del roster
# ---------------------------------------------------------------------------
def encode_handshake_init(identity_key: bytes,
                          nonce: bytes) -> bytes:
    """Codifica el INIT: la clave de identidad y
    el nonce de un lado."""
    body = {
        "phase": "init",
        "identity_key": identity_key.hex(),
        "nonce": nonce.hex(),
    }
    return encode_msg(
        KIND_HANDSHAKE, json.dumps(body).encode("utf-8"),
    )


def decode_handshake_init(payload: bytes) -> tuple[bytes, bytes]:
    """Decodifica el INIT: ``(identity_key, nonce)``.

    Lanza :class:`ProtocolError` si el cuerpo no
    vale (o no es un INIT).
    """
    try:
        d = json.loads(payload.decode("utf-8"))
        if d["phase"] != "init":
            raise KeyError("phase")
        return (
            bytes.fromhex(d["identity_key"]),
            bytes.fromhex(d["nonce"]),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise ProtocolError(f"init malformado: {e}") from e


def encode_handshake_proof(proof: HandshakeProof) -> bytes:
    """Codifica la PROOF: el nonce, el del par y
    la firma, con la clave que firma."""
    body = {
        "phase": "proof",
        "identity_key": proof.identity_key.hex(),
        "sig_kind": proof.sig_kind,
        "nonce": proof.nonce.hex(),
        "peer_nonce": proof.peer_nonce.hex(),
        "signature": proof.signature.hex(),
    }
    return encode_msg(
        KIND_HANDSHAKE, json.dumps(body).encode("utf-8"),
    )


def decode_handshake_proof(payload: bytes) -> HandshakeProof:
    """Decodifica la PROOF.

    Lanza :class:`ProtocolError` si el cuerpo no
    vale (o no es una PROOF).
    """
    try:
        d = json.loads(payload.decode("utf-8"))
        if d["phase"] != "proof":
            raise KeyError("phase")
        return HandshakeProof(
            identity_key=bytes.fromhex(d["identity_key"]),
            sig_kind=str(d["sig_kind"]),
            nonce=bytes.fromhex(d["nonce"]),
            peer_nonce=bytes.fromhex(d["peer_nonce"]),
            signature=bytes.fromhex(d["signature"]),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise ProtocolError(f"prueba malformada: {e}") from e


def encode_roster(roster: Roster,
                  keyring: dict[str, bytes]) -> bytes:
    """Codifica el roster (0x08): la forma canónica
    del roster (:meth:`smcp.core.roster.Roster.to_dict`)
    y el keyring (clave por nodo, en hex)."""
    body = {
        "roster": roster.to_dict(),
        "keyring": {
            node_id: key.hex()
            for node_id, key in keyring.items()
        },
    }
    return encode_msg(
        KIND_ROSTER, json.dumps(body).encode("utf-8"),
    )


def decode_roster(payload: bytes) -> tuple[Roster, dict[str, bytes]]:
    """Decodifica el roster (0x08):
    ``(roster, keyring)``.

    Lanza :class:`ProtocolError` si el cuerpo no
    vale.
    """
    try:
        d = json.loads(payload.decode("utf-8"))
        keyring = {
            str(node_id): bytes.fromhex(key)
            for node_id, key in d["keyring"].items()
        }
        return Roster.from_dict(d["roster"]), keyring
    except (AttributeError, KeyError, TypeError,
            ValueError) as e:
        raise ProtocolError(f"roster malformado: {e}") from e


def _phase(payload: bytes) -> str:
    """La fase de un mensaje de handshake (sin
    validar el resto)."""
    try:
        return str(json.loads(payload.decode("utf-8"))["phase"])
    except (KeyError, TypeError, ValueError) as e:
        raise ProtocolError(f"handshake malformado: {e}") from e


# ---------------------------------------------------------------------------
# Los actores
# ---------------------------------------------------------------------------
class InferenceRequester:
    """Alice por el transporte: pide, verifica, firma.

    ``transport`` es el :class:`~smcp.core.transport.MeshTransport`
    del nodo (in-memory o QUIC); ``key`` su clave de
    petición — la que paga, la que recibe el ordinal y
    la que ``H`` compromete.
    """

    def __init__(self, *, transport: MeshTransport,
                 key: Secp256k1KeyPair) -> None:
        self._transport = transport
        self._key = key

    def request(
        self, *, to: str, prompt: str, mesh_id: str,
        funding: TxIn, funding_sats: int = PER_INFERENCE_SATOSHIS,
        timeout: float = 30.0,
    ) -> tuple[str, Transaction]:
        """Pide ``prompt`` a ``to``; devuelve ``(respuesta, tx firmada)``.

        Envía la petición (0x04), espera la respuesta (0x07) y
        los términos (0x05) — en cualquier orden—, verifica los
        términos y firma su input (:func:`sign_payment`: un
        término que no verifica no se firma) y devuelve la tx
        firmada (0x06) al servidor. La tx firmada es el recibo
        de Alice: el ordinal va a su nombre y el txid identifica
        la inscripción.

        Lanza :class:`TimeoutError` si el servidor no responde a
        tiempo y :class:`~smcp.core.membership.ProtocolError` si
        los términos no verifican.
        """
        rid = new_request_id()
        self._transport.send(to, encode_inference_request(
            rid, prompt=prompt, mesh_id=mesh_id,
            requester_pubkey=self._key.public_key,
            funding=funding, funding_sats=funding_sats,
        ))
        response: str | None = None
        terms: Transaction | None = None
        deadline = time.monotonic() + timeout
        while response is None or terms is None:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"el servidor {to!r} no respondió en {timeout}s",
                )
            for frm, payload in self._transport.poll():
                if frm != to:
                    continue
                kind, body = decode_msg(payload)
                if kind == KIND_INFERENCE_RESPONSE:
                    r, resp = decode_inference_response(body)
                    if r == rid:
                        response = resp
                elif kind == KIND_PAYMENT_TERMS:
                    r, tx = decode_payment_terms(body)
                    if r == rid:
                        terms = tx
            time.sleep(0.01)
        # Verifica antes de firmar (DPP): sign_payment verifica
        # los términos y solo entonces firma el input de fondeo.
        sign_payment(
            terms, requester_key=self._key, mesh_id=mesh_id,
            funding_sats=funding_sats,
        )
        self._transport.send(to, encode_signed_payment(rid, terms))
        return response, terms


class InferenceResponder:
    """Bob por el transporte: sirve peticiones y cobra.

    ``transport`` es el :class:`~smcp.core.transport.MeshTransport`
    del nodo; ``server`` el :class:`InferenceServer` que ejecuta
    la inferencia, construye los términos, emite y cuenta.
    """

    def __init__(self, *, transport: MeshTransport,
                 server: InferenceServer) -> None:
        self._transport = transport
        self._server = server
        # La petición original, por request_id: settle la
        # re-verifica con la tx firmada (la malla, la clave y
        # el fondeo de Alice).
        self._pendientes: dict[str, InferenceRequest] = {}

    def serve_next(self) -> str | None:
        """Atiende **un** mensaje del transporte; devuelve su ``request_id``.

        Una petición (0x04) se sirve: la respuesta (0x07) y los
        términos (0x05) viajan al solicitante. Un pago firmado
        (0x06) se re-verifica, se emite por ARC y se cuenta: es
        el cobro. Devuelve ``None`` si no había nada. Un pago
        para un ``request_id`` desconocido es una violación del
        protocolo y se dice (:class:`ProtocolError`), no se
        ignora.
        """
        for frm, payload in self._transport.poll():
            kind, body = decode_msg(payload)
            if kind == KIND_INFERENCE_REQUEST:
                rid, req = decode_inference_request(body)
                self._pendientes[rid] = req
                response, tx = asyncio.run(self._server.serve(req))
                self._transport.send(frm, encode_inference_response(rid, response))
                self._transport.send(frm, encode_payment_terms(rid, tx))
                return rid
            if kind == KIND_SIGNED_PAYMENT:
                rid, tx = decode_signed_payment(body)
                req = self._pendientes.pop(rid, None)
                if req is None:
                    raise ProtocolError(f"pago sin petición: {rid}")
                asyncio.run(self._server.settle(tx, req))
                return rid
        return None

    def serve_while(self, stop: Callable[[], bool],
                    poll_secs: float = 0.01) -> None:
        """Sirve mensajes hasta que ``stop()`` sea verdadero.

        El bucle de un nodo que sirve: drena el transporte,
        atiende lo que llega y duerme ``poll_secs`` entre
        drains.
        """
        while not stop():
            self.serve_next()
            time.sleep(poll_secs)


class JoinWire:
    """El join v3 por el transporte: identidad (BRC-103)
    y rosters entre dos nodos.

    ``transport`` es el :class:`~smcp.core.transport.MeshTransport`
    del nodo; ``roster``, ``key`` y ``keyring`` su estado
    de join (:func:`smcp.core.join.found`). Un
    emparejamiento por instancia: un nodo con varios
    pares corre una por par.

    La secuencia es simétrica (ningún nodo es el
    iniciador), pero el cable necesita un primer
    mensaje — cualquiera puede darlo (:meth:`start`).
    Cada lado verifica la prueba del par **antes** de
    intercambiar nada: una prueba que no cuadra es
    un MITM (o un bug) y el join **falla cerrado** —
    no se degrada al intercambio simple.

    Los rosters se cruzan **dos veces**: sin
    avales (cada lado conoce el roster del par,
    y con él el *epoch* que avalar) y con ellos
    (cada lado ya avaló al par en el suyo). El
    join completa cuando el roster del par trae
    mi admisión — su aval a mí.
    """

    def __init__(self, *, transport: MeshTransport,
                 roster: Roster, key: KeyPair,
                 keyring: dict[str, bytes]) -> None:
        self._transport = transport
        self._roster = roster
        self._key = key
        self._keyring = keyring
        self._peer: str | None = None
        self._own_nonce: bytes | None = None
        self._own_proof: HandshakeProof | None = None
        self._peer_key: bytes | None = None
        self._peer_proof: HandshakeProof | None = None
        self._result: JoinResult | None = None

    def start(self, to: str) -> None:
        """Da el primer paso: genera su nonce y
        envía el INIT a ``to``."""
        if self._own_nonce is not None:
            raise ProtocolError("el join ya empezó")
        self._peer = to
        self._own_nonce = new_nonce()
        self._transport.send(
            to, encode_handshake_init(self._key.public_key, self._own_nonce),
        )

    def handle(self, frm: str,
               payload: bytes) -> JoinResult | None:
        """Procesa **un** mensaje del transporte.

        Los mensajes que no son del join (gossip,
        gists, inferencias) se ignoran: el transporte
        es multiplexado por tipo. Devuelve el
        :class:`~smcp.core.join.JoinResult` cuando el
        emparejamiento completa — y el mismo resultado
        si llega una retransmisión del roster —;
        ``None`` mientras la secuencia sigue.
        """
        kind, body = decode_msg(payload)
        if kind == KIND_HANDSHAKE:
            if _phase(body) == "init":
                self._on_init(frm, body)
            else:
                self._on_proof(frm, body)
            return None
        if kind == KIND_ROSTER:
            return self._on_roster(body)
        return None

    def pump(self) -> JoinResult | None:
        """Drena el transporte: atiende lo que
        llega y devuelve el resultado si el join
        completó."""
        result = None
        for frm, payload in self._transport.poll():
            result = self.handle(frm, payload) or result
        return result

    def serve_while(self, stop: Callable[[], bool],
                    poll_secs: float = 0.01) -> JoinResult | None:
        """Espera un emparejamiento hasta que
        ``stop()`` sea verdadero.

        El bucle de un nodo que empareja: drena el
        transporte, atiende lo que llega y duerme
        ``poll_secs`` entre drains. Devuelve el
        resultado, o ``None`` si pararon antes.
        """
        while not stop():
            result = self.pump()
            if result is not None:
                return result
            time.sleep(poll_secs)
        return None

    # -- la máquina de estados ---------------------------
    def _on_init(self, frm: str, payload: bytes) -> None:
        """El par inicia: registro su clave y su
        nonce, genero el mío y firmo
        (nonce_del_par ‖ nonce_propio)."""
        if self._own_nonce is not None:
            raise ProtocolError("el join ya empezó")
        identity_key, peer_nonce = decode_handshake_init(payload)
        self._peer = frm
        self._peer_key = identity_key
        self._own_nonce = new_nonce()
        self._own_proof = sign_handshake(
            self._key, peer_nonce=peer_nonce,
            own_nonce=self._own_nonce,
        )
        self._transport.send(frm, encode_handshake_proof(self._own_proof))

    def _on_proof(self, frm: str, payload: bytes) -> None:
        """La prueba del par: la verifico contra **mi**
        nonce (liga la prueba a esta sesión — un
        replay de otra no cuadra — y la firma a la
        clave que trae — una sustituida no verifica).
        Una prueba que no cuadra es un MITM: el join
        falla cerrado, no se degrada."""
        if self._own_nonce is None:
            raise ProtocolError("prueba sin handshake empezado")
        proof = decode_handshake_proof(payload)
        if not verify_handshake(proof, my_nonce=self._own_nonce):
            raise ProtocolError("la prueba del par no verifica")
        self._peer_key = proof.identity_key
        self._peer_proof = proof
        if self._own_proof is None:
            # Yo inicié: completo mi prueba y la envío.
            self._own_proof = sign_handshake(
                self._key, peer_nonce=proof.nonce,
                own_nonce=self._own_nonce,
            )
            self._transport.send(frm, encode_handshake_proof(self._own_proof))
        # El handshake está verificado en los dos
        # sentidos: envío mi roster (y el par, el suyo).
        self._transport.send(frm, encode_roster(self._roster, self._keyring))

    def _on_roster(self, payload: bytes) -> JoinResult | None:
        """El roster del par.

        Con su roster en la mano se avala al par
        en **mi** roster (el *epoch* que se avala
        es el que su roster declara — por eso el
        roster viaja antes que el aval) y se
        reconcilia: mi mitad del emparejamiento
        cerró, y mi roster, que ya trae mi aval,
        vuelve al par. Cuando el roster del par
        trae **mi** admisión (su aval a mí), la
        otra mitad también cerró: se reconcilia
        de nuevo y el join completa.

        Que mi mitad no cierre (cluster distinto,
        sesión o certificado que no cuadra) es un
        fallo cerrado: se dice en el resultado y
        no se sigue intercambiando.
        """
        if self._result is not None:
            # Un roster que llega tras completar es
            # una retransmisión: el resultado ya está.
            return self._result
        peer_key = self._peer_key
        own_nonce = self._own_nonce
        own_proof = self._own_proof
        peer_proof = self._peer_proof
        if (peer_key is None or own_nonce is None
                or own_proof is None or peer_proof is None):
            raise ProtocolError("roster sin handshake verificado")
        peer_roster, peer_keyring = decode_roster(payload)
        result = pair_local(
            roster=self._roster, key=self._key,
            keyring=self._keyring,
            peer_roster=peer_roster,
            peer_key=PeerIdentity(peer_key),
            peer_keyring=peer_keyring,
            session=Session(
                a_nonce=own_nonce, b_nonce=peer_proof.nonce,
                a_proof=own_proof, b_proof=peer_proof,
            ),
        )
        if not result.a_trusts_b or result.mutual:
            # O mi mitad no cerró (fallo), o las
            # dos cerraron: en los dos casos, el
            # resultado es final.
            self._result = result
            return result
        # Mi mitad cerró y la del par no: envío
        # mi roster, que ya trae mi aval al par.
        self._transport.send(
            self._peer, encode_roster(self._roster, self._keyring),
        )
        return None
