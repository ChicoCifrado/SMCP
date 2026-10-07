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
0x03  HANDSHAKE          reservado (identidad BRC-103)
0x04  INFERENCE_REQUEST  Alice -> Bob
0x05  PAYMENT_TERMS      Bob -> Alice (la tx sin firmar)
0x06  SIGNED_PAYMENT     Alice -> Bob (la tx firmada)
0x07  INFERENCE_RESPONSE Bob -> Alice (off-chain)
===== =================== ====================================

Todos llevan ``request_id`` (hex aleatorio) para
correlacionar la petición con sus respuestas en un
transporte de datagramas sin estado, y se codifican
en JSON — el mismo formato que el anuncio de gossip
(:mod:`mesh_node`).

La secuencia
--------------
::

    Alice pide (0x04)  ->  Bob sirve y devuelve la
    respuesta (0x07) y los términos (0x05)  ->
    Alice verifica y firma (0x06)  ->  Bob
    verifica, emite por ARC y cuenta.

Los actores
--------------
:class:`InferenceRequester` (Alice) y
:class:`InferenceResponder` (Bob) corren sobre
cualquier :class:`~smcp.core.transport.MeshTransport`:
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
from smcp.core.intercambio import (
    InferenceRequest,
    InferenceServer,
    sign_payment,
)
from smcp.core.membership import ProtocolError
from smcp.core.mesh_node import decode_msg, encode_msg
from smcp.core.tiers import PER_INFERENCE_SATOSHIS
from smcp.core.transport import MeshTransport
from smcp.core.txbuild import Transaction, TxIn

__all__ = [
    "KIND_HANDSHAKE",
    "KIND_INFERENCE_REQUEST",
    "KIND_INFERENCE_RESPONSE",
    "KIND_PAYMENT_TERMS",
    "KIND_SIGNED_PAYMENT",
    "InferenceRequester",
    "InferenceResponder",
    "decode_inference_request",
    "decode_inference_response",
    "decode_payment_terms",
    "decode_signed_payment",
    "encode_inference_request",
    "encode_inference_response",
    "encode_payment_terms",
    "encode_signed_payment",
    "new_request_id",
]

#: Handshake de identidad BRC-103 — **reservado**: es el
#: siguiente paso de esta capa. :mod:`smcp.core.identidad`
#: es hoy una llamada; su mensaje viaja por aquí.
KIND_HANDSHAKE = 0x03
#: Alice -> Bob: el prompt, la malla, su clave y su UTXO.
KIND_INFERENCE_REQUEST = 0x04
#: Bob -> Alice: los términos (la tx sin firmar, DPP).
KIND_PAYMENT_TERMS = 0x05
#: Alice -> Bob: la tx con su input firmado (la Payment).
KIND_SIGNED_PAYMENT = 0x06
#: Bob -> Alice: la respuesta, fuera de cadena.
KIND_INFERENCE_RESPONSE = 0x07


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
