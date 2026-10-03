"""Intercambio — la secuencia de inferencia v3, de punta a punta.

Qué resuelve este módulo
------------------------
El template (:mod:`delm.core.inscripcion`) y la emisión
(:mod:`delm.core.arc`) son piezas: construyen y verifican
la tx, y la emiten. Lo que ninguna de las dos hace es la
**secuencia** que el flujo de la malla sostiene — la que
``test_exchange_thesis.py`` probó para v2:

    otro nodo pide una inferencia  ->  el servidor la
    sirve y construye los ``PaymentTerms``  ->  el
    solicitante verifica y firma su input (``Payment``)
    ->  el servidor emite por ARC y espera el
    ``PaymentACK``  ->  y solo entonces el historial sube

Este módulo es esa secuencia con las piezas de v3: una
sola tx que paga y ancla, y sin ancla de membresía — la
identidad fuera de cadena es el roster
(:mod:`delm.core.roster`), no una tx de 1 sat.

Los dos lados
--------------
* :class:`InferenceServer` (Bob, el que sirve): ejecuta
  la inferencia, firma ``H``, construye los términos y —
  al recibir la tx firmada— verifica, emite por ARC y
  cuenta (:func:`delm.core.contrib.record_inference`).
* :func:`sign_payment` (Alice, la que pide): verifica los
  términos y firma su input.

Lo que este módulo NO hace
--------------------------
* No es el transporte: el intercambio de mensajes (petición,
  términos, tx firmada, respuesta) es de la capa de
  transporte (QUIC; x402 como opción) — aquí los mensajes
  son llamadas, como en la tesis de v2.
* No es una wallet: el UTXO de fondeo lo aporta quien
  llama (:mod:`delm.core.spv` es la wallet del nodo).
* No ejecuta el modelo: :mod:`delm.core.llm` es el modelo;
  aquí solo se le pide la respuesta.
* No es el join: entrar en la malla es el roster, un
  intercambio de claves off-chain.
"""
from __future__ import annotations

from dataclasses import dataclass

from delm.core.arc import ArcTxStatus, Broadcaster, broadcast_transaction
from delm.core.bsv_keys import Secp256k1KeyPair
from delm.core.contrib import ContributionLedger
from delm.core.inscripcion import (
    ORDINAL_SATOSHIS,
    InscriptionReceipt,
    InscriptionRequest,
    build_payment_terms,
    extract_inscription,
    server_signature,
    sign_requester_input,
    verify_payment_terms,
)
from delm.core.llm import LLMClient
from delm.core.membership import ProtocolError
from delm.core.tiers import PER_INFERENCE_SATOSHIS
from delm.core.txbuild import Transaction, TxIn

__all__ = [
    "InferenceRequest",
    "InferenceServer",
    "PaymentAck",
    "sign_payment",
]


# ---------------------------------------------------------------------------
# La petición
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class InferenceRequest:
    """Lo que Alice pide: el prompt y cómo pagarlo.

    ``funding`` es el UTXO de Alice — exactamente
    :data:`PER_INFERENCE_SATOSHIS`, porque la plantilla
    v3.0 no lleva cambio— y ``requester_pubkey`` su clave:
    la que paga, la que recibe el ordinal, y la que ``H``
    compromete.
    """

    prompt: str
    mesh_id: str
    requester_pubkey: bytes
    funding: TxIn
    funding_sats: int = PER_INFERENCE_SATOSHIS


# ---------------------------------------------------------------------------
# El ack
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PaymentAck:
    """El ``PaymentACK`` de DPP: la tx aceptada, y el comprobante.

    ``status`` es lo que ARC dijo (el estado de la tx en la
    red); ``receipt`` es lo que la tx dice (el ordinal, el
    parent, la firma sobre ``H``). El txid es el mismo en
    los dos — y es la clave con la que
    :func:`delm.core.contrib.record_inference` cuenta.
    """

    receipt: InscriptionReceipt
    status: ArcTxStatus

    @property
    def txid(self) -> str:
        """El txid de la inscripción: la clave del historial."""
        return self.receipt.txid


# ---------------------------------------------------------------------------
# El servidor (Bob)
# ---------------------------------------------------------------------------
class InferenceServer:
    """El lado que sirve: ejecuta, construye, emite, cuenta.

    Parameters
    ----------
    server_key, llm, arc:
        La clave del servidor (firma ``H`` y cobra), el
        modelo que ejecuta la inferencia, y la vía de
        emisión (:class:`delm.core.arc.ArcClient`, o un
        doble que cumpla :class:`Broadcaster`).
    ledger, peer_id:
        El ledger de contribuciones y el id del nodo que
        sirve. Si ambos vienen, el ``PaymentACK`` cuenta la
        inferencia; si no, el intercambio se verifica y se
        emite pero no sube historial — lo que es cierto para
        un nodo que sirve sin estar en el roster de
        contribuciones.
    fee_sats:
        La fee que paga el servidor de sus 99 sats
        (0 a 98; el knob es :data:`PER_INFERENCE_SATOSHIS`).
    """

    def __init__(self, *, server_key: Secp256k1KeyPair,
                 llm: LLMClient, arc: Broadcaster,
                 ledger: ContributionLedger | None = None,
                 peer_id: str | None = None,
                 fee_sats: int = 0) -> None:
        # La fee sale de los 99 sats del servidor: con 99 o
        # más, el pago no cierra (le quedaría 0 o menos).
        tope = PER_INFERENCE_SATOSHIS - ORDINAL_SATOSHIS - 1
        if not 0 <= fee_sats <= tope:
            raise ProtocolError(
                f"fee de {fee_sats} sats; la plantilla deja "
                f"[0, {tope}] (la fee sale de los "
                f"{PER_INFERENCE_SATOSHIS - ORDINAL_SATOSHIS} "
                "sats del servidor)"
            )
        self._key = server_key
        self._llm = llm
        self._arc = arc
        self._ledger = ledger
        self._peer_id = peer_id
        self._fee_sats = fee_sats

    async def serve(self, req: InferenceRequest) -> tuple[str, Transaction]:
        """Ejecuta la inferencia y construye los ``PaymentTerms``.

        La respuesta viaja **fuera de cadena** — lo que la
        tx ancla es ``H``, no el contenido (la decisión de
        v2, que v3 hereda: publicar el hash de un prompt es
        tan identificador como el prompt). Quien llama
        entrega el texto al solicitante por el transporte.
        """
        response = await self._llm.complete(req.prompt)
        request = InscriptionRequest(
            req.mesh_id, req.requester_pubkey,
            self._key.public_key,
        )
        signature = server_signature(
            mesh_id=req.mesh_id,
            requester_pubkey=req.requester_pubkey,
            server_key=self._key,
        )
        tx = build_payment_terms(
            request=request, signature=signature,
            funding=req.funding, funding_sats=req.funding_sats,
            fee_sats=self._fee_sats,
        )
        return response, tx

    async def settle(self, tx: Transaction,
                     req: InferenceRequest) -> PaymentAck:
        """Verifica la ``Payment`` firmada, emite y cuenta.

        Re-verifica los términos **con la tx firmada** — la
        firma de Alice no cambia lo que la tx compromete,
        pero esta verificación es la que cierra el
        intercambio—, exige que el input esté firmado (emitir
        una tx sin firmar es tirarla a la red para que el
        minero la rechace), emite por ARC y espera el estado
        aceptado: ese es el ``PaymentACK``. Y solo entonces
        cuenta la inferencia; si el historial no la cuenta
        (nodo sin VRAM anunciada, txid repetido), la
        secuencia está rota y se dice, no se ignora.
        """
        if not tx.inputs[0].script_sig:
            raise ProtocolError(
                "la Payment no está firmada: el input de "
                "fondeo va sin scriptSig"
            )
        ok, why = verify_payment_terms(
            tx, mesh_id=req.mesh_id,
            requester_pubkey=req.requester_pubkey,
            funding_sats=req.funding_sats,
        )
        if not ok:
            raise ProtocolError(f"la Payment no verifica: {why}")
        status = await broadcast_transaction(tx, self._arc)
        receipt = extract_inscription(tx)
        if self._ledger is not None and self._peer_id is not None:
            counted, why2 = self._ledger.record_inference(
                self._peer_id, txid=receipt.txid,
                satoshis=receipt.server_satoshis,
            )
            if not counted:
                raise ProtocolError(
                    f"el historial no cuenta la inferencia: {why2}"
                )
        return PaymentAck(receipt=receipt, status=status)


# ---------------------------------------------------------------------------
# El cliente (Alice)
# ---------------------------------------------------------------------------
def sign_payment(tx: Transaction, *,
                 requester_key: Secp256k1KeyPair,
                 mesh_id: str,
                 funding_sats: int = PER_INFERENCE_SATOSHIS) -> None:
    """Alice: verifica los términos y firma su input (la ``Payment``).

    Verifica **antes** de firmar — lo que Alice comprueba es
    que ``H`` compromete su petición, que la firma del
    servidor es de quien dice servir, y que la aritmética es
    la pactada (1 sat de ordinal a su nombre + 99 menos fee
    al servidor). Un término que no verifica no se firma.
    """
    ok, why = verify_payment_terms(
        tx, mesh_id=mesh_id,
        requester_pubkey=requester_key.public_key,
        funding_sats=funding_sats,
    )
    if not ok:
        raise ProtocolError(f"los términos no verifican: {why}")
    sign_requester_input(tx, 0, requester_key)
