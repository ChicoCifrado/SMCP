"""ARC — la capa de emisión: el ``PaymentACK`` de DPP.

Qué resuelve este módulo
------------------------
:mod:`delm.core.inscripcion` construye y firma la tx de v3,
pero deliberadamente **no la emite**: el ``PaymentACK`` de DPP
(BRC-27) es de la capa de transporte. Esta es esa capa — un
cliente HTTP para **ARC** (Authoritative Response Component, el
servicio de emisión de BSV; ver
``https://bitcoin-sv.github.io/arc/``), con lo que una
inscripción firmada llega a la red y vuelve su estado.

El contrato (ARC v1):

* ``POST /v1/tx`` — el hex crudo de la tx como *body* en
  texto plano. Cabeceras de comportamiento: ``X-WaitFor``
  (qué estado esperar antes de responder), ``X-MaxTimeout``
  (cuánto, tope 30 s) y switches de validación
  (``X-SkipFeeValidation``, ``X-ForceValidation``, …).
* ``GET /v1/tx/{txid}`` — el estado corriente de una tx.
* ``GET /v1/policy`` y ``GET /v1/health`` — la política de
  fees y la salud del servicio.
* Auth: ``Authorization: Bearer <token>`` — opcional; ARC
  también sirve sin ella.
* Los errores son *problem details* (RFC 7807) con códigos
  propios de ARC (460-469, 473) además de los HTTP usuales.

El estado de una tx avanza ``QUEUED → RECEIVED → STORED → … →
ACCEPTED_BY_NETWORK → SEEN_ON_NETWORK → MINED``; ``REJECTED`` y
``DOUBLE_SPEND_ATTEMPTED`` son terminales y malos.
:meth:`ArcClient.broadcast` sostiene la petición con
``X-WaitFor`` y sondea después hasta el objetivo: el
``PaymentACK`` es el estado aceptado, no el 200 de la petición.

Lo que este módulo NO hace
--------------------------
* No es una wallet: no elige UTXOs ni construye tx (eso es
  :mod:`delm.core.spv` y :mod:`delm.core.txbuild`).
* No sirve callbacks: ``X-CallbackUrl`` de ARC queda como
  follow-up; el sondeo cubre el flujo del ``PaymentACK``.
* No verifica la inscripción — eso es
  :func:`delm.core.inscripcion.verify_inscription`.
* No habla con Bitcoin Core ni con ningún RPC de nodo: ARC es
  la vía de emisión (decisión de la rama: lo de BTC/Core
  queda fuera del proyecto).
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Protocol

import aiohttp

from delm.core.txbuild import Transaction

__all__ = [
    "ArcClient",
    "ArcError",
    "ArcHealth",
    "ArcHttpError",
    "ArcPolicy",
    "ArcRejectedError",
    "ArcTimeoutError",
    "ArcTxStatus",
    "Broadcaster",
    "broadcast_transaction",
    "ACCEPTED_BY_NETWORK",
    "ACCEPTED_STATUSES",
    "ANNOUNCED_TO_NETWORK",
    "DOUBLE_SPEND_ATTEMPTED",
    "MINED",
    "MINED_IN_STALE_BLOCK",
    "QUEUED",
    "RECEIVED",
    "REJECTED",
    "REQUESTED_BY_NETWORK",
    "SEEN_IN_ORPHAN_MEMPOOL",
    "SEEN_ON_NETWORK",
    "SENT_TO_NETWORK",
    "STORED",
    "TERMINAL_STATUSES",
    "UNKNOWN",
]

# ---------------------------------------------------------------------------
# Los estados de una tx, tal como los define ARC (txStatus)
# ---------------------------------------------------------------------------
UNKNOWN = "UNKNOWN"
QUEUED = "QUEUED"
RECEIVED = "RECEIVED"
STORED = "STORED"
ANNOUNCED_TO_NETWORK = "ANNOUNCED_TO_NETWORK"
REQUESTED_BY_NETWORK = "REQUESTED_BY_NETWORK"
SENT_TO_NETWORK = "SENT_TO_NETWORK"
ACCEPTED_BY_NETWORK = "ACCEPTED_BY_NETWORK"
SEEN_IN_ORPHAN_MEMPOOL = "SEEN_IN_ORPHAN_MEMPOOL"
SEEN_ON_NETWORK = "SEEN_ON_NETWORK"
DOUBLE_SPEND_ATTEMPTED = "DOUBLE_SPEND_ATTEMPTED"
REJECTED = "REJECTED"
MINED_IN_STALE_BLOCK = "MINED_IN_STALE_BLOCK"
MINED = "MINED"

#: Los estados que el servidor sabe esperar (``X-WaitFor``).
_WAIT_FOR_VALUES = frozenset({
    QUEUED,
    RECEIVED,
    STORED,
    ANNOUNCED_TO_NETWORK,
    REQUESTED_BY_NETWORK,
    SENT_TO_NETWORK,
    ACCEPTED_BY_NETWORK,
    SEEN_ON_NETWORK,
})

#: Estados en los que la tx ya no puede avanzar. Los buenos
#: (minada) y los malos (rechazada, doble gasto) son terminales
#: por igual: no tiene sentido seguir sondando.
TERMINAL_STATUSES = frozenset({
    MINED,
    REJECTED,
    DOUBLE_SPEND_ATTEMPTED,
    MINED_IN_STALE_BLOCK,
})

#: Lo que el ``PaymentACK`` necesita: la red ha visto la tx.
#: ``MINED_IN_STALE_BLOCK`` no cuenta — el bloque se quedó
#: huérfano y la tx volvió al mempool.
ACCEPTED_STATUSES = frozenset({
    ACCEPTED_BY_NETWORK,
    SEEN_ON_NETWORK,
    MINED,
})

#: El estado que se pide con ``X-WaitFor``: el primero que
#: cuenta como aceptado. El servidor no entiende ``MINED`` en
#: esa cabecera — si el objetivo es solo minado, se sondea.
_SERVER_WAIT = ACCEPTED_BY_NETWORK

#: Tope de ``X-MaxTimeout``: el servidor sostiene la petición
#: como máximo 30 s (por defecto 5).
MAX_SERVER_WAIT = 30

#: Plazo por defecto del sondeo de :meth:`ArcClient.broadcast`.
DEFAULT_DEADLINE = 60.0

#: Cuánto duerme el sondeo entre consultas.
DEFAULT_POLL_INTERVAL = 0.5

#: Tiempo de vida de una petición HTTP. Mayor que
#: :data:`MAX_SERVER_WAIT` para que el margen lo ponga el
#: cliente, no la competencia: una petición sostenida por el
#: servidor dura hasta 30 s.
DEFAULT_HTTP_TIMEOUT = 35.0


# ---------------------------------------------------------------------------
# Errores
# ---------------------------------------------------------------------------
class ArcError(Exception):
    """La base de los errores de la capa de emisión."""


class ArcHttpError(ArcError):
    """ARC respondió con un error: sus *problem details* (RFC 7807).

    Los campos son los del objeto de error de ARC: ``title``
    corto, ``detail`` largo, y —cuando la tx llegó a
    identificarse— su ``txid``.
    """

    def __init__(self, *, http_status: int, title: str,
                 detail: str = "", txid: str = "",
                 extra_info: str = "") -> None:
        super().__init__(
            f"ARC {http_status} {title}"
            + (f": {detail}" if detail else "")
        )
        self.http_status = http_status
        self.title = title
        self.detail = detail
        self.txid = txid
        self.extra_info = extra_info


class ArcRejectedError(ArcError):
    """La tx alcanzó un estado terminal malo (rechazo, doble gasto)."""


class ArcTimeoutError(ArcError):
    """La tx no alcanzó el estado objetivo dentro del plazo."""


# ---------------------------------------------------------------------------
# Las respuestas
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ArcTxStatus:
    """El estado de una tx, tal como lo devuelve ARC.

    ``block_hash``, ``block_height`` y ``merkle_path`` vienen
    llenos cuando la tx está minada (la prueba de Merkle en
    formato BUMP, BRC-74); ``competing_txs`` son las tx que
    intentan gastar los mismos inputs.
    """

    txid: str
    tx_status: str
    block_hash: str = ""
    block_height: int = 0
    merkle_path: str = ""
    extra_info: str = ""
    competing_txs: tuple[str, ...] = ()

    @property
    def accepted(self) -> bool:
        """¿Cuenta como ``PaymentACK``?"""
        return self.tx_status in ACCEPTED_STATUSES

    @property
    def terminal(self) -> bool:
        """¿No puede avanzar más (para bien o para mal)?"""
        return self.tx_status in TERMINAL_STATUSES


@dataclass(frozen=True)
class ArcPolicy:
    """La política del servicio: límites y fee mínima de minado."""

    max_script_size: int
    max_tx_sigops_counts: int
    max_tx_size: int
    mining_fee_satoshis: int
    mining_fee_bytes: int
    standard_format_supported: bool


@dataclass(frozen=True)
class ArcHealth:
    """La salud del servicio (metamorph)."""

    healthy: bool
    version: str = ""
    reason: str = ""


def _competing(raw: Any) -> tuple[str, ...]:
    """``competingTxs``: la API las devuelve en grupos anidados."""
    flat: list[str] = []
    for entry in raw or []:
        if isinstance(entry, list):
            flat.extend(str(txid) for txid in entry)
        else:
            flat.append(str(entry))
    return tuple(flat)


def _parse_tx_status(data: dict[str, Any]) -> ArcTxStatus:
    try:
        txid = str(data["txid"])
        tx_status = str(data["txStatus"])
    except KeyError as exc:
        raise ArcError(f"respuesta de ARC sin {exc}") from exc
    return ArcTxStatus(
        txid=txid,
        tx_status=tx_status,
        block_hash=str(data.get("blockHash") or ""),
        block_height=int(data.get("blockHeight") or 0),
        merkle_path=str(data.get("merklePath") or ""),
        extra_info=str(data.get("extraInfo") or ""),
        competing_txs=_competing(data.get("competingTxs")),
    )


def _json(body: str) -> dict[str, Any]:
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise ArcError(f"respuesta no es JSON: {body[:200]}") from exc
    if not isinstance(data, dict):
        raise ArcError("respuesta de ARC no es un objeto JSON")
    return data


def _problem(status: int, body: str, reason: str | None) -> ArcHttpError:
    """El *problem details* de ARC, o un eco del cuerpo crudo."""
    try:
        data = json.loads(body)
        if not isinstance(data, dict):
            data = {}
    except ValueError:
        data = {}
    return ArcHttpError(
        http_status=status,
        title=str(data.get("title") or reason or f"error {status}"),
        detail=str(data.get("detail") or ""),
        txid=str(data.get("txid") or ""),
        extra_info=str(data.get("extraInfo") or ""),
    )


class ArcClient:
    """Cliente HTTP de ARC: emite tx y pregunta por su estado.

    Parameters
    ----------
    base_url:
        La raíz del servicio (``http://127.0.0.1:3000``); la
        barra final sobra.
    api_key:
        El token de ``Authorization: Bearer``. ``None`` para el
        ARC sin auth.
    timeout:
        Plazo de cada petición HTTP. Por defecto mayor que el
        tope de 30 s que el servidor puede sostener una petición
        (``X-MaxTimeout``), para que el margen lo ponga el
        cliente y no la competencia.

    Cada petición abre y cierra su sesión: un cliente es un
    objeto de configuración, no de conexión — no hay que
    cerrarlo.
    """

    def __init__(self, base_url: str, *, api_key: str | None = None,
                 timeout: float = DEFAULT_HTTP_TIMEOUT) -> None:
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = aiohttp.ClientTimeout(total=timeout)

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if extra:
            headers.update(extra)
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def _get_json(self, path: str) -> dict[str, Any]:
        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            async with session.get(
                f"{self._base}{path}", headers=self._headers()
            ) as resp:
                body = await resp.text()
                if resp.status != 200:
                    raise _problem(resp.status, body, resp.reason)
                return _json(body)

    async def _post_hex(self, path: str, tx_hex: str,
                        extra: dict[str, str]) -> dict[str, Any]:
        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            async with session.post(
                f"{self._base}{path}", data=tx_hex,
                headers=self._headers(extra),
            ) as resp:
                body = await resp.text()
                if resp.status != 200:
                    raise _problem(resp.status, body, resp.reason)
                return _json(body)

    # ---------------------------------------------------------------- emitir
    async def submit(self, tx_hex: str, *,
                     wait_for: str | None = None,
                     max_timeout: int | None = None) -> ArcTxStatus:
        """Emite una tx: ``POST /v1/tx`` con el hex crudo.

        ``wait_for`` pide al servidor que sostenga la petición
        hasta ese estado (``X-WaitFor``; tope ``max_timeout``,
        máximo :data:`MAX_SERVER_WAIT` segundos). Sin ellos, la
        petición vuelve en cuanto ARC acepta la tx para
        procesarla — el estado aún no es de red.
        """
        if not tx_hex.strip():
            raise ValueError("tx_hex vacío")
        if wait_for is not None and wait_for not in _WAIT_FOR_VALUES:
            raise ValueError(
                f"X-WaitFor {wait_for!r} no es un estado esperable"
            )
        if max_timeout is not None and not 0 <= max_timeout <= MAX_SERVER_WAIT:
            raise ValueError(
                f"X-MaxTimeout {max_timeout} fuera de [0, {MAX_SERVER_WAIT}]"
            )
        extra = {"Content-Type": "text/plain"}
        if wait_for:
            extra["X-WaitFor"] = wait_for
        if max_timeout is not None:
            extra["X-MaxTimeout"] = str(max_timeout)
        return _parse_tx_status(
            await self._post_hex("/v1/tx", tx_hex, extra)
        )

    async def broadcast(self, tx_hex: str, *,
                        target: frozenset[str] = ACCEPTED_STATUSES,
                        poll_interval: float = DEFAULT_POLL_INTERVAL,
                        deadline: float = DEFAULT_DEADLINE) -> ArcTxStatus:
        """Emite y espera: el ``PaymentACK`` de DPP (BRC-27).

        Sostiene la petición con ``X-WaitFor`` (hasta
        :data:`MAX_SERVER_WAIT` s) y sondea
        ``GET /v1/tx/{txid}`` después si el objetivo no se
        alcanzó así — p. ej. ``MINED``, que el servidor no
        sabe esperar.

        Lanza :class:`ArcRejectedError` en un estado terminal
        malo (``REJECTED``, ``DOUBLE_SPEND_ATTEMPTED``) y
        :class:`ArcTimeoutError` si ``deadline`` se agota antes
        de alcanzar ``target``.
        """
        if not target:
            raise ValueError("objetivo vacío: no hay estado que esperar")
        if poll_interval < 0 or deadline <= 0:
            raise ValueError("poll_interval o deadline inválidos")
        wait_for = _SERVER_WAIT if target & ACCEPTED_STATUSES else None
        server_wait = min(MAX_SERVER_WAIT, max(0, int(deadline)))
        result = await self.submit(
            tx_hex, wait_for=wait_for,
            max_timeout=server_wait if wait_for else None,
        )
        stop = time.monotonic() + deadline
        while True:
            if result.tx_status in target:
                return result
            if result.tx_status in TERMINAL_STATUSES:
                raise ArcRejectedError(
                    f"tx {result.txid} en estado terminal "
                    f"{result.tx_status}"
                    + (f": {result.extra_info}" if result.extra_info else "")
                )
            if time.monotonic() >= stop:
                raise ArcTimeoutError(
                    f"tx {result.txid} no alcanzó {sorted(target)} "
                    f"en {deadline} s (estado: {result.tx_status})"
                )
            await asyncio.sleep(poll_interval)
            result = await self.status(result.txid)

    # -------------------------------------------------------------- consultar
    async def status(self, txid: str) -> ArcTxStatus:
        """El estado corriente de una tx ya emitida."""
        if not txid.strip():
            raise ValueError("txid vacío")
        return _parse_tx_status(
            await self._get_json(f"/v1/tx/{txid.strip()}")
        )

    async def policy(self) -> ArcPolicy:
        """La política del servicio: límites y fee mínima de minado."""
        data = await self._get_json("/v1/policy")
        policy = data.get("policy")
        if not isinstance(policy, dict):
            raise ArcError("respuesta de política sin 'policy'")
        fee = policy.get("miningFee")
        if not isinstance(fee, dict):
            raise ArcError("respuesta de política sin 'miningFee'")
        return ArcPolicy(
            max_script_size=int(policy.get("maxscriptsizepolicy") or 0),
            max_tx_sigops_counts=int(
                policy.get("maxtxsigopscountspolicy") or 0
            ),
            max_tx_size=int(policy.get("maxtxsizepolicy") or 0),
            mining_fee_satoshis=int(fee.get("satoshis") or 0),
            mining_fee_bytes=int(fee.get("bytes") or 0),
            standard_format_supported=bool(
                policy.get("standardFormatSupported")
            ),
        )

    async def health(self) -> ArcHealth:
        """La salud del servicio (metamorph)."""
        data = await self._get_json("/v1/health")
        return ArcHealth(
            healthy=bool(data.get("healthy")),
            version=str(data.get("version") or ""),
            reason=str(data.get("reason") or ""),
        )


class Broadcaster(Protocol):
    """Lo que la emisión necesita: emitir una tx y esperar su aceptación.

    :class:`ArcClient` lo satisface estructuralmente; un doble en
    proceso lo sustituye en los tests sin red (el contrato de wire
    de ARC lo sujetan ``tests/test_arc.py``).
    """

    async def broadcast(
        self,
        tx_hex: str,
        *,
        target: frozenset[str] = ...,
        poll_interval: float = ...,
        deadline: float = ...,
    ) -> ArcTxStatus: ...


async def broadcast_transaction(tx: Transaction, client: Broadcaster,
                                **kwargs: Any) -> ArcTxStatus:
    """Emite una tx construida localmente y verifica su identidad.

    El paso de emisión del flujo de inscripción v3: la tx ya
    firmada por el solicitante (DPP ``Payment``) se serializa,
    se emite por ARC y se espera su aceptación. El txid que
    ARC devuelve se compara con el de la tx local — si no
    casan, la serialización está rota, y es mejor fallar aquí
    que contar una inferencia (:func:`delm.core.contrib.record_inference`)
    que nunca se ancló.

    ``kwargs`` pasan a :meth:`ArcClient.broadcast`
    (``target``, ``poll_interval``, ``deadline``).
    """
    result = await client.broadcast(tx.serialize().hex(), **kwargs)
    local = tx.txid()
    if result.txid != local:
        raise ArcError(
            f"ARC devolvió txid {result.txid}; la tx local es {local}"
        )
    return result
