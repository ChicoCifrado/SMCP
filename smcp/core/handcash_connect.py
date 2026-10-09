"""HandCash Connect — el adaptador que envía el pago.

Qué resuelve este módulo
------------------------
La identidad de pago (:mod:`smcp.core.handcash`)
dice *adónde* van los pagos; este módulo es el
*cómo*: habla con la API de HandCash Connect
(v3) para enviar el
:class:`~smcp.core.handcash.PaymentIntent`. La
nota de finalización de la inscripción viaja en
el campo ``note`` del pago — metadata fuera de
la cadena que la billetera del receptor muestra
al recibir: la notificación de que la inferencia
completó.

La firma
--------
Cada llamada de cuenta se firma con la **clave
de acceso del usuario** (el *auth token*: 32
bytes secp256k1). La firma es ECDSA sobre
``MÉTODO\nendpoint\nmarca\ncuerpo\nnonce``
(digest SHA-256, codificación DER) y viaja en
las cabeceras ``oauth-signature``,
``oauth-publickey`` (la clave pública
comprimida, 33 bytes), ``oauth-timestamp`` y
``oauth-nonce``. Es lo que hace
``createAuthInterceptor`` del SDK oficial
(``@handcash/sdk``), reproducido aquí en Python
con ``cryptography`` — el mismo esquema, leído
del código fuente del SDK.

Las credenciales
----------------
* **App** (appId/appSecret): identifican la
  aplicación; las crea el dashboard de HandCash
  (``dashboard.handcash.io``). Vienen de
  ``HANDCASH_APP_ID``/``HANDCASH_APP_SECRET`` o
  de ``~/.smcp/handcash.app`` (JSON, 0600).
* **Usuario** (auth token): la clave de acceso.
  De ``HANDCASH_AUTH_TOKEN`` o de
  ``~/.smcp/handcash.authtoken`` (64 hex).

Sin credenciales de app la API rechaza todo
(``401 Invalid app-id``) — verificado contra
la API real.

El monto
--------
La API no recibe satoshis: ``sendAmount`` viaja
en la **moneda de denominación** (fiat, o
BTC). El adaptador pide la tasa de cambio a la
propia API (``/v3/connect/exchangeRate/USD``,
que devuelve versión y tasa), convierte los
satoshis del intento con ella y manda la
versión para que el servidor convierta a la
misma tasa: el pago cierra en los satoshis que
la inscripción presupone.

Lo que este módulo NO hace
--------------------------
* No elige el monto ni el destinatario: recibe
  el :class:`~smcp.core.handcash.PaymentIntent`
  ya construido (el contrato con la
  infraestructura de inscripciones).
* No custodia fondos: la firma autoriza pagos
  desde la billetera del usuario; la clave de
  acceso es material secreto (0600).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from smcp.core.bsv_keys import Secp256k1KeyPair
from smcp.core.handcash import PaymentIntent, handcash_note
from smcp.core.membership import ProtocolError

#: La base de la API de Connect (del SDK oficial).
HANDCASH_API_BASE = "https://cloud.handcash.io"

#: Timeout de las llamadas (segundos).
HANDCASH_TIMEOUT = 15.0

#: La clave de acceso: 64 caracteres hex (32 bytes).
_AUTH_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class HandCashError(RuntimeError):
    """La API de HandCash rechazó (o no supo) una llamada.

    ``status`` es el código HTTP (``None`` si no
    hubo respuesta) e ``info`` el detalle que la
    API añade al mensaje.
    """

    def __init__(self, message: str,
                 status: int | None = None,
                 info: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.info = info


@dataclass(frozen=True)
class HandCashAppCredentials:
    """Las credenciales de la aplicación (appId,
    appSecret)."""

    app_id: str
    app_secret: str


def default_app_credentials_path() -> Path:
    """Dónde viven las credenciales de app."""
    return Path.home() / ".smcp" / "handcash.app"


def default_auth_token_path() -> Path:
    """Dónde vive la clave de acceso del usuario."""
    return Path.home() / ".smcp" / "handcash.authtoken"


def load_app_credentials(
        path: Path | None = None) -> HandCashAppCredentials | None:
    """Las credenciales de app: entorno primero,
    luego ``~/.smcp/handcash.app``.

    ``None`` si no hay ninguna: el pago no se
    puede enviar (la API rechaza el app-id).
    """
    app_id = os.environ.get("HANDCASH_APP_ID", "").strip()
    app_secret = os.environ.get("HANDCASH_APP_SECRET", "").strip()
    if app_id and app_secret:
        return HandCashAppCredentials(app_id, app_secret)
    p = path if path is not None else (
        default_app_credentials_path())
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    app_id = str(data.get("app_id") or "").strip()
    app_secret = str(data.get("app_secret") or "").strip()
    if not app_id or not app_secret:
        return None
    return HandCashAppCredentials(app_id, app_secret)


def _auth_token_bytes(token: str) -> bytes:
    """La clave de acceso como 32 bytes raw."""
    txt = (token or "").strip()
    if not _AUTH_TOKEN_RE.match(txt):
        raise ProtocolError(
            "auth token: se esperan 64 caracteres "
            "hex (una clave secp256k1 de 32 bytes)"
        )
    return bytes.fromhex(txt)


def load_auth_token(
        path: Path | None = None) -> bytes | None:
    """La clave de acceso del usuario: entorno
    primero, luego ``~/.smcp/handcash.authtoken``.

    ``None`` si no hay ninguna: las llamadas de
    cuenta (perfil, saldo, pago) no se pueden
    firmar.
    """
    token = os.environ.get("HANDCASH_AUTH_TOKEN", "")
    if token.strip():
        return _auth_token_bytes(token)
    p = path if path is not None else (
        default_auth_token_path())
    if not p.exists():
        return None
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError:
        return None
    if not raw.strip():
        return None
    return _auth_token_bytes(raw)


def denomination_amount(sats: int, rate: float) -> float:
    """Satoshis a la moneda de denominación.

    ``rate`` es cuántas unidades de la moneda de
    denominación vale un BSV: los satoshis se
    pasan a BSV (1e8 por unidad) y se multiplican
    por la tasa. El redondeo a 8 decimales es el
    del campo ``sendAmount``; el servidor convierte
    de vuelta a la misma tasa.
    """
    if rate <= 0:
        raise HandCashError(
            f"tasa de cambio {rate}: no positiva"
        )
    amount = round(sats * rate / 100_000_000.0, 8)
    if amount <= 0:
        raise HandCashError(
            f"{sats} sats a tasa {rate}: el monto "
            "redondea a 0 en la moneda de "
            "denominación"
        )
    return amount


@dataclass(frozen=True)
class PaymentResult:
    """El recibo del pago: lo que la API devolvió.

    ``units`` es el monto en la moneda del
    instrumento (BSV), ``satoshi_fees`` la fee en
    satoshis, y ``fiat_units``/``fiat_currency``
    el equivalente en la moneda de denominación.
    ``record`` es el registro completo, por si la
    API añade campos.
    """

    transaction_id: str
    note: str
    units: float | None = None
    satoshi_fees: int | None = None
    fiat_units: float | None = None
    fiat_currency: str | None = None
    record: dict[str, Any] | None = None

    @classmethod
    def from_record(
            cls, record: dict[str, Any]) -> "PaymentResult":
        """Construye el recibo del registro de la
        API (``WalletTransactionRecord``)."""
        fiat = record.get("fiatEquivalent") or {}
        if not isinstance(fiat, dict):
            fiat = {}
        return cls(
            transaction_id=str(record.get(
                "transactionId") or ""),
            note=str(record.get("note") or ""),
            units=(float(record["units"])
                   if record.get("units") is not None
                   else None),
            satoshi_fees=(int(record["satoshiFees"])
                          if record.get("satoshiFees")
                          is not None else None),
            fiat_units=(float(fiat["units"])
                        if fiat.get("units") is not None
                        else None),
            fiat_currency=(str(fiat.get("currencyCode")
                               or "") or None),
            record=record,
        )


class HandCashConnect:
    """Cliente de la API de HandCash Connect.

    Todas las llamadas llevan las cabeceras de la
    app (``app-id``/``app-secret``) y, al tener
    clave de acceso, la firma ``oauth-*`` de la
    cuenta. ``now_iso`` y ``nonce`` se inyectan
    para las pruebas (la firma depende de ambos).
    """

    def __init__(
            self, app_id: str, app_secret: str,
            auth_token: bytes,
            base_url: str = HANDCASH_API_BASE,
            timeout: float = HANDCASH_TIMEOUT,
            now_iso: Callable[[], str] | None = None,
            nonce: Callable[[], str] | None = None,
    ) -> None:
        if not app_id or not app_secret:
            raise HandCashError(
                "credenciales de app vacías"
            )
        if len(auth_token) != 32:
            raise ProtocolError(
                f"auth token de {len(auth_token)} "
                "bytes; se esperan 32"
            )
        self._app_id = app_id
        self._app_secret = app_secret
        # La clave de la cuenta: firma y da la
        # clave pública comprimida (33 bytes).
        self._key = Secp256k1KeyPair.from_private_bytes(
            "handcash", auth_token)
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._now_iso = now_iso or (
            lambda: datetime.now(timezone.utc)
            .isoformat())
        self._nonce = nonce or (
            lambda: secrets.token_hex(8))

    # ------------------------------------------------------------ firma
    def _headers(self, method: str, endpoint: str,
                 body: str) -> dict[str, str]:
        """Las cabeceras de una llamada firmada."""
        ts = self._now_iso()
        nonce = self._nonce()
        payload = (
            f"{method}\n{endpoint}\n{ts}\n"
            f"{body}\n{nonce}"
        )
        digest = hashlib.sha256(
            payload.encode("utf-8")).hexdigest()
        return {
            "app-id": self._app_id,
            "app-secret": self._app_secret,
            "oauth-publickey": self._key.public_key.hex(),
            "oauth-signature": self._key.sign_der(
                digest).hex(),
            "oauth-timestamp": ts,
            "oauth-nonce": nonce,
        }

    # ----------------------------------------------------------- HTTP
    def _request(
            self, method: str, endpoint: str,
            *, body: dict[str, Any] | None = None,
            params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Una llamada firmada; el cuerpo que se
        firma es el que viaja, byte por byte."""
        import httpx  # type: ignore

        payload = "" if body is None else json.dumps(
            body, separators=(",", ":"))
        headers = self._headers(method, endpoint,
                                payload)
        if body is not None:
            headers["content-type"] = "application/json"
        with httpx.Client(
                base_url=self._base_url,
                timeout=self._timeout) as client:
            response = client.request(
                method, endpoint,
                content=payload.encode("utf-8")
                if payload else None,
                headers=headers, params=params)
        if response.status_code >= 400:
            raise HandCashError(
                _error_message(response),
                status=response.status_code,
                info=_error_info(response))
        if not response.content:
            return {}
        return response.json()

    # --------------------------------------------------------- endpoints
    def exchange_rate(
            self, currency: str = "USD") -> dict[str, Any]:
        """La tasa de cambio del BSV en la moneda
        (versión, tasa, símbolo, expiración)."""
        if not re.fullmatch(r"[A-Z]{3}", currency):
            raise ProtocolError(
                f"moneda {currency!r}: código ISO 4217 "
                "de 3 letras"
            )
        return self._request(
            "GET", f"/v3/connect/exchangeRate/"
                   f"{currency}")

    def spendable_balances(self) -> list[dict[str, Any]]:
        """Los saldos gastables de la billetera."""
        items = self._request(
            "GET",
            "/v3/connect/wallet/spendableBalances",
        ).get("items") or []
        return [i for i in items
                if isinstance(i, dict)]

    def wallet_address(self) -> dict[str, Any]:
        """Una dirección de la billetera (y su
        clave pública, si la API la devuelve)."""
        return self._request(
            "GET", "/v3/connect/wallet/address")

    def current_user_profile(self) -> dict[str, Any]:
        """El perfil del usuario dueño de la clave."""
        return self._request(
            "GET",
            "/v3/connect/profile/currentUserProfile")

    def payment(self, transaction_id: str) -> dict[str, Any]:
        """El detalle de un pago por su txid."""
        return self._request(
            "GET", "/v3/connect/wallet/payment",
            params={"transactionId": transaction_id})

    def pay(self, intent: PaymentIntent,
            currency: str = "USD") -> PaymentResult:
        """Envía el pago: la nota viaja en el
        ``note`` del pago.

        Primero pide la tasa de cambio (y su
        versión), convierte los satoshis del
        intento a la moneda de denominación y manda
        el pago con esa versión: el servidor convierte
        a la misma tasa, y el pago cierra en los
        satoshis que la inscripción presupone.
        """
        rate = self.exchange_rate(currency)
        version = str(rate.get("exchangeRateVersion")
                      or "")
        if not version:
            raise HandCashError(
                "la tasa de cambio no trae versión"
            )
        send_amount = denomination_amount(
            intent.sats, float(rate.get("rate") or 0))
        record = self._request(
            "POST", "/v3/connect/wallet/pay",
            body={
                "instrumentCurrencyCode": "BSV",
                "denominationCurrencyCode": currency,
                "exchangeRateVersion": version,
                "note": handcash_note(intent.note),
                "receivers": [{
                    "destination": intent.recipient,
                    "sendAmount": send_amount,
                }],
            })
        return PaymentResult.from_record(record)

    # ------------------------------------------------------- constructores
    @classmethod
    def from_defaults(
            cls, **kwargs: Any) -> "HandCashConnect":
        """Construye el cliente de las credenciales
        por defecto (entorno y ``~/.smcp``).

        Raises :class:`HandCashError` con el qué
        falta — app o usuario — para que el llamante
        lo diga sin adivinar.
        """
        creds = load_app_credentials()
        if creds is None:
            raise HandCashError(
                "sin credenciales de app: "
                "HANDCASH_APP_ID y HANDCASH_APP_SECRET, "
                "o ~/.smcp/handcash.app (del dashboard "
                "de HandCash)"
            )
        token = load_auth_token()
        if token is None:
            raise HandCashError(
                "sin clave de acceso: HANDCASH_AUTH_TOKEN "
                "o ~/.smcp/handcash.authtoken"
            )
        return cls(creds.app_id, creds.app_secret,
                   token, **kwargs)


def _error_message(response: Any) -> str:
    """El mensaje de error de la API, si lo hay."""
    try:
        data = response.json()
    except ValueError:
        return (response.text or "").strip()[:200]
    if isinstance(data, dict) and data.get("message"):
        return str(data["message"])
    return (response.text or "").strip()[:200]


def _error_info(response: Any) -> Any:
    """El detalle ``info`` de la API, si lo hay."""
    try:
        data = response.json()
    except ValueError:
        return None
    if isinstance(data, dict):
        return data.get("info")
    return None


__all__ = [
    "HANDCASH_API_BASE", "HANDCASH_TIMEOUT",
    "HandCashAppCredentials", "HandCashConnect",
    "HandCashError", "PaymentResult",
    "default_app_credentials_path",
    "default_auth_token_path", "denomination_amount",
    "load_app_credentials", "load_auth_token",
]
