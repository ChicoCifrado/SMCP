"""test_handcash_connect: el adaptador que envía el pago.

El contrato que se fija aquí:

* **La firma es la del SDK.** Las cabeceras
  ``oauth-*`` se construyen como en
  ``createAuthInterceptor`` de ``@handcash/sdk``:
  firma ECDSA-DER sobre
  ``MÉTODO\nendpoint\nmarca\ncuerpo\nnonce``
  (digest SHA-256), y la clave pública
  comprimida (33 bytes) viaja en
  ``oauth-publickey``. La firma se verifica
  con el verificador del propio repo.
* **El cuerpo firmado es el que viaja.** La
  firma cubre los bytes exactos del cuerpo
  (vacío en las GET).
* **El pago convierte con la tasa de la API.**
  ``sendAmount`` viaja en la moneda de
  denominación: satoshis -> BSV -> moneda, con
  la versión de la tasa para que el servidor
  convierta a la misma.
* **La nota viaja en el pago.** El ``note``
  del cuerpo es la nota de finalización del
  intento.
* **Los errores de la API se dicen.** El
  mensaje de la API (y su ``status``) se
  propagan, no se tragan.
* **Las credenciales: entorno y luego
  fichero.** ``None`` si no hay nada — el
  pago no se envía a ciegas.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import (
    utils as asym_utils,
)

import smcp.core.handcash_connect as hc
from smcp.core.bsv_keys import verify_public
from smcp.core.handcash import (
    PaymentIdentity,
    PaymentIntent,
    parse_handle,
)
from smcp.core.handcash_connect import (
    HandCashConnect,
    HandCashError,
    PaymentResult,
    denomination_amount,
    load_app_credentials,
    load_auth_token,
)
from smcp.core.membership import ProtocolError
from smcp.core.spv import pubkey_to_address

#: Una clave de acceso de pruebas (32 bytes).
TOKEN = bytes(range(32))

#: Marca y nonce fijos: la firma es
#: reproducible en las pruebas.
TS = "2026-10-09T12:00:00+00:00"
NONCE = "fijoparaeltest"


def _have_hash160() -> bool:
    """¿Hay ripemd160 (hash160) en este
    intérprete? Sin él, las direcciones no
    se validan."""
    try:
        pubkey_to_address(bytes(33))
    except Exception:  # noqa: BLE001 - sin ripemd160
        return False
    return True


def _connect(**kw: Any) -> HandCashConnect:
    """Un cliente con marca y nonce fijos."""
    kw.setdefault("now_iso", lambda: TS)
    kw.setdefault("nonce", lambda: NONCE)
    return HandCashConnect(
        "app-id-de-prueba", "app-secreto",
        TOKEN, **kw)


class _ScriptedClient:
    """Un ``httpx.Client`` de pruebas: graba
    las llamadas y responde en orden."""

    def __init__(
            self, script: "_Script",
            base_url: str | None = None,
            timeout: float | None = None) -> None:
        self._script = script
        self._base_url = base_url

    def __enter__(self) -> "_ScriptedClient":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def request(
            self, method: str, endpoint: str,
            content: bytes | None = None,
            headers: Any = None,
            params: Any = None) -> httpx.Response:
        self._script.calls.append({
            "method": method,
            "endpoint": endpoint,
            "base_url": self._base_url,
            "content": content,
            "headers": dict(headers or {}),
            "params": dict(params or {}),
        })
        status, payload = (
            self._script.responses.pop(0))
        # Un ``str`` responde sin JSON: el
        # error de la API sin cuerpo.
        if isinstance(payload, str):
            return httpx.Response(status, text=payload)
        return httpx.Response(status, json=payload)


class _Script:
    """Las respuestas programadas (en orden)
    y las llamadas grabadas."""

    def __init__(self) -> None:
        self.responses: list[
            tuple[int, Any]] = []
        self.calls: list[dict[str, Any]] = []


@pytest.fixture()
def script(monkeypatch: pytest.MonkeyPatch) -> _Script:
    """Intercepta ``httpx.Client`` con un
    guion de respuestas."""
    s = _Script()

    def factory(
            base_url: str | None = None,
            timeout: float | None = None,
    ) -> _ScriptedClient:
        return _ScriptedClient(s, base_url, timeout)

    monkeypatch.setattr("httpx.Client", factory)
    return s


# ------------------------------------------------------------------ firma

def _digest(method: str, endpoint: str,
            body: str) -> str:
    """El digest que firma la cabecera."""
    payload = (
        f"{method}\n{endpoint}\n{TS}\n"
        f"{body}\n{NONCE}")
    return hashlib.sha256(
        payload.encode()).hexdigest()


def _sig_rs(head: dict[str, str]) -> bytes:
    """La firma de la cabecera, como ``r || s``."""
    r, s = asym_utils.decode_dss_signature(
        bytes.fromhex(head["oauth-signature"]))
    return (r.to_bytes(32, "big")
            + s.to_bytes(32, "big"))


def test_firma_es_la_del_sdk(
        script: _Script) -> None:
    """Las cabeceras oauth se construyen como
    en el SDK, y la firma verifica contra
    la clave pública comprimida."""
    script.responses.append((200, {}))
    con = _connect()
    con._request("GET", "/v3/connect/wallet/address")
    assert len(script.calls) == 1
    head = script.calls[0]["headers"]
    assert head["app-id"] == "app-id-de-prueba"
    assert head["app-secret"] == "app-secreto"
    assert head["oauth-timestamp"] == TS
    assert head["oauth-nonce"] == NONCE
    # La clave pública: comprimida, 33 bytes.
    pub = bytes.fromhex(head["oauth-publickey"])
    assert len(pub) == 33
    # La firma: DER válida sobre el digest
    # del payload (cuerpo vacío en la GET).
    assert verify_public(
        pub,
        _digest("GET", "/v3/connect/wallet/address", ""),
        _sig_rs(head))


def test_la_firma_cubre_el_cuerpo_que_viaja(
        script: _Script) -> None:
    """La POST firma los bytes exactos del
    cuerpo JSON."""
    script.responses.append(
        (200, {"transactionId": "t"}))
    con = _connect()
    con._request("POST", "/v3/connect/wallet/pay",
                 body={"note": "inferencia completada"})
    content = script.calls[0]["content"]
    assert content is not None
    assert json.loads(content) == {
        "note": "inferencia completada"}
    head = script.calls[0]["headers"]
    assert head["content-type"] == "application/json"
    assert verify_public(
        bytes.fromhex(head["oauth-publickey"]),
        _digest("POST", "/v3/connect/wallet/pay",
                content.decode()),
        _sig_rs(head))


def test_la_clave_publica_es_la_de_la_cuenta() -> None:
    """``oauth-publickey`` es la comprimida de
    la clave de acceso."""
    con = _connect()
    head = con._headers(
        "GET", "/v3/connect/profile/currentUserProfile",
        "")
    assert head["oauth-publickey"] == (
        con._key.public_key.hex())


# -------------------------------------------------------------- endpoints

def test_exchange_rate(script: _Script) -> None:
    """La tasa viene de la API (el cuerpo
    va vacío)."""
    script.responses.append((200, {
        "exchangeRateVersion": "v42",
        "rate": 300.0, "fiatSymbol": "$",
        "estimatedExpireDate": "pronto"}))
    con = _connect()
    rate = con.exchange_rate("USD")
    assert rate["rate"] == 300.0
    assert script.calls[0]["endpoint"] == (
        "/v3/connect/exchangeRate/USD")
    assert script.calls[0]["method"] == "GET"


def test_moneda_ha_ser_iso4217() -> None:
    """El código de moneda son 3 letras."""
    con = _connect()
    with pytest.raises(ProtocolError):
        con.exchange_rate("pesos")


def test_saldos_gastables(script: _Script) -> None:
    """Los saldos son los ``items`` del registro."""
    script.responses.append((200, {"items": [
        {"currencyCode": "BSV",
         "spendableBalance": 0.0000249}]}))
    con = _connect()
    saldos = con.spendable_balances()
    assert saldos == [{"currencyCode": "BSV",
                       "spendableBalance": 0.0000249}]


def test_perfil_y_pago(script: _Script) -> None:
    """Perfil y detalle de pago: las rutas y
    los parámetros."""
    script.responses.append((200, {"id": "yo"}))
    script.responses.append((200, {"transactionId": "tx"}))
    con = _connect()
    assert con.current_user_profile() == {"id": "yo"}
    assert con.payment("tx") == {"transactionId": "tx"}
    assert script.calls[0]["endpoint"] == (
        "/v3/connect/profile/currentUserProfile")
    assert script.calls[1]["endpoint"] == (
        "/v3/connect/wallet/payment")
    assert script.calls[1]["params"] == {"transactionId": "tx"}


# ------------------------------------------------------------------ pago

def test_pago_convierte_con_la_tasa(
        script: _Script) -> None:
    """El pago: tasa primero, luego el envío
    con la versión de la tasa, la nota y el
    destino; el recibo mapea el registro."""
    script.responses.append((200, {
        "exchangeRateVersion": "v42", "rate": 300.0}))
    script.responses.append((200, {
        "transactionId": "abc123",
        "type": "PAY", "time": 1,
        "note": "inferencia completada",
        "units": 0.00000249, "satoshiFees": 43,
        "fiatEquivalent": {
            "currencyCode": "USD",
            "units": 0.000747}}))
    ident = PaymentIdentity(
        handle=parse_handle("$Chicocifrado"))
    intent = PaymentIntent(
        sats=249, identity=ident,
        note="inferencia completada")
    con = _connect()
    res = con.pay(intent)
    assert isinstance(res, PaymentResult)
    assert res.transaction_id == "abc123"
    assert res.note == "inferencia completada"
    assert res.units == 0.00000249
    assert res.satoshi_fees == 43
    assert res.fiat_units == 0.000747
    assert res.fiat_currency == "USD"
    # La llamada de tasa y luego la de pago.
    assert script.calls[0]["endpoint"].startswith(
        "/v3/connect/exchangeRate/")
    assert script.calls[1]["endpoint"] == (
        "/v3/connect/wallet/pay")
    assert script.calls[1]["method"] == "POST"
    body = json.loads(script.calls[1]["content"])
    assert body["instrumentCurrencyCode"] == "BSV"
    assert body["denominationCurrencyCode"] == "USD"
    assert body["exchangeRateVersion"] == "v42"
    assert body["note"] == "inferencia completada"
    assert body["receivers"] == [{
        "destination": "chicocifrado@handcash.io",
        "sendAmount": 0.000747}]


@pytest.mark.skipif(
    not _have_hash160(), reason="requiere ripemd160")
def test_pago_a_direccion_legacy(
        script: _Script) -> None:
    """Sin handle, el destino es la dirección."""
    script.responses.append((200, {
        "exchangeRateVersion": "v1", "rate": 1.0}))
    script.responses.append((200, {"transactionId": "t"}))
    direccion = pubkey_to_address(bytes(33))
    ident = PaymentIdentity(legacy_address=direccion)
    intent = PaymentIntent(
        sats=1000, identity=ident,
        note="inferencia terminada")
    con = _connect()
    con.pay(intent, currency="BTC")
    assert script.calls[0]["endpoint"] == (
        "/v3/connect/exchangeRate/BTC")
    body = json.loads(script.calls[1]["content"])
    assert body["denominationCurrencyCode"] == "BTC"
    assert body["receivers"][0]["destination"] == direccion


def test_pago_sin_version_de_tasa(
        script: _Script) -> None:
    """La tasa sin versión no sirve: el servidor
    no sabría a qué tasa convertir."""
    script.responses.append((200, {"rate": 300.0}))
    con = _connect()
    intent = PaymentIntent(
        sats=10, identity=PaymentIdentity(
            handle=parse_handle("$Chicocifrado")),
        note="inferencia completada")
    with pytest.raises(HandCashError):
        con.pay(intent)


# ---------------------------------------------------------- conversion

def test_denomination_amount() -> None:
    """Satoshis a la moneda: BSV (1e8) por
    tasa, redondeado a 8 decimales."""
    assert denomination_amount(249, 300.0) == 0.000747
    assert denomination_amount(100_000_000, 300.0) == 300.0
    assert denomination_amount(
        100_000_000, 1e-8) == 1e-08


def test_denomination_amount_rechaza() -> None:
    """Tasa no positiva, o un monto que
    redondea a cero."""
    with pytest.raises(HandCashError):
        denomination_amount(249, 0.0)
    with pytest.raises(HandCashError):
        denomination_amount(249, -1.0)
    # 1 sat a tasa mínima redondea a 0.
    with pytest.raises(HandCashError):
        denomination_amount(1, 1e-9)


# ------------------------------------------------------------ errores

def test_error_de_la_api(script: _Script) -> None:
    """El mensaje y el status de la API se
    propagan."""
    script.responses.append(
        (401, {"message": "Invalid app-id",
               "info": {}}))
    con = _connect()
    with pytest.raises(HandCashError) as exc:
        con.exchange_rate("USD")
    assert "Invalid app-id" in str(exc.value)
    assert exc.value.status == 401


def test_error_sin_json(script: _Script) -> None:
    """Un error sin cuerpo JSON se dice igual."""
    script.responses.append((502, "Bad Gateway"))
    con = _connect()
    with pytest.raises(HandCashError) as exc:
        con.exchange_rate("USD")
    assert exc.value.status == 502
    assert "Bad Gateway" in str(exc.value)


# ------------------------------------------------------ credenciales

def test_credenciales_del_entorno(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """HANDCASH_APP_ID y HANDCASH_APP_SECRET
    primero."""
    monkeypatch.setenv("HANDCASH_APP_ID", "app-env")
    monkeypatch.setenv("HANDCASH_APP_SECRET",
                       "secreto-env")
    creds = load_app_credentials()
    assert creds is not None
    assert creds.app_id == "app-env"
    assert creds.app_secret == "secreto-env"


def test_credenciales_del_fichero(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Sin entorno, ``~/.smcp/handcash.app``
    (la ruta se inyecta)."""
    monkeypatch.delenv("HANDCASH_APP_ID",
                       raising=False)
    monkeypatch.delenv("HANDCASH_APP_SECRET",
                       raising=False)
    f = tmp_path / "handcash.app"
    f.write_text(json.dumps({
        "app_id": "app-file",
        "app_secret": "secreto-file"}))
    creds = load_app_credentials(f)
    assert creds is not None
    assert creds.app_id == "app-file"
    assert creds.app_secret == "secreto-file"


def test_credenciales_ausentes(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Ni entorno ni fichero: ``None`` (no se
    envía a ciegas)."""
    monkeypatch.delenv("HANDCASH_APP_ID",
                       raising=False)
    monkeypatch.delenv("HANDCASH_APP_SECRET",
                       raising=False)
    assert load_app_credentials(
        tmp_path / "no.json") is None
    # Fichero roto o incompleto, lo mismo.
    roto = tmp_path / "roto.json"
    roto.write_text("{no json")
    assert load_app_credentials(roto) is None
    incompleto = tmp_path / "inc.json"
    incompleto.write_text(json.dumps(
        {"app_id": "solo-el-id"}))
    assert load_app_credentials(incompleto) is None


def test_auth_token_del_entorno(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """HANDCASH_AUTH_TOKEN: 64 hex a 32 bytes."""
    monkeypatch.setenv(
        "HANDCASH_AUTH_TOKEN", TOKEN.hex())
    assert load_auth_token() == TOKEN


def test_auth_token_del_fichero(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Sin entorno, ``~/.smcp/handcash.authtoken``
    (la ruta se inyecta)."""
    monkeypatch.delenv("HANDCASH_AUTH_TOKEN",
                       raising=False)
    f = tmp_path / "handcash.authtoken"
    f.write_text(TOKEN.hex() + "\n")
    assert load_auth_token(f) == TOKEN
    assert load_auth_token(
        tmp_path / "no.txt") is None


def test_auth_token_roto(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Un token que no es 64 hex es error de
    protocolo, no un silencio."""
    monkeypatch.setenv("HANDCASH_AUTH_TOKEN", "corto")
    with pytest.raises(ProtocolError):
        load_auth_token()


def test_from_defaults_dice_que_falta(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Sin credenciales (o sin clave), el error
    dice qué falta."""
    monkeypatch.delenv("HANDCASH_APP_ID",
                       raising=False)
    monkeypatch.delenv("HANDCASH_APP_SECRET",
                       raising=False)
    monkeypatch.delenv("HANDCASH_AUTH_TOKEN",
                       raising=False)
    monkeypatch.setattr(
        hc, "default_app_credentials_path",
        lambda: tmp_path / "no.json")
    monkeypatch.setattr(
        hc, "default_auth_token_path",
        lambda: tmp_path / "no.txt")
    with pytest.raises(HandCashError) as exc:
        HandCashConnect.from_defaults()
    assert "credenciales de app" in str(exc.value)
    # Con app pero sin clave de acceso.
    f = tmp_path / "no.json"
    f.write_text(json.dumps({
        "app_id": "app", "app_secret": "secreto"}))
    with pytest.raises(HandCashError) as exc:
        HandCashConnect.from_defaults()
    assert "clave de acceso" in str(exc.value)


# ------------------------------------------------------- recibo

def test_recibo_sin_equivalente() -> None:
    """El registro sin ``fiatEquivalent`` ni
    ``units`` se mapea a ``None``."""
    res = PaymentResult.from_record(
        {"transactionId": "t", "note": "n"})
    assert res.transaction_id == "t"
    assert res.units is None
    assert res.satoshi_fees is None
    assert res.fiat_units is None
    assert res.fiat_currency is None
