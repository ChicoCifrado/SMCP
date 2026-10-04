"""Tests de smcp.core.electrumsv — cliente REST del daemon (sin daemon).

Se usa un transporte HTTP simulado (se inyecta en el cliente) para
probar el contrato REST: rutas, métodos, payloads y el flujo
trazable create -> broadcast -> log. No requiere ElectrumSV
corriendo (la integración real se verifica contra el daemon).

Contrato verificado contra ElectrumSV 1.4.0b1:
* Rutas `/v1/{network}/dapp/...` (montadas por el módulo dapp `restapi`).
* El `wallet_name` incluye la extensión `.sqlite`.
* Los GET envían body `{}` (el dapp parsea el JSON del body).
* `create_tx` exige `{"wallet_name", "account_id", "password",
  "outputs": [{"script_pubkey": "<hex>", "value": <sats>}]}`.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from smcp.core.electrumsv import (
    DEFAULT_TX_LOG,
    ElectrumSV,
    ElectrumSVError,
    read_wif,
)


class FakeTransport:
    """Simula el daemon: graba llamadas y devuelve respuestas fijas."""

    def __init__(self, responses: dict[tuple[str, str], Any] | None = None):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.responses = responses or {}

    def urlopen(self, req, timeout: int = 60):
        self.calls.append((req.get_method(), req.full_url,
                           json.loads(req.data) if req.data else None))
        key = (req.get_method(), req.full_url)
        if key in self.responses:
            payload = self.responses[key]
        else:
            payload = {}
        return _FakeResponse(payload)


class _FakeResponse:
    def __init__(self, payload: Any):
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def client(monkeypatch):
    """Cliente con transporte simulado."""
    esv = ElectrumSV()
    transport = FakeTransport()
    monkeypatch.setattr("urllib.request.urlopen", transport.urlopen)
    monkeypatch.setattr("urllib.request.Request", _Req)
    return esv, transport


class _Req:
    """Request que captura method/url/data para el FakeTransport."""

    def __init__(self, url, data=None, headers=None, method=None):
        self.full_url = url
        self.data = data
        self.headers = headers or {}
        self._method = method

    def get_method(self):
        return self._method or ("POST" if self.data else "GET")


def test_base_url_y_network():
    esv = ElectrumSV(base_url="http://127.0.0.1:9999/", network="main")
    assert esv.base_url == "http://127.0.0.1:9999"
    assert esv.network == "main"
    assert esv._url("/wallets") == (
        "http://127.0.0.1:9999/v1/main/dapp/wallets")


def test_list_wallets_es_get(client):
    esv, transport = client
    transport.responses[("GET", esv._url("/wallets"))] = {"wallets": []}
    result = esv.list_wallets()
    assert result == {"wallets": []}
    method, url, body = transport.calls[0]
    assert method == "GET"
    assert url.endswith("/v1/main/dapp/wallets")
    # Los GET envian body {} (el dapp parsea el JSON del body).
    assert body == {}


def test_load_wallet_pasa_password_y_nombre(client):
    """load_wallet: POST /wallets/{name}/load_wallet con body."""
    esv, transport = client
    path = esv._url("/wallets/w.sqlite/load_wallet")
    transport.responses[("POST", path)] = {
        "wallet_id": 1, "parent_wallet": "w.sqlite", "accounts": {}}
    result = esv.load_wallet("w.sqlite", password="test")
    assert result["parent_wallet"] == "w.sqlite"
    method, url, body = transport.calls[0]
    assert method == "POST"
    assert url.endswith("/v1/main/dapp/wallets/w.sqlite/load_wallet")
    assert body == {"wallet_name": "w.sqlite", "password": "test"}


def test_balance_get_con_body_vacio(client):
    esv, transport = client
    path = esv._url("/wallets/w.sqlite/1/utxos/balance")
    transport.responses[("GET", path)] = {
        "confirmed_balance": 0, "unconfirmed_balance": 0}
    result = esv.balance("w.sqlite", "1")
    assert result["confirmed_balance"] == 0
    method, url, body = transport.calls[0]
    assert method == "GET"
    assert body == {}


def test_utxos_con_parametros(client):
    esv, transport = client
    path = esv._url("/wallets/w.sqlite/1/utxos")
    transport.responses[("GET", path)] = {"utxos": []}
    result = esv.utxos("w.sqlite", "1", confirmed_only=True)
    assert result == {"utxos": []}
    method, url, body = transport.calls[0]
    assert method == "GET"
    assert body == {"confirmed_only": True}


def test_create_tx_pasa_script_pubkey_hex(client):
    """La pieza clave: create_tx exige script_pubkey en hex
    (para inscripciones BSV-21 / OP_RETURN) y pasa wallet_name
    y account_id en el body."""
    esv, transport = client
    path = esv._url("/wallets/w.sqlite/1/txs/create")
    transport.responses[("POST", path)] = {"txid": "abc", "rawtx": "0100"}
    out = esv.create_tx("w.sqlite", "1",
                        [{"script_pubkey": "006a0b68656c6c6f", "value": 0}],
                        password="test")
    assert out == {"txid": "abc", "rawtx": "0100"}
    _, url, body = transport.calls[0]
    assert url.endswith("/v1/main/dapp/wallets/w.sqlite/1/txs/create")
    assert body["wallet_name"] == "w.sqlite"
    assert body["account_id"] == "1"
    assert body["password"] == "test"
    assert body["outputs"] == [
        {"script_pubkey": "006a0b68656c6c6f", "value": 0}]


def test_broadcast_pasa_rawtx(client):
    esv, transport = client
    path = esv._url("/wallets/w.sqlite/1/txs/broadcast")
    transport.responses[("POST", path)] = {"txid": "abc"}
    result = esv.broadcast("w.sqlite", "1", "0100...")
    assert result == {"txid": "abc"}
    _, _, body = transport.calls[0]
    assert body == {"rawtx": "0100..."}


def test_fetch_transaction_pasa_txid(client):
    esv, transport = client
    path = esv._url("/wallets/w.sqlite/1/txs/fetch")
    transport.responses[("POST", path)] = {"txid": "tx1"}
    result = esv.fetch_transaction("w.sqlite", "1", "tx1")
    assert result == {"txid": "tx1"}
    _, _, body = transport.calls[0]
    assert body == {"txid": "tx1"}


def test_send_tracked_flujo_completo_y_log(client, tmp_path):
    """create -> broadcast -> log append-only (trazabilidad)."""
    esv, transport = client
    create_path = esv._url("/wallets/w.sqlite/1/txs/create")
    bc_path = esv._url("/wallets/w.sqlite/1/txs/broadcast")
    transport.responses[("POST", create_path)] = {
        "txid": "tx123", "rawtx": "0100"}
    transport.responses[("POST", bc_path)] = {"txid": "tx123"}
    log = tmp_path / "txs.jsonl"
    out = esv.send_tracked("w.sqlite", "1",
                           [{"script_pubkey": "76a91488ac", "value": 500}],
                           purpose="pago nodo bob", password="test",
                           tx_log=log)
    assert out["txid"] == "tx123"
    assert out["purpose"] == "pago nodo bob"
    assert out["logged"] is True
    # Se llamo a create y a broadcast
    methods = [c[0] for c in transport.calls]
    assert methods == ["POST", "POST"]
    # El log tiene la tx con su propósito
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["txid"] == "tx123"
    assert entry["purpose"] == "pago nodo bob"
    assert entry["wallet"] == "w.sqlite"
    assert entry["account"] == "1"


def test_send_tracked_log_es_append_only(client, tmp_path):
    esv, transport = client
    create_path = esv._url("/wallets/w.sqlite/1/txs/create")
    bc_path = esv._url("/wallets/w.sqlite/1/txs/broadcast")
    transport.responses[("POST", create_path)] = {
        "txid": "t1", "rawtx": "01"}
    transport.responses[("POST", bc_path)] = {"txid": "t1"}
    log = tmp_path / "txs.jsonl"
    esv.send_tracked("w.sqlite", "1",
                     [{"script_pubkey": "76a91488ac", "value": 1}],
                     purpose="a", tx_log=log)
    transport.responses[("POST", create_path)] = {
        "txid": "t2", "rawtx": "02"}
    transport.responses[("POST", bc_path)] = {"txid": "t2"}
    esv.send_tracked("w.sqlite", "1",
                     [{"script_pubkey": "76a91488ac", "value": 1}],
                     purpose="b", tx_log=log)
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 2  # append, no reescritura


def test_daemon_no_alcanzable_levanta_error():
    esv = ElectrumSV(base_url="http://127.0.0.1:1")
    with pytest.raises(ElectrumSVError, match="no alcanzable"):
        esv.list_wallets()


def test_read_wif_falta_levanta(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_wif(tmp_path / "no-existe.wif")


def test_read_wif_vacio_levanta(tmp_path):
    p = tmp_path / "vacio.wif"
    p.write_text("   \n")
    with pytest.raises(ValueError, match="vacío"):
        read_wif(p)


def test_default_tx_log_bajo_smcp():
    assert DEFAULT_TX_LOG == Path.home() / ".smcp" / "electrumsv.txs.jsonl"
