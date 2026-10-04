"""Tests del token BSV-21 DELM (capa F — token).

El bridge Node se mockea (no requiere Node ni
red): se verifica la logica del modulo Python
(invocacion del bridge, parseo de resultados,
comodines DeLM).
"""
from __future__ import annotations

import json
import os
from unittest import mock

import pytest

from smcp.core.token_bsv21 import (
    TOKEN_DECIMALS,
    TOKEN_SUPPLY,
    TOKEN_SYMBOL,
    Bsv21Result,
    balances,
    buy,
    deploy,
    list_token_utxos,
    pay_for_inference,
    send,
    token_id_from_deploy,
)


def _fake_bridge(output: str):
    """Mock de subprocess.run que devuelve ``output``."""
    proc = mock.Mock()
    proc.stdout = output
    proc.stderr = ""
    return proc


class TestTokenId:
    """tokenId = <deployTxid>_<outputIndex>."""

    def test_deploy_output_0(self):
        txid = "a" * 64
        assert token_id_from_deploy(txid) == f"{txid}_0"

    def test_real_deploy(self):
        # el deploy real del token DELM
        txid = "8d7f483498d83358e8c0b61b55334b1650d50ffce1539a482bc245dfc65c4410"
        assert token_id_from_deploy(txid).endswith("_0")
        assert token_id_from_deploy(txid).startswith(txid)


class TestDeploy:
    """deployBsv21Mint via bridge."""

    @mock.patch("smcp.core.token_bsv21.subprocess.run")
    @mock.patch("smcp.core.token_bsv21._read_wif")
    def test_deploy_default(self, _wif, run):
        _wif.return_value = "WIF"
        run.return_value = _fake_bridge(
            json.dumps({"ok": True, "txid": "t" * 64, "tokenId": "t" * 64 + "_0"})
        )
        res = deploy()
        assert res.ok
        assert res.txid == "t" * 64
        assert res.token_id == "t" * 64 + "_0"
        # se invoco con los parametros por defecto
        payload = json.loads(run.call_args.kwargs["input"])
        assert payload["action"] == "deploy"
        assert payload["symbol"] == TOKEN_SYMBOL
        assert payload["amount"] == TOKEN_SUPPLY
        assert payload["decimals"] == TOKEN_DECIMALS

    @mock.patch("smcp.core.token_bsv21.subprocess.run")
    @mock.patch("smcp.core.token_bsv21._read_wif")
    def test_deploy_with_destination(self, _wif, run):
        _wif.return_value = "WIF"
        run.return_value = _fake_bridge(
            json.dumps({"ok": True, "txid": "x" * 64, "tokenId": "x" * 64 + "_0"})
        )
        deploy(destination_address="1MjR4vi4aa1sfXcZbz2vAm1bpZhJ37ozAQ")
        payload = json.loads(run.call_args.kwargs["input"])
        assert payload["destination"] == "1MjR4vi4aa1sfXcZbz2vAm1bpZhJ37ozAQ"

    @mock.patch("smcp.core.token_bsv21.subprocess.run")
    def test_deploy_no_node(self, run):
        run.side_effect = FileNotFoundError()
        res = deploy()
        assert not res.ok
        assert "node" in res.error.lower()


class TestSend:
    """sendBsv21 value-based."""

    @mock.patch("smcp.core.token_bsv21.subprocess.run")
    @mock.patch("smcp.core.token_bsv21._read_wif")
    def test_send_one_recipient(self, _wif, run):
        _wif.return_value = "WIF"
        run.return_value = _fake_bridge(
            json.dumps({"ok": True, "txid": "s" * 64})
        )
        res = send(
            token_id="tok_0",
            recipients=[
                {"amount": "100000", "destination": {"address": "1ABC"}}
            ],
        )
        assert res.ok
        payload = json.loads(run.call_args.kwargs["input"])
        assert payload["action"] == "send"
        assert payload["tokenId"] == "tok_0"
        assert payload["recipients"][0]["amount"] == "100000"

    def test_send_no_recipients(self):
        res = send(token_id="tok_0", recipients=[])
        assert not res.ok
        assert "destinatarios" in res.error

    @mock.patch("smcp.core.token_bsv21.subprocess.run")
    @mock.patch("smcp.core.token_bsv21._read_wif")
    def test_send_error(self, _wif, run):
        _wif.return_value = "WIF"
        run.return_value = _fake_bridge(
            json.dumps({"ok": False, "error": "insufficient"})
        )
        res = send(token_id="tok_0", recipients=[{"amount": "1", "destination": {"address": "1"}}])
        assert not res.ok
        assert res.error == "insufficient"


class TestBalances:
    """getBsv21Balances."""

    @mock.patch("smcp.core.token_bsv21.subprocess.run")
    @mock.patch("smcp.core.token_bsv21._read_wif")
    def test_balances(self, _wif, run):
        _wif.return_value = "WIF"
        run.return_value = _fake_bridge(
            json.dumps({"ok": True, "balances": [{"sym": "DELM", "amt": "1000000", "dec": 0}]})
        )
        res = balances()
        assert res.ok
        assert res.raw["balances"][0]["sym"] == "DELM"


class TestBuy:
    """buyBsv21 (marketplace)."""

    @mock.patch("smcp.core.token_bsv21.subprocess.run")
    @mock.patch("smcp.core.token_bsv21._read_wif")
    def test_buy(self, _wif, run):
        _wif.return_value = "WIF"
        run.return_value = _fake_bridge(
            json.dumps({"ok": True, "txid": "b" * 64})
        )
        res = buy(token_id="tok_0", outpoint="txid_0", amount="1000")
        assert res.ok
        payload = json.loads(run.call_args.kwargs["input"])
        assert payload["action"] == "buy"
        assert payload["outpoint"] == "txid_0"


class TestPayForInference:
    """Comodin DeLM: pagar a un nodo en DELM."""

    @mock.patch("smcp.core.token_bsv21.subprocess.run")
    @mock.patch("smcp.core.token_bsv21._read_wif")
    def test_pay_for_inference(self, _wif, run):
        _wif.return_value = "WIF"
        run.return_value = _fake_bridge(
            json.dumps({"ok": True, "txid": "p" * 64})
        )
        res = pay_for_inference(
            token_id="tok_0",
            node_address="1NQPbNEscdNJ3iPYpoWFwVW9uDtMojEQuy",
            amount="1000",
        )
        assert res.ok
        payload = json.loads(run.call_args.kwargs["input"])
        assert payload["recipients"][0]["destination"]["address"] == "1NQPbNEscdNJ3iPYpoWFwVW9uDtMojEQuy"


class TestListTokenUtxos:
    """listBsv21."""

    @mock.patch("smcp.core.token_bsv21.subprocess.run")
    @mock.patch("smcp.core.token_bsv21._read_wif")
    def test_list(self, _wif, run):
        _wif.return_value = "WIF"
        run.return_value = _fake_bridge(
            json.dumps({"ok": True, "utxos": [{"outpoint": "o_0", "tags": ["bsv21:tok_0"]}]})
        )
        res = list_token_utxos(token_id="tok_0", limit=10)
        assert res.ok
        assert res.raw["utxos"][0]["outpoint"] == "o_0"


class TestBadOutput:
    """Manejo de salidas no JSON / vacias."""

    @mock.patch("smcp.core.token_bsv21.subprocess.run")
    @mock.patch("smcp.core.token_bsv21._read_wif")
    def test_non_json_output(self, _wif, run):
        _wif.return_value = "WIF"
        run.return_value = _fake_bridge("not json at all")
        res = balances()
        assert not res.ok
        assert "no JSON" in res.error
        assert res.raw is None

    @mock.patch("smcp.core.token_bsv21.subprocess.run")
    @mock.patch("smcp.core.token_bsv21._read_wif")
    def test_empty_output(self, _wif, run):
        _wif.return_value = "WIF"
        run.return_value = _fake_bridge("")
        res = balances()
        assert not res.ok
        assert res.raw is None

    @mock.patch("smcp.core.token_bsv21.subprocess.run")
    @mock.patch("smcp.core.token_bsv21._read_wif")
    def test_timeout(self, _wif, run):
        _wif.return_value = "WIF"
        import subprocess
        run.side_effect = subprocess.TimeoutExpired(cmd="node", timeout=120)
        res = balances()
        assert not res.ok
        assert "timeout" in res.error.lower()
