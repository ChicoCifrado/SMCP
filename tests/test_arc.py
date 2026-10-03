"""test_arc: el cliente ARC, contra un ARC falso en localhost.

No hay red exterior: un servidor ``aiohttp`` local hace
de ARC y responde lo que cada caso necesita — un estado,
una secuencia de estados, o un *problem details* de
error. Lo que sujetan los tests, en orden de importancia:

1. el contrato de wire: hex crudo en texto plano, y
   las cabeceras ``X-WaitFor`` / ``X-MaxTimeout`` /
   ``Authorization``;
2. el parseo de estado (con ``competingTxs`` nulos y
   anidados), de política y de salud;
3. el mapeo de errores de ARC (problem details, cuerpo
   no JSON, 404) a :class:`ArcHttpError`;
4. ``broadcast``: no sondea cuando el servidor sostiene
   la petición, sondea cuando no, rechaza estados
   terminales malos y falla con :class:`ArcTimeoutError`
   pasado el plazo;
5. ``broadcast_transaction``: emite una tx real y
   comprueba que el txid de ARC casa con el de la tx
   local.
"""
from __future__ import annotations

import asyncio

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from delm.core.arc import (
    ACCEPTED_BY_NETWORK,
    ArcClient,
    ArcError,
    ArcHttpError,
    ArcRejectedError,
    ArcTimeoutError,
    DOUBLE_SPEND_ATTEMPTED,
    QUEUED,
    REJECTED,
    SEEN_ON_NETWORK,
    STORED,
    broadcast_transaction,
)
from delm.core.txbuild import (
    Transaction,
    TxIn,
    TxOut,
    p2pkh_lock,
)

TX_HEX = "01" * 128

TXID = "a" * 64


def _payload(*, txid: str = TXID,
             tx_status: str = ACCEPTED_BY_NETWORK,
             **over: object) -> dict[str, object]:
    """Una respuesta de ARC, con los campos que la API define."""
    data: dict[str, object] = {
        "timestamp": "2023-03-09T12:03:48Z",
        "blockHash": "",
        "blockHeight": 0,
        "txid": txid,
        "merklePath": "",
        "txStatus": tx_status,
        "extraInfo": "",
        "competingTxs": None,
        "status": 200,
        "title": "OK",
    }
    data.update(over)
    return data


async def _start(routes: list) -> tuple[str, TestServer]:
    """Levanta un ARC falso en localhost; devuelve (base_url, servidor)."""
    app = web.Application()
    app.add_routes(routes)
    server = TestServer(app)
    await server.start_server()
    return str(server.make_url("/")), server


def test_submit_posts_raw_hex_as_plain_text():
    async def go():
        seen: dict[str, object] = {}

        async def handler(request: web.Request) -> web.Response:
            seen["method"] = request.method
            seen["path"] = request.path
            seen["content_type"] = request.content_type
            seen["body"] = await request.text()
            seen["authorization"] = request.headers.get("Authorization")
            return web.json_response(_payload())

        base, server = await _start([web.post("/v1/tx", handler)])
        try:
            status = await ArcClient(base).submit(TX_HEX)
        finally:
            await server.close()
        assert seen["method"] == "POST"
        assert seen["path"] == "/v1/tx"
        assert seen["content_type"] == "text/plain"
        assert seen["body"] == TX_HEX
        assert seen["authorization"] is None
        assert status.txid == TXID
        assert status.tx_status == ACCEPTED_BY_NETWORK
        assert status.accepted
        assert not status.terminal
        assert status.competing_txs == ()

    asyncio.run(go())


def test_submit_sends_bearer_and_wait_headers():
    async def go():
        seen: dict[str, str | None] = {}

        async def handler(request: web.Request) -> web.Response:
            seen["authorization"] = request.headers.get("Authorization")
            seen["wait_for"] = request.headers.get("X-WaitFor")
            seen["max_timeout"] = request.headers.get("X-MaxTimeout")
            return web.json_response(_payload())

        base, server = await _start([web.post("/v1/tx", handler)])
        try:
            await ArcClient(base, api_key="token-de-prueba").submit(
                TX_HEX, wait_for=SEEN_ON_NETWORK, max_timeout=12,
            )
        finally:
            await server.close()
        assert seen["authorization"] == "Bearer token-de-prueba"
        assert seen["wait_for"] == SEEN_ON_NETWORK
        assert seen["max_timeout"] == "12"

    asyncio.run(go())


def test_submit_validates_arguments():
    async def go():
        client = ArcClient("http://arc-de-prueba.invalid")
        with pytest.raises(ValueError):
            await client.submit("")
        # MINED no es un estado que el servidor sepa esperar.
        with pytest.raises(ValueError):
            await client.submit(TX_HEX, wait_for="MINED")
        with pytest.raises(ValueError):
            await client.submit(TX_HEX, max_timeout=31)
        with pytest.raises(ValueError):
            await client.status("")

    asyncio.run(go())


def test_submit_maps_problem_details():
    async def go():
        problem = {
            "type": "https://bitcoin-sv.github.io/arc/#/errors?id=_465",
            "title": "Fee too low",
            "status": 465,
            "detail": "The fees are too low",
            "instance": "https://arc.example/errors/1",
            "txid": TXID,
            "extraInfo": "arc error 465",
        }

        async def handler(request: web.Request) -> web.Response:
            return web.json_response(problem, status=465)

        base, server = await _start([web.post("/v1/tx", handler)])
        try:
            with pytest.raises(ArcHttpError) as err:
                await ArcClient(base).submit(TX_HEX)
        finally:
            await server.close()
        assert err.value.http_status == 465
        assert err.value.title == "Fee too low"
        assert err.value.detail == "The fees are too low"
        assert err.value.txid == TXID
        assert err.value.extra_info == "arc error 465"
        assert "465" in str(err.value)

    asyncio.run(go())


def test_submit_maps_non_json_error_body():
    async def go():
        async def handler(request: web.Request) -> web.Response:
            return web.Response(text="gateway exploded", status=502)

        base, server = await _start([web.post("/v1/tx", handler)])
        try:
            with pytest.raises(ArcHttpError) as err:
                await ArcClient(base).submit(TX_HEX)
        finally:
            await server.close()
        assert err.value.http_status == 502
        # Sin JSON, el título es el del motivo HTTP.
        assert err.value.title == "Bad Gateway"

    asyncio.run(go())


def test_status_reads_the_txid_path():
    async def go():
        seen: dict[str, str] = {}

        async def handler(request: web.Request) -> web.Response:
            seen["path"] = request.path
            return web.json_response(
                _payload(competingTxs=[[TXID, "b" * 64]]),
            )

        base, server = await _start([web.get("/v1/tx/{txid}", handler)])
        try:
            status = await ArcClient(base).status(TXID)
        finally:
            await server.close()
        assert seen["path"] == f"/v1/tx/{TXID}"
        assert status.competing_txs == (TXID, "b" * 64)

    asyncio.run(go())


def test_status_not_found_is_an_http_error():
    async def go():
        async def handler(request: web.Request) -> web.Response:
            return web.json_response(
                {
                    "title": "Not found",
                    "status": 404,
                    "detail": "The requested resource could not be found",
                },
                status=404,
            )

        base, server = await _start([web.get("/v1/tx/{txid}", handler)])
        try:
            with pytest.raises(ArcHttpError) as err:
                await ArcClient(base).status(TXID)
        finally:
            await server.close()
        assert err.value.http_status == 404
        assert err.value.title == "Not found"

    asyncio.run(go())


def test_policy_and_health_parse():
    async def go():
        async def policy_handler(request: web.Request) -> web.Response:
            return web.json_response({
                "timestamp": "2019-08-24T14:15:22Z",
                "policy": {
                    "maxscriptsizepolicy": 500000,
                    "maxtxsigopscountspolicy": 4294967295,
                    "maxtxsizepolicy": 10000000,
                    "miningFee": {"satoshis": 1, "bytes": 1000},
                    "standardFormatSupported": True,
                },
            })

        async def health_handler(request: web.Request) -> web.Response:
            return web.json_response({
                "healthy": True, "version": "v1.0.0",
            })

        base, server = await _start([
            web.get("/v1/policy", policy_handler),
            web.get("/v1/health", health_handler),
        ])
        try:
            client = ArcClient(base)
            policy = await client.policy()
            health = await client.health()
        finally:
            await server.close()
        assert policy.max_script_size == 500000
        assert policy.max_tx_sigops_counts == 4294967295
        assert policy.max_tx_size == 10000000
        assert policy.mining_fee_satoshis == 1
        assert policy.mining_fee_bytes == 1000
        assert policy.standard_format_supported
        assert health.healthy
        assert health.version == "v1.0.0"
        assert health.reason == ""

    asyncio.run(go())


def test_broadcast_does_not_poll_when_server_waits():
    async def go():
        gets = {"n": 0}

        async def handler(request: web.Request) -> web.Response:
            if request.method == "GET":
                gets["n"] += 1
            return web.json_response(_payload())

        base, server = await _start([
            web.post("/v1/tx", handler),
            web.get("/v1/tx/{txid}", handler),
        ])
        try:
            # El servidor sostiene la petición hasta el
            # estado aceptado: no hay nada que sondar.
            result = await ArcClient(base).broadcast(TX_HEX)
        finally:
            await server.close()
        assert result.accepted
        assert gets["n"] == 0

    asyncio.run(go())


def test_broadcast_polls_until_the_target():
    async def go():
        gets = {"n": 0}

        async def handler(request: web.Request) -> web.Response:
            if request.method == "POST":
                # El servidor no sostiene: vuelve en STORED.
                return web.json_response(_payload(tx_status=STORED))
            gets["n"] += 1
            return web.json_response(
                _payload(tx_status=ACCEPTED_BY_NETWORK),
            )

        base, server = await _start([
            web.post("/v1/tx", handler),
            web.get("/v1/tx/{txid}", handler),
        ])
        try:
            result = await ArcClient(base).broadcast(
                TX_HEX, poll_interval=0.01,
            )
        finally:
            await server.close()
        assert result.tx_status == ACCEPTED_BY_NETWORK
        assert gets["n"] >= 1

    asyncio.run(go())


@pytest.mark.parametrize("bad", [REJECTED, DOUBLE_SPEND_ATTEMPTED])
def test_broadcast_rejects_terminal_bad_status(bad):
    async def go():
        async def handler(request: web.Request) -> web.Response:
            return web.json_response(
                _payload(tx_status=bad, extraInfo="no"),
            )

        base, server = await _start([web.post("/v1/tx", handler)])
        try:
            with pytest.raises(ArcRejectedError) as err:
                await ArcClient(base).broadcast(TX_HEX)
        finally:
            await server.close()
        assert bad in str(err.value)

    asyncio.run(go())


def test_broadcast_times_out():
    async def go():
        async def handler(request: web.Request) -> web.Response:
            return web.json_response(_payload(tx_status=QUEUED))

        base, server = await _start([
            web.post("/v1/tx", handler),
            web.get("/v1/tx/{txid}", handler),
        ])
        try:
            with pytest.raises(ArcTimeoutError):
                await ArcClient(base).broadcast(
                    TX_HEX, poll_interval=0.01, deadline=0.05,
                )
        finally:
            await server.close()

    asyncio.run(go())


def _unsigned_tx() -> Transaction:
    """Una tx sin firmar: construirla y serializarla no necesita claves."""
    return Transaction(
        inputs=[TxIn("ab" * 32, 0)],
        outputs=[TxOut(1, p2pkh_lock(bytes(20)))],
    )


def test_broadcast_transaction_checks_the_txid():
    async def go():
        async def handler(request: web.Request) -> web.Response:
            # Un ARC de verdad deriva el txid del hex que le dan.
            raw = await request.text()
            txid = Transaction.parse(bytes.fromhex(raw)).txid()
            return web.json_response(_payload(txid=txid))

        base, server = await _start([web.post("/v1/tx", handler)])
        try:
            tx = _unsigned_tx()
            result = await broadcast_transaction(tx, ArcClient(base))
        finally:
            await server.close()
        assert result.txid == tx.txid()
        assert result.accepted

    asyncio.run(go())


def test_broadcast_transaction_fails_on_txid_mismatch():
    async def go():
        async def handler(request: web.Request) -> web.Response:
            return web.json_response(_payload(txid="f" * 64))

        base, server = await _start([web.post("/v1/tx", handler)])
        try:
            with pytest.raises(ArcError) as err:
                await broadcast_transaction(
                    _unsigned_tx(), ArcClient(base),
                )
        finally:
            await server.close()
        assert "txid" in str(err.value)

    asyncio.run(go())
