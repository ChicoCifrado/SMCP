"""Tests de BIP340 (Schnorr secp256k1, x-only) — verificación contra vectores oficiales.

El esquema de firma de Nostr es **BIP340**. ``delm.core.nostr`` lo implementa
fiel a la referencia oficial (``bitcoin/bips`` ``bip-0340/reference.py``) y se
**verifica contra los vectores oficiales** (``bip-0340/test-vectors.csv``), que
viven en ``tests/data/bip340_vectors.csv``.

Estos tests son la *prueba de honestidad*: si la implementación se desvía de
la referencia (un bug en la aritmética de punto, en ``lift_x``, en el
``tagged_hash`` o en la firma), alguno de los 19 vectores falla.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path

import pytest

from delm.core.nostr import (
    pubkey_gen,
    schnorr_sign,
    schnorr_verify,
)

_VECTORS_CSV = Path(__file__).parent / "data" / "bip340_vectors.csv"


def _rows() -> list[list[str]]:
    """Carga los 19 vectores oficiales (índices 0-18)."""
    assert _VECTORS_CSV.exists(), f"faltan los vectores: {_VECTORS_CSV}"
    with open(_VECTORS_CSV, newline="") as f:
        reader = csv.reader(f)
        next(reader)  # header
        return [row for row in reader if row]


# -- Verificación contra todos los vectores ------------------------------------
def test_all_vectors_verify():
    """``schnorr_verify`` reproduce el ``verification result`` de cada vector.

    Los 19 vectores cubren: firmas válidas (TRUE) y casos que deben rechazar
    (FALSE) — clave no en la curva, ``has_even_y(R)`` falso, mensaje negado,
    ``s`` negado, ``sG - eP`` infinito, ``sig[0:32]`` no en la curva, ``sig``
    fuera de rango, pubkey fuera de rango, mensaje de tamaño 0/1/17/100.
    """
    rows = _rows()
    assert len(rows) == 19, f"se esperaban 19 vectores, hay {len(rows)}"
    for (idx, _seckey, pubkey_hex, _aux, msg_hex, sig_hex, result, _comment) in rows:
        msg = bytes.fromhex(msg_hex)
        sig = bytes.fromhex(sig_hex)
        expected = result == "TRUE"
        got = schnorr_verify(msg, bytes.fromhex(pubkey_hex), sig)
        assert got == expected, (
            f"vector {idx}: schnorr_verify={got}, esperado {expected} "
            f"({_comment})"
        )


# -- Generación de pubkey contra los vectores ---------------------------------
def test_all_vectors_pubkey_gen():
    """``pubkey_gen`` reproduce la ``public key`` de cada vector con seckey.

    Solo los vectores con ``secret key`` (0-3 y 15-18) tienen seckey; los de
    solo verificación (4-14) no.
    """
    rows = _rows()
    checked = 0
    for (idx, seckey_hex, pubkey_hex, _aux, _msg, _sig, _result, _comment) in rows:
        if not seckey_hex:
            continue
        got = pubkey_gen(bytes.fromhex(seckey_hex))
        expected = bytes.fromhex(pubkey_hex)
        assert got == expected, f"vector {idx}: pubkey_gen no coincide"
        checked += 1
    # 8 vectores con seckey (0,1,2,3 y 15,16,17,18).
    assert checked == 8, f"se verificaban 8 pubkey_gen, hay {checked}"


# -- Firma determinista contra los vectores -----------------------------------
def test_all_vectors_sign():
    """``schnorr_sign`` reproduce la ``signature`` exacta de cada vector.

    BIP340 es *determinista* (el nonce es una función de la clave, el mensaje
    y el ``aux_rand``), así que la firma debe ser *byte a byte* la del vector.
    Esto es el chequeo más fuerte: si la firma no coincide, la aritmética o
    el ``tagged_hash`` están mal.
    """
    rows = _rows()
    checked = 0
    for (idx, seckey_hex, _pub, aux_hex, msg_hex, sig_hex, _result, _comment) in rows:
        if not seckey_hex:
            continue
        sig = schnorr_sign(
            bytes.fromhex(msg_hex),
            bytes.fromhex(seckey_hex),
            bytes.fromhex(aux_hex),
        )
        expected = bytes.fromhex(sig_hex)
        assert sig == expected, (
            f"vector {idx}: schnorr_sign no coincide "
            f"({_comment})"
        )
        checked += 1
    assert checked == 8


# -- Round-trip (firma -> verificación) ---------------------------------------
def test_sign_verify_roundtrip():
    """Una firma BIP340 verifica contra su pubkey (y el mensaje original)."""
    seckey = bytes.fromhex(
        "0340034003400340034003400340034003400340034003400340034003400340"
    )
    aux = bytes.fromhex("00" * 32)
    msg = b"delm nostr round-trip"
    sig = schnorr_sign(msg, seckey, aux)
    pubkey = pubkey_gen(seckey)
    assert len(sig) == 64
    assert len(pubkey) == 32
    assert schnorr_verify(msg, pubkey, sig)


def test_verify_rejects_wrong_message():
    """La misma firma + pubkey *no* verifica con un mensaje distinto."""
    seckey = bytes.fromhex(
        "0340034003400340034003400340034003400340034003400340034003400340"
    )
    sig = schnorr_sign(b"uno", seckey, bytes.fromhex("00" * 32))
    pubkey = pubkey_gen(seckey)
    assert not schnorr_verify(b"dos", pubkey, sig)


def test_verify_rejects_wrong_key():
    """La firma *no* verifica contra un pubkey distinto."""
    seckey_a = bytes.fromhex(
        "0340034003400340034003400340034003400340034003400340034003400340"
    )
    seckey_b = bytes.fromhex(
        "0340034003400340034003400340034003400340034003400340034003400341"
    )
    sig = schnorr_sign(b"msg", seckey_a, bytes.fromhex("00" * 32))
    pubkey_b = pubkey_gen(seckey_b)
    assert not schnorr_verify(b"msg", pubkey_b, sig)


# -- Guardas de rango / longitud --------------------------------------------
def test_verify_rejects_short_pubkey():
    assert not schnorr_verify(b"m", b"short", b"x" * 64)


def test_verify_rejects_short_sig():
    assert not schnorr_verify(b"m", b"0" * 32, b"x" * 60)


def test_sign_rejects_short_aux_rand():
    with pytest.raises(ValueError):
        schnorr_sign(b"m", bytes.fromhex("03" * 32), b"short")


def test_sign_rejects_zero_seckey():
    with pytest.raises(ValueError):
        schnorr_sign(b"m", b"\x00" * 32, b"\x00" * 32)


def test_pubkey_gen_rejects_zero_seckey():
    with pytest.raises(ValueError):
        pubkey_gen(b"\x00" * 32)


# -- Relay de red (NostrRelayServer / NostrRelayClient) ----------------------
# El relay de red es la pieza que cierra el objetivo: un relay Nostr real
# (WebSocket) swappable con :class:`NostrRelay` (in-memory). Estos tests
# verifican el round-trip: el servidor expone el puerto, el cliente conecta,
# publica, y el relay verifica la firma BIP340 y emite a los demás
# (excluyendo al remitente). Mismo espíritu que
# ``test_mesh.py::test_mesh_pipeline_runs_over_quic``: funciones normales
# (no ``async def``), con polling para el async.


@pytest.fixture
def relay_server():
    """Un :class:`NostrRelayServer` corriendo (expone el puerto)."""
    from delm.core.nostr import NostrRelayServer
    server = NostrRelayServer()
    server.start()
    yield server
    server.stop()


def _make_client(uri: str):
    from delm.core.nostr import NostrRelayClient
    c = NostrRelayClient(uri)
    c.connect()
    return c


def _wait_receive(client, timeout: float = 5.0, interval: float = 0.05) -> list:
    """Espera a que ``client`` reciba eventos (drain y devuelve)."""
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        evs = client.events()
        if evs:
            return evs
        time.sleep(interval)
    return []


def test_relay_server_exposes_port(relay_server):
    """El servidor expone el puerto tras ``start()``."""
    assert relay_server.port > 0


def test_relay_client_receives_excluding_sender(relay_server):
    """El relay emite a los demás, **excluyendo al remitente**.

    ``c1`` publica; ``c2`` lo recibe; ``c1`` **no** lo recibe (el relay no
    emite de vuelta al que envía).
    """
    from delm.core.nostr import NostrEvent, NostrKey
    key = NostrKey.new()
    c1 = _make_client(f"ws://127.0.0.1:{relay_server.port}")
    c2 = _make_client(f"ws://127.0.0.1:{relay_server.port}")
    try:
        ev = NostrEvent.signed(key, 0, 10000, [["d", "n1"]], "hello")
        assert c1.publish(ev) is True  # el relay verificó la firma y aceptó
        # c2 lo recibe (el relay lo emitió).
        got = _wait_receive(c2)
        assert len(got) == 1
        assert got[0].content == "hello"
        # c1 NO lo recibe (el relay excluye al remitente).
        assert c1.events() == []
    finally:
        c1.close()
        c2.close()


def test_relay_rejects_bad_signature(relay_server):
    """Una firma **inválida** se rechaza (``publish`` devuelve False).

    Un evento cuya firma no verifica contra su ``pubkey`` es rechazado por
    el relay (la verificación la hace el relay, la autoridad). El rechazo se
    guarda en ``dropped()`` (mismo contrato que el relay in-memory).
    """
    from delm.core.nostr import NostrEvent, NostrKey
    key = NostrKey.new()
    c1 = _make_client(f"ws://127.0.0.1:{relay_server.port}")
    try:
        bad = NostrEvent(
            pubkey=key.pubkey,
            created_at=0,
            kind=10000,
            tags=[["d", "n1"]],
            content="bad-sig",
            sig=bytes(range(64)),  # firma no verificable
        )
        assert c1.publish(bad) is False  # el relay la rechazó
        dropped = c1.dropped()
        assert len(dropped) == 1
        assert dropped[0].content == "bad-sig"
    finally:
        c1.close()


def test_relay_client_same_contract_as_inmemory(relay_server):
    """:class:`NostrRelayClient` expone el **mismo contrato** que
    :class:`NostrRelay` (in-memory): ``publish`` / ``events`` / ``dropped``.
    """
    from delm.core.nostr import NostrEvent, NostrKey
    key = NostrKey.new()
    c1 = _make_client(f"ws://127.0.0.1:{relay_server.port}")
    try:
        for name in ("publish", "events", "dropped"):
            assert hasattr(c1, name)
        ev = NostrEvent.signed(key, 0, 10000, [["d", "n1"]], "c")
        assert isinstance(c1.publish(ev), bool)
        assert isinstance(c1.events(), list)
        assert isinstance(c1.dropped(), list)
    finally:
        c1.close()


# -- Malla sobre Nostr (NostrTransport) --------------------------------------
# ``NostrTransport`` lleva la malla (capa 3) **a red**: implementa
# ``MeshTransport`` (``send``/``poll``/``close``) sobre un
# :class:`NostrRelayClient`. El relay emite a los demás (**excluye al
# remitente**), así el transporte es *best-effort broadcast*: ``t1.send``
# llega a ``t2`` (y a los demás, si los hay). Mismo espíritu que los tests
# del relay: funciones normales + polling para el async.


def _make_transport(relay_server):
    """Crea un :class:`NostrTransport` conectado al relay (devuelve (t, c))."""
    from delm.core.nostr import NostrRelayClient, NostrKey, NostrTransport
    key = NostrKey.new()
    client = NostrRelayClient(f"ws://127.0.0.1:{relay_server.port}")
    client.connect()
    return NostrTransport(client, key), client


def _wait_poll(transport, timeout: float = 5.0, interval: float = 0.05) -> list:
    """Espera a que el transporte tenga datagramas (poll y devuelve)."""
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        got = transport.poll()
        if got:
            return got
        time.sleep(interval)
    return []


def test_nostr_transport_peer_id_is_pubkey(relay_server):
    """El ``peer_id`` de un :class:`NostrTransport` es su ``pubkey`` x-only."""
    t, c = _make_transport(relay_server)
    try:
        # El peer_id es el pubkey (hex de 64) y coincide con la key.
        assert len(t.peer_id) == 64
        assert t.peer_id == t.key.pubkey.hex()
    finally:
        c.close()


def test_nostr_transport_roundtrip(relay_server):
    """``t1.send`` llega a ``t2`` (el relay emite a los demás).

    ``t1.send(to, payload)`` firma un ``NostrEvent`` y lo publica; el relay
    lo emite a ``t2`` (y a los demás, si los hay). ``t2.poll()`` devuelve
    ``[(from_id, payload), ...]`` con el ``from_id`` del remitente.
    """
    t1, c1 = _make_transport(relay_server)
    t2, c2 = _make_transport(relay_server)
    try:
        t1.send(t2.peer_id, b"hola malla")
        got = _wait_poll(t2)
        assert len(got) == 1
        from_id, payload = got[0]
        assert payload == b"hola malla"
        # El from_id es el pubkey del remitente (t1).
        assert from_id == t1.key.pubkey.hex()
        # t1 NO lo recibe (el relay excluye al remitente).
        assert t1.poll() == []
    finally:
        c1.close()
        c2.close()


def test_nostr_transport_is_mesh_transport(relay_server):
    """:class:`NostrTransport` implementa ``MeshTransport`` (swappable).

    Es swappable con :class:`InMemoryTransport` / :class:`QuicTransport`:
    mismo contrato (``send``/``poll``/``close``), así un ``MeshNode`` lo usa
    sin cambiar.
    """
    from delm.core.transport import MeshTransport
    t, c = _make_transport(relay_server)
    try:
        assert isinstance(t, MeshTransport)
        for name in ("send", "poll", "close"):
            assert hasattr(t, name)
    finally:
        c.close()
