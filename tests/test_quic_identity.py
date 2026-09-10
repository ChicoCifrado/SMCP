"""Tests del **enlace identidad-cert** del transporte QUIC (issue #5).

El cert de cada :class:`~delm.core.quic_host.QuicHostNode` tiene
``CN = peer_id`` (la identidad del nodo): el **enlace identidad-cert**
(issue #5). El cliente, tras el handshake, verifica que el ``CN`` del
cert del par (el servidor) coincida con el ``peer_id`` del par. Si no
coincide, el par no es quien dice ser (un **MITM** con un cert propio) y
la conexión no se usa (el datagrama no fluye).

Estos tests (con la malla real :class:`QuicHostSwarm`, 2 nodos ``"A" <
"B"`` — ``"A"`` es cliente, ``"B"`` es servidor) verifican:

* **Legítimo**: ``"A"`` envía a ``"B"`` y ``"B"`` lo recibe (el enlace
  verifica).
* **MITM**: ``"B"`` presenta un cert con ``CN != "B"`` (un cert propio);
  ``"A"`` rechaza el enlace y ``"B"`` no recibe (el MITM es detectado).
* **insecure** (fallback): con ``insecure=True``, el enlace no se
  verifica (el MITM converge).
* **CN = peer_id**: el cert del nodo tiene ``CN = peer_id`` (la
  identidad enlazada).
"""
from __future__ import annotations

import time

import pytest

from delm.core.quic_host import QuicHostSwarm


def _send_and_wait(swarm, sender: str, receiver: str, timeout=20.0):
    """``sender`` envía a ``receiver``; espera a que ``receiver`` lo reciba.

    Devuelve ``True`` si ``receiver`` recibe el datagrama (el enlace
    funciona), ``False`` si no (el enlace está roto, p. ej. un MITM).
    """
    swarm.transport_for(sender).send(receiver, b"probe")
    deadline = time.time() + timeout
    while time.time() < deadline:
        msgs = swarm.transport_for(receiver).poll()
        if msgs:
            return True
        time.sleep(0.1)
    return False


# -- Legítimo: el enlace verifica (A envía a B, B recibe) ------------------
def test_legit_link_verifies():
    """Malla legítima: ``"A"`` (cliente) envía a ``"B"`` (servidor); ``"B"``
    lo recibe (el enlace identidad-cert verifica)."""
    swarm = QuicHostSwarm()
    swarm.add_peer("A")
    swarm.add_peer("B")
    swarm.start()
    try:
        assert _send_and_wait(swarm, "A", "B", timeout=25), (
            "el enlace no verificó (B no recibió de A)"
        )
    finally:
        swarm.close()


# -- MITM: el nodo con un cert propio es rechazado ------------------------
def test_mitm_rejected():
    """``"B"`` presenta un cert con ``CN = "evil"`` (distinto de su
    ``peer_id = "B"``): un **MITM**. ``"A"`` (cliente) verifica el ``CN``
    del cert de ``"B"``, no coincide con ``"B"`` y rechaza el enlace.
    ``"B"`` no recibe (el MITM es detectado)."""
    swarm = QuicHostSwarm()
    swarm.add_peer("A")
    swarm.add_peer("B")
    # Simula un MITM: "B" presenta un cert con CN = "evil" (no "B").
    swarm.set_cert_cn("B", "evil")
    swarm.start()
    try:
        # "A" envía a "B"; si el MITM no fuera detectado, "B" recibiría.
        got = _send_and_wait(swarm, "A", "B", timeout=12)
        assert not got, (
            "el MITM no fue detectado (B recibió de A a pesar del CN "
            "distinto)"
        )
    finally:
        swarm.close()


# -- insecure (fallback): el enlace no se verifica ------------------------
def test_insecure_fallback_no_verify():
    """Con ``insecure=True`` (fallback), el enlace no se verifica: el MITM
    (``"B"`` con ``CN = "evil"``) converge (``"B"`` recibe de ``"A"``)."""
    swarm = QuicHostSwarm(insecure=True)
    swarm.add_peer("A")
    swarm.add_peer("B")
    swarm.set_cert_cn("B", "evil")
    swarm.start()
    try:
        assert _send_and_wait(swarm, "A", "B", timeout=25), (
            "el fallback insecure no debería rechazar el enlace"
        )
    finally:
        swarm.close()


# -- CN = peer_id: la identidad enlazada -----------------------------------
def test_cert_cn_is_peer_id():
    """El cert del nodo tiene ``CN = peer_id`` (la identidad enlazada,
    issue #5): el ``CN`` es la identidad que firma gists/anuncios."""
    from cryptography.x509.oid import NameOID

    swarm = QuicHostSwarm()
    swarm.add_peer("A")
    try:
        node = swarm._nodes["A"]
        cns = node._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cns, "el cert no tiene un CN"
        assert cns[0].value == "A", (
            f"el CN del cert no es el peer_id (es {cns[0].value!r})"
        )
    finally:
        swarm.close()


if __name__ == "__main__":  # pragma: no cover
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
