"""Tests de la **guardia de relay Nostr** (issue #6).

El :class:`~delm.core.nostr.NostrRelayServer` (el relay de red) tiene una
guardia:

* **Rate-limit por ``pubkey``**: umbral de eventos/segundo por identidad
  (los excedentes se rechazan).
* **Dedup**: ventana de ids de eventos ya vistos (los reenvíos del mismo
  ``id`` se rechazan).
* **Límite de tamaño**: los ``raw`` de más de ``max_event_bytes`` se
  rechazan.
* **Persistencia opcional** (opt-in): snapshot/restore del estado del relay
  (eventos aceptados + estado de rate-limit + ids vistos).

El rate-limit y el dedup son la lógica de :meth:`_guard_why`; se prueban
**directamente** (unit, determinista — sin red, todos en la misma ventana).
El límite de tamaño y el snapshot/restore se prueban de punta a punta (vía
:class:`NostrRelayClient` + :class:`NostrRelayServer`).
"""
from __future__ import annotations

import os
import tempfile

from delm.core.nostr import NostrEvent, NostrKey, NostrRelayClient, NostrRelayServer


# -- Helpers ---------------------------------------------------------------
def _make_key() -> NostrKey:
    """Una clave de Nostr (x-only, BIP340)."""
    return NostrKey.new()


def _make_event(key: NostrKey, content: str) -> NostrEvent:
    """Un evento Nostr firmado (``kind=10000``)."""
    return NostrEvent.signed(key, 0, 10000, [["d", "n1"]], content)


def _make_client(server_port: int) -> NostrRelayClient:
    """Un cliente de red conectado al servidor."""
    c = NostrRelayClient(f"ws://127.0.0.1:{server_port}")
    c.connect()
    return c


# -- Rate-limit por pubkey (unit, determinista) ---------------------------
def test_rate_limit_rejects_excess():
    """Ráfaga sobre el umbral: los excedentes se rechazan.

    Con ``rate_limit=3`` (eventos/seg por ``pubkey``), 5 eventos de la misma
    identidad: los primeros 3 se aceptan (``_guard_why`` devuelve ``None``),
    los excedentes se rechazan (devuelve ``"rate-limit"``). Se prueba
    **directamente** (sin red): todos caen en la misma ventana, así el
    resultado es determinista.
    """
    server = NostrRelayServer(rate_limit=3)
    key = _make_key()
    # 5 eventos de la misma pubkey (mismos ids distintos -> no es dedup).
    results = [server._guard_why(_make_event(key, f"rate-{i}")) for i in range(5)]
    accepted = sum(1 for r in results if r is None)
    rejected = sum(1 for r in results if r == "rate-limit")
    # Los primeros 3 se aceptan; los excedentes (2) se rechazan.
    assert accepted == 3, f"accepted={accepted} (esperado 3)"
    assert rejected == 2, f"rejected={rejected} (esperado 2)"
    # El rechace es por rate-limit (no por dedup ni firma).
    assert all(r in (None, "rate-limit") for r in results), (
        f"rechaces inesperados: {results}"
    )


# -- Dedup (unit, determinista) --------------------------------------------
def test_dedup_rejects_rebroadcast():
    """Reenvío del mismo ``id``: se dedup (un solo broadcast).

    Un evento ya visto (en ``_seen``) se rechaza (``"duplicado"``). Se
    prueba **directamente**: se simula que el evento fue aceptado (añadiéndolo
    a ``_seen``) y se comprueba que su reenvío se rechaza.
    """
    server = NostrRelayServer()
    key = _make_key()
    ev = _make_event(key, "dedup-test")
    # El evento fue aceptado antes: está en ``_seen``.
    server._seen[ev.event_id().hex()] = None
    # El reenvío (mismo id) se rechaza (dedup).
    assert server._guard_why(ev) == "duplicado"


# -- Límite de tamaño de evento (punta a punta) ---------------------------
def test_max_event_bytes_rejects_oversized():
    """Evento sobre ``max_event_bytes``: se rechaza.

    Con ``max_event_bytes=64`` (pequeño), un evento con ``content`` largo (el
    ``raw`` supera el límite) se rechaza (mismo path de ``rejected``). Se
    prueba de punta a punta (vía red).
    """
    server = NostrRelayServer(max_event_bytes=64)
    server.start()
    try:
        client = _make_client(server.port)
        try:
            key = _make_key()
            ev = _make_event(key, "x" * 200)  # el raw supera 64 bytes
            # El relay lo rechaza (demasiado grande).
            assert client.publish(ev) is False, (
                "el evento sobre max_event_bytes no se rechazó"
            )
        finally:
            client.close()
    finally:
        server.stop()


# -- Snapshot/restore (persistencia opcional) ------------------------------
def test_snapshot_restore_rebroadcasts_same():
    """Snapshot/restore: el estado reconstruido re-broadcasta igual.

    Un relay con ``state_path`` guarda su estado (eventos aceptados + ids
    vistos + estado de rate-limit) al aceptar. Un relay restaurado
    (``load_state``) reconstruye el estado y re-broadcasta igual que el
    original (los mismos eventos aceptados).
    """
    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "relay_state.json")
        # Relay original: acepta eventos y guarda su estado.
        server = NostrRelayServer(state_path=state_path)
        server.start()
        try:
            client = _make_client(server.port)
            try:
                key = _make_key()
                for i in range(3):
                    ev = _make_event(key, f"snap-{i}")
                    assert client.publish(ev) is True, (
                        f"el publish {i} no se aceptó"
                    )
                # El estado se guardó (state_path existe).
                assert os.path.exists(state_path), (
                    "el state_path no se creó"
                )
            finally:
                client.close()
        finally:
            server.stop()
        # Relay restaurado: carga el estado y re-broadcasta igual.
        restored = NostrRelayServer()
        restored.start()
        try:
            restored.load_state(state_path)
            # El estado restaurado tiene los mismos eventos aceptados.
            with restored._state_lock:
                restored_events = [ev.content for ev in restored._accepted]
            assert restored_events == ["snap-0", "snap-1", "snap-2"], (
                f"el estado restaurado no coincide: {restored_events}"
            )
            # Los ids vistos también se restauraron (dedup reconstruido).
            with restored._state_lock:
                seen_count = len(restored._seen)
            assert seen_count >= 3, (
                f"los ids vistos no se restauraron: {seen_count}"
            )
        finally:
            restored.stop()


# -- El default no cambia (efímero, sin state_path) ------------------------
def test_default_is_ephemeral():
    """El default (sin ``state_path``) es efímero: no guarda estado.

    Un relay por defecto no crea ``state_path`` (el default sigue efímero,
    como antes). El comportamiento de ``publish`` no cambia.
    """
    server = NostrRelayServer()
    server.start()
    try:
        client = _make_client(server.port)
        try:
            key = _make_key()
            ev = _make_event(key, "ephemeral")
            # El default acepta (el rate-limit default es 100).
            assert client.publish(ev) is True, (
                "el default no aceptó"
            )
            # No hay state_path (efímero).
            assert server._state_path is None, (
                "el default no debería tener state_path"
            )
        finally:
            client.close()
    finally:
        server.stop()


if __name__ == "__main__":  # pragma: no cover
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
