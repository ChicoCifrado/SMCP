# Changelog

Todas las notas de cambios de SMCP (Shared Mesh Context Protocol) están en
este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es/1.1/) y las
versiones siguen [Versionado Semántico](https://semver.org/lang/es/).

## [0.2.0] — 2026-09-09

### Añadido
- **Capa 3 sobre red (Nostr)** — `NostrTransport` (adaptador BIP340 al
  contrato `MeshTransport`) + `NostrSwarm` (orquestador, equivalente a
  `QuicSwarm`): la malla (gossip/requirements/heartbeat) corre sobre red
  vía Nostr. `MeshNetwork`/`MeshPipeline` lo activan con `nostr=True`.
- **Capa 4 (despliegue)** — discovery/relays/bootstrap/control-plane:
  `NostrDiscoveryTransport` (un transporte por nodo, cada uno con su
  `NostrRelayClient`), relay de red Nostr (WebSocket), bootstrap multi-proceso.
- **Transporte QUIC entre hosts** — `QuicHostNode` (un nodo sobre QUIC real,
  event loop asyncio en un hilo, M conexiones: por par, cliente `connect()` o
  servidor `serve()` en un puerto dedicado) + `QuicHostSwarm` (asigna 1 puerto
  por par; el par mayor es servidor y escucha, el menor se conecta) +
  `QuicHostTransport` (mismo contrato `send`/`poll` que `QuicSwarm`). El
  transporte corre sobre sockets UDP reales (no loopback).
- **Demo multi-host** — `run_multihost_demo.py`: 1 relay + 2 nodos en procesos
  distintos, gossip/heartbeat por Nostr, convergencia al mismo conjunto de
  gists. La demo de punta a punta del despliegue multi-host.
- **Capa 4: transporte Nostr real** — BIP340 verificado contra los 19 vectores
  oficiales + eventos + relay + `NostrDiscoveryTransport`.

### Cambiado
- La malla (capa 3) ya no corre solo in-proceso: corre sobre red (Nostr/QUIC).
- El README refleja el estado "sobre red" (180 tests, 4 demos).

### No rompedor
- El contrato `MeshTransport` (`send`/`poll`/`pump`) no cambia:
  `InMemoryTransport`/`QuicTransport`/`NostrTransport`/`QuicHostTransport`
  son intercambiables detrás de la misma interfaz.
- La capa 5 (seguridad) sigue integrada por defecto.

## [0.1.0] — 2026-09-08

### Añadido
- **Núcleo DeLM (clean-room)** — `SharedContext` (gist/author/admit),
  `TaskQueue` (dependencias), `Pipeline` (despliegue selectivo), `Unfolding`
  (expansión).
- **Capa 1 (identidad)** — `KeyPair` (BIP340, x-only), firma/verificación.
- **Capa 2 (integridad)** — `SecureSharedContext` (admisión verificada,
  inmutabilidad, ledger).
- **Capa 5 (seguridad)** — `Taint` (prompt-injection), `Injection`
  (detección), `Ledger` (audit).
- **Licencia** — GPL-3.0-only (copyleft).
- **Suite** — 18 tests (núcleo + seguridad + taint).

[0.2.0]: https://github.com/ChicoCifrado/SMCP/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/ChicoCifrado/SMCP/compare/0.0.0...0.1.0
