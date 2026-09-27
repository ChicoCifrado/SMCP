# Changelog

Todas las notas de cambios de SMCP (Shared Mesh Context Protocol) están en
este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es/1.1/) y las
versiones siguen [Versionado Semántico](https://semver.org/lang/es/).

## [0.3.0] — 2026-09-27

### Añadido
- **La malla como intercambio** — `contrib.py` (challenge/capacity report
  firmado con nonce y expiración, `ContributionLedger` con cadena de hashes
  tamper-evident, `ExchangePolicy` que acredita crédito solo por capacidad
  verificada y mientras el nodo está vivo) + `placement.py` (`PlacementPlan`
  que reparte los pesos entre peers y dice si es admisible; SMCP planifica y
  admite, MeshLLM ejecuta). VRAM verificada a cambio de inferencia.
- **`delm fit`** — `llmfit.py` (seam hacia la herramienta externa `llmfit`:
  responde "¿qué modelo puede correr esta caja y a qué velocidad?";
  `LlmfitRunner`, `SystemProfile`/`FitRow`/`FitReport`). Verificado contra
  `llmfit 1.1.16` y expuesto en la web.
- **smcp-serve (ACP)** — `delm/serve.py`: SMCP como agente ACP por stdio
  (stdout = JSON-RPC, config/key en el servidor, sesiones efímeras,
  `authenticate` no-op). Cierra el bucle: mismo `DelmPipeline` que `/api/run`.
- **CLI unificada** — `delm` + `python -m delm` (issue #9).
- **API actions** — scan, taint, config, ledger export, SSE y meshllm.
- **Consola 3D (Three.js) + API server** — web multipágina con fuente OpenCode
  y report PDF; página de estado en vivo que recuerda la última página.
- **Capa 4: demo multi-host sobre QUIC** (default) + modo Nostr; transporte de
  discovery mDNS (swappable con `DiscoveryBus`); rotación/revocación de la
  clave del owner (control-plane).
- **Capa 2: persistencia append-only** del `AdmissionLedger` + replay/auditoría.
- **Capa 1: modo estricto** — fin del fallback HMAC silencioso; dependencias
  principales declaradas + CI.
- **RSI loop (L1)** — auto-modificación vía el pipeline verificado + métrica
  HCI (Headroom-Closed Index) y demo RSI que la mide.

### Cambiado
- La malla ya no es solo in-proceso: se planifica, admite y ejecuta como
  intercambio de VRAM por inferencia.
- El README refleja el estado actual (528 tests, 38 archivos).
- `pyproject` declara extras `delm[web]` y pin `aiozeroconf>=0.1.8`.

### No rompedor
- El contrato `MeshTransport` (`send`/`poll`/`pump`) no cambia: los
  transportes siguen siendo intercambiables detrás de la misma interfaz.
- La capa 5 (seguridad) sigue integrada por defecto; el modo estricto solo
  endurece el trust anchor, no lo rompe.

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

[0.3.0]: https://github.com/ChicoCifrado/SMCP/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/ChicoCifrado/SMCP/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/ChicoCifrado/SMCP/compare/0.0.0...0.1.0
