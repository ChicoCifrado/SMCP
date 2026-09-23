# OpenDesign × SMCP — Compatibilidad

**Resumen ejecutivo:** No son drop-in (runtimes distintos: Node ~24/pnpm vs Python 3.11+/FastAPI), pero **sí son compatibles por protocolo**. OpenDesign *delega* el loop completo del agente al CLI (no lo reimplementa) y añade agentes como un **cambio de un archivo** (`RuntimeAgentDef`). SMCP ya expone un FastAPI rico y un cliente OpenAI-compatible. La vía canónica es **A (adaptador ACP)**: SMCP expone un CLI `smcp-serve` que habla ACP por stdio y OpenDesign lo consume como cualquier otro agente. La vía B (provider OpenAI-compatible) es la más rápida de prototipar.

---

## 1. Hechos de compatibilidad

- **OpenDesign** — Apache-2.0, monorepo Node ~24 + pnpm. Desktop local-first (Electron + daemon + web). No comparte runtime con SMCP.
- **SMCP (DeLM)** — Python 3.11+, FastAPI. Servidor `smcp_api.py` (FastAPI, `/api/*`) + `api_server.py` (vanilla, :8099). Cliente `OpenAICompatibleClient` que consume LLMs vía OpenAI-compatible.
- **Lenguaje de integración:** ACP (Agent Client Protocol) + OpenAI-compatible. Son los dos protocolos que OpenDesign ya habla.

## 2. Cómo añade OpenDesign un agente (el anclaje)

- **Tesis:** "hablar con el agente, no reimplementarlo." OpenDesign detecta el CLI, le pasa *skill + prompt + working dir* y hace *stream* de su salida a la web UI.
- **Un agente = un `RuntimeAgentDef`** (data spec, no clase). Añadir uno es **un archivo** en `apps/daemon/src/runtimes/defs/<cli>.ts` + registro en `registry.ts`. Sin engine edits, sin clase, sin `run()`.
- **`streamFormat` soportados:** `acp-json-rpc`, `claude-stream-json`, `copilot-stream-json`, `dsh-profile-jsonl`, `json-event-stream`, `pi-rpc`, `plain`, `qoder-stream-json`.
- **Precedente real:** `hermes.ts` ya existe. Conecta vía **ACP** (`hermes acp --accept-hooks` para enumerar modelos). Es el patrón a clonar para SMCP.
- **BYOK:** OpenDesign acepta *cualquier* endpoint OpenAI-compatible como provider de modelo (BYOK).

## 3. Qué expone SMCP hoy

- **FastAPI (`smcp_api.py`):** `/api/config`, `/api/health`, `/api/runs` (create/get/state/outcome/cancel), `/api/context`, `/api/ledger`, `/api/metrics`, `/api/unfold`, `/api/verifier/check`, `/api/demo/{name}`, `/api/scan`, `/api/taint`, `/api/ledger/export`, `/api/runs/{id}/events`, `/api/meshllm`.
- **Cliente OpenAI-compatible:** `OpenAICompatibleClient` consume LLMs (es el mismo que hizo el wiring P2 contra `127.0.0.1:8888/v1`).
- **Web propio:** `web/` (7 páginas) + `web/assets/api.js` (el cliente JS).
- **Falta:** un **CLI que hable ACP** por stdio. Es la pieza que SMCP no expone hoy y que la vía A requiere.

## 4. Vías de integración (ordenadas por ajuste)

- **A — Adaptador ACP (canónica, el ajuste limpio).**
  - SMCP expone un CLI `smcp-serve` que habla **ACP por stdio** (el loop de agente: model calls, tools, context, permissions, resume, cancel).
  - OpenDesign añade `apps/daemon/src/runtimes/defs/smcp.ts` (`bin: 'smcp-serve'`, `streamFormat: 'acp-json-rpc'`) + lo registra en `registry.ts`.
  - **Cambio en SMCP:** envolver el loop existente (FastAPI ya lo tiene; falta el bind ACP/stdio). **Cambio en OpenDesign:** 1 archivo + registro.
  - **Por qué es la canónica:** encaja con la tesis de OpenDesign y con el precedente `hermes.ts`. SMCP deja de ser "un endpoint" y pasa a ser "un agente" para OpenDesign.

- **B — Provider OpenAI-compatible (la más rápida de prototipar).**
  - SMCP expone `/v1/chat/completions` (OpenAI-compatible) que internamente orquesta su loop (shared context, admission, selective unfolding).
  - OpenDesign lo consume vía **BYOK** como provider de modelo.
  - **Cambio en SMCP:** 1 endpoint fino sobre el loop. **Cambio en OpenDesign:** 0 (BYOK ya existe).
  - **Límite:** OpenDesign ve a SMCP como *un modelo*, no como *un agente*. No expone tools/permisos/resume. Menos ajuste que A, más velocidad.

- **C — Skill/MCP ligero (la menos canónica).**
  - OpenDesign consume el FastAPI de SMCP como una **skill/MCP** (una herramienta más, no un agente).
  - **Límite:** SMCP queda relegado a "una herramienta". No es el modelo de integración que OpenDesign prioriza (agente, no endpoint). Útil como puente temporal hasta A.

## 5. Riesgos / bloqueantes

- **A (ACP):** SMCP debe implementar el **bind ACP/stdio** sobre su loop. Es el único cambio no-trivial; todo el resto ya existe en FastAPI.
- **B (BYOK):** el endpoint `/v1/chat/completions` debe **serializar el loop** (admission + unfolding) en una sola llamada. La latencia del thinking (17 tok/s en el 27B local) puede hacer el stream lento; usar un modelo pequeño para el provider.
- **Licencia:** OpenDesign **Apache-2.0** × SMCP **GPL-3.0** — compatibles en el sentido de que ambos son OSI y permiten enlazar; no hay conflicto, pero el artefacto de integración (el `smcp.ts` o el CLI `smcp-serve`) debe declarar la licencia resultante si se publica.
- **Runtime:** Node ~24 (OpenDesign) × Python 3.11+ (SMCP) — **no comparten proceso**. La integración es por **protocolo (stdio/HTTP)**, no por import. Nunca asumir un shared runtime.

## 6. Veredicto

- **Compatibles por protocolo, no drop-in.** Mismo plano de integración que OpenDesign ya usa con Hermes (ACP) y con cualquier endpoint OpenAI-compatible (BYOK).
- **A es la recomendada:** el ajuste limpio, el precedente existe (`hermes.ts`), y SMCP ya tiene el 90% del loop en FastAPI — solo falta el bind ACP/stdio.
- **B es el prototipo:** 1 endpoint, 0 cambios en OpenDesign, resultado en una tarde. Útil para validar el flujo antes de invertir en A.
- **C es el puente:** solo si A/B no dan tiempo; relega a SMCP a "herramienta".

## 7. Próximos pasos (concretos)

- **B primero (validar):** exponer `/v1/chat/completions` en `smcp_api.py` sobre el loop; apuntar OpenDesign BYOK a `127.0.0.1:8099/v1`. Verificar que el stream llega a la web UI.
- **Luego A (consolidar):** implementar `smcp-serve` (CLI, ACP/stdio) reutilizando el loop de `smcp_api.py`; añadir `smcp.ts` en `apps/daemon/src/runtimes/defs/` + registro en `registry.ts`.
- **Paridad con Hermes:** clonar la forma de `hermes.ts` (mismo `streamFormat`, misma detección de modelos) para que SMCP sea indistinguible de un agente más del catálogo.

## 8. Referencias

- **OpenDesign** — `https://github.com/nexu-io/open-design` (Apache-2.0). Clonado en `~/.hermes/cache/scratch/open-design`.
- **Adapter contract** — `open-design/apps/daemon/src/runtimes/types.ts` (`RuntimeAgentDef`); `defs/hermes.ts` (precedente ACP); `registry.ts` (registro).
- **SMCP** — `/mnt/d/Hermes/DeLM/delm` (GPL-3.0). `smcp_api.py` (FastAPI, `/api/*`), `api_server.py` (:8099), `delm/core/llm.py` (`OpenAICompatibleClient`).
- **P2 (wiring verificado)** — `tests/test_meshllm_wiring.py` (el contrato SMCP→OpenAI-compatible ya probado contra `127.0.0.1:8888`).
