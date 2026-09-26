# Arquitectura de SMCP — por capa

Documento canónico de **cómo está construido** el paquete: qué piezas tiene
cada capa, qué interfaces las atraviesan y cómo fluye un dato de punta a punta.
El README es el "qué es"; este es el "cómo está montado".

- **Alcance**: el paquete `delm/` (la librería), su CLI, la web/API y las demos.
- **Fuera de alcance**: la re-derivación del paper. Las piezas del núcleo DeLM
  (contexto compartido, cola, admisión, unfolding) están en
  `delm/core/{shared_context,task_queue,admission,unfolding,verifier}.py` y son
  las que el paper describe; las capas 1–5 son la capa de seguridad que el
  paper **no** trae.
- **Doc relacionada**: [`threat-model.md`](threat-model.md) — quién es el
  adversario, qué garantiza cada capa y, sobre todo, **qué no**.

Convención tipográfica del repo: los diagramas son ASCII y los identificadores
van en `backticks`.

---

## 0. Mapa general

Las capas no son una pila rígida: la **capa 0 (núcleo)** es la mecánica, las
**capas 1+2** la endurecen por dentro, y las **capas 3, 4 y 5** son planos
*transversales* que pueden activarse o no según el despliegue. Todas comparten
las mismas tres primitivas: un modelo de datos (`Gist`), una firma
(`provenance.KeyPair`) y una interfaz de transporte *swappable*.

```
                        ┌─────────────────────────────────────────┐
                        │            Agents (LLM)                 │
                        │  DelmPipeline · MeshWorker · harness    │
                        └───────────────┬─────────────────────────┘
                                        │ produces / consumes gists
  ══════════════════════════════════════▼═════════════════════════════════
  CAPA 5 — anti prompt-injection            (transversal, on by default)
    injection · injection_hardened · taint   → cuarentena en render/unfold
  ──────────────────────────────────────────────────────────────────────────
  CAPA 4 — despliegue multi-proceso
    deployment (Owner/DiscoveryBus/DeploymentNode) · nostr · mdns
  ──────────────────────────────────────────────────────────────────────────
  CAPA 3 — malla / propagación
    gossip · requirements · heartbeat · transport · mesh_* · quic_host
  ──────────────────────────────────────────────────────────────────────────
  CAPA 1+2 — proveniencia e integridad       (on by default)
    provenance · secure_context · ledger
  ──────────────────────────────────────────────────────────────────────────
  CAPA 0 — núcleo DeLM (los mecanismos de carga)
    gist · shared_context (C) · task_queue (T) · admission · verifier ·
    unfolding (G→S→raw) · llm · pipeline
  ══════════════════════════════════════════════════════════════════════════
                 MEJORAS (opt-in)            hci · rsi · metrics ·
                                            expansion · harness_client
```

Tres primitivas atraviesan **todas** las capas y no se re-derivan por capa:

| Primitiva | Dónde vive | Regla |
| --- | --- | --- |
| Modelo de datos | `core/gist.py` | un solo `Gist`; las capas añaden metadatos, no tipos nuevos |
| Firma | `core/provenance.py` | `KeyPair` (ed25519) + `digest_of` + `verify_public` |
| Transporte | `core/transport.py`, `core/deployment.py` | interfaz *swappable*, default in-memory |

Esa última es la regla de diseño dominante del repo: **toda superficie de
"red" tiene un default in-memory que es el camino testeable**. Un test nunca
requiere un socket, un relay o un modelo real.

---

## 1. Capa 0 — Núcleo DeLM (los mecanismos de carga)

El núcleo del paper (Mao & Mirhoseini, arXiv:2606.10662): en vez de un
orquestador central, los agentes coordinan de forma descentralizada a través de
dos estructuras globales.

```
   ┌──────────────┐        claim()          ┌────────────────┐
   │  TaskQueue T │◄───────────────────────  │  N workers     │
   │  (con deps)  │                         │  (paralelos)   │
   └──────┬───────┘                         └───────┬────────┘
          │  ▲                                     │
          │  └────────── admit(compress→verify) ◄──┘
          │                                    
   ┌──────▼──────────────────────────────────────────┐
   │        SharedContext C  (estado verificado)     │
   │        snapshot reads · escrituras atómicas     │
   │        (write-before-publish)                   │
   └──────┬──────────────────────────────────────────┘
          │ snapshot
          ▼
   ┌──────────────────────────────────────────────────┐
   │ Unfolding:  G  →  S  →  raw   (bajo demanda)     │
   └──────────────────────────────────────────────────┘
```

- **Modelo de datos** (`gist.py`): `Gist` (el resumen compacto), `Summary`
  (evidencia referenciada), `RefTag` (ancla al texto original), `GistKind`.
- **Contexto compartido C** (`shared_context.py`): los `snapshot` son lecturas
  sin bloqueo; las escrituras son **write-before-publish** (el respaldo se
  escribe antes de hacer visible el gist).
- **Cola T** (`task_queue.py`): una tarea es elegible solo si sus dependencias
  están hechas. `claim` es el **único** punto de serialización: una tarea
  `RUNNING`/`DONE` no se re-reclama.
- **Admisión** (`admission.py`): la puerta. Un resultado crudo nunca entra
  directo a `C`; se comprime en un gist, se **verifica contra su evidencia** y
  se admite si pasa. Si falla, reintenta con feedback; al agotar reintentos,
  descarta o devuelve a la cola.
- **Verificador** (`verifier.py`): `RuleVerifier` es la puerta determinista
  (sin claves, sin LLM): comprueba *grounding* (el gist está anclado en el
  texto) y *fidelidad* (el gist no introduce afirmaciones ausentes de su
  evidencia).
- **Despliegue selectivo** (`unfolding.py`): de grueso a fino bajo demanda. Lo
  desplegado es **local a la llamada** — no se re-escribe en `C`, así la capa de
  gists sigue limpia para los demás.
- **Cliente de modelo** (`llm.py`): `LLMClient` es la interfaz;
  `FakeLLMClient` (determinista, sin red) y `OpenAICompatibleClient`
  (cualquier endpoint OpenAI-compatible) son implementaciones.
- **Pipeline** (`pipeline.py`): `Worker` / `DelmPipeline` corren en paralelo
  sobre la cola compartida. Al agotarse la cola, el último worker decide si
  generar más subtareas o finalizar. **No hay merge central** de resultados:
  ese es el punto del paper.

## 2. Capas 1+2 — Proveniencia e integridad (on by default)

Endurecen `C` en el mismo proceso. No son un módulo opcional: `DelmPipeline`
usa `SecureSharedContext` y firma cada gist por defecto.

```
   worker
     │  Gist { author_id, digest, signature }
     ▼
  ┌────────────────────────────────────────────────────────┐
  │ SecureSharedContext.admit(gist)                         │
  │   1. TrustGate      ¿el autor puede escribir?            │
  │   2. verify_public  ¿la firma del digest es válida?     │
  │   3. integridad     digest almacenado == digest recomputado
  │   4. inmutabilidad  re-admitir un label exige digest idéntico
  │   5. ledger         admit/overwrite/reject → traza append-only
  └───────────────┬────────────────────────────────────────┘
                  ▼
              C (verificado)  +  AdmissionLedger
```

- **`provenance.py`** — `digest_of` (SHA-256 de un **serializado canónico**,
  independiente del orden de los campos y de los campos de firma) + `KeyPair`
  (ed25519). El **modo estricto es el default**: si falta `cryptography`,
  `KeyPair.new()` lanza en vez de degradar en silencio a HMAC. Con
  `allow_hmac_fallback` / `STRICT_MODE=False` degrada a HMAC (pre-shared key)
  **con warning visible**.
- **`ledger.py`** — `TrustGate` decide quién escribe (`TrustPolicy`:
  `ALLOWLIST` / `DENYLIST` / `REQUIRE_SIGNED`) y `AdmissionLedger` es
  append-only con **cadena de hashes** (cada entrada encadena el hash de la
  anterior → rastro auditable y reproducible; dump/load/export opcionales).
- **`secure_context.py`** — el superconjunto endurecido de `SharedContext`,
  con las cinco comprobaciones de arriba. Reusa el verificador de la capa 0.

## 3. Capa 3 — Malla / propagación

El plano donde varios agentes/nodos comparten `C` por la red. Tres policing
pieces (modeladas sobre MeshLLM) + el transporte.

```
   ┌──────────────┐  gossip/heartbeat  ┌──────────────┐
   │  MeshNode A  │ ─────────────────► │  MeshNode B  │
   │  firma+publica│ ◄───────────────── │  firma+publica│
   └──────┬───────┘                    └──────┬───────┘
          └──────── MeshNetwork (drena hasta convergencia) ────────┐
                                                                   ▼
                                                   todos convergen al mismo C
```

- **`gossip.py`** — propagación de estado de pares: *floor de versión* (un par
  por debajo no se ingiere ni se re-difunde), *regla path-rich* (un anuncio
  transitorio solo avanza `addr` si es al menos tan path-rich como el
  existente), *re-difusión* y *cambio significativo* (solo se re-propaga si algo
  significativo cambió).
- **`requirements.py`** — requisitos de malla **inmutables**: cambiarlos
  (floor, generación de protocolo, política de atestación) **deriva una malla
  nueva** (`mesh_id` nuevo), no muta la existente. Un par que no pasa el gate
  se rechaza en el ingest. La atestación de release es **provenance de build**
  (el binario lo publicó un firmante de confianza), no attestation de runtime.
- **`heartbeat.py`** — TTL, `sweep` de pares caídos, revivir y retiro.
- **`transport.py`** — el contrato `send`/`poll` de la malla, con tres
  implementaciones intercambiables: `InMemoryTransport` (default, tests),
  `QuicTransport` (aioquic) y `NostrTransport` (BIP340 sobre relay). `QuicSwarm`
  / `NostrSwarm` construyen el par (transporte por nodo).
- **`mesh_node.py` / `mesh_network.py` / `mesh_pipeline.py`** — un par (firma
  y publica gists, heartbeat, ciclo de vida), la red que los conecta y drena
  hasta convergencia, y `MeshPipeline`: el pipeline corre **sobre** la malla
  (cada worker publica su gist por la malla y lo admite en el `C` de su nodo).
- **`quic_host.py`** — el transporte de red **real** entre hosts: por par, un
  nodo servidor (el de mayor índice) y uno cliente (el de menor), cada uno con
  su event loop asyncio en un hilo. El cert es auto-firmado con **`CN =
  peer_id`** y el cliente verifica post-handshake que el `CN` coincida con el
  `peer_id` esperado (enlace identidad-cert; `insecure=True` desactiva la
  comprobación explícitamente).

## 4. Capa 4 — Despliegue multi-proceso

Todo lo que hace falta para que la malla salga del in-proceso: descubrirse,
anunciarse, arrancar en confianza y obedecer al owner.

- **`deployment.py`** —
  - **Discovery**: los nodos se anuncian con TTL (re-announce) y dedupe por
    `(node, epoch)`. El transporte de anuncio es **swappable**: `DiscoveryBus`
    (in-memory, default) con el mismo contrato que `NostrDiscoveryTransport`
    y `MdnsDiscoveryTransport`, así que `DeploymentNode` no cambia.
  - **Bootstrap**: el **trust anchor** es la clave pública del `Owner`
    (ed25519, reusando `provenance.KeyPair`). El owner firma cada anuncio y
    cada orden; un anuncio/orden **no verificable se descarta** (anti-MITM).
  - **Control-plane**: el owner emite órdenes firmadas (up/down, rotación) y el
    nodo las verifica y ejecuta. La rotación de la clave del owner rompe la
    cadena de confianza de forma explícita.
- **`nostr.py`** — transporte de anuncio sobre un relay Nostr: `NostrKey`
  (x-only BIP340), `NostrEvent` (NIP-01), el relay in-memory (tests) y el de
  red (`NostrRelayServer` / `NostrRelayClient`), más `NostrDiscoveryTransport`.
  La firma BIP340 se verifica contra los **19 vectores oficiales**.
  La guardia del relay incluye rate-limit por `pubkey`, dedup, límite de tamaño
  de evento y snapshot/restore opcional.
- **`mdns.py`** — discovery por multicast (`MdnsDiscoveryTransport` +
  `MdnsBus`), el tercer transporte swappable del mismo contrato.

## 5. Capa 5 — Anti prompt-injection (on by default)

El contexto compartido es también la **entrada** de cada agente, así que una
fuente envenenada puede orientar a todos los que la lean.

```
   fuente (documento que lee un agente)
     │  admission: ¿el texto lleva instrucciones inyectadas?
     ▼
   injection.detect(text)  ── heurístico, determinista, sin LLM ──┐
   injection_hardened.detect(text)  ── + normalización anti-evasión
     │  veredicto → taint de la fuente
     ▼
   ┌────────────────────────────────────────────────────────────┐
   │ TaintRegistry:  CLEAN · SUSPICIOUS · CONFIRMED             │
   │  Cierre transitivo: un gist derivado hereda el taint       │
   └───────────────┬────────────────────────────────────────────┘
                   ▼  render / unfolding
      CONFIRMED se OMITEN · SUSPICIOUS se enmarcan como dato no confiable
```

- **`injection.py`** — detector determinista (catálogo de regex) que marca
  fuentes con instrucciones inyectadas. Es una **heurística**, no un
  clasificador (ver la no-garantía en el threat model).
- **`injection_hardened.py`** — capa de normalización anti-evasión: quita
  zero-width/invisibles, NFKD + sin diacríticos, homoglifos, leetspeak,
  espaciado por letra y split por líneas — *antes* de pasar el mismo catálogo.
  Reduce la superficie de false-negative sin añadir un LLM.
- **`taint.py`** — niveles `CLEAN` / `SUSPICIOUS` / `CONFIRMED` con **cierre
  transitivo** (un gist derivado de una fuente envenenada hereda el taint), y
  la **cuarentena** aplicada tanto en el render (los `CONFIRMED` se omiten, los
  `SUSPICIOUS` se enmarcan como *dato no confiable*) como en el unfolding.

## 6. Mejoras (opt-in)

- **`metrics.py`** — `MetricsTracker`: coste y latencia por tarea; agregado al
  final del pipeline.
- **`expansion.py`** — `ExpansionPolicy`: la política del paso "generate more"
  (el último worker decide si crear más subtareas o finalizar).
- **`hci.py` / `rsi.py`** — la métrica **Headroom-Closed Index** (HCI) y el loop
  RSI L1 (proponer → verificar → retener/sucesor), que usa el HCI para medir
  cuánto headroom se cierra con una mejora.
- **`harness_client.py`** — backend de agente (DeepSeek Harness) detrás de la
  interfaz `LLMClient`; **opt-in** (`use_harness` / `DELM_HARNESS`), con import
  lazy para que la suite siga verde sin el SDK.

## 7. La CLI, la web y las demos

- **`cli.py` + `__main__.py`** — una sola CLI (`delm` == `python -m delm`, el
  mismo parser). `delm demo <nombre>` despacha la demo como **subprocess** a su
  módulo (cada demo conserva su propio `main()` y, en multi-host, sus procesos
  hijos) y devuelve su exit code; `delm test` corre la suite; `delm
  config-check` resuelve la config con la key enmascarada. Detalle en el
  README → "La CLI `delm`".
- **`api_server.py` + `smcp_api.py`** — la API de la web (FastAPI): estado en
  vivo, lanzar la suite/demos, y las acciones de sesión (scan, taint, config,
  export del ledger, SSE, meshllm). Sirve el estático de `web/`.
- **`web/`** — la UI (7 páginas). Es una vista sobre el mismo estado que la
  API expone; no añade lógica de dominio.
- **`demo/`** — las 6 demos. Cubren: pipeline end-to-end (sin API key),
  Capas 1+2, Capa 5, multi-host sobre QUIC/Nostr, el loop RSI y el modelo real.

## 8. Interfaces transversales (el contrato del repo)

Tres interfaces concentran el diseño y son lo que haría barato cambiar de
backend:

| Interface | Default in-memory | Alternativas (mismo contrato) | Consumidores |
| --- | --- | --- | --- |
| `LLMClient` | `FakeLLMClient` | `OpenAICompatibleClient`, `HarnessLLMClient` | pipeline, expanding, RSI |
| `MeshTransport` (`send`/`poll`) | `InMemoryTransport` | `QuicTransport`, `NostrTransport`, `QuicHostTransport` | `mesh_node`, `mesh_network` |
| descubrimiento (`register`/`publish`/`deliver`/`nodes`) | `DiscoveryBus` | `NostrDiscoveryTransport`, `MdnsDiscoveryTransport` | `DeploymentNode` |

Y dos primitivas de seguridad que **no** se re-derivan por capa:
`provenance.KeyPair`/`verify_public` (la única firma) y
`TaintRegistry` (el único modelo de taint).

## 9. Los flujos de punta a punta

### Admisión (el corazón)

```
raw del modelo
  └─ compress → Gist + Summary (evidencia referenciada)
       └─ verify: grounding (anclado al original) + fidelidad (no añade afirmaciones)
            └─ taint: ¿la fuente lleva inyección? → nivel
                 └─ gate + firma (Capas 1+2) + inmutabilidad
                      └─ ledger (append-only) → C visible
```

### Gossip / convergencia de la malla

```
MeshNode A: firma su gist (BIP340/ed25519) → publish por el transporte
           → gossip/heartbeat a los vecinos
MeshNetwork: drena en rondas hasta que no hay más entradas
           → todos los nodos convergen al mismo conjunto de gists
```

### Bootstrap y control-plane (capa 4)

```
Owner (trust anchor: su clave pública)
  ├─ firma anuncio  → nodos: verifican contra la clave del owner; si no, descartan
  ├─ firma orden up/down → nodo: verifica y ejecuta
  └─ rota la clave  → la cadena de confianza se rompe de forma explícita
```

### Transporte: el mismo contrato, tres redes

```
InMemoryTransport ─┐
QuicTransport     ─┼─→ implements MeshTransport.send/poll ─→ MeshNetwork ─→ convergencia
NostrTransport    ─┘
```

## 10. Reglas de contribución (las que mantienen esto coherente)

1. **Suite verde siempre**; el conteo del README debe cuadrar con
   `pytest --collect-only` (lo verifica `scripts/check_readme_count.py` en CI).
2. **Reusa `provenance`**: firma/edición nueva = `KeyPair` + `verify_public`,
   nunca un esquema de firma nuevo.
3. **Determinismo por construcción**: el tiempo entra por un `now` inyectable;
   los tests usan `FakeLLMClient`. Un test que necesite reloj de pared o modelo
   real es un bug.
4. **Seguridad por defecto**: `SecureSharedContext`, la cuarentena de taint y el
   detector endurecido son el camino por defecto, no opt-in.
5. **Transporte swappable con default in-memory**: la suite pasa sin sockets.
6. **Ningún relay/modelo real en la suite**: eso es una preocupación de runtime,
   no una dependencia de test.
