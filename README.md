# SMCP — Shared Mesh Context Protocol

> **SMCP** (no confundir con **SMTP**). Implementación *clean-room* del núcleo de
> coordinación de **DeLM** (Mao & Mirhoseini, *Decentralized Multi-Agent Systems
> with Shared Context*, arXiv:2606.10662) más una capa de seguridad propia.

No es una copia del repositorio de referencia: es una re-derivación del mismo
núcleo, expresada como una librería pequeña y testeable, con una capa de
seguridad (proveniencia, integridad y anti prompt-injection) que el paper no
incluye.

---

## Para qué sirve

DeLM sustituye al orquestador central por dos estructuras globales:

- un **contexto compartido** `C` — gists compactos y *verificados* del progreso
  acumulado, visibles para todos los agentes; y
- una **cola de tareas** `T` — subtareas pendientes que los agentes reclaman
  de forma asíncrona (con dependencias).

Un agente reclama una tarea, lee un *snapshot* de `C`, razona en local y escribe
un gist que se **comprime, verifica contra su evidencia y admite** en `C` solo
si pasa. El progreso intermedio deja de ser un mensaje efímero y se convierte
en **estado reutilizable**.

SMCP captura esos mecanismos de carga (los que de verdad hacen el trabajo) y,
encima, **endurece el contexto compartido** — que es la memoria de todos los
agentes — con una capa de seguridad que el paper no trae.

---

## Qué incluye

### Núcleo DeLM (los mecanismos de carga)

- **Contexto compartido (`SharedContext`)** — el estado verificado `C`. Solo
  entran gists admitidos. Las lecturas son *snapshots* sin bloqueo; las
  escrituras son atómicas (write-before-publish: el contenido de respaldo se
  escribe antes de hacer visible el gist).
- **Cola de tareas (`TaskQueue`)** — la cola con dependencias. Una tarea solo es
  elegible cuando sus dependencias están hechas. El `claim` es el único punto
  de serialización (una tarea `RUNNING`/`DONE` no puede re-reclamar).
- **Admisión (`AdmissionPipeline`)** — la puerta. Un resultado crudo nunca entra
  directo a `C`: se (a) **comprime** en un gist (+ un `Summary` con evidencia
  referenciada), (b) **verifica** contra su evidencia y (c) **admite** si pasa.
  Si falla, reintenta con feedback y, al agotar reintentos, descarta o devuelve
  a la cola.
- **Verificador (`RuleVerifier`)** — la puerta determinista, sin claves.
  Verifica el *grounding* (el gist está anclado en el texto original) y la
  fidelidad (el gist no introduce afirmaciones ausentes de su evidencia).
- **Despliegue selectivo (`Unfolding`)** — de lo grueso a lo fino, bajo demanda.
  Los agentes leen la capa de gists por defecto; cuando necesitan detalle,
  *despliegan* (`G -> S -> raw`). Lo desplegado es **local a la llamada**: no se
  re-escribe en `C`, así la capa de gists se mantiene limpia para los demás.
- **Cliente de modelo (`LLMClient`)** — agnóstico al modelo. `FakeLLMClient`
  (determinista, sin red) demuestra todo el pipeline sin coste;
  `OpenAICompatibleClient` lo corre contra cualquier endpoint OpenAI-compatible
  (OpenRouter, un proveedor directo, un servidor local).
- **Pipeline (`Worker` / `DelmPipeline`)** — el bucle descentralizado. N workers
  corren en paralelo sobre la cola compartida; cada uno reclamar, leer, razonar
  y admitir. Al agotarse la cola, el último worker decide si generar más
  subtareas o finalizar. **No hay orquestador central** que merge resultados:
  ese es el punto.

### Capa de seguridad (lo que el paper no trae)

- **Proveniencia e integridad (Capas 1+2)** — cada gist lleva el *author* que lo
  admitió y una **firma ed25519** sobre su **digest canónico** (SHA-256 del
  contenido, independiente del orden y de los campos de firma). Un `TrustGate`
  decide quién puede escribir (allowlist / denylist / require-signed). La
  **inmutabilidad** impide sobrescribir: re-admitir un label solo vale si el
  digest es idéntico. Un `AdmissionLedger` append-only con cadena de hashes
  deja un rastro auditables y reproducible.
- **Anti prompt-injection (Capa 5)** — el contexto compartido también es la
  *entrada* de cada agente, así que una fuente envenenada puede orientar a todos
  los que la lean. Un **detector determinista** (sin LLM) marca fuentes con
  instrucciones inyectadas, y un **modelo de taint** (`CLEAN` / `SUSPICIOUS` /
  `CONFIRMED`) con **cierre transitivo** acota el alcance: un gist derivado de
  una fuente envenenada hereda el taint, y la **cuarentena** se aplica tanto en
  el render (los `CONFIRMED` se omiten; los `SUSPICIOUS` se enmarcan como *dato
  no confiable, no instrucciones*) como en el despliegue selectivo (el `raw` de
  un gist bloqueado no se expone).

---

## Mejoras adicionales (capa anti-evasión, observabilidad y expansión)

Tres módulos nuevos en `delm.core` que cierran los huecos reconocidos en el
análisis, sin romper la disciplina del proyecto (deterministas, testeables,
sin LLM en el loop):

### Detector de inyección endurecido (`delm.core.injection_hardened`)

El detector baseline es un catálogo de regex sobre el texto crudo, evadible
con zero-width chars, homoglifos, leetspeak, acentos, palabras espaciadas
por letra o payloads partidos en líneas. El detector endurecido normaliza
antes de correr el mismo catálogo:

1. strip de zero-width/invisibles (ZWSP, ZWNJ, bidi, soft hyphen, LRM/RLM,
   selectores de variación);
2. NFKD + drop de marcas combinadas (pliega acentos y fullwidth);
3. lowercase;
4. homoglifos: tabla reducida de confusables cirílico/griego;
5. leetspeak (0->o, 3->e, @->a, ...);
6. whitespace: newlines/tabs simples -> espacio (el catálogo no cruza
   newlines); huecos anchos -> exactamente dos espacios;
7. colapso de palabras espaciadas por letra ("i g n o r e" -> "ignore"),
   capturando la run entera en un solo grupo — no se pierden letras del
   medio;
8. scan de regiones: el peor caso (todo el payload espaciado con espacios
   simples) se detecta compactando cada region letter-spaced y chequeando
   firmas ordenadas *dentro de la región* — acotado, sin falsos positivos
   de documentos legítimos que mencionen "send" y una URL en párrafos
   distintos.

`SecureSharedContext` lo usa por defecto (`hardened_injection=True`,
opt-out disponible) y anota `[evasion]` en el reason del taint cuando el
hit solo fue posible tras normalizar. `HardenedVerdict` expone
`evasion_detected`, `baseline_clean` y `region_hits` para telemetría A/B.

### Métricas (`delm.core.metrics`)

`MetricsTracker` registra coste/latencia por tarea: `timed()` como context
manager (mutable in-flight), precios por modelo (tabla 2026 orientativa,
overrideable), agregado con percentiles p50/p95, admit rate, retries,
breakdown por worker **y por modelo**, serializable a JSON para el ledger.
Si el bloque lanza, el registro se escribe igual con `admitted=False` y
`error`, y la excepción se re-lanza. `DelmPipeline` crea uno por defecto,
lo pasa a cada worker y vuelca el agregado en `PipelineOutcome.metrics`.

### Política de expansión (`delm.core.expansion`)

`ExpansionPolicy` decide cuándo invocar el paso "generate more subtasks":
queue viva -> no; sin señal (done+failed==0) -> no; `target_progress`
opt-in alcanzado -> no; presupuesto agotado -> no; `failure-storm`
(fail_ratio >= umbral) -> no (terminal, documentado); si no, burst acotado
`n_new = min(max_burst, budget_remaining)`. `DelmPipeline` la consulta con
el estado real de la cola cuando se configura (`expansion_policy=...`,
`expansion_budget=...`) y acota el burst generado a `n_new`.

Los tres módulos están cableados en el pipeline real y cubiertos por
`tests/test_mejoras.py`.

## Cómo usarlo

### Instalar

```bash
cd delm
pip install -e .
```

Requiere Python 3.11+.

### Demo sin API key

```bash
python -m delm.demo.run_demo
```

Muestra el pipeline de punta a punta: un corpus semilla entra a la cola, 4
workers paralelos reclaman, razonan y admiten sus gists, el gist de la unidad de
carga se despliega selectivamente (`G -> S -> raw`) y un finalizador produce la
respuesta solo a partir del contexto compartido.

### Demos de seguridad

```bash
python -m delm.demo.run_security_demo   # Capas 1+2: firma, integridad, inmutabilidad, ledger
python -m delm.demo.run_taint_demo      # Capa 5: cuarentena de prompt-injection
```

### Demo multi-host (capa 3 sobre red)

```bash
python -m delm.demo.run_multihost_demo          # QUIC (default): 2 nodos, procesos distintos
python -m delm.demo.run_multihost_demo --nostr  # relay Nostr: 1 relay + 2 nodos
```

El **default** corre sobre **QUIC** (el despliegue real): 2 nodos en
**procesos distintos** que se conectan entre sí (``B`` servidor, ``A``
cliente), cada uno firma su gist (BIP340), se intercambian gossip/heartbeat
por QUIC y convergen al mismo conjunto de gists. La flag ``--nostr``
arranca el modo anterior (1 relay Nostr + 2 nodos que se intercambian
gossip/heartbeat por Nostr). Es la demo de punta a punta del despliegue
multi-host (la malla corre sobre red, no in-proceso).

### Probar

```bash
python -m pytest
```

El suite está repartido en doce archivos, todos deterministas:

- `test_delm.py` — el núcleo: cola, contexto, admisión, despliegue, pipeline.
- `test_security.py` — Capas 1+2: digest, firma, gate, ledger, y que el pipeline
  usa el contexto seguro y firma.
- `test_taint.py` — Capa 5: detector, niveles de taint, cierre transitivo,
  cuarentena en render y despliegue, y que el pipeline la trae por defecto.
- `test_mejoras.py` — métricas (coste/latencia) y expansión cableadas en el
  pipeline real.
- `test_config.py` — loader de config: env > YAML > default, y que la key no
  se toma del YAML.
- `test_real_model_wiring.py` — wiring de punta a punta (config → cliente →
  pipeline) contra un mock OpenAI-compatible, sin red externa.
- `test_gossip.py` — capa 3: floor de versión, regla path-rich, re-difusión,
  cambio significativo, retiro.
- `test_requirements.py` — capa 3: inmutabilidad, `policy_hash`, atestación
  de release, gates de admisión.
- `test_heartbeat.py` — capa 3: registro, beat, frescura, `sweep`, revivir,
  retiro.
- `test_mesh.py` — capa 3: transport/nodo/red/pipeline (integración),
  incluyendo el pipeline corriendo **sobre QUIC** (aioquic).
- `test_nostr.py` — BIP340 (Schnorr secp256k1, x-only) verificado contra los
  19 vectores oficiales, y el relay de red Nostr (`NostrRelayServer`/
  `NostrRelayClient`): el round-trip, la verificación de firma y el rechazo.
- `test_deployment.py` — capa 4: discovery, relays, bootstrap (firma del
  owner) y control-plane (órdenes firmadas), y el transporte Nostr (in-memory
  y de red) swappable con `DiscoveryBus`.

### Usar un modelo real

La config de modelo se resuelve con `delm/config.py`: **entorno > YAML >
default**. La API key **solo por entorno** (nunca en el YAML ni en el repo).

```bash
# config/model_config.yaml (git-ignored)
#   model: unsloth/Qwen3.8-27B-GGUF
#   base_url: http://127.0.0.1:8888/v1
#   api_key: ""            # se inyecta por entorno, nunca por archivo
export DELM_API_KEY="..."   # o bien: export OPENAI_API_KEY="..."
python -m delm.demo.run_real_demo --tasks 4 --workers 4
```

`load_config()` lee `DELM_MODEL`/`DELM_BASE_URL`/`DELM_API_KEY` (o `OPENAI_*`)
y el YAML de `config/model_config.yaml`; `build_client()` devuelve un
`OpenAICompatibleClient` listo para `DelmPipeline`. `run_real_demo` muestra la
config resuelta (ocultando la key) antes de correr y avisa si falta el modelo.

O, programáticamente:

```python
import asyncio
from delm.core.llm import OpenAICompatibleClient
from delm.core.pipeline import DelmPipeline
from delm.core.task_queue import Task

async def main():
    llm = OpenAICompatibleClient(
        model="google/gemini-3-flash",        # cualquier id OpenAI-compatible
        base_url="https://openrouter.ai/api/v1",
        api_key="sk-...",
    )
    pipe = DelmPipeline(llm=llm, n_workers=4)
    tasks = [Task(label=f"t{i}", body="...", kind="solve") for i in range(8)]
    out = await pipe.run(tasks)
    print(out.answer)

asyncio.run(main())
```

El mismo `model` / `base_url` / `api_key` que el `config/model_config.yaml` de la
referencia. El `DelmPipeline` trae la capa de seguridad **activa por defecto**
(cada worker firma con su identidad; el contexto verifica cada firma).

> **Nota de despliegue:** el `run_real_demo` apunta por defecto a un endpoint
> local (Unsloth, `127.0.0.1:8888`). Si el modelo aún no está cargado en el
> runtime, la primera llamada devuelve `No model loaded`; cárgalo antes
> (`POST /api/inference/load`) o usa un endpoint siempre-disponible. La wiring
> de punta a punta (config → cliente → pipeline) está cubierta por
> `tests/test_real_model_wiring.py` contra un mock OpenAI-compatible, sin red
> externa.

---

## Progreso actual

**Hecho y verificado:**

- **Núcleo DeLM completo** — contexto, cola con dependencias, admisión con
  verificación, despliegue selectivo, workers paralelos, finalizador. Corre de
  punta a punta sin API key.
- **Capas 1+2 integradas por defecto** — el pipeline firma cada gist y el
  contexto seguro verifica; no es un módulo opcional, es el camino por defecto.
- **Capa 5 integrada por defecto** — la cuarentena de prompt-injection corre en
  el render y en el despliegue; el detector escanea el texto *y* el `raw`.
- **190 tests en verde** (14 núcleo + 18 seguridad + 15 taint + 28 mejoras +
  16 config + 2 wiring + 55 capa 3: 13 gossip + 12 requirements + 10
  heartbeat + 17 malla: transport/nodo/red/pipeline + QUIC e2e + Nostr e2e +
  3 QUIC entre hosts: framing/round-trip/malla completa + 19 capa 3/4 Nostr:
  BIP340 contra los 19 vectores + relay de red + NostrTransport + convergencia
  de malla + 13 capa 4: discovery/relays/bootstrap/control-plane + transporte
  Nostr de red + 8 mDNS: el transporte de discovery mDNS (swappable con
  `DiscoveryBus`, mismo contrato que `DeploymentNode` no cambia) + 2 demo
  multi-host: convergencia sobre QUIC (default) y Nostr (`--nostr`), y 4
  demos que pasan.
- **Agnóstico al modelo** — el mismo pipeline corre con `FakeLLMClient` (demo)
  o con cualquier endpoint OpenAI-compatible (producción).
- **Config de modelo real de serie** — `delm/config.py` resuelve la config
  (entorno > YAML > default), la API key solo por entorno, y
  `run_real_demo` corre el pipeline contra un endpoint real; la wiring está
  probada de punta a punta por `test_real_model_wiring.py`.

**En construcción / pendiente:**

- **Capa 3 integrada en el pipeline** — el transporte de malla está cableado:
  `transport.py` (`InMemoryTransport` in-proceso + `QuicTransport` aioquic),
  `mesh_node.py` (un par: firma/publica gists, heartbeat, ciclo de vida),
  `mesh_network.py` (conecta nodos, drena hasta convergencia) y
  `mesh_pipeline.py` (`MeshPipeline`: el pipeline corre **sobre** la malla —
  cada worker publica su gist **por la malla** y lo admite en el
  `SecureSharedContext` de su nodo; al drenar, todos los nodos convergen al
  mismo conjunto de gists). Cubierto por `test_mesh.py` (17 tests,
  incluyendo la convergencia sobre red vía Nostr).
- **Capa 4 — despliegue multi-proceso** — `delm/core/deployment.py`: discovery
  (el owner firma cada anuncio; un nodo se publica y los demás lo descubren),
  relays (el bus hace broadcast: un publish llega a todos), bootstrap
  (la firma del owner es el *trust anchor*: un anuncio/orden no verificable se
  descarta, anti-MITM) y control-plane (el owner emite órdenes firmadas
  up/down que el nodo verifica y ejecuta). El transporte de anuncio
  (`DiscoveryBus`) es in-memory y **swappable**: `NostrDiscoveryTransport`
  (vía un relay Nostr) y `MdnsDiscoveryTransport` (vía un medio mDNS,
  `delm/core/mdns.py`) implementan la misma interfaz y se usan en su lugar —
  `DeploymentNode` no cambia. Cubierto por `test_deployment.py` (13 tests) y
  `test_mdns.py` (8 tests).
- **Despliegue multi-nodo (red)** — la capa 3 **corre sobre red** vía Nostr:
  `NostrSwarm` (equivalente a `QuicSwarm`) crea un `NostrRelayServer` (el
  relay) y, por par, una `NostrKey` (identidad = `pubkey` x-only) + un
  `NostrRelayClient`; `NostrTransport` (adaptador BIP340 al contrato
  `MeshTransport` `send`/`poll`) reemplaza a `InMemoryTransport`/`QuicTransport`
  y `MeshNetwork`/`MeshPipeline` lo activan con `nostr=True`. La convergencia
  es la misma que in-memory/QUIC (2 nodos, gossip, converge al mismo conjunto
  de gists). El **transporte QUIC entre hosts** (`quic_host.py`) está
  implementado: `QuicHostSwarm` (equivalente a `QuicSwarm`, pero con red real)
  crea un `QuicHostNode` por par (cada uno con su event loop asyncio en un
  hilo), asigna un puerto por par (el par de mayor índice es servidor y
  escucha; el de menor, cliente y se conecta) y expone `QuicHostTransport`
  (mismo contrato `send`/`poll` que `QuicSwarm`). Cubierto por
  `test_quic_host.py` (framing, round-trip 1 par, malla completa 3 nodos).
  El `NostrDiscoveryTransport` soporta la forma de red (un transporte por
  nodo, cada uno con su `NostrRelayClient`).
- **Modelo real en producción** — la config de serie existe y la wiring está
  probada; queda por fijar un endpoint concreto y estable (hoy apunta al
  local de Unsloth, cuyo modelo hay que cargar antes de correr).

**Conocido / por diseño:**

- **El detector de inyección es heurístico, no un clasificador.** Un *false
  positive* solo cuarentena (recuperable); un *false negative* queda contenido
  porque el taint marca la fuente no-confiable de todos modos. No se añadió un
  clasificador LLM a propósito: costaría por gist y reintroduciría
  no-determinismo; el umbral + taint ya contienen el caso.
- **La firma ed25519 tiene fallback HMAC** si `cryptography` no está disponible
  (pre-shared key). En producción se asume `cryptography` presente; el fallback
  es para que el framework corra con cero dependencias.

---

## Estructura

```
delm/
  core/
    gist.py            Gist, Summary, RefTag, GistKind   (el modelo de datos)
    shared_context.py  SharedContext                     (el C verificado)
    secure_context.py  SecureSharedContext               (C + seguridad)
    task_queue.py      TaskQueue, Task                   (el T con dependencias)
    admission.py       AdmissionPipeline                 (compress -> verify -> admit)
    verifier.py        RuleVerifier, LLMVerifier         (la puerta de verificación)
    unfolding.py       Unfolding                         (G -> S -> raw)
    llm.py             LLMClient, FakeLLMClient, OpenAICompatibleClient
    config.py          ModelConfig + load_config         (config de modelo real)
    pipeline.py        Worker, DelmPipeline              (el bucle descentralizado)
    provenance.py      digest canónico + firma ed25519/HMAC
    ledger.py          AdmissionLedger + TrustGate       (auditoría + gate)
    injection.py       detector de prompt-injection
    taint.py           TaintRegistry (niveles + cierre transitivo)
    metrics.py         MetricsTracker                    (coste/latencia por tarea)
    expansion.py       ExpansionPolicy                   (paso "generate more")
    gossip.py          PeerAnnouncement/GossipTable      (propagación transitoria)
    requirements.py    MeshRequirements/AdmissionEvaluator (requisitos inmutables)
    heartbeat.py       HeartbeatTracker                  (TTL + detección de caída)
    transport.py       InMemoryTransport/QuicTransport   (datagramas de malla)
    mesh_node.py       MeshNode                          (un par: firma+publica)
    mesh_network.py    MeshNetwork                       (conecta nodos, drena)
    mesh_pipeline.py   MeshPipeline/MeshWorker           (pipeline sobre la malla)
    deployment.py      Owner/DiscoveryBus/DeploymentNode (capa 4: discovery, relays, bootstrap, control-plane)
    nostr.py           BIP340 + NostrEvent + NostrRelay/Server/Client (capa 4: relay de red)
    mdns.py            MdnsBus/MdnsDiscoveryTransport    (capa 4: discovery mDNS, swappable con DiscoveryBus)
  demo/
    run_demo.py        demo end-to-end (sin API key)
    run_real_demo.py   demo contra un modelo real (config-driven)
    run_security_demo.py   demo Capas 1+2
    run_taint_demo.py      demo Capa 5
  tests/
    test_delm.py       núcleo
    test_security.py   Capas 1+2
    test_taint.py      Capa 5
    test_mejoras.py    metrics + expansion cableados
    test_config.py     loader de config (env / yaml / precedencia)
    test_real_model_wiring.py   wiring de cliente real (mock OpenAI-compat)
    test_gossip.py     capa 3: propagación transitoria
    test_requirements.py capa 3: requisitos inmutables
    test_heartbeat.py  capa 3: heartbeat
    test_mesh.py       capa 3: transport/nodo/red/pipeline (integración)
    test_nostr.py      capa 4: BIP340 (19 vectores) + relay de red (NostrRelayServer/Client)
    test_deployment.py capa 4: discovery, relays, bootstrap, control-plane, transporte Nostr
    test_mdns.py       capa 4: discovery mDNS (MdnsDiscoveryTransport, swappable con DiscoveryBus)
    test_demo_multihost.py  demo multi-host: convergencia QUIC (default) + Nostr (slow)
```

---

## Relación con el repo de referencia

El repositorio de referencia (`github.com/yuzhenmao/DeLM`) envuelve ese núcleo
con los harness de SWE-bench y LongBench-v2 (ejecución Docker, tooling ACI,
`pass@N`). Este proyecto es una **re-derivación clean-room** de ese núcleo — el
contexto compartido verificado, la cola con dependencias, la verificación en
admisión, el despliegue selectivo y los workers paralelos — expresada como una
librería pequeña y testeable, **más** una capa de seguridad (Capas 1+2 y Capa 5)
que el paper no incluye. No es una copia de ese codebase.

---

## Licencia

GPL-3.0 (copyleft). El texto completo está en [`LICENSE`](LICENSE).
