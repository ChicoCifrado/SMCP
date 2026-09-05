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

### Probar

```bash
python -m pytest
```

El suite está repartido en tres archivos, todos deterministas:

- `test_delm.py` — el núcleo: cola, contexto, admisión, despliegue, pipeline.
- `test_security.py` — Capas 1+2: digest, firma, gate, ledger, y que el pipeline
  usa el contexto seguro y firma.
- `test_taint.py` — Capa 5: detector, niveles de taint, cierre transitivo,
  cuarentena en render y despliegue, y que el pipeline la trae por defecto.

### Usar un modelo real

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
- **47 tests en verde** (14 núcleo + 16 seguridad + 15 taint) y 3 demos que
  pasan.
- **Agnóstico al modelo** — el mismo pipeline corre con `FakeLLMClient` (demo)
  o con cualquier endpoint OpenAI-compatible (producción).

**En construcción / pendiente:**

- **Plano de transporte** — las reglas de transporte (QUIC/iroh con cifrado
  extremo-a-extremo, discovery Nostr/mDNS, bootstrap firmado, control-plane del
  owner) solo aplican al distribuir a multi-nodo. **No está construido** a
  propósito (YAGNI): el framework es in-proceso hoy.
- **`generate_more` (round-2)** — el paso de "generar más subtareas" está
  cableado en la interfaz pero la heurística de cuándo generar más no está
  afinada todavía.
- **Tracker de coste/latencia** — no hay métricas de coste por tarea ni de
  latencia acumulada todavía.
- **Modelo real cableado de serie** — `OpenAICompatibleClient` existe y se
  documenta, pero no hay una configuración de serie apuntando a un endpoint
  concreto (por diseño, no se hardcodea una API key).

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
    pipeline.py        Worker, DelmPipeline              (el bucle descentralizado)
    provenance.py      digest canónico + firma ed25519/HMAC
    ledger.py          AdmissionLedger + TrustGate       (auditoría + gate)
    injection.py       detector de prompt-injection
    taint.py           TaintRegistry (niveles + cierre transitivo)
  demo/
    run_demo.py        demo end-to-end (sin API key)
    run_security_demo.py   demo Capas 1+2
    run_taint_demo.py      demo Capa 5
  tests/
    test_delm.py       núcleo
    test_security.py   Capas 1+2
    test_taint.py      Capa 5
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
