# SMCP — Shared Mesh Context Protocol

> **SMCP** (no confundir con **SMTP**). Una malla de nodos que **comparten
> VRAM de forma verificable y reciben inferencia a cambio**, sobre un núcleo de
> coordinación *clean-room* de **DeLM** (Mao & Mirhoseini, *Decentralized
> Multi-Agent Systems with Shared Context*, arXiv:2606.10662) y una capa de
> seguridad propia.

SMCP junta **tres piezas** en una sola CLI y una sola Web UI:

| Pieza | Qué aporta | Dónde vive |
|---|---|---|
| **DeLM** (clean-room) | contexto compartido verificado `C` + cola de tareas `T` entre agentes distribuidos | `smcp/core/{gist,shared_context,secure_context,task_queue,admission}.py` |
| **MeshLLM** | agrupa GPU/memoria entre máquinas y expone **una API OpenAI-compatible** en `:9337` | externo (Rust); SMCP apunta a su endpoint |
| **llmfit** | dimensiona un modelo contra el hardware real (fit, tok/s, quant) | externo (Rust/PyPI); adaptador en `smcp/core/llmfit.py` |

La idea, en una frase: **los nodos de distintos usuarios se unen a una malla,
contribuyen con su VRAM y, a cambio, obtienen acceso a la inferencia de la malla
— y si esa VRAM se reparte bien, entre todos pueden correr modelos que no caben
en ninguna máquina sola.**

## Smart contract BSV (protocolo permissionless)

`smcp/core/contract.py` — el "smart contract" en BSV no es un
programa que se ejecuta en la cadena (BSV no tiene EVM). Es un
**locking script** que gobierna quien puede gastar un output:

    P2PKH(nodeKey)   --  OP_DUP OP_HASH160 <20> OP_EQUALVERIFY
                             OP_CHECKSIG

El output del contract solo lo gasta el nodo cuya clave esta en
el locking script. La cadena garantiza que el bounty lo cobra el
nodo que resolvio la tarea, y nadie mas.

**Protocolo permissionless**: nadie controla la red; todos
colaboran haciendo inferencia para recibir satoshis:

1. Treasury fondea un output P2PKH(nodeKey) con `bounty` sats.
2. Cualquier nodo (permissionless) resuelve la tarea y propone
   un gist.
3. La malla verifica el gist (n-grams >=4) y lo firma (ed25519).
4. El nodo cobra via `POST /api/contract/claim`: construye y
   firma la tx que gasta el output del contract y paga el bounty
   al nodo. El gasto es la **tx de anclaje** (outpoint de
   atribucion al nodo).
5. La tx se difunde via ARC.

Cubierto por `tests/test_contract.py` (9 tests): P2PKH, firma,
pago al nodo, cambio, UTXO insuficiente, roundtrip.

## Token BSV-21 DELM (capa F — economia tokenizada)

`smcp/core/token_bsv21.py` — la moneda de la red mesh.
El token DELM es la contrapartida en token del bounty
en sats: los nodos ganan DELM por resolver inferencias
y el DELM se puede listar/vender en 1sat.market.

Es un **bridge** al SDK nativo `@1sat/actions` (Node.js)
— el unico SDK que opera BSV-21 de forma nativa contra
el indexer unificado `api.1sat.app`. Python delega via
subprocess al bridge (`bsv21-bridge/bsv21.mjs`).

Operaciones:
- `deploy` — `deployBsv21Mint` (supply fijo 1.000.000, 0 dec)
- `send` — `sendBsv21` (value-based, a direcciones)
- `balances` — `getBsv21Balances` (agregados)
- `list` — `listBsv21` (UTXOs de token del wallet)
- `buy` — `buyBsv21` (comprar listing OrdLock en 1sat.market)
- `pay_for_inference` — comodo DeLM: pagar a un nodo en DELM

El WIF viene de `DELM_TOKEN_WIF` o `~/.smcp/token.wif`.
El tokenId es `<deployTxid>_0`. El indexer 1sat solo
activa el token una vez la tx de deploy confirma en bloque.

**TokenId canonico**: se despliego 3 veces por error
(3 tokenIds con `sym: DELM`). El canónico es
`8d7f4834..._0` (el primero, con funding parcial en
el overlay). Los otros dos (`5c6c7efb..._0`,
`491f8442..._0`) quedan como **tokens muertos**: no
se gastan ni se listan. El supply efectivo de DELM
es **1.000.000** (el del canónico). El código usa
`TOKEN_ID_CANONICO` por defecto (`token_bsv21.py`)
y `DEFAULT_TOKEN_ID` (`bsv21-bridge/bsv21.mjs`).

**Anclaje SMCP ↔ DELM (on-chain, 2026-10-04)**:
el tokenId `8d7f483498d83358e8c0b61b55334b1650d50ffce1539a482bc245dfc65c4410_0`
(bloque génesis **969519**) es el anclaje on-chain
permanente del proyecto SMCP. Custodia: `1EqkBCLhykcHkr7o9AnHwgrgzAsAbGF3Dz`
(garracifrada@handcash.io, identity `03ed40e2…080909`,
custodia conjunta con el propietario). Los **1M DELM**
viven en el tip de 1 sat (`8d7f4834_0`, inscripción
`deploy+mint`), intactos y sin gastar. Funding vivo:
**574 sats** (UTXO `da2cfe03…_1`, bloque 969530) —
suficiente para una tx de sweep (~200-500 sats).
Control verificado read-only: `@1sat/cli sweep scan
--wif <token.wif> --only bsv21` (indexer público
`api.1sat.app` — ve el UTXO de 1 sat con la inscripción
BSV-21, sin depender del install).

**Activacion del overlay (BRC-0062 / formato BEEF)**:
el overlay 1sat requiere una tx de **funding** para
dar de alta el token como operativo (enviar/listar/comprar).
El funding se construye en **formato BEEF** (BRC-0062):
- `toHexBEEF()` del `@bsv/sdk` serializa la tx + los
  **merkle paths** (BUMP, BRC-74) de los inputs confirmados
- los merkle paths se obtienen via `services.beef.getProof(txid)`
  del `@1sat/wallet-node` (el servicio de headers de 1sat)
- `services.bsv21.submitFunding(tokenId, beefBytes)` envia
  el BEEF (octet-stream) al endpoint `/{tokenId}/fund`
- el overlay responde con el estado: `balance`, `credits`,
  `is_active`, `min_funding`

El overlay exige `min_funding: 10000000` (10M sats ~=
0.1 BSV) para `is_active: true`. Un funding parcial genera
`credits` pero no activa el token. Los inputs confirmados
(tienen merkle path en el servicio) son los unicos validos
para el BEEF; los inputs de mempool fallan con
`missing previous transaction` (el BEEF necesita la cadena
ancestral completa).

**API**: `POST /api/token/pay` — paga a un nodo en DELM
(`{token_id, node_address, amount}`). Es la contrapartida
en token de `/api/contract/claim` (bounty en sats).

## Infraestructura de wallets (SPV + pagos)

Dos piezas, cada una con su rol — no se sustituyen:

**ElectrumSV headless** (`smcp/core/electrumsv.py`) —
la wallet SPV real. El daemon firma **localmente** con
las claves del fichero wallet (sqlite, cifrado con
password local) y valida contra el servidor SPV
(reference_server/ElectrumX) sin entregarle nada
secreto. A diferencia de HandCash (custodial), las
claves nunca salen del daemon.
- Cliente REST del daemon: `http://127.0.0.1:9999/v1/{network}/dapp`
  — las rutas `/dapp/...` las monta el módulo dapp
  `restapi`; el daemon debe arrancar con `-dapp restapi`
  (como hace `electrumsv-sdk`), si no dan 404.
- El `wallet_name` incluye la extensión `.sqlite`; los
  GET envían body `{}` (el dapp parsea el JSON del body).
- Lecturas (sin clave): `wallets`, `load_wallet`, `account`,
  `utxos`, `balance`, `history`, `fetch_transaction`
- Escrituras (firma local): `create_tx` (construir SIN emitir),
  `broadcast` (rawtx), `create_and_broadcast`, `split_utxos`
- **`create_tx` exige `script_pubkey` en hex** — outputs
  con scripts arbitrarios (OP_RETURN, inscripciones). El
  body es `{"wallet_name", "account_id", "password",
  "outputs": [{"script_pubkey": "<hex>", "value": <sats>}]}`.
  No acepta `{"address": ...}`.
- **Trazabilidad**: `send_tracked()` = create -> inspeccionar
  -> broadcast -> log append-only (`~/.smcp/electrumsv.txs.jsonl`).
  Toda tx queda anclada por txid on-chain y registrada local.
- El WIF del proyecto (`~/.smcp/token.wif`, 0600) es
  mainnet comprimido (`L...`, 52 chars) — importable en
  ElectrumSV via "Importing from text" (crea una cuenta de
  UNA dirección; no es un seed HD).
- El daemon se arranca con `electrumsv-sdk` (ver skill
  `electrumsv-wallet`): `electrumsv-sdk start --background
  electrumsv` (requiere `node`, `simple_indexer`,
  `reference_server`, `electrumx`). Contrato verificado
  contra ElectrumSV 1.4.0b1; el dapp de ejemplo tiene dos
  bugs a parchear (`ARGTYPES`, `get_fee_estimator`) — ver
  `references/daemon-rest.md` del skill.

**HandCash** (ya probado) — pagos con `note` (<=25 chars,
metadata off-chain) via `Connect.pay`. Custodial: las claves
las gestiona HandCash, útil para pagos rápidos pero no para
soberanía. AppId/AppSecret en `~/.hermes/.env`; authToken en
`~/.smcp/handcash.authtoken` (0600).

**BSV-21 (DELM)** — el bridge `bsv21-bridge/bsv21.mjs`
(SDK `@1sat/actions`) es quien construye las inscripciones
(deploy+mint, transfer) y opera contra el overlay 1sat.
ElectrumSV puede gastar los sats y crear outputs con
`script_pubkey` arbitrario, pero la semántica BSV-21
(indexer, funding BRC-0062/BEEF) la implementa el SDK.
No duplicarla en Python.

**Regla de seguridad de claves**: el WIF/seed vive en
`~/.smcp/` (0600), NUNCA en `/tmp` (pruning 72h) ni en
el chat. Un WIF que vivió solo en `/tmp` se perdió y hubo
que recuperarlo del historial de sesión — eso es un parche,
no un backup.

Cubierto por `tests/test_token_bsv21.py` (15 tests):
tokenId, deploy, send, balances, buy, pay_for_inference,
list, y manejo de errores (no-JSON, timeout, node ausente).

El bridge Node (`bsv21-bridge/`) usa:
`@1sat/actions`, `@1sat/wallet-node`, `@1sat/templates`,
`@bsv/sdk`. Requiere Node >= 18.

## Libro de inferencias (identificar y confirmar)

`smcp/core/registro.py` — la pieza que une el flujo de
inferencia (`intercambio`) con el anclaje (`inscripcion`)
y el token (capa F).

Cada **completion exitosa** (status 200 de la inferencia)
produce un `InferenceRecord`:
- `txid` — la prueba en cadena (el ordinal viaja a Alice)
- `completed_at` — timestamp de la completion (reloj del nodo;
  la cadena da el *bloque*, el reloj da el *momento*)
- `mesh_id`, `server_pubkey`, `requester_pubkey` — identidades
- `pay_method` — `bsv`, `delm` o `both` (la red de incentivos:
  el nodo elige cobrar en sats, en DELM, o en ambos)
- `satoshis` y `delm_amount` — lo cobrado en cada moneda

El `InferenceServer` (capa de intercambio) registra la
inferencia en `settle()`: tras verificar, emitir por ARC y
contar, el libro guarda *cual* tx, *cuando* ocurrio y *como*
se cobro. El nodo puede cobrar en BSV (el flujo v3, 250 sats)
o en DELM (capa F, `pay_method="delm"`).

**Identificar una inferencia específica** (tres claves):
1. `txid` — la unica prueba en cadena
2. `inference_id` — `sha256(txid:mesh:server)` — id estable
3. `(mesh, server, ventana)` — consulta por rango temporal

**Que NO hace** (por decision, como `anchor.py`): no hashea
el contenido de la inferencia. Se prueba que ocurrio, no que
decia. El prompt y la respuesta viajan fuera de cadena.

**API** (consultable):
- `GET /api/inferences` — el libro (filtra por mesh, servidor, ventana)
- `GET /api/inferences/{txid}` — identifica una inferencia y confirma que ocurrió
- `GET /api/inferences/totals` — totales (inferencias, sats, DELM)

Cubierto por `tests/test_registro.py` (9) y dos tests de
union en `tests/test_intercambio.py` (completion→timestamp→
registro→cobro, en BSV y en DELM).

## Release 0.4.0 — La malla en vivo

La malla deja de ser una biblioteca de pruebas y se convierte
en una **superficie operativa de punta a punta**: un operador
abre la consola, ve la malla en 3D con nodos reales, lanza un
run contra un modelo local y cada inferencia admitida queda
anclada a la cadena de bloques BSV con su timestamp.

- **Consola Motor** — runs asincronos por SSE con cancelacion
  en vivo (ya no hay una peticion que bloquea 240 s); modo
  Proyecto intacto.
- **Malla 3D** — peers reales de `/api/mesh`: tamano = raiz de
  la VRAM, color vivo/muerto, halo ambar por VRAM reservada,
  posicion estable por identidad, ficha completa por nodo.
- **Persistencia de runs** — al recargar, el run activo se
  reanuda en vivo (SSE con replay).
- **Inferencia real admitida** — el gist es un span literal del
  trajectory; el pipeline contra Qwen3.8-27B-GGUF local admite
  en 1 intento (46.6 s, gist firmado ed25519, contexto size 1).
- **Anclaje BSV** — una transaccion por inferencia, sin hashear
  el contenido; firma secp256k1, inclusion Merkle, verificacion
  contra cabecera.
- **Tres tiers** — precios que se cruzan en 1.000 inferencias;
  x402 en el tier metered.

Detalle por cambio: [`CHANGELOG.md`](CHANGELOG.md).

---

No es una copia del repositorio de referencia de DeLM: es una re-derivación del
mismo núcleo, expresada como una librería pequeña y testeable, con una capa de
seguridad (proveniencia, integridad y anti prompt-injection) que el paper no
incluye.

---

## Para qué sirve

### 1. Contexto compartido entre agentes (`C`)

DeLM sustituye al orquestador central por dos estructuras globales:

- un **contexto compartido** `C` — gists compactos y *verificados* del progreso
  acumulado, visibles para todos los agentes; y
- una **cola de tareas** `T` — subtareas pendientes que los agentes reclaman
  de forma asíncrona (con dependencias).

Un agente reclama una tarea, lee un *snapshot* de `C`, razona en local y escribe
un gist que se **comprime, verifica contra su evidencia y admite** en `C` solo
si pasa. El progreso intermedio deja de ser un mensaje efímero y se convierte
en **estado reutilizable**. Eso es lo que los agentes repartidos por la malla
comparten: no un result chunk, sino estado verificado.

### 2. VRAM compartida, verificada, pagada en satoshis

Cada nodo declara su capacidad; la malla **no se la cree**: la exige firmada,
ligada a un reto de un solo uso, con caducidad, y encadenada en un log de
admisiones. El único dinero es el **satoshi**, y se mueve en la cadena
(`smcp/core/tiers.py` fija los precios; `x402` verifica el pago de una
inferencia; `anchor.py` demuestra que ocurrió).

**No hay moneda interna.** Hubo una: un "crédito" float que un nodo ganaba por
GiB y hora y gastaba por petición. Se eliminó, y el motivo es la línea que
decide el diseño: **un nodo que gana por existir no tiene ningún incentivo para
servir a nadie.** Una caja de 16 GiB enchufada generaba valor sin haber hecho
una sola inferencia, que es exactamente lo contrario de "a cambio reciben
acceso a inferencia" — y una invitación a mantener una flota de máquinas
paradas a cargo de otro.

Lo que queda donde estaba el saldo es un **contador**: cuántas inferencias **de
la red** ha servido cada nodo (`smcp/core/reputation.py`). No se gasta, no se
transfiere, no compra nada. Es el ranking que un nodo enseña al resto para que
sepan cuánto ha servido, y sube **solo** con un ancla verificada en la que el
solicitante es **otro** nodo: ejecutar inferencia contra uno mismo no se ancla.

### 3. Reparto de las capas de un modelo entre varios nodos

Un 27B Q4 no cabe en una tarjeta de 16 GB. Repartido, sí. `smcp mesh plan`
**dimensiona el modelo con llmfit, decide qué nodos lo alojan y en qué
proporción, lo admite o lo rechaza con un motivo, y produce un plan
determinista** que se puede loguear y comparar entre observadores.

> **SMCP planifica y admite; MeshLLM ejecuta.** El runtime de inferencia
> pipeline-parallel entre hosts es trabajo de MeshLLM/vLLM, no de aquí: SMCP no
> reimplementa el transporte de tensores, decide *quién hospeda qué* y entrega
> un plan auditable. La ejecución es la API OpenAI-compatible de la malla.

### Lo que este proyecto **no** es

- **No hay mejora recursiva (RSI).** Hay código de exploración en
  `smcp/core/{rsi,hci}.py` y su demo, con sus tests, pero **no forma parte de la
  tesis** ni de la hoja de ruta: está pendiente de decidir *dónde* y *cómo*
  encaja (ver `TODO.md`).
- **No hay atestación de hardware.** Una capacidad declarada es una afirmación
  firmada por una identidad, no una prueba de que esa VRAM existe. Lo que se
  garantiza está escrito en [`docs/threat-model.md`](docs/threat-model.md) y lo
  repite cada salida de `smcp mesh check`.
- **No hay modelo de negocio, ni stake, ni slashing.** La honestidad aquí es
  *acotada y auditable*, no absoluta.

---

## Qué incluye

> **Doc de referencia:** [`docs/architecture.md`](docs/architecture.md) — la
> arquitectura por capa (piezas, interfaces, flujos),
> [`docs/threat-model.md`](docs/threat-model.md) — quién es el adversario, qué
> garantiza cada capa de seguridad y **qué no**, y
> [`docs/inscripcion-v3.md`](docs/inscripcion-v3.md) — la especificación de
> la inscripción de inferencia v3 (el template de la tx, los BRC que adopta
> y lo que queda abierto). Este README es el "qué es";
> los docs son el "cómo está montado" y el "qué está garantizado".

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

> El detalle por capa, con adversario / garantías / **no-garantías**, está en
> [`docs/threat-model.md`](docs/threat-model.md). Léelo antes de describir esta
> capa como "segura": la lista de lo que **no** cubre es parte de la propuesta.

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

Tres módulos nuevos en `smcp.core` que cierran los huecos reconocidos en el
análisis, sin romper la disciplina del proyecto (deterministas, testeables,
sin LLM en el loop):

### Detector de inyección endurecido (`smcp.core.injection_hardened`)

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

### Métricas (`smcp.core.metrics`)

`MetricsTracker` registra coste/latencia por tarea: `timed()` como context
manager (mutable in-flight), precios por modelo (tabla 2026 orientativa,
overrideable), agregado con percentiles p50/p95, admit rate, retries,
breakdown por worker **y por modelo**, serializable a JSON para el ledger.
Si el bloque lanza, el registro se escribe igual con `admitted=False` y
`error`, y la excepción se re-lanza. `DelmPipeline` crea uno por defecto,
lo pasa a cada worker y vuelca el agregado en `PipelineOutcome.metrics`.

### Política de expansión (`smcp.core.expansion`)

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

### La CLI `smcp`

Un solo binario, una sola puerta de entrada. `smcp` y `python -m smcp` son **el
mismo parser** (`smcp/cli.py`), así que no pueden divergir.

```bash
smcp --help                     # o: python -m smcp --help
smcp version                    # versión + Python
smcp config-check               # resuelve la config de modelo (key oculta)
smcp fit                        # qué modelos caben en ESTA máquina (llmfit)
smcp fit --check                # ¿el modelo de la config cabe aquí? (2 si no)
smcp test                       # la suite; --slow para los tests lentos
smcp gates                      # los gates de calidad (ver abajo)
smcp demo                       # demo principal (pipeline, sin API key)
smcp demo --list                # lista las demos
```

Los siete subcomandos son `demo`, `test`, `config-check`, `fit`, `mesh`,
`gates` y `version`.

`config-check` resuelve la config con la **misma** precedencia que
`run_real_demo --dry-run` (entorno > YAML > default) y muestra la API key
**enmascarada** (`sk-s***7890`); sale con `0` si modelo y `base_url` resuelven, y
con `2` si no (para que un script pueda bifurcar sin parsear la salida).

`smcp demo <nombre>` despacha la demo **como subprocess** a su propio módulo
(`python -m smcp.demo.<módulo>`) y devuelve su código de salida. Motivo: cada
demo ya tiene su contrato (`main()`/`run()`, su propio reporte por stdout, y en
el caso multi-host sus propios procesos hijos), así que la CLI es un envoltorio
fino y honesto en vez de un segundo sitio donde haya que mantener la lógica. Los
flags de cada demo se pasan tal cual (`--nostr`, `--dry-run`, `--tasks`, …).

Equivalentes por demo (siguen siendo válidos y son los que usa la web/API):

| CLI                     | Equivalente directo                   |
| ----------------------- | ------------------------------------- |
| `smcp demo`             | `python -m smcp.demo.run_demo`        |
| `smcp demo security`    | `python -m smcp.demo.run_security_demo` |
| `smcp demo taint`       | `python -m smcp.demo.run_taint_demo`  |
| `smcp demo multihost`   | `python -m smcp.demo.run_multihost_demo` |
| `smcp demo rsi`         | `python -m smcp.demo.run_rsi_demo`    |
| `smcp demo real`        | `python -m smcp.demo.run_real_demo`   |
| `smcp test`             | `python -m pytest`                    |

### Dimensionar el modelo local: `smcp fit` ([llmfit](https://github.com/AlexsJones/llmfit))

Ser **agnóstico al modelo** no es lo mismo que estar **dimensionado**. Antes de
levantar un runtime local (MeshLLM, llama.cpp, vLLM, Ollama) hay que responder
una pregunta que nada en el repo respondía: *¿qué modelo cabe en esta máquina y
a qué velocidad?* Un Q2 de 27B va bien en una RTX 4060 Ti de 16 GB; un Q5 del
mismo modelo, no. [`llmfit`](https://github.com/AlexsJones/llmfit) lee el host
(RAM, núcleos, GPU/VRAM, backend) y ordena el catálogo por fit, velocidad,
calidad y contexto. `smcp fit` es la costura: `smcp/core/llmfit.py` lo invoca y
parsea su JSON, y la CLI lo convierte en tres vistas del mismo catálogo, de
menor a mayor compromiso.

```bash
smcp fit                                  # tabla: qué corre aquí (y a qué tok/s)
smcp fit -n 20 --use-case coding          # más filas, filtradas por caso de uso
smcp fit --all                            # incluye los que NO caben (too_tight)
smcp fit --sort tps --search qwen         # ordena y busca (en el lado de SMCP)
smcp fit --memory 24G --ram 64G           # simula otra máquina
smcp fit --profile ryzen-ai-max-plus-395  # un perfil de hardware de llmfit
smcp fit --json                           # para scripts y la API web

smcp fit --check                          # ¿cabe el modelo de la config? (2 si no)
smcp fit --check --json                   # el veredicto como dato, mismo exit code

smcp fit --write-config config/model_config.yaml            # persiste el top-1
smcp fit --write-config cfg.yaml --base-url http://127.0.0.1:9337/v1
```

Tres propiedades que hacen que esto sea integración y no un *wrapper*:

- **llmfit es una herramienta externa opcional, nunca una dependencia.** Se
  busca en `$DELM_LLMFIT_BIN`, en el `PATH` y, como último recurso, como
  `python -m llmfit` (el `pip`/`uv` del mismo proyecto). Si no está, la CLI
  explica cómo instalarlo y sale con `3` — nunca un traceback. Un
  `$DELM_LLMFIT_BIN` explícito que no funciona es un error de configuración y
  **no** cae al `PATH` en silencio.
- **`--check` cierra el círculo con `smcp/config.py`.** No pregunta "qué modelo
  es bueno" sino "**el modelo que el pipeline ya tiene configurado, ¿cabe aquí?**".
  Resuelve la config con la precedencia de siempre (entorno > YAML > default),
  busca ese id en el catálogo y sale con `2` si no cabe, proponiendo los que sí.
  Un id servido por un runtime local (`unsloth/Qwen3.8-27B-GGUF:UD-Q2_K_XL`)
  se normaliza a su fila del catálogo; un id que no está en el catálogo se
  informa como *desconocido* y **no** es un fallo — la config manda, llmfit
  asesora. El veredicto se calcula sobre el catálogo **completo**, nunca sobre
  la tabla filtrada: un modelo que no cabe es justo la fila que la vista
  esconde, y ningún filtro pedido para elegir otro modelo puede borrarlo.
- **`--write-config` es el paso que convierte el consejo en endpoint.** Escribe
  el top-1 como `model_config.yaml` para un runtime local, con el `quant` que
  eligió llmfit, el tamaño en disco frente al residente y la velocidad estimada
  en comentarios. Es lo único que toca el disco, y **nunca** pisa un archivo
  existente sin `--force`.

**Por qué el binario solo recibe flags globales.** En llmfit 1.1.16 el
vocabulario de filtros vive en `recommend` (`--use-case`, `--min-fit`,
`--runtime`, `--force-runtime`) y **no** en `fit`: `llmfit fit --use-case coding`
sale con `2` (*unexpected argument*). Pero `recommend` nunca devuelve filas
`too_tight`, así que un modelo que no cabe volvería "desconocido" en vez de "no
cabe" — y el veredicto es justo lo que `smcp fit` viene a dar. El reparto es por
eso **el binario trae, SMCP estrecha**: se llama a `fit` (catálogo completo) y
los filtros se aplican sobre las filas ya parseadas. Además, llmfit tiene *dos*
vocabularios para el mismo JSON — su CLI dice `fit_level: "Too Tight"` y su API
REST `fit_level: "too_tight"`, igual con `llama.cpp`/`LlamaCpp` — y el adaptador
los reconcilia en un solo sitio para que el resto del módulo solo vea códigos.

Lo que **no** hace: no modifica la config por su cuenta, no descarga modelos, no
sirve nada y no decide la arquitectura del mesh. `smcp fit` es un asesor
determinista con salida parseable; cambiar la config es una decisión explícita
del operador.

Cubierto por `tests/test_llmfit.py` (74 tests) con un ejecutable falso: la suite
no necesita el binario, ni red, ni GPU. Contra el llmfit de verdad hay un test
opt-in marcado `slow` que se salta si no está instalado. El payload falso habla
el vocabulario real de llmfit 1.1.16 a propósito (`"Too Tight"`, `"CPU+GPU"`,
`"llama.cpp"`), porque reconciliar las dos variantes de su JSON es justo lo que
se rompe si solo se prueba contra códigos limpios.

### La malla: `smcp mesh` (VRAM verificada ⇄ inferencia)

Aquí es donde las tres piezas se juntan. llmfit dice cuánta memoria pide un
modelo; la malla dice quién tiene VRAM *verificada*; DeLM comparte el `C` entre
los agentes que razonan sobre lo que la malla ejecuta.

```bash
smcp mesh                                     # = status: quién ofrece y cuánto ha servido
smcp mesh contribute --vram-gb 16 --vram-advertised-gb 8   # 16 físicos, ofrezco 8
smcp mesh observe  --peer-id local --seconds 3600   # "te he visto 1h viva" (no acredita)
smcp mesh infer    --peer-id local --txid <tx> --satoshis 100  # 1 inferencia anclada
smcp mesh reputation                          # el ranking de quién ha servido
smcp mesh plan "Qwen/Qwen3-32B"              # lo dimensiona llmfit y lo reparte
smcp mesh plan "Qwen/Qwen3-32B" --memory-gb 40 --layers 64   # sin llmfit
smcp mesh plan "Qwen/Qwen3-32B" --memory-gb 400; echo $?     # 2 = no cabe
smcp mesh tiers levels                       # los tres precios, y si x402 encaja en cada uno
smcp mesh tiers quote --inferences N [--dedicated] [--offers-vram]
smcp mesh anchor --anchor anchor.json --header header.json   # ancla de inferencia (sin contenido)
smcp mesh membership verify --proof proof.json --header header.json   # gate de pertenencia BSV
smcp mesh reserve --peer-id nodo-b --memory-gb 6     # tier de pago único
smcp mesh release  --reservation-id nodo-b#1
smcp mesh check                               # audita cadena e historial
smcp mesh --help
```

El ciclo completo, en la misma máquina, es este:

```console
$ smcp mesh contribute --vram-gb 16 --vram-advertised-gb 8   # 16 físicos, ofrezco 8
=== smcp mesh: contribución admitida ===
nodo       : local
firma      : ed25519 · digest 520427c288fce0fa…
capacidad  : 16.0G VRAM · 64G RAM · 12 núcleos · cuda
$ smcp mesh observe --peer-id local --seconds 3600
local: +3600s observado · inferencias servidas 0
nota: observar NO acredita nada. El historial sube solo con `smcp mesh infer`.
$ smcp mesh plan "Qwen/Qwen3-32B" --memory-gb 40 --layers 64
=== smcp placement ===
modelo   : Qwen/Qwen3-32B
memoria  : 40.0G requeridos · 48.0G verificados en la malla
veredicto : ok · 3 nodo(s)

  nodo                 memoria  vmax  ofrece  usa  disp    uso    layers
  nodo-b                 20.4G    24G   24.0G  0.0G  24.0G   85%     0-31    0.256
  nodo-a                 13.3G    16G   16.0G  0.0G  16.0G   83%    32-52    0.167
  nodo-c                  6.2G     8G    8.0G  0.0G   8.0G   78%    53-63    0.078
```

**Tres números de VRAM, porque son tres preguntas distintas:**

| número | qué es | quién decide | firmado |
|---|---|---|---|
| `vram_gb` | el máximo físico del hardware | el nodo (afirmación) | sí |
| `vram_advertised_gb` | lo que el dueño **ofrece** a la malla | el dueño | sí, anclado |
| `vram_shared_gb` | lo que la malla está usando ahora | telemetría | **no, a propósito** |
| `vram_available_gb` | `min(ofrecida, física) − usada` | derivado | derivado |

El plan se calcula **contra `vram_available_gb`**, nunca contra `vram_gb`. Un nodo
con 24 GB de los que ofrece 4 tiene 4 disponibles, y planificar contra la cifra
de cabecera admite planes que no van a funcionar. La diferencia entre
`total_vram_gb` y `total_advertised_gb` es la capacidad que los dueños están
decidiendo no compartir — un número que antes la malla no podía ver.

Lo que se reparte se decide con lo **ofrecido**, no con el hardware. Antes
inflar la cifra compraba enrutamiento *y* multiplicaba el pago, porque
`credits_per_gib_hour` usaba el mismo número para las dos cosas. Hoy no queda
nada que multiplicar: la reputación cuenta inferencias, y esas no dependen de
cuánto hardware se anuncie. Un nodo con 24 GB que ofrece 4 GiB es proveedor,
porque es lo que está dispuesto a compartir — y si no ofrece ninguno, es un
consumidor (`metered`) y no aparece en el ranking.

`vram_shared_gb` está fuera del digest firmado a propósito: cambia en cada
heartbeat, y anclarlo marcaría como manipulado a todo nodo honesto en menos de
un minuto. `capacity_claim_status()` cruza la afirmación firmada con la
detección local y señala `claim_exceeds_detected` **sin corregir** — detección y
afirmación vienen del mismo host por el mismo canal sin autenticar, así que
ninguna es evidencia.

Y lo que sigue en pie: **la capacidad es una afirmación firmada, no una
medición**. Quien quiera inflar de forma consistente solo tiene que mentir
también en su detección local. Eso exige un testigo externo.

### Reservas dedicadas (tier de pago único)

Un plan es JSON, y dos planes pueden nombrar el mismo nodo y los mismos GiB y
ser ambos válidos. Nada en un plan impide que el segundo despierte. Así que la
reserva es una reclamación mutable, bajo lock, sobre lo **disponible**:

```python
from smcp.core.reservation import ReservationBook
book = ReservationBook()
book.publish_snapshot(led.peers)              # línea base desde el ledger

res, why = book.reserve("nodo-b", 6.0, ttl_s=900.0)
# → ('nodo-b#1', 'reserved')   u   (None, 'not_enough_available')
book.move(res, "nodo-c")                      # failover: la carga cambia de nodo
book.release(res)
```

Tres cosas que no son obvias:

**Comprobación y cuenta en la misma sección crítica.** Leer el hueco libre y
luego incrementar es una doble venta esperando un tick de scheduler. Con
dieciséis hilos pidiendo 1 GiB contra 8 GiB, exactamente ocho ganan.

**La generación va en cada reserva.** Un snapshot es lo que un nodo *reporta*,
no lo que esta malla repartió: un informe anterior a una reserva no puede
conocerla. Por eso las reservas **sobreviven** a un snapshot — limpiarlas en
cada uno las liberaba en vivo y entregaba la misma VRAM al siguiente llamador.
Se re-marcan a la generación nueva y solo se descarta lo que ya no cabe.

**Reserva ≠ telemetría.** `vram_shared_gb` es lo que el nodo dice que usa;
`book.reservations` es lo que esta malla ha entregado. Son independientes y las
dos restan. Si el nodo informa de las reservas de la malla, se restan dos
veces: pesimista, que es la dirección correcta — la malla promete menos en
lugar de sobrevender.

`ReservationBook` **no se persiste**, a propósito. Una reserva es una promesa
sobre los próximos minutos de scheduling local; recargarla tras un reinicio
mantendría VRAM que nadie usa o liberaría VRAM que alguien prometió. Empezar
vacío es mejor que las dos cosas, y por eso una reserva no es un recibo de pago:
el lado del pago es un ledger, esto es un scheduler.

Cuatro propiedades que hacen que esto no sea un registro de promesas:

- **La capacidad se firma, no se cree.** La malla emite un reto de un solo uso
  (`Challenge`), el nodo responde con un `CapacityReport` firmado por su clave y
  ligado a ese reto, con caducidad. Repetir un "tengo 64G" de ayer no vale: el
  nonce se quemó. Y un `peer_id` queda **atado a su clave** para siempre
  (`peer_key_changed`), así que un nombre no se puede re-apuntar a otra clave
  para heredar el puesto de otro.
- **Estar vivo no cuenta para nada.** `observe` solo deja constancia de cuánto
  tiempo la malla ha visto al nodo; no acredita nada, y su salida lo dice para
  que nadie lo lea como un descuido. El historial sube por un único camino:
  `record_inference`, que exige ancla con txid y no cuenta dos veces la misma.
- **Solo se cuenta lo que pidió la red.** El ancla lleva el **solicitante**
  (`requester_pubkey`, formato v2) y se niega a construirse si es el propio
  nodo. Ejecutar inferencia contra uno mismo —lo más barato y lo más fácil de
  multiplicar— no deja registro, así que el ranking no se puede inflar solo.
- **El valor es el satoshi y va por la cadena.** `tiers.py` fija los precios
  (100 sat por inferencia en `metered`), `x402` verifica el pago y `anchor.py`
  prueba que la inferencia ocurrió. No hay saldo interno que alguien pueda
  gastar sin que nadie se entere.
- **Nada de lo que esto afirma es invisible.** Cada admisión —y cada
  **rechazo**— entra en una cadena de hashes (`verify_chain`) que sobrevive a un
  save/load, y `smcp mesh check` la verifica y dice, en mayúsculas, lo que no
  prueba.

`smcp mesh` y la web (página **Malla**, `smcp/web/static/malla.html`) comparten el fichero de
estado vía `smcp.core.contrib.default_state_path()`: aportar desde el navegador
se ve en `smcp mesh status` y al revés. Eso está fijado en un test que lanza la
CLI como subprocess.

Cubierto por `tests/test_contrib.py` (32), `tests/test_placement.py` (22),
`tests/test_mesh_cli.py` (25) y `tests/test_api_mesh.py` (20) — 99 tests, ninguno
necesita GPU, ni MeshLLM, ni llmfit instalado, y **ninguno escribe el estado real
de la malla** (todo va a `tmp_path`).


### Instalar

```bash
cd smcp
pip install -e .
```

Requiere Python 3.11+.

### SMCP como agente ACP (`smcp-serve`)

La integración canónica ([`DESIGNCOMPAT.md`](DESIGNCOMPAT.md), vía A): en vez de
que un tercero reimplemente el loop, SMCP **habla el protocolo** y se registra
como un agente más de su catálogo.

```bash
pip install "smcp[acp]"      # agent-client-protocol
smcp-serve                    # backend determinista (FakeLLMClient), sin key
smcp-serve --backend real     # endpoint real (DELM_MODEL / DELM_BASE_URL)
smcp-serve --check            # verifica el extra y sale
```

`smcp-serve` habla **ACP (Agent Client Protocol) por stdio** — JSON-RPC 2.0, el
mismo protocolo y el mismo `streamFormat` (`acp-json-rpc`) que ya usa Hermes.
Con OpenDesign es **un archivo**: `defs/smcp.ts` con `bin: 'smcp-serve'` + el
registro en `registry.ts`.

Cómo mapea:

- **una sesión ACP = un run de SMCP**: el prompt del editor se divide en tareas
  (una por línea), pasan por el `DelmPipeline` real (comprimir → verificar →
  admitir en el contexto firmado) y el resultado vuelve como `session/update`;
- `prompt` responde `end_turn` de inmediato y el run ocurre en background
  (es el contrato ACP: la salida llega como notificaciones);
- **`session/cancel`** aborta el run en vuelo (igual que `RunManager.cancel`
  de la API HTTP);
- lo que se reporta es lo que **se admitió** al contexto compartido, no lo que
  se intentó — que es justo la tesis del protocolo.

No reimplementa nada: es el mismo `DelmPipeline` que usa `/api/runs`, así que
un run ACP y un run HTTP son el mismo pipeline sobre la misma puerta de
admisión. `list_sessions` devuelve vacío a propósito (los runs son efímeros; lo
que persiste es el contexto compartido, no el historial), y `authenticate` es
no-op: el *trust anchor* de SMCP es la clave del owner, no un login.

### Extras (dependencias por transporte)

Las capas de red tienen dependencias opcionales declaradas como **extras** en
`pyproject.toml` (`[project.optional-dependencies]`):

```bash
pip install smcp[nostr]   # websockets  -> relay Nostr de red (capa 4)
pip install smcp[quic]    # aioquic     -> QUIC entre hosts (capa 3)
pip install smcp[mdns]    # aiozeroconf -> mDNS discovery (capa 4)
pip install smcp[web]     # fastapi + uvicorn -> la API y la web (:8099)
pip install smcp[acp]     # agent-client-protocol -> smcp-serve (agente ACP)
pip install smcp[docs]    # pdoc        -> doc generable de la API (opt-in)
pip install smcp[all]     # todos los anteriores
```

El núcleo (capas 1-5, firma, integridad, inmutabilidad, taint) **no necesita
extras**: corre con stdlib. El fallback HMAC (pre-shared key) también es stdlib
(no requiere `cryptography`), pero el **modo estricto** (default) hace que el
pipeline real no lo use sin que nadie lo note — ver
[Conocido/por diseño](#conocido--por-diseño).

### Demo sin API key

```bash
smcp demo                    # == python -m smcp.demo.run_demo
```

Muestra el pipeline de punta a punta: un corpus semilla entra a la cola, 4
workers paralelos reclaman, razonan y admiten sus gists, el gist de la unidad de
carga se despliega selectivamente (`G -> S -> raw`) y un finalizador produce la
respuesta solo a partir del contexto compartido.

### Demos de seguridad

```bash
smcp demo security           # Capas 1+2: firma, integridad, inmutabilidad, ledger
smcp demo taint              # Capa 5: cuarentena de prompt-injection
```

### Demo multi-host (capa 3 sobre red)

```bash
smcp demo multihost                 # QUIC (default): 2 nodos, procesos distintos
smcp demo multihost --nostr         # relay Nostr: 1 relay + 2 nodos
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
smcp test                  # == python -m pytest
smcp test --slow           # solo los tests marcados `slow` (handshake QUIC, subprocess)
```

Equivale a `python -m pytest` (los `addopts` por defecto son `-m 'not slow'`).
`smcp test --slow` añade `-m slow`, que **pisa** el `-m 'not slow'` de los
addopts (pytest aplica el último `-m`).

El suite está repartido en sesenta archivos, todos deterministas:

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
- `test_nostr_relay_guard.py` — capa 4: la **guardia del relay Nostr**
  (`NostrRelayServer`): rate-limit por `pubkey` (los excedentes se
  rechazan), dedup (reenvío del mismo `id` → un solo broadcast), límite de
  tamaño de evento (`max_event_bytes`) y snapshot/restore opcional
  (persistencia del estado: eventos aceptados + ids vistos + rate-limit).
- `test_deployment.py` — capa 4: discovery, relays, bootstrap (firma del
  owner) y control-plane (órdenes firmadas), y el transporte Nostr (in-memory
  y de red) swappable con `DiscoveryBus`.
- `test_mdns.py` — capa 4: discovery mDNS (`MdnsDiscoveryTransport`,
  swappable con `DiscoveryBus`).
- `test_quic_host.py` — transporte QUIC entre hosts: framing, round-trip
  y malla completa sobre sockets reales.
- `test_quic_identity.py` — enlace identidad-cert del QUIC (legítimo,
  MITM rechazado, insecure, `CN = peer_id`).
- `test_demo_multihost.py` — demo multi-host (2 nodos en procesos distintos):
  test de integración **slow** (handshake QUIC ~60-120 s) que verifica la
  convergencia sobre QUIC (default) y Nostr (`--nostr`).
- `test_hci.py` — métrica Headroom-Closed Index (Benchmark, BenchFamily,
  HCIMeter, DeterministicScorer, SMCP_FAMILY).
- `test_rsi.py` / `test_rsi_demo.py` — loop RSI L1: proponer/verificar/
  retener/sucesor + demo que mide el avance de HCI.
- `test_provenance_strict.py` — modo estricto del provenance (sin degradación
  silenciosa a HMAC).
- `test_harness_adapter.py` — adaptador DeepSeek Harness (import lazy,
  `build_client`, `DELM_HARNESS` opt-in).
- `test_owner_rotation.py` — rotación/revocación de la clave del owner
  (control-plane, cadena de confianza).
- `test_ledger_persistence.py` — persistencia append-only del
  `AdmissionLedger` (dump/load/export, opt-in).
- `test_meshllm_wiring.py` — wiring SMCP→MeshLLM (opt-in `slow`; se skipea
  sin endpoint; **2 passed** vs malla pública 2026-09-23).
- `test_meshllm_thesis.py` — la tesis contra un endpoint **real** (opt-in
  `slow`): report firmado → plan → inferencia de verdad → **ancla que verifica**
  → el historial sube. Tres casos: la cadena completa, dos inferencias reales
  seguidas, y que un endpoint caído no mueve el contador. Se skipea sin
  endpoint:
  `MESH_LLM_URL=http://127.0.0.1:9337/v1 python -m pytest tests/test_meshllm_thesis.py -m slow -v`.
- `test_cli.py` — la CLI unificada (issue #9): los subcomandos
  (`demo`/`test`/`config-check`/`version`), el despacho de cada demo a su módulo,
  el passthrough de flags, `--slow` pisando el `-m 'not slow'` de los addopts,
  el enmascarado de la key en `config-check`, y que `python -m smcp` funciona
  como subprocess (el contrato público).
- `test_contrib.py` — el intercambio: reto de un solo uso y caducidad (replay,
  reto/informe vencidos, reto ligado al par, malla equivocada), firma que ata
  los números (inflar la VRAM tras firmar invalida el digest), el `peer_id`
  atado a su clave, la cadena que detecta manipulación y persiste los rechazos,
  y la **reputación**: que solo cuente un ancla con txid, que la misma
  transacción no cuente dos veces, que un nodo sin VRAM ofrecida no cuente, y
  que `observe` no acredite nada. Incluye el test que **fija la limitación**:
  una afirmación firmada pero falsa se admite (no hay atestación de hardware),
  y por eso es auditable.
- `test_reputation.py` — el ranking: ordena por inferencias servidas (no por
  VRAM anunciada), separa los satoshis del mérito en su propia columna, deja al
  consumidor visible y marcado, y reconstruye el número desde anclas
  verificadas contra una cabecera. Incluye que **sin cabecera no cuenta nada**
  (un ledger sin verificar es una afirmación) y que el historial no es un
  saldo — fijado por ausencia de API.
- `test_placement.py` — el reparto: rechazo con motivo y *cuánta* VRAM falta,
  que no se use capacidad no admitida ni sin crédito, la exclusividad del
  orden greedy (más VRAM primero), la suma exacta de stages, los rangos de capas
  que teselan `[0, n-1]`, el plan por memoria cuando no se conocen las capas,
  determinismo byte a byte y round-trip para replay de auditoría.
- `test_mesh_cli.py` — `smcp mesh`: la identidad se crea una vez y se reutiliza
  (si no, ninguna contribución sería atribuible), dos "nodos" contra el mismo
  estado (que es una malla), `plan` dimensiona con llmfit o se la salta con
  `--memory-gb`, `check` detecta la cadena alterada, y un estado de otra malla no
  se mezcla. Ningún camino imprime la clave privada.
- `test_api_mesh.py` — la misma superficie en la web, con el test de que **CLI y
  web ven la misma malla** (la API escribe y un subprocess de `smcp mesh status`
  lo lee).
- `test_llmfit.py` — la integración con llmfit: el parseo de sus filas y su
  hardware, los filtros/orden/veredicto, el descubrimiento del binario
  (`$DELM_LLMFIT_BIN` → `PATH` → `python -m llmfit`) y sus fallos (no instalado,
  sale con error, no-JSON, timeout), y el subcomando `smcp fit`: la tabla,
  `--check` (incluido el caso en que el modelo no cabe y la tabla lo oculta),
  `--write-config` sin pisar un archivo existente, y que la API key nunca se
  imprime. Con un ejecutable falso, así que no necesita el binario ni GPU.
- `test_api_fit.py` — la superficie web de `smcp fit`: `/api/fit` (filtros
  validados, tabla, hardware, y el veredicto juzgando el catálogo entero —la
  fila `too_tight` que la tabla esconde—) y `/api/fit/apply` (escribe la config
  con las notas de llmfit, conserva el `base_url` existente, nunca ecoa la key,
  y funciona aunque llmfit no esté). El config se redirige a `tmp_path`.
- `test_api_actions.py` / `test_api_config.py` / `test_api_demo.py` /
  `test_api_inspect.py` / `test_api_runs.py` — la API interactiva de
  `smcp/web/app.py` + `smcp/web/api.py`: las acciones de sesión (scan, taint, config,
  export del ledger, SSE, meshllm), las demos in-proceso, la inspección del
  contexto y el gestor de runs (35 tests en total).
- `test_serve.py` — `smcp-serve` (SMCP como agente ACP): los helpers de prompt
  y tareas, que el módulo importe **sin** el SDK (el extra es opcional), el
  ciclo de vida ACP (initialize/new_session/prompt/cancel/close), que un prompt
  corre el `DelmPipeline` real y emite `session/update` al cliente, que
  `list_sessions`/`authenticate` son no-ops honestos, y un smoke **slow** que
  habla JSON-RPC real por stdio con `python -m smcp.serve`.

### Web UI y API

```bash
pip install smcp[web]        # fastapi + uvicorn
smcp-serve-web                # http://127.0.0.1:8099
```

El servidor es ahora **superficie del paquete** (`smcp/web/`), no un script
suelto en la raíz del repo: `pip install smcp[web]` instala el servidor y los
estáticos que sirve, y la UI funciona igual instalada que en desarrollo.

Lo único que necesita un checkout es correr **la suite** y contar
`tests/` / `smcp/core/`. Sin checkout, `/api/status` responde `repo: false`
con la lista de lo no disponible, y `POST /api/run/tests` devuelve un motivo
accionable en vez de un error de pytest — es una degradación explícita, no
un cero silencioso que la UI leería como "el proyecto tiene cero tests".

`smcp-serve-web` expone:

- `/api/functions` — lista de funciones (demo, seguridad, taint, multi-host, tests).
- `/api/run/<id>` — lanza la función (subprocess) y devuelve JSON.
- `/api/status` — estado en vivo del filesystem: módulos core, archivos/`def test_`, demos, páginas web.
- `/api/fit` — qué modelos caben en **este** host (llmfit) + el veredicto
  sobre el modelo de la config. Filtros: `limit`, `use_case`, `min_fit`,
  `runtime`, `sort`, `search`, `include_too_tight`, y overrides de hardware
  (`memory`, `ram`, `cpu_cores`, `max_context`). llmfit ausente **no** es un
  error HTTP: responde `available: false` + `hint` para que la UI pueda pintar
  la instalación.
- `/api/fit/apply` — adopta un modelo de la tabla como config (el mismo
  escritor que `PUT /api/config`, con el veredicto de llmfit en comentarios).
- `/api/mesh` — el intercambio: quién aporta VRAM verificada, su crédito y la
  integridad de la cadena.
- `/api/mesh/contribute` — firma la capacidad de este nodo y la admite (crea la
  identidad si no existe). Rechazos → `400` con el motivo, y **quedan
  registrados** en la cadena.
- `/api/mesh/observe` — marca el nodo como observado. **No acredita nada**
  (responde `credits_accrued: false`): el uptime es procedencia, no historial.
- `/api/mesh/infer` — cuenta **una inferencia verificada** en el historial del
  nodo. Es el único camino del ingreso: exige txid, no admite dos veces la misma
  transacción, y rechaza a quien no ofrece VRAM (`not_a_provider`).
- `/api/mesh/reputation` — el ranking: inferencias servidas por nodo.
- `/api/mesh/plan?model=…` — plan de reparto (dimensiona con llmfit salvo que se
  pase `memory_gb`). `llmfit` ausente no es un error HTTP: `available: false` +
  `hint`.
- `/api/mesh/check` — auditoría: cadena, rechazos, saldos, y lo que no prueba.
- `/` — estático de `web/` (11 páginas: inicio, núcleo, seguridad, demos,
  arquitectura, lab, contexto, ledger, **estado en vivo**, **malla**, consola 3D).

`smcp/web/static/estado.html` + `smcp/web/static/assets/estado.js` leen `/api/status` en vivo y permiten
lanzar suite/demo/taint desde el navegador. `smcp/web/static/assets/fit.js` añade la
sección **Modelo local (llmfit)**: los filtros de `smcp fit`, la tabla, el
veredicto en rojo/verde/neutro y un botón *usar* por fila que llama a
`/api/fit/apply` y refresca la config mediante el evento
`smcp:config-changed` (los dos módulos de la página no se conocen entre sí).
`smcp/web/static/malla.html` + `smcp/web/static/assets/malla.js` son la página **Malla**: el intercambio
y el reparto de modelos (contribuir, observar, planear, auditar). Comparte
fichero de estado con la CLI, así que lo que se aporta en el navegador se ve en
`smcp mesh status`. `smcp/web/static/assets/app.js` guarda la última página en `localStorage`
y la restaura al volver al home.

### Usar un modelo real

La config de modelo se resuelve con `smcp/config.py`: **entorno > YAML >
default**. La API key **solo por entorno** (nunca en el YAML ni en el repo).

```bash
# config/model_config.yaml (git-ignored)
#   model: unsloth/Qwen3.8-27B-GGUF
#   base_url: http://127.0.0.1:8888/v1
#   api_key: ""            # se inyecta por entorno, nunca por archivo
export DELM_API_KEY="..."   # o bien: export OPENAI_API_KEY="..."
python -m smcp.demo.run_real_demo --tasks 4 --workers 4
```

`load_config()` lee `DELM_MODEL`/`DELM_BASE_URL`/`DELM_API_KEY` (o `OPENAI_*`)
y el YAML de `config/model_config.yaml`; `build_client()` devuelve un
`OpenAICompatibleClient` listo para `DelmPipeline`. `run_real_demo` muestra la
config resuelta (ocultando la key) antes de correr y avisa si falta el modelo.

O, programáticamente:

```python
import asyncio
from smcp.core.llm import OpenAICompatibleClient
from smcp.core.pipeline import DelmPipeline
from smcp.core.task_queue import Task

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

### Los gates, en un comando

Los gates de calidad estaban en cuatro sitios que había que recordar y mantener
por separado: el workflow del CI, `smcp test`, un
`scripts/check_readme_count.py` invocado por ruta, y el README. Una lista de
gates duplicada es una lista que **se puede encoger sin que nada falle**: el
build se debilita en silencio.

Ahora la lista vive una sola vez, en `smcp/core/gates.py`, y tanto la CLI como
el CI la llaman:

```bash
smcp gates                    # todos: readme, ruff, pyright, tests, slow
smcp gates --blocking         # los que bloquean el commit (sin `slow`)
smcp gates ruff pyright       # gates concretos
smcp gates --list             # qué hay, y si está instalado
make help                     # los mismos, como atajos
```

Se para en el primer fallo: un lint roto no debería costar 50 s de suite para
descubrirlo. Y un gate cuya herramienta no está se reporta como **omitido**, con
nombre y qué instalar — nunca como verde, porque un linter ausente que se
reporta como `ok` es cómo un proyecto deja de linterse sin que nadie lo note.

| Gate      | Qué comprueba                                            |
| --------- | -------------------------------------------------------- |
| `readme`  | el conteo de tests del README cuadra con la suite         |
| `ruff`    | lint                                                     |
| `pyright` | type-check                                               |
| `tests`   | suite completa (el default de pyproject excluye `slow`)  |
| `slow`    | tests marcados `slow` (handshake QUIC, subprocess)       |

## Progreso actual

**Hecho y verificado:**

- **Núcleo DeLM completo** — contexto, cola con dependencias, admisión con
  verificación, despliegue selectivo, workers paralelos, finalizador. Corre de
  punta a punta sin API key.
- **Capas 1+2 integradas por defecto** — el pipeline firma cada gist y el
  contexto seguro verifica; no es un módulo opcional, es el camino por defecto.
- **Capa 5 integrada por defecto** — la cuarentena de prompt-injection corre en
  el render y en el despliegue; el detector escanea el texto *y* el `raw`.
- **1260 tests en verde** (14 núcleo + 18 seguridad + 10 persistencia: dump/load
  /export del `AdmissionLedger` (append-only, opt-in) + 8 rotación: rotación/
  revocación de la clave del owner (control-plane, cadena de confianza) +
  15 taint + 31 mejoras + 16 config + 2 wiring + 83 capa 3: 13 gossip +
  12 requirements + 10 heartbeat + 17 malla: transport/nodo/red/pipeline +
  QUIC e2e + Nostr e2e +    4 QUIC entre hosts: framing/round-trip/malla completa/close que
   drena las salidas +
  4 identidad: el enlace identidad-cert del QUIC (legítimo/MITM/insecure/
  `CN=peer_id`) + 19 Nostr: BIP340 contra los 19 vectores + relay de red +
  NostrTransport + convergencia + 5 guardia de relay (rate-limit por `pubkey`,
  dedup, límite de tamaño, snapshot/restore, default efímero) +
  21 capa 4: 13 discovery/relays/bootstrap/control-plane + transporte Nostr
  de red + 8 mDNS: discovery swappable con `DiscoveryBus` (el contrato de
  `DeploymentNode` no cambia) + 9 provenance estricto: no degrada a HMAC en
  silencio (lanza en estricto, warning en no-estricto) + 6 adaptador DeepSeek
  Harness (import lazy, `build_client`, `DELM_HARNESS` opt-in) +
  1 demo multi-host (convergencia sobre QUIC) +
  34 RSI/HCI (fuera de tesis, ver abajo): 9 loop L1 + 3 demo RSI (HCI
  10.48→21.19) + 22 métrica HCI (Benchmark/BenchFamily/HCIMeter/
  DeterministicScorer) +
  19 CLI base: los subcomandos `demo`/`test`/`config-check`/`version`, el
  despacho de demos, `--slow` y el enmascarado de la key (`fit` y `mesh` tienen
  suite propia) +
  74 llmfit: el adaptador (el vocabulario real de llmfit 1.1.16 —`fit_level`
  humano de su CLI y código de máquina de su API, `llama.cpp`/`vLLM`,
  `category`—, filtros, orden, veredicto, runner con descubrimiento y errores)
  y el subcomando `smcp fit` (tabla, `--check` con su exit code,
  `--write-config` sin pisar, llmfit ausente como exit `3`) +
  19 `/api/fit*` (validación de filtros, veredicto sobre el catálogo entero,
  cero secretos, el escritor de config compartido con `PUT /api/config`) +
  33 del intercambio (reto de un solo uso y caducidad, firma que ata los
  números, `peer_id` ligado a su clave, cadena con rechazos persistentes, y la
  reputación: solo cuenta un ancla con txid, la misma transacción no cuenta dos
  veces, un nodo sin VRAM ofrecida no cuenta, y `observe` no acredita nada) +
  15 de reputación (orden por inferencias, satoshis en su columna, consumidor
  marcado, board verificado contra cabecera, y sin cabecera no cuenta nada) +
  18 del reparto (rechazo accionable, la puerta de proveedores, exclusividad
  del greedy, suma exacta de stages, capas que teselan `[0, n-1]`,
  determinismo y replay) +
  27 de `smcp mesh` (identidad persistente, dos nodos sobre un estado,
  `infer`/`reputation`, `plan` con y sin llmfit, `check` que detecta la cadena
  alterada) +
  23 de `/api/mesh/*` incluido el que comprueba que CLI y web ven la misma malla,
  y el que fija que observar no acredita +
  32 del ancla (el solicitante es obligatorio y distinto del nodo: sin eso,
  inferencia local y petición de red serían lo mismo) +
   60 anclaje a BSV (Fase 1): 26 bytes canónicos del ledger (v1/v2 y por qué v1
   no era reproducible), 18 wallet SPV (BRC-75 maestro, BRC-42 derivación,
   BRC-43 `keyId`) + 16 anclaje (identidad secp256k1, reloj del nodo,
   rebroadcast frente a reemplazo en mempool) +
   38 del template SMCP3 (v3): 23 inscripción (el hash `H` compromete
   (mesh_id, solicitante) con prefijo de longitud y nada más; el envelope
   BRC-160 rueda construir→parsear con el body de último; el flujo DPP
   construye una tx que verifica; cada manipulación —hash, firma, fondeo,
   cerradura, inclusión— se rechaza con su motivo) + 15 txbuild (el
   serializador BSV —legacy, BSV no tiene segwit—: varints, pushes, P2PKH,
   DER desde `r‖s`, txid; y el sighash legacy completo —ALL/NONE/SINGLE/
   ANYONECANPAY, `FindAndDelete` de OP_CODESEPARATOR— contra los vectores
   de `sighash.json` de Bitcoin Core) +
   41 del roster (membresia explícita por avales firmados: el fundador es
   su propio primer avalado; la reconciliación pinnea solo lo que un miembro
   que ya se tiene avaló —iteración a punto fijo, confianza transitiva,
   acotada por profundidad—; un aval de un extraño no pinnea nada; re-key y
   cluster ajeno se rechazan; el epoch es monotonicidad firmada, no reloj;
   y el fingerprint no es la autoridad —la clave completa sí—) +
   6 de tesis del intercambio encadenada de punta a punta (publicar capacidad
  firmado → la malla coloca carga → otro nodo pide una inferencia → el ancla lo
  demuestra contra la cabecera → y solo entonces el historial sube), y el
   caso que la hipótesis descartaba: un ancla auto-solicitada no llega a
   construirse +
   15 ARC (el cliente de emisión: hex crudo en texto plano,
   `X-WaitFor`/`X-MaxTimeout`/`Authorization`, *problem details*
   RFC 7807, sondeo hasta el `PaymentACK` y el chequeo de txid
   contra la tx local) +
   6 intercambio (la secuencia v3 de punta a punta: pedido,
   inferencia, PaymentTerms, Payment firmada, emisión por ARC,
   PaymentACK y solo entonces el historial y el ranking) +
    5 join (el join v3: gratis y off-chain — dos nodos se avalan
    en el roster, confianza mutua verificada sin gastar nada;
    y el join con el intercambio componen el flujo) +
     9 mensajería (la secuencia v3 **por el transporte**: los
     mensajes 0x08-0x0D en JSON con `request_id`, y los actores —
     Alice pide, verifica y firma; Bob sirve y cobra; y el join
     por el wire: handshake BRC-103 en los dos sentidos y
     rosters cruzados dos veces (crudo y con avales), con el
     MITM que no pinnea nada y el replay que no verifica— sobre
     el bus in-memory, cada par en su hilo) +
     3 malla-v3 (la v3 **dentro del bucle del nodo**: el
     despachador `MeshV3` mantiene un `JoinWire` por par y
     el respondedor de inferencias, y el nodo enruta cada
     datagrama a su plano en el mismo drenaje que el gossip
     — join e intercambio corren en `run_tick`, sin hilos
     aparte— y las herramientas se **descubren al arrancar**:
     el modelo que MeshLLM ofrece (`/models`) y el llmfit
     del host con su versión, con el reporte diciendo lo
     que falta) +
  21 ACP (`smcp-serve`: handshake, ciclo de vida, el contrato de firmas de los
  overrides contra `acp.Agent`, prompt con el pipeline real, cancelación, smoke
  JSON-RPC por stdio) +
  35 API: 12 acciones de sesión (scan, taint, config, export del ledger) +
  7 demos in-proceso + 7 inspección del contexto + 6 gestor de runs +
  3 config +
  4 demos que pasan. 10 tests `slow` se excluyen del default
  (`-m 'not slow'`): handshake QUIC multi-host, adaptador Harness, llmfit real,
  el smoke ACP por stdio y los 3+2 de la malla contra un endpoint real
  (`test_meshllm_thesis.py`, `test_meshllm_wiring.py`, opt-in).
- **Agnóstico al modelo** — el mismo pipeline corre con `FakeLLMClient` (demo)
  o con cualquier endpoint OpenAI-compatible (producción).
- **Modelo local dimensionado por hardware** — `smcp fit` (`smcp/core/llmfit.py`)
  responde qué modelos caben en el host, verifica contra la config que el
  pipeline realmente usa (`--check`, sale `2` si no cabe) y puede persistir el
  top-1 como `model_config.yaml`. llmfit es una dependencia **externa
  opcional**: el install base no cambia.

- **Config de modelo real de serie** — `smcp/config.py` resuelve la config
  (entorno > YAML > default), la API key solo por entorno, y
  `run_real_demo` corre el pipeline contra un endpoint real; la wiring está
  probada de punta a punta por `test_real_model_wiring.py`.

**Hecho y verificado (la malla como intercambio):**

- **La malla tiene modelo de recurso, sin moneda** — `smcp/core/contrib.py`:
  `Challenge` (reto de un solo uso) + `CapacityReport` (capacidad firmada,
  ligada al reto, con caducidad) + `ContributionLedger` (admisión con motivo,
  cadena de hashes que sobrevive a save/load, e `record_inference` — el único
  camino del historial). Ni `ExchangePolicy` ni saldos: el valor es el satoshi
  y se mueve en la cadena. 33 tests.
- **La reputación es historial, no saldo** — `smcp/core/reputation.py`: el
  ranking de inferencias servidas por nodo, con el board verificado
  (reconstruido desde anclas contra una cabecera) junto al cheap de contadores.
  15 tests.
- **El reparto de un modelo entre nodos** — `smcp/core/placement.py`:
  `ModelSpec` (se construye desde una fila de llmfit) + `plan_placement` (greedy
  por VRAM verificada, `PlanReject` accionable, y la puerta de **proveedores**:
  solo se coloca carga donde el nodo ofrece capacidad). 18 tests.
- **Las tres piezas en una sola superficie** — `smcp mesh
  {status,contribute,observe,plan,check}`, `/api/mesh*` y la página **Malla**
  (`smcp/web/static/malla.html`), las tres sobre el **mismo fichero de estado** (lo resuelve
  `smcp.core.contrib.default_state_path()`; hay un test que aporta por HTTP y lo
  lee con la CLI en subprocess). 45 tests.
- **Identidad persistente** — `KeyPair.save`/`load` (ed25519, `chmod 600`): sin
  esto, cada `contribute` regeneraría la clave y ninguna contribución sería
  atribuible a un nodo. **Rechaza persistir una clave HMAC**: su mitad privada
  *es* el secreto compartido, o sea, el trust anchor del verificador.
- **La inscripción de inferencia v3 (SMCP3)** — `inscripcion.py` +
  `txbuild.py`: una tx por inferencia — pago y anclaje son la misma
  transacción. Alice paga 250 sats; el ordinal de 1 sat es el comprobante
  (envelope BRC-160 en el locking script: `H = SHA-256(len‖mesh_id‖
  solicitante)` + la firma del servidor sobre `H`, BRC-220) y viaja a
  Alice; Bob cobra el resto menos la fee de la tx. El **txid** es la clave
  que cuenta el historial: una inferencia = una inscripción = un txid.
  42 tests (incluida la medición de la fee de relay: la plantilla
  serializa 452–453 bytes y, con el precio de 250 sats (presupuesto
  de fee de 249), cierra hasta ~0.55 sat/vB — cubre la banda objetivo
  de 0.1–0.5 entera; `relay_budget()`, ver doc).
- **Emisión por ARC y la secuencia completa** — `arc.py` +
  `intercambio.py`: DPP (BRC-27) sobre ARC (el servicio de emisión de BSV,
  no un nodo): `serve` ejecuta la inferencia y construye los `PaymentTerms`
  (la respuesta viaja off-chain); `sign_payment` verifica antes de firmar
  del lado del solicitante; `settle` emite por ARC (`POST /v1/tx`, hex
  crudo, `X-WaitFor`), espera el estado aceptado —el `PaymentACK`— y
  **solo entonces** cuenta con `record_inference` (sin VRAM anunciada o
  txid repetido, lanza). 21 tests.
- **El join v3: gratis y off-chain** — `join.py` sobre `roster.py`: dos
  nodos se emparejan (intercambio de claves, avales mutuos,
  reconciliación confiando solo en lo que ya se confía) y la confianza
  mutua queda **verificada** sin gastar nada. `JOIN_SATOSHIS` pasó de 1 a
  0: el freno Sybil es el trabajo —cada inferencia servida cuesta una fee
  que paga el servidor, lineal con el fraude—, no la entrada. 5 tests.
- **Identidad en el join (BRC-103)** — `identidad.py`: el intercambio de
  claves afirmaba la clave del par sin probar que la controla; ahora un
  handshake simétrico (cada lado genera un nonce de 32 bytes y firma
  `nonce_del_par ‖ nonce_propio` con la misma clave que avala el roster)
  prueba el control vivo de ambas claves, ligado a la sesión. `pair()`
  verifica la sesión **antes** de intercambiar nada y falla cerrado si
  alguna prueba no cuadra (MITM o bug) — sin sesión, el intercambio
  simple sigue disponible y `authenticated` (`True`/`False`/`None`) lo
  dice. BRC-52 (certificados con revelación selectiva) queda como opción
  sobre este handshake: necesita una política de certificadores. 8 tests.
- **Fee por defecto del intercambio, medida** — `intercambio.py`: una tx
  sin fee no la reenvía ningún nodo con relay normal, así que el default
  dejó de ser 0: `DEFAULT_FEE_SATOSHIS = 50` es la **fee media de BSV
  medida el 2026-10-08** (WhatsOnChain: tasa media en bloque ~0.11
  sat/vB, tx mediana ~180 sats, pools mayoritarios desde ~0.07, el más
  estricto 0.5) aplicada al tamaño fijo de la plantilla (453 B). Fija en
  sats porque el template fija el tamaño; Bob cobra 199 de 249. El knob
  sigue siendo `fee_sats`.
- **x402, ahora BRC-120** — `x402.py`: el verificador del role de
  verifier de la x402 v1.0 congelada (challenge/proof en
  `X402-Challenge`/`X402-Proof`, binding determinista de la petición,
  protección de replay por el nonce UTXO de la capa de liquidación, sin
  estado por cliente). Es el mecanismo natural de `metered`, y solo de
  él. 67 tests.

**En construcción / pendiente:**

- **La inscripción v3: lo abierto, decidido y escrito** —
  `docs/inscripcion-v3.md` §Abierto: `hash(resultado)` (SMCP4) y batching
  (BRC-220 modo *batch*, BRC-122 — rompe "una inferencia = una tx") son
  decisiones pendientes, y BRC-77 queda como opción de interoperabilidad.
  Cerrados por trabajo real: la fee de relay (medida: 452–453 bytes;
  el precio subió de 100 a 250 sats para que el presupuesto de 249
  cierre la banda de 0.1–0.5 sat/vB — hasta ~0.55; el default del
  software, 1 sat/vB, sigue sin cerrar y el knob es
  `PER_INFERENCE_SATOSHIS`) y la identidad en el join (BRC-103,
  handshake simétrico en `identidad.py`; BRC-52 como opción sobre él).
- **Dónde y cómo entra el RSI** — el código de exploración (`rsi.py`, `hci.py`,
  `run_rsi_demo.py`, sus tests) sigue en el repo y en verde, pero **no es parte
  de la tesis** ni de la hoja de ruta. Está por decidir si el bucle de mejora
  recursiva se aplica (a) a la política de la malla —reparto, tarifas, admisión—
  que es donde ya hay un bucle `observar → decidir → verificar → retener` con
  ledger, o (b) a los agentes que razonan sobre `C`. Ver `TODO.md`.
- **La ejecución del reparto es de MeshLLM** — SMCP produce el plan y el
  endpoint; el runtime pipeline-parallel entre hosts es de MeshLLM/vLLM. La
  integración pendiente no es de código aquí sino de contrato: publicar el plan
  en el formato que el executor consuma y poder auditar después qué se ejecutó
  frente a lo que se planificó.
- **Atestación de capacidad** — hoy una capacidad es una afirmación firmada
  (ver `docs/threat-model.md`). Subirla a atestación real (TPM/SGX, o
  challenge de *hardware* sobre la GPU) es el salto que convierte "honesto" en
  "verificable"; también el sitio natural donde encajaría slashing.
- **El intercambio no viaja por la malla todavía** — la cadena de contribuciones
  es local al estado de cada vista; falta el datagrama que la propaga y el
  gossip de capacidades (el hueco natural: `PeerAnnouncement.capabilities`, hoy
  una tupla de strings sin esquema, y `AdmissionEvaluator`, que existe y nunca
  se invoca en runtime).
- **Capa 3 integrada en el pipeline** — el transporte de malla está cableado:
  `transport.py` (`InMemoryTransport` in-proceso + `QuicTransport` aioquic),
  `mesh_node.py` (un par: firma/publica gists, heartbeat, ciclo de vida),
  `mesh_network.py` (conecta nodos, drena hasta convergencia) y
  `mesh_pipeline.py` (`MeshPipeline`: el pipeline corre **sobre** la malla —
  cada worker publica su gist **por la malla** y lo admite en el
  `SecureSharedContext` de su nodo; al drenar, todos los nodos convergen al
  mismo conjunto de gists). Cubierto por `test_mesh.py` (17 tests,
  incluyendo la convergencia sobre red vía Nostr).
- **Capa 4 — despliegue multi-proceso** — `smcp/core/deployment.py`: discovery
  (el owner firma cada anuncio; un nodo se publica y los demás lo descubren),
  relays (el bus hace broadcast: un publish llega a todos), bootstrap
  (la firma del owner es el *trust anchor*: un anuncio/orden no verificable se
  descarta, anti-MITM) y control-plane (el owner emite órdenes firmadas
  up/down que el nodo verifica y ejecuta). El transporte de anuncio
  (`DiscoveryBus`) es in-memory y **swappable**: `NostrDiscoveryTransport`
  (vía un relay Nostr) y `MdnsDiscoveryTransport` (vía un medio mDNS,
  `smcp/core/mdns.py`) implementan la misma interfaz y se usan en su lugar —
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
  (mismo contrato `send`/`poll` que `QuicSwarm`). **Enlace identidad-cert**
  (issue #5): cada nodo genera su cert con `CN = peer_id` (la identidad que
  firma gists/anuncios) y el cliente, tras el handshake, verifica que el `CN`
  del cert del par coincida con su `peer_id` — un MITM (un nodo con un cert
  propio, `CN != peer_id`) es rechazado; `QuicHostSwarm(insecure=True)` es el
  fallback explícito (no verifica). Cubierto por `test_quic_host.py`
  (framing, round-trip 1 par, malla completa 3 nodos) y `test_quic_identity.py`
  (legítimo, MITM rechazado, insecure, `CN = peer_id`).
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
  (pre-shared key). **El modo estricto es el default** (`STRICT_MODE=True` en
  `provenance.py`): el pipeline real **no degrada silenciosamente** a HMAC —
  `KeyPair.new()` lanza `RuntimeError` si falta `cryptography`, en vez de
  firmar con la clave pre-compartida sin que nadie lo note. Para el modo de
  test/zero-deps, `STRICT_MODE=False` o `allow_hmac_fallback=True` degradan a
  HMAC **con warning visible** (el fallback ya no es silencioso). Los extras
  (`smcp[nostr]`, `smcp[quic]`, `smcp[mdns]`, `smcp[all]`) declaran las deps
  reales en `pyproject.toml`.

---

## Estructura

```
smcp/
  config.py           ModelConfig + load_config + build_client (config de modelo)
  cli.py              la CLI unificada (demo/test/config-check/fit/mesh/version)
  __main__.py         `python -m smcp` == `smcp` (mismo parser)
  serve.py            smcp-serve: SMCP como agente ACP por stdio (vía A)
  web/                la capa web, DENTRO del paquete (smcp[web])
    app.py            FastAPI :8099 — /api/status, /api/run, estático
    api.py            el router interactivo (/api/runs, /api/scan, …)
    static/                11 páginas (nav común en todas) + assets
      index.html nucleo.html seguridad.html demos.html arquitectura.html
      play.html context.html ledger.html estado.html malla.html console.html
      mesh3d.html
      js/                   three.min.js (la escena 3D de `console.html`)
      console.js            consola 3D: motor DeLM en vivo (SSE) + funciones
      assets/
        app.js               tema dark/light + recordar última página
        api.js               fetch/JSON/SSE + pip de salud (compartido)
        runs.js              cliente del motor de runs (POST /api/runs, SSE,
                             cancelacion en vivo) — usado por la consola
        estado.js            estado en vivo: señales, config, runs, acciones
        fit.js               sección llmfit: tabla, veredicto y "usar" un modelo
        malla.js             la malla: intercambio, reparto y auditoría
        mesh3d.js            la malla en 3D: peers reales, VRAM, reservas
        runs.js              cliente del motor de runs (SSE, reconexion)
        context.js ledger.js play.js demos.js seguridad.js   una por página
        style.css            design system · OpenCode.otf · smcp-mark.svg
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
    ledger_canon.py    bytes canónicos v1/v2: el digest que se ancla a BSV
    injection.py       detector de prompt-injection
    injection_hardened.py  detector endurecido (+ tests)
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
    quic_host.py       QUIC host server/client           (transporte entre hosts)
    harness_client.py  HarnessLLMClient                  (DeepSeek Harness, opt-in)
    hci.py             Headroom-Closed Index             (métrica de mejora)
    run_store.py       persistencia de runs en disco (SQLite)
    benchmark.py       throughput vs nodos, latencia p50/p95
    multi_node_bench.py  cada worker con SU modelo (malla real)
    rsi.py             RSILoop + Successor               (loop RSI L1)
    llmfit.py          LlmfitRunner + FitReport/veredicto (dimensionar el modelo local)
     contrib.py         Challenge/CapacityReport + ContributionLedger
     reputation.py      ReputationBoard: el ranking de inferencias servidas
     tiers.py           los tres precios (satoshis) y donde encaja x402
     x402.py            verificador de challenge/proof, offline y sin estado (BRC-120)
      anchor.py          una tx por inferencia, sin hashear el contenido
      membership.py      membresia anclada en BSV, verificada por el grafo
      txbuild.py         serializador de tx BSV (legacy; sighash contra vectores de Core)
       inscripcion.py     template SMCP3 v3: una tx paga e inscribe (BRC-160/220/27)
       arc.py             cliente ARC: emisión por HTTP (el PaymentACK de DPP)
        intercambio.py     la secuencia v3 de punta a punta (DPP + ARC + historial)
         join.py            el join v3: gratis, off-chain, en el roster (avales)
        identidad.py       auth mutua BRC-103: prueba de control de la clave del par
     reservation.py     reserva atomica de VRAM dedicada (tier de pago unico)
     reservation_ipc.py el cerrojo entre procesos de la reserva
     wiring.py          el camino de admision que une reserva y ledger
     capability.py      lo que un nodo dice que puede, y con que prueba
     telemetry.py       la evidencia de que lo esta haciendo
     roster.py          membresia explicita por avales firmados
     backend.py         que expone un nodo, por descubrimiento y con firma
     placement.py       ModelSpec/Stage/PlacementPlan (reparto entre nodos)
    bsv_keys.py        ECDSA-secp256k1 (la firma que ancla a BSV)
    timechain.py       el reloj del nodo: qué publicó, reenvía y no ha probado
    spv.py             la wallet del nodo: maestro, derivación BRC-42 y dirección
    electrumsv.py      integración ElectrumSV headless: wallet SPV (REST daemon)
    txbuild.py         serializador de txs BSV (firmar, txid, sighash)
    gates.py           los gates de calidad, en una lista, en un solo sitio
  demo/
    run_demo.py        demo end-to-end (sin API key)
    run_real_demo.py   demo contra un modelo real (config-driven)
    run_security_demo.py   demo Capas 1+2
    run_taint_demo.py      demo Capa 5
    run_multihost_demo.py  demo multi-host (QUIC / Nostr)
    run_rsi_demo.py        demo RSI L1 (mide HCI)
  tests/   (65 archivos — ver lista arriba)
docs/
  architecture.md     arquitectura por capa (piezas, interfaces, flujos)
  threat-model.md     adversario / garantías / NO-garantías por capa
  inscripcion-v3.md   especificación de la inscripción de inferencia v3
                      (el template de la tx, los BRC adoptados, lo abierto)
scripts/
  check_readme_count.py   gate de conciliación README ↔ pytest (`smcp gates readme`)
Makefile
  make help / gates / lint / types / test / coverage — delega en `smcp gates`
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
