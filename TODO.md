# TODO — Lanzamiento SMCP

> Resumen: lo que falta para lanzar el producto.
> El core (malla, contrato BSV, token BSV-21) funciona.
> Faltan: testing duro, HCI, poda de codigo muerto y
> el rebrand total de DeLM a SMCP.

## 1. Fase de testing

- [x] **Libro de inferencias** (`delm/core/registro.py`)
  - [x] `InferenceRecord`: txid + timestamp + identidades + cobro (sats/DELM)
  - [x] `InferenceRegistry`: append-only, persistente (jsonl), consultable
  - [x] Union en `InferenceServer.settle()`: completion (status 200) → timestamp → registro
  - [x] Cobro en BSV (`pay_method="bsv"`) y en DELM (`pay_method="delm"`)
  - [x] API: `GET /api/inferences`, `/api/inferences/{txid}`, `/api/inferences/totals`
  - [x] Tests: 9 (test_registro) + 2 (union en test_intercambio)
- [ ] **Tests contra modelo real (no mockeado)**
  - [ ] alice/bob dual-node con Qwen3.8-27B en VRAM (14-15 GB)
  - [ ] verificacion extremo a extremo de las capas A-E
  - [ ] inferencia real -> gist -> verificacion -> bounty cobrado
- [ ] **Tests de la capa F (token) contra cadena real**
  - [ ] activar el token en el overlay 1sat (funding 10M sats / BRC-0062 BEEF)
  - [ ] `sendBsv21` real a otro nodo
  - [ ] `listBsv21` + `buyBsv21` en 1sat.market
  - [ ] flujo `/api/token/pay` con DELM real (no mock)
  - [ ] flujo `/api/inferences` con cobro DELM real (capa F conectada)
- [ ] **Tests de carga / estabilidad**
  - [ ] malla con N nodos (N>=3) sobre red real (QUIC)
  - [ ] reconexion, particiones, revivir nodos caidos
  - [ ] gates de seguridad bajo inyeccion adversaria
- [ ] **Property-based tests** para admission/verify
- [ ] **Benchmark multi-nodo** documentado (tok/s por nodo)

## 2. HCI

- [ ] **Onboarding guiado** (primer arranque: generar claves, unirse a malla)
- [ ] **Dashboard de nodo** (VRAM, inferencias, sats, DELM, reputacion)
- [ ] **CLI amigable**: `delm mesh join` interactivo, `delm status`
- [ ] **Web UI** (ya existe en `delm/web/`) — pulir:
  - [ ] vista de contexto compartido `C` verificado
  - [ ] cola de tareas `T` en tiempo real
  - [ ] historial de pagos (sats + DELM)
- [ ] **Mensajes de error accionables** (no solo stack traces)
- [ ] **Accesibilidad**: ayuda `--help` coherente, ejemplos

## 3. Eliminar codigo que no se usa

- [ ] **Auditoria de modulos** (`delm/core/`, 61 modulos)
  - [ ] todos tienen referencias; revisar los de pocas refs:
    - `mesh_pipeline.py` (1 ref) — ¿se usa o es alternativa a `pipeline.py`?
    - `multi_node_bench.py`, `benchmark.py` — consolidar
    - `hci.py` (2 refs) — ¿es la HCI actual o hay que reescribirla (punto 2)?
    - `mdns.py`, `mesh_network.py`, `wiring.py`, `run_store.py`, `expansion.py`
  - [ ] demoscritas (`delm/demo/run_*_demo.py`) — ¿mantener o quitar?
- [ ] **Dependencias no usadas** en `pyproject.toml` / `package.json`
- [ ] **Codigo duplicado**: `injection.py` vs `injection_hardened.py`
- [ ] **Config git-ignored** (`config/*.json`) — plantillas de ejemplo en repo

## 4. Rebrand total a SMCP

- [ ] **Paquete Python**: `delm` -> `smcp` (`pyproject.toml` name, imports)
  - [ ] `import delm.core.*` -> `import smcp.core.*` (149 ficheros)
  - [ ] CLI `delm` -> `smcp` (`smcp-serve` ya existe)
- [ ] **Docs**: README (ya tiene titulo SMCP), CHANGELOG, DESIGNCOMPAT
- [ ] **Token**: simbolo DELM -> decidir (¿SMCP? ¿mantener DELM como homenaje al paper?)
- [ ] **Nombres internos**: clases/funciones `Delm*` -> `Smcp*`
  - `DelmPipeline`, `DelmNode`, etc.
- [ ] **Handles**: repo GitHub ya es `ChicoCifrado/SMCP` (ok)
- [ ] **Identidad de red**: mDNS service type, cadena de genesis

## 5. Lanzamiento

- [ ] **Release tagged** (v0.5.0) con assets (wheel, Docker)
- [ ] **Docker image** (`smcp-node`) con nodo completo
- [ ] **Instalador** (`pip install smcp`, `cargo` para externos)
- [ ] **Documentacion de operador** (como correr un nodo productivo)
- [ ] **Economia**: parametrizo treasury, bounty, fee del overlay
- [ ] **Seguridad**: audit del locking script + gates
- [ ] **Anuncio**: BSV/DeLM communities, 1sat.market listing

## Estado actual (2026-10-04)

- Core: malla, contexto verificado, cola, admission, gates — listo
- Capa E: smart contract BSV (bounty P2PKH) — listo
- Capa F: token BSV-21 DELM — desplegado on-chain (3 despliegues confirmados)
- **Libro de inferencias (registro.py): completion→timestamp→registro→cobro (BSV/DELM) — listo**
- Overlay 1sat: token indexado, `is_active: false` (falta funding 10M sats via BEEF)
- Bridge: `@1sat/actions` integrado, BRC-0062/BEEF funcionando
- Tests: 1201 + 11 nuevos = **1212** (9 test_registro + 2 union en test_intercambio)
- API: 42 rutas (3 nuevas: /api/inferences, /api/inferences/{txid}, /api/inferences/totals)
- Commits: `9df24dd` (contract), `db143a0` (token capa F), `97e3209` (tokenId canonico)

## Red de incentivos (BSV + DELM)

El nodo (Bob) puede cobrar la inferencia en:
- **BSV (sats)** — el flujo v3: 100 sats (1 ordinal a Alice + 99 a Bob)
- **DELM** — capa F: `pay_method="delm"`, cobra unidades DELM
- **both** — las dos monedas

Alice paga a Bob con BSV (o DELM) para hacer peticiones de inferencia.
Esto crea una red de incentivos que atrae nuevos nodos:
- **Proveedores**: comparten GPU, sirven inferencias, ganan BSV/DELM
- **Consumidores**: usan la red (tier `metered`), pagan por inferencia

El libro de inferencias (`registro.py`) es el registro de la red:
quién sirvió qué, cuándo, y cómo cobró. La prueba en cadena es
el txid (el ordinal viaja a Alice); el libro es el índice off-chain.

## Decision de supply (2026-10-04)

- **TokenId canonico**: `8d7f4834..._0` (deploy original, con funding
  parcial en el overlay). Supply efectivo DELM = **1.000.000**.
- Se desplego 3 veces por error; los otros dos (`5c6c7efb..._0`,
  `491f8442..._0`) quedan como **tokens muertos** (no se gastan
  ni se listan). No hay transaccion nueva: es una convencion de codigo
  (`TOKEN_ID_CANONICO` en `token_bsv21.py`, `DEFAULT_TOKEN_ID` en
  `bsv21-bridge/bsv21.mjs`).
- Holders del canonico: 900k en `1Eqk...` (wallet del proyecto)
  + 100k en `1MNF...` (por la transferencia `6b8de05f`).
- Para reducir el supply en cadena (burn) habria que transferir a una
  direccion sin clave; no reduce el `amt` del deploy (inmutable).
