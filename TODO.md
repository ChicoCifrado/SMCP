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
- [ ] **CLI amigable**: `smcp mesh join` interactivo, `smcp status`
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

- [x] **Paquete Python**: `delm` -> `smcp` (`pyproject.toml` name, imports)
  - [x] `import delm.core.*` -> `import smcp.core.*` (149 ficheros)
  - [x] CLI `delm` -> `smcp` (`smcp-serve` ya existe)
  - [x] Entry points: `smcp`, `smcp-serve`, `smcp-serve-web`
    (alias `delm-demo`/`delm-real-demo` se conservan por compat)
  - [x] Env vars `DELM_*` se conservan (config, no paquete)
  - [x] Docs: README, CHANGELOG, DESIGNCOMPAT, docs/*.md, ci.yml, requirements.txt
  - [x] "DeLM" (paper) y "DELM" (token) se conservan — solo cambia el paquete/CLI
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
- **Wallet SPV ElectrumSV headless (`smcp/core/electrumsv.py`) — reescrita contra la REST API real (1.4.0b1), 14 tests verdes**
- **Infraestructura de wallets robusta (2026-10-04):**
  - SPV verificada read-only vs `electrumx.gorillapool.io` (ElectrumX 1.20.2, mainnet): `scripthash.get_history(1Eqk)` → 14 txs, el tip DELM de 1M aparece en la historia restaurada
  - **Adaptador BRC-100 (`bsv21-bridge/delm-brc100.mjs`)**: surface self-custodial HandCash Desktop (`WalletClient('auto')` + scripts BRC-162). **Emite BRC-162 binario** (el wire real de la wallet moderna). **VALIDADO contra el código compilado real de HandCash Desktop v1.3.425** (AppImage extraída → `app.asar` → `dist/assets/index-D6d5nUgF.js`): el bundle contiene `Q4t="BSV21"`, `G4t="4253563231"`, `MG=(1n<<64n)-1n`, `k9=[66,83,86,50,49]`; el encode compilado (`writeBin(k9)`, deploy?`OP_0`:`writeBin([...tokenIdToWire(n)])`, `OP_2DROP`, `writeAmount`, deploy?`writeBin(cbor)`:`OP_0`, `OP_2DROP`, `writeScript(rest)`) es **idéntico** al port de `encodeBsv21Binary`. El wire generado offline decodifica == DELM_TOKEN_ID. Bridge: proxy HTTP `app.all('*')` en https://127.0.0.1:2121 (TLS) y http://127.0.0.1:3321; reenvía al renderer vía IPC. Errores reales: USE_PBSV21_SCOPE, INVALID_PBSV21_SCOPE, MISSING_PBSV21_SCOPE_TAG (el adaptador usa `p bsv21 id` correcto)
  - Auditoría on-chain: el deploy `8d7f4834_vout0` (1M DELM) está intacto y sin gastar (bloquea a `1Eqk`); el transfer a `1MNF` (`6b8de05f`) es **inválido como BSV-21** (gastó el change, no el tip — no conserva saldo)
- **Control de los DELM (2026-10-04):** `@1sat/cli sweep scan --wif <token.wif> --only bsv21` ve los **1M DELM** en `1Eqk` (read-only, sin transacciones). tokenId `8d7f4834…_0`, symbol DELM, amount 1000000, 1 UTXO, no listado. 1Sat Ordinals usa un **indexer público** (`api.1sat.app`): ve el UTXO de 1 sat con la inscripción BSV-21 en la dirección, sin depender del install (a diferencia de HandCash, que asocia collectables al install BRC-39).
  - **Wallet garracifrada restaurada** en HandCash Desktop v1.3.425 (AppImage extraída, WSL + Xvfb :99, CDP :9222): identity `03ed40e2…080909`, 554 sats, SYNCED. Custodia conjunta (garracifrada + propietario desde la misma app).
  - **Anclaje SMCP ↔ DELM**: el tokenId `8d7f4834…_0` es el punto de referencia permanente del protocolo de anclaje por inferencia (bloque génesis 969519).
- Rebrand fase 3 (poda) + fase 4 (delm→smcp) — COMPLETADOS y pusheados
- Tests: **1064** (gate README OK; 11 ficheros no coleccionan por `ECDSA-secp256k1` ausente en este entorno — preexistente)
- API: 42 rutas (3 nuevas: /api/inferences, /api/inferences/{txid}, /api/inferences/totals)
- Commits: `9df24dd` (contract), `db143a0` (token capa F), `97e3209` (tokenId canonico), `f4f2fab` (rebrand), `ab2a859`+`fac9713` (ElectrumSV), `6e1b9a9` (cliente REST real)

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
- Holders del canonico: **1M en `1Eqk...`** (wallet del proyecto, control verificado via `sweep scan`). Los 100k de la transferencia `6b8de05f` a `1MNF` son **invalidos** (no conservan saldo) — se ignoran por directiva.
- **Anclaje SMCP ↔ DELM**: tokenId `8d7f483498d83358e8c0b61b55334b1650d50ffce1539a482bc245dfc65c4410_0` (bloque 969519). Es el anclaje on-chain permanente del protocolo de anclaje por inferencia. Custodia conjunta (garracifrada + propietario).
- Funding vivo: **574 sats** en UTXO `da2cfe03…_1` (bloque 969530) — suficiente para una tx de sweep (~200-500 sats).
