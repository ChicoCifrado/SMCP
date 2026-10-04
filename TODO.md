# TODO — Lanzamiento SMCP

> Resumen: lo que falta para lanzar el producto.
> El core (malla, contrato BSV, token BSV-21) funciona.
> Faltan: testing duro, HCI, poda de codigo muerto y
> el rebrand total de DeLM a SMCP.

## 1. Fase de testing

- [ ] **Tests contra modelo real (no mockeado)**
  - [ ] alice/bob dual-node con Qwen3.8-27B en VRAM (14-15 GB)
  - [ ] verificacion extremo a extremo de las capas A-E
  - [ ] inferencia real -> gist -> verificacion -> bounty cobrado
- [ ] **Tests de la capa F (token) contra cadena real**
  - [ ] activar el token en el overlay 1sat (funding 10M sats / BRC-0062 BEEF)
  - [ ] `sendBsv21` real a otro nodo
  - [ ] `listBsv21` + `buyBsv21` en 1sat.market
  - [ ] flujo `/api/token/pay` con DELM real (no mock)
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
- Overlay 1sat: token indexado, `is_active: false` (falta funding 10M sats via BEEF)
- Bridge: `@1sat/actions` integrado, BRC-0062/BEEF funcionando
- Tests: 1201 (15 de token)
- Commits: `9df24dd` (contract), `db143a0` (token capa F)
