# Inscripción de inferencia v3 — especificación

## Estado

**Implementada** (`delm/core/inscripcion.py` + `delm/core/txbuild.py`
+ `delm/core/arc.py` + `delm/core/intercambio.py`, con tests
offline: `tests/test_inscripcion.py`, `tests/test_txbuild.py`,
`tests/test_arc.py`, `tests/test_intercambio.py`).
`arc.py` es la capa de emisión que el flujo pide en el paso 4:
cliente HTTP de ARC (el servicio de emisión de BSV) — emite la tx
firmada y sondea hasta el `PaymentACK`. No habla con Bitcoin Core ni
con ningún RPC de nodo: ARC es la vía.
`intercambio.py` es la **secuencia** de punta a punta (la migración
del flujo): pedido -> inferencia -> `PaymentTerms` -> `Payment`
firmada -> emisión por ARC -> `PaymentACK` -> y solo entonces
`record_inference` y el ranking. Y el **join v3** (gratis,
off-chain) está cableado en el roster: `smcp.core.join` es la
secuencia de emparejamiento (intercambio de claves, avales
mutuos, reconciliación) sobre `smcp.core.roster` — y por eso
`JOIN_SATOSHIS` pasó de 1 a 0 (ver `tiers.py`).
v2 (`delm/core/anchor.py`, `membership.py`, `tiers.py`) sigue en verde y
sin tocar: v3 es un formato nuevo que convive con v2 — no lo reemplaza
hasta que una decisión lo haga. Lo que v3 **no** cambia todavía: el
flujo de la malla sigue contando inferencias por `record_inference` con
el txid de la inscripción, y el intercambio sigue sin propagarse por
la red — el template, su verificación y la secuencia son el primero,
el transporte es el paso siguiente.

## De dónde viene

La economía de la rama (`abde364`) ya decidió: sin moneda interna, el
único dinero es el satoshi en cadena, y `record_inference` —que exige un
txid y no admite doble conteo— es el único camino del historial. Esta
spec responde a la pregunta pendiente: **cuál es el template de la
transacción que paga y ancla una inferencia.**

Las decisiones de economía que fija (y que no son de este documento
sino de la conversación que la originó):

* Una sola tx por inferencia: pago y anclaje son la misma transacción.
* Alice (solicitante) paga 250 sats; Bob (servidor) ejecuta la
  inferencia, ancla el hash por 1 satoshi (un ordinal), y cobra
  249 sats menos la fee de la tx — la fee la paga Bob de su parte.
* El ordinal se transfiere al solicitante: es el comprobante.
* El **txid** de la tx de inscripción es la clave que cuenta
  `record_inference`. Una inferencia = una inscripción = un txid.
* La unión a la malla (join) es **gratis y off-chain**: intercambio de
  claves públicas. La dirección del pago la fijan los roles: quien
  solicita paga, quien sirve cobra.

## Qué cambia respecto a v2

| | v2 (hoy) | v3 (esta spec) |
|---|---|---|
| Unión a la malla | output de membresía anclado en BSV (`membership.py`) | intercambio de claves off-chain (el roster que ya existe) |
| Pago por inferencia | el ancla *declara* satoshis sin verificar pago alguno | una tx paga 250 sats y ancla, las dos cosas a la vez |
| Qué se publica | outpoints y pubkeys del ancla | `hash(mesh_id ‖ solicitante)` + firma del servidor, dentro de un ordinal de 1 sat |
| Comprobante | `InclusionProof` contra cabecera que elige el verificador | txid + ordinal en poder del solicitante + certificado SPV |
| Freno Sybil | 1 sat por inscripción (débil; documentado en `tiers.py`) | la fee de una tx por inferencia, pagada por el servidor |

## BRCs adoptados

Del registro (bsv.brc.dev), con lo que cada uno aporta:

| BRC | Qué aporta a v3 |
|---|---|
| **BRC-159** (1Sat Ordinals) | El ordinal de 1 sat como comprobante: el token es la cadena de outputs de 1 sat, su *origin* es el outpoint, y la transferencia la da el orden de satoshis. El ordinal viaja a Alice y es el receipt. |
| **BRC-160** (Inscription Envelopes) | El formato del envelope: `OP_FALSE OP_IF "ord" … OP_ENDIF` **en el script de bloqueo del output de 1 sat**, con content-type (campo 1), body (campo 0) y campos de aplicación (2 servidor, 4 versión, 5 firma, 6 nota) antes del body. El *parent* no viaja: es el outpoint del input que paga, que la tx ya lleva en su input 0. **Corrige la idea de "datos en OP_RETURN"**: el sitio estándar de una inscripción de 1 sat es el envelope en el locking script, no un output OP_RETURN. OP_RETURN queda como sitio opcional para metadatos MAP. |
| **BRC-220** (NotaryHash) | El modelo de notarización de hash firmado — **y el repo ya lo implementa**: `bsv_keys.py` (ECDSA-secp256k1, firmas de 64 bytes `r‖s`), `ledger_canon.py` (prefijos de longitud `u32be`) y `timechain.py` (certificados) citan BRC-220, y el registro lo confirma: define `ECDSA-secp256k1`, permite firmas de 64 bytes `r‖s` **o DER**, y canonicaliza con prefijos de longitud. v3 lo usa tal cual: el servidor hashea `H` localmente, lo firma localmente, y la cadena lleva el hash y la firma — nunca el contenido. Su modo *batch* (merkle root de muchas pruebas en una tx) queda como optimización futura. |
| **BRC-27** (DPP) | El flujo de pago: el comerciante construye la tx (`PaymentTerms`), el cliente firma su input (`Payment`), el comerciante emite y confirma (`PaymentACK`). Es exactamente el flujo de la tx única: Bob construye, Alice firma su UTXO, Bob emite. |
| **BRC-77** (Message Signature) | Opción de interoperabilidad futura, no necesaria para v3.0: firma con claves derivadas por contraparte sobre BRC-42/43 (que el repo ya implementa en `spv.py`). Para v3.0 basta la firma BRC-220 con la pubkey del servidor incrustada en la inscripción — la inscripción ya es pública, así que el secreto por contraparte de BRC-77 no aporta aquí. |
| **BRC-10 / BRC-11** (TSC merkle proof) | El formato del certificado de inclusión. La `InclusionProof` actual ya tiene los mismos campos (`txid`, `index`, `path`, `merkle_root`, `height`); alinear nombres y serialización. |
| **BRC-36** (outpoints) | Forma canónica de escribir outpoints. El repo usa `txid:vout`; verificar la forma canónica de BRC-36 al implementar. |
| **BRC-42 / 43 / 75** | Ya adoptados (derivación, keyId, mnemónico). Se quedan. |
| **BRC-120** (x402) | El verificador x402 (`x402.py`) ya implementaba el role de verifier de x402 v1.0; ahora está alineado con el estándar: el docstring nombra la designación y la spec congelada, los campos MUST del challenge se exigen en el shape check, y los motivos de rechazo son `Failure` tipado para el mapeo de §9 (402/400). |

Referencia (no adoptado ahora): **BRC-122** (ARIA) — inferencia
auditable con pre-commitment por época y merkle root de registros. Su
patrón (`OP_FALSE OP_RETURN "ARIA" <json>`) y sus reglas de JSON
canónico son útiles, pero su modelo de épocas es otra arquitectura;
queda como referencia para el batching futuro.

## La transacción

Una tx, construida por Bob (DPP), firmada por Alice, emitida por Bob:

* **Input:** un UTXO de Alice con ≥ 250 sats (si es más, el exceso
  vuelve a Alice como cambio — DPP lo prevé).
* **Output 1 — 1 sat → Alice**, locking script:

  ```
  OP_FALSE OP_IF
    "ord"
    OP_1  0x0a "text/plain"     # content-type del body
    OP_2  <33B pubkey servidor> # quién sirvió (BRC-220: comprimida)
    OP_4  0x03                  # versión de formato: SMCP3
    OP_5  <64B r‖s>             # firma secp256k1 sobre H (BRC-220)
    OP_6  <1B nota>             # código de NOTAS_COMPLETADO
    OP_0  <32B crudos>          # body: H, el hash, en crudo
  OP_ENDIF
  <P2PKH(Alice)>
  ```

  El envelope es un no-op (`OP_FALSE OP_IF` no empuja nada), así que el
  output se gasta normal con la clave de Alice: **el ordinal es de
  Alice, y los datos viajan dentro del ordinal**. Quien posee el
  comprobante posee el registro. Esa es la propiedad que hace mejor el
  envelope que un OP_RETURN aparte.

* **Output 2 — 99 − fee sats → Bob** (P2PKH del servidor). De aquí
  sale la fee del minero.

El *parent* **no viaja**: es el outpoint del input que paga, que la tx
ya lleva en su input 0 (la plantilla es exactamente 1 input) — el
comprobante lo deriva, y la cadena no repite 36 bytes que ya están en
la tx. La proveniencia del receipt sigue siendo el pago mismo.

### La nota

Al finalizar la inferencia, el pago dice al receptor que la inferencia
completó. La nota (campo 6) es un **código de 1 byte** sobre un
vocabulario fijo — siempre las mismas, nunca texto libre:

```
NOTAS_COMPLETADO = ("inferencia completada", "inferencia terminada",
                    "inferencia resuelta", "inferencia lista")
```

El código lo elige `H` (`nota_para`: el primer byte de `H` módulo el
vocabulario): determinista y sin estado — la misma petición lleva
siempre la misma nota, y el vocabulario rota por el hash. Una nota
fuera del vocabulario es otra versión del formato, no una nota
silenciosa. El texto completo en la tx serían ~20 bytes de relay por
inferencia; el código, 1.

### El hash

```
H = SHA-256( uint16be(len(mesh_id)) ‖ mesh_id ‖ solicitante_pubkey[33] )
```

`mesh_id` en UTF-8, `solicitante_pubkey` en 33 bytes crudos. El
prefijo de longitud evita la ambigüedad de la concatenación (la misma
lección de determinismo de BRC-220: codificación fija, nunca JSON).

**Deliberadamente no es el hash del resultado.** Hashear la respuesta
requiere CPU que la decisión de economía descarta, y —como v2 ya
documentó con `content_sha256`— publicar el hash del contenido permite
a un observador de la cadena confirmar que alguien ejecutó esa
conversación, porque el hash de un prompt es tan identificador como el
prompt. Lo que se publica es *que una inferencia verificada ocurrió en
este mesh, para este solicitante, servida por este nodo* — no qué dijo.

## El flujo

1. **Alice → Bob** (por QUIC; x402 como opción de transporte): la
   petición — prompt, `mesh_id`, su pubkey de solicitante.
2. **Bob**: ejecuta la inferencia, calcula `H`, la firma (secp256k1,
   64 bytes `r‖s` — la convención BRC-220 del repo),
   construye la tx (`PaymentTerms`): input de Alice (250 sats),
   outputs [1 sat → Alice con envelope, 99−fee → Bob].
3. **Alice**: verifica `H` (lo recomputa de `mesh_id` y su pubkey),
   la firma contra la identidad de Bob, y los outputs (¿1 sat a mí con
   el envelope? ¿99−fee a Bob? ¿el input es mío?). Firma su input
   (`Payment`) y devuelve la tx.
4. **Bob**: emite por ARC (`smcp.core.arc`: `POST /v1/tx`,
   `X-WaitFor` hasta `ACCEPTED_BY_NETWORK` y sondeo
   `GET /v1/tx/{txid}` después), espera confirmación, envía a Alice
   el **txid** y el certificado (`path`, `merkle_root`, `height` —
   BRC-10/11). Es el `PaymentACK`.
5. **Alice**: receipt = (txid, ordinal en su wallet, certificado).
   Verificación offline: firma sobre `H` + inclusión contra una
   cabecera de bloque que ella confíe.
6. **La malla**: `record_inference(peer_id=Bob, txid=<txid>)`. Sin
   doble conteo: el txid es único por construcción.

## Qué prueba el comprobante, y qué no

Prueba: que el poseedor de la clave que firmó (la pubkey de 33 bytes
incrustada en la inscripción) ancló `H`; que `H` compromete (`mesh_id`,
solicitante); que la tx movió 250 sats de Alice a (1 sat ordinal a
Alice + 99−fee a Bob) — el grafo de la tx dice quién pagó y quién
cobró; que Alice posee el ordinal; y, con el certificado, en qué altura
salió.

No prueba: qué se respondió (ver arriba; `hash(resultado)` quedó
**descartado** — publicar el hash de un prompt es tan identificador
como el prompt); que la respuesta fue
correcta (la cadena no ejecuta el modelo); ni que la fee fue "justa"
— la paga Bob de los 249, y si la fee de relay superara 249 sats el
tier no cierra (supuesto económico, ver Abierto).

## Tiers bajo v3

Componibles: el nivel de pago por uso está *incluido* en los otros dos
— un nodo `free` o `ded` que consume capacidad de otro paga por
consumo con este mecanismo.

| nivel (nombre código) | join | por inferencia |
|---|---|---|
| `free` (tier 3) | **0** — off-chain, intercambio de claves | 0 por capacidad propia; metered al consumir de otros |
| `ded` (tier 2) | 100 000 sats (0.001 BSV) | incluye metered |
| `metered` (tier 1) | 0 | 250 sats (esta tx) |

El cambio contra v2 es uno: `JOIN_SATOSHIS` de `free`, de 1 a 0.

**La consecuencia honesta, escrita donde vive hoy** (`tiers.py` dice:
"entrar es gratis, pero servir no lo es — cada inferencia servida
exige una tx con fee, y la fee la paga el servidor"): el freno
se mueve de la identidad al trabajo: cada inferencia servida exige
una tx con fee que paga el servidor, así que fabricar *N* inferencias
cuesta *N* fees —
el coste escala linealmente con el fraude, que es la propiedad que
importa. Y como la reputación cuenta inferencias *servidas* (no nodos),
y una inferencia local no ancla ni paga nada, el Sybil no gana nada
inflando entradas: solo inflando trabajo real, que es justo lo que el
ranking mide. Lo que se pierde: el número de *nodos* deja de estar
frenado por coste de entrada.

## Lo que cambia en el código (implementado)

* **`delm/core/txbuild.py`** — el serializador de transacciones que
  `membership.py` anticipó: formato legacy (BSV no tiene segwit),
  varints, pushes, P2PKH, DER desde `r‖s`, txid, y el sighash legacy
  completo (ALL/NONE/SINGLE/ANYONECANPAY, `FindAndDelete` de
  OP_CODESEPARATOR) validado contra los vectores de
  `sighash.json` de Bitcoin Core.
* **`delm/core/inscripcion.py`** — el template SMCP3: `H` con prefijo
  de longitud, el envelope BRC-160 (campos 1, 2, 4, 5, 6 y el body 0
  de último, crudo), la construcción DPP (`build_payment_terms` →
  `sign_requester_input`) y la verificación del comprobante
  (`verify_payment_terms` antes de emitir, `verify_inscription` con
  la prueba de inclusión después).
* **`delm/core/arc.py`** — la capa de emisión (el `PaymentACK`):
  cliente HTTP de ARC (`POST /v1/tx` con el hex crudo en texto
  plano, `GET /v1/tx/{txid}`, política y salud), con el estado de
  la tx tipado, los *problem details* (RFC 7807) mapeados a
  excepciones, y `broadcast`/`broadcast_transaction` que sostienen
  la petición con `X-WaitFor` y sondean hasta el objetivo —
  comparando el txid de ARC con el de la tx local. Todo contra un
  ARC falso en localhost (`tests/test_arc.py`), sin red.
* **`delm/core/intercambio.py`** — la secuencia de punta a punta:
  `InferenceServer.serve` ejecuta la inferencia y construye los
  `PaymentTerms` (la respuesta viaja fuera de cadena, como en v2);
  `sign_payment` verifica y firma del lado del solicitante;
  `InferenceServer.settle` re-verifica la `Payment` firmada, exige
  el input firmado, emite por ARC, espera el estado aceptado y —
  solo entonces— cuenta con `record_inference` (y lanza si el
  historial no cuenta: nodo sin VRAM anunciada o txid repetido).
  `Broadcaster` (en `arc.py`) es la vía de emisión inyectable:
  `ArcClient` en producción, un doble en proceso en los tests.
  La tesis del intercambio, offline, en `tests/test_intercambio.py`
  (el patrón de `test_exchange_thesis.py` de v2).
* **`tiers.py`**: `JOIN_SATOSHIS` de `free` 1 → 0, y su docstring —
  el freno Sybil cambia de sitio (de la entrada al trabajo), y ese
  es el sitio donde está documentado hoy.
* **`delm/core/join.py`** — el join v3, cableado en el roster:
  `found` funda el roster de un nodo (el fundador es su propio
  primer avalado) y `pair` es la secuencia de emparejamiento —
  intercambio de claves, avales mutuos, reconciliación de rosters
  confiando solo en lo que ya se confía, y la prueba de confianza
  mutua verificada. Todo off-chain, sin gastar nada. Offline, en
  `tests/test_join.py` (el join y el intercambio componen el flujo
  v3: la misma identidad por `peer_id`).
* **`membership.py`**: sin cambios (v2). El join v3 es el roster
  (`smcp.core.roster`): intercambio de claves firmado entre pares.
* **`anchor.py`**: sin cambios (v2). v3 es formato nuevo con su
  propia versión (`OP_4 = 3`).
* **`x402.py`**: alineado con BRC-120 — el verificador del role
  de verifier de x402 v1.0 congelada (§4-§9): el docstring nombra
  la designación y la spec canónica, el shape check exige todos los
  campos MUST del challenge (incluido `require_mempool_accept`),
  el decoder ya no pone defaults silenciosos a campos obligatorios
  (`query`, `require_mempool_accept`), y los motivos de rechazo son
  `Failure` tipado para el mapeo de estados de §9. 58 tests offline.
* **`bsv_keys.py` / `ledger_canon.py`**: sin cambios — v3 reutiliza las
  primitivas BRC-220 que ya existen (firma `r‖s`, prefijos `u32be`);
  no hay nuevo código criptográfico para la firma.

## Abierto

1. **`hash(resultado)`** — SMCP4, *cerrado por decisión:
   no*. CPU en el servidor y privacidad en la cadena; y
   publicar el hash de un prompt es tan identificador
   como el prompt. El formato sigue versionado (`OP_4`)
   si la decisión cambia.
2. **Batching** — BRC-220 modo *batch* (merkle root de muchas pruebas
   en una tx) y BRC-122 (épocas con pre-commitment) como optimización
   de coste. Rompe "una inferencia = una tx", así que requiere
   rediseñar el conteo antes de adoptarlo.
3. **Fee de relay** — *cerrado por medición, y el
   precio se movió con ella*. La plantilla serializa
   **385–386 bytes** (varía 1 byte por la firma
   DER), no los ~250 estimados: el envelope de
   BRC-160 viaja en el script de bloqueo del
   ordinal (firma de 64 B, `H` de 32 B crudos,
   nota de 1 B; el parent no viaja). La medición
   dictó el precio: para cerrar la banda objetivo
   de **0.1–0.5 sat/vB** hacían falta 39–193
   sats de fee, y el presupuesto es el precio
   menos el ordinal — así que `PER_INFERENCE_SATOSHIS`
   subió de 100 a **250 sats** (presupuesto de
   249, techo de ~0.65 sat/vB):
   * el default del software (`minrelaytxfee` =
     1 sat/vB) **sigue sin cerrar** — harían
     falta ~386 sats;
    * la banda objetivo (0.1-0.5 sat/vB) **cierra
      entera**: a 0.1 bastan ~39 sats, a 0.5
      ~193, y a Bob le quedan 210-56 sats;
    * **comprobado contra la red el 2026-10-08**
      (WhatsOnChain, mainnet): la tasa media en
      bloque de los últimos bloques (970088-
      970090) es **~0.11 sat/vB**, la tx mediana
      paga ~180 sats por ~1790 B (~0.10), los
      pools mayoritarios (taal, GorillaPool, qdlnk,
      CUVVE, SA100) aceptan desde ~69 sat/KB
      (**~0.07 sat/vB**) y el más estricto
      (Bitofsin) pide 0.5 — la banda queda
      validada por medición, no por suposición;
    * **la fee por defecto del intercambio es
      `DEFAULT_FEE_SATOSHIS = 43`**
      (`smcp/core/intercambio.py`): la fee media
      de la red (0.11 sat/vB) aplicada al tamaño
      de la plantilla (386 B). Es **fija en sats**
      porque el template fija el tamaño (solo la
      firma DER varía 1 byte) — una fee fija es
      una tasa fija. Con ella la tx paga relay a
      la tasa media con margen sobre el mínimo de
      los pools mayoritarios, y Bob cobra 206 de
      los 249. El default anterior (0) dejaba la
      tx sin relay alguno — solo la minan pools
      que aceptan txs sin fee. El knob sigue
      siendo ``fee_sats`` (0 a 248).
   El corte de `tier_for_inferences` se movió con
   el precio: 100 000 / 250 = **400 inferencias**
   (la división sigue siendo exacta). La medición
    vive en `relay_budget()` (`smcp/core/inscripcion.py`)
    y `tests/test_relay_fee.py`; la fee por defecto,
    en `DEFAULT_FEE_SATOSHIS` (`smcp/core/intercambio.py`).
    El knob, si la tarifa objetivo sube, es
    `PER_INFERENCE_SATOSHIS`
    (`precio = tamaño x tarifa + 1`).
4. **Identidad en el join** — *cerrado con BRC-103*.
   El intercambio de claves afirmaba la clave del
   par sin probar que la controla (un MITM activo
   la sustituía en el cable y el aval acababa
   firmado contra la clave del atacante). Ahora
   `smcp/core/identidad.py` lleva el handshake de
   BRC-103, adaptado en su **variante simétrica**
   (el join no tiene iniciador: los dos lados
   generan un nonce de 32 bytes y firman
   `nonce_del_par ‖ nonce_propio` con la misma
   `KeyPair` que avala el roster). `pair()` toma
   una `Session` opcional: con ella, cada clave
   debe probar su control vivo ligado a la sesión
   — una prueba que no cuadra es MITM o bug y el
   join **falla cerrado**; sin ella, el intercambio
   simple de hoy sigue disponible (`authenticated`
   en el resultado distingue los tres estados:
   `True`/`False`/`None`). Desviación documentada:
   BRC-103 firma con derivación BRC-100; SMCP
   firma con la clave directamente (la malla no
   tiene derivación de claves) — la propiedad de
   prueba de control se preserva. **BRC-52**
   (certificados de identidad con campos firmados
   por un certificador, revelación selectiva y
   revocación por outpoint) queda como opción
   *sobre* este handshake: necesita una política de
   certificadores, que es una decisión de diseño,
   no código.
5. **BRC-77** — v3.0 adopta la convención BRC-220 que ya tiene el repo
   (64 bytes `r‖s`, pubkey incrustada). BRC-77 (firmas con claves
   derivadas, BRC-42/43) queda como opción de interoperabilidad con el
   ecosistema de mensajes de BSV; migrar es un cambio de formato
   versionado (`OP_4`).
