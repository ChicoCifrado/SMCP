# Merkle Trees y SPV — analisis para SMCP

Fuente: BSV Academy (hub.bsvblockchain.org)
- Bitcoin Primitives: Merkle Trees
  - Working Blockchains and Merkle Proofs
  - Key Takeaways: Transaction Merkle Trees
- Merkle Trees (details) + SPV Deep Dive

URL: https://hub.bsvblockchain.org/higher-learning/bsv-academy/
  bitcoin-primitives-merkle-trees/merkle-trees-in-bitcoin-and-bsv/
  working-blockchains-and-merkle-proofs/

## Conceptos clave (para SMCP)

### Working Blockchains
- Cada participante mantiene SU PROPIA base de datos de
  transacciones, acompanada de Merkle proofs.
- Son "Working Blockchains": SUBCONJUNTOS de la blockchain
  total que retienen la MISMA integridad criptografica a
  traves del proof-of-work de cada bloque.
- Cualquiera verifica su conjunto local comprobando el
  Merkle proof contra los registros de otro.

### Merkle proof (de un txid a la raiz)
1. Identificar la hoja: el txid de la tx de interes.
2. Hash hermano: el hash del nodo hermano.
3. Hash padre: concatenar hoja + hermano, hashear.
4. Repetir hacia arriba.
5. Alcanzar la raiz (Merkle root).

### Block header (80 bytes, SIEMPRE)
- Version (4) | PrevBlockHash (32) | **MerkleRoot (32)**
- Time (4) | Bits (4) | Nonce (4)
- El Merkle Root encapsula TODAS las txs del bloque.
- Detectar header falso: hashearlo; si no termina en
  ceros, es falso (hacerlo requiere ASICs iterando nonce).
- Los headers estan encadenados hasta Genesis -> falsificar
  uno exige rehacer TODOS los siguientes (infeasible).

### Ventajas del Merkle tree (vs hashear la lista de txids)
1. Verificacion EFICIENTE: solo la Merkle path (pocos hashes),
   no todos los txids.
2. Validacion PARCIAL: verificar txs individuales sin bajar
   todo el conjunto.
3. Escalabilidad: la profundidad crece LOGARITMICAMENTE.
4. Tolerancia a fallos: un hash que no cuadra senala la
   ubicacion exacta de la corrupcion.
5. Ahorro de ancho de banda: solo las Merkle paths, no la
   lista completa.

### SPV (Simplified Payment Verification)
- Los headers acumulados son ~68MB; la blockchain completa
  es >10TB. Un SPV solo guarda headers (80 bytes/bloque).
- "Merkle Root es lo que comparamos contra el valor
  calculado desde nuestro txid + Merkle Path. Si coincide,
  tenemos prueba DEFINITIVA de que la tx estuvo en el
  bloque con ese header."

## Aplicacion a SMCP (el protocolo de anclaje por inferencia)

### 1. SMCP ya es una Working Blockchain
- Cada nodo (alice/bob) mantiene SU PROPIO libro de
  inferencias (`smcp/core/registro.py`, append-only jsonl).
- Cada inferencia = una tx on-chain (el anclaje).
- Los nodos verifican el libro del otro comprobando el
  Merkle proof de cada inferencia (txid) contra la raiz
  del bloque. -> working blockchain con la misma integridad
  criptografica que la cadena completa.

### 2. El anclaje DELM es verificable por SPV
- El deploy DELM (`8d7f4834`, bloque 969519) es una tx.
- Cualquier nodo puede probar que el token DELM existe
  SIN bajar la blockchain: header del bloque 969519 +
  Merkle path de `8d7f4834` -> Merkle root del header.
- Esto es exactamente lo que hace el SPV wallet de
  ElectrumSV (verificado vs gorillapool: get_history(1Eqk)
  -> 14 txs) y lo que el adaptador BRC-100 valida con
  inputBEEF (BRC-176 = tx + Merkle paths BUMP/BRC-74).

### 3. La inferencia ES la verificacion (sin hashear contenido)
- Principio SMCP: "la tx ES el mecanismo de verificacion;
  NO se hashea el contenido."
- El Merkle tree refuerza esto: la integridad viene del
  POW del bloque (el header) + la Merkle path, NO de un
  hash del contenido de la inferencia. El gist/contenido
  viaja off-chain; la prueba on-chain es el txid.
- Coherente con "Embedded data and scripts can be trusted
  as authentic" (Key Takeaways): los datos incrustados en
  la tx (la inscripcion BSV-21) son autenticos por la
  Merkle root, no por un hash externo.

### 4. Consenso ante conflicto (doble gasto de inferencias)
- "In the event of a conflict between transaction sets or
  Merkle roots, the BSV network reaches consensus."
- Si dos nodos registran la misma inferencia (doble gasto
  del bounty), la cadena resuelve cual tx es valida por
  orden de confirmacion. El nodo honesto sigue la raiz
  con mas POW.

### 5. Escalabilidad del libro de inferencias
- La profundidad del Merkle tree crece LOGARITMICAMENTE:
  verificar una inferencia entre N inferencias cuesta
  O(log N) hashes, no O(N). El libro puede crecer sin
  que la verificacion se vuelva cara.

## Conexiones con el codigo SMCP

**SMCP YA implementa el modelo de BSV Academy — con mas
rigor del que describe la doc.**

- `smcp/core/membership.py`:
  - `verify_merkle_proof(txid, index, path, root)` — la
    Merkle proof con la **trampa de endianness** documentada
    (conversion interno<->presentacion; "un verificador que
    mezcla las dos produce una raiz distinta y rechaza
    pruebas legitimas").
  - `BlockHeader` — la cabecera (Merkle root + height).
  - `InclusionProof` — prueba de que un outpoint esta en un
    bloque. **"Verificable por cualquiera con una cabecera.
    Es la unica parte que exige confianza en el mundo
    exterior, y por eso merkle_root viaja aqui: el
    verificador compara contra la cabecera que *el* cree, no
    contra la que le manda el que pide la membresia."**
  - `MembershipProof` — prueba de pertenencia completa:
    (1) output que cumple el lock + prueba de inclusion,
    (2) firma de la clave de membresia sobre el vinculo,
    (3) pubkey de membresia. Orden: **inclusion primero**
    ("si la tx no esta en un bloque no hay nada que firmar,
    y buscar la firma primero solo gasta trabajo de un
    atacante").
- `smcp/core/inscripcion.py`:
  - `verify_inscription(tx, mesh_id, requester_pubkey,
    funding_sats, inclusion: InclusionProof, header: BlockHeader)`
    — verifica el comprobante completo (inclusion + pago).
    "Que la cabecera sea la correcta **no** se prueba aqui —
    esa es la decision del verificador (SPV, BRC-96): la
    confianza esta en la cadena de cabeceras que *el* elige,
    no en la prueba."
- `smcp/core/electrumsv.py` (SPV headless): sincroniza
  cabeceras + verifica merkle path (principio SPV).
- `bsv21-bridge/delm-brc100.mjs`: `createAction` con
  `inputBEEF` (BRC-176) = la tx + los merkle paths de
  los inputs. Eso ES el Merkle proof en accion.
- `smcp/core/registro.py`: el libro append-only = la
  working blockchain local del nodo.
- Anclaje on-chain: tokenId `8d7f4834..._0` (bloque 969519).

### El principio central (ya implementado)

La confianza no esta en la prueba, sino en la **cadena de
cabeceras que el verificador elige**. `InclusionProof.verify`
compara la raiz de la prueba contra la cabecera que el
verificador trae — no contra la que le manda el contraparte.
Esto es SPV puro: ningun nodo confia en el otro; cada uno
verifica contra la cadena de headers que el considera valida.

## Conclusion

SMCP ya implementa, de forma natural y rigurosa, el modelo
de Working Blockchains de BSV Academy:
- Cada nodo = working blockchain (su libro de inferencias).
- Cada inferencia = tx anclada, verificable por Merkle
  proof contra el header del bloque (SPV).
- La integridad la da el POW del header + la Merkle path,
  NO un hash del contenido (coherente con el principio
  "la tx ES la verificacion").
- Ante conflicto (doble gasto de bounty), la cadena
  resuelve por consenso (orden de confirmacion).
- **Ya existe** la maquinaria: `verify_merkle_proof`,
  `BlockHeader`, `InclusionProof`, `MembershipProof`,
  `verify_inscription` (con la trampa de endianness
  documentada y el orden inclusion->firma).

No hay que construir el modelo — hay que **exponerlo** en
la API del nodo (un endpoint que acepte txid + Merkle path
+ header y devuelva la verificacion, para que un nodo
pruebe una inferencia ajena sin confiar en el otro).

## Diseno: POST /api/inferences/{txid}/verify

Probar una inferencia ajena por SPV (sin confiar en
el otro nodo). El verificador trae SU cadena de headers; el
endpoint verifica la inclusion contra la raiz que el
eligio (no contra la que manda el contraparte).

**Request** (el nodo que verifica aporta la prueba):
```json
{
  "mesh_id": "malla-...",
  "requester_pubkey": "03...",
  "funding_sats": 100,
  "inclusion": {
    "txid": "8d7f4834...",
    "index": 1,
    "path": ["<hermano1>", "<hermano2>", "..."],
    "merkle_root": "<raiz del bloque>",
    "height": 969519
  },
  "header": {
    "merkle_root": "<raiz>",
    "height": 969519,
    "raw": "<80 bytes hex>"
  }
}
```

**Response**:
```json
{
  "ok": true,
  "verified": true,
  "inclusion": true,
  "payment_terms": true,
  "inference_id": "sha256(txid:mesh:server)",
  "header": {"height": 969519, "block_hash": "..."}
}
```

**Implementacion (esbozo)** — reutiliza
`verify_inscription` de `smcp.core.inscripcion` y
`InclusionProof`/`BlockHeader` de `smcp.core.membership`:
```python
from smcp.core.inscripcion import verify_inscription
from smcp.core.membership import InclusionProof, BlockHeader

@router.post("/inferences/{txid}/verify")
def verify_inference(txid: str, body: VerifyInference) -> dict:
    inclusion = InclusionProof(
        txid=txid, index=body.inclusion.index,
        path=body.inclusion.path,
        merkle_root=body.inclusion.merkle_root,
        height=body.inclusion.height)
    header = BlockHeader(
        merkle_root=body.header.merkle_root,
        height=body.header.height,
        raw=bytes.fromhex(body.header.raw) if body.header.raw else b"")
    # La tx completa viaja en el request (o se obtiene del
    # registro local / del SPV). verify_inscription exige
    # la tx para extraer los terminos de pago.
    tx = fetch_transaction(txid)   # SPV / registro local
    ok, reason = verify_inscription(
        tx, mesh_id=body.mesh_id,
        requester_pubkey=bytes.fromhex(body.requester_pubkey),
        funding_sats=body.funding_sats,
        inclusion=inclusion, header=header)
    return {"ok": ok, "verified": ok, "reason": reason, ...}
```

**Orden** (el que ya impone `verify_inscription`):
inclusion primero, terminos de pago despues. "Si la tx
no esta en un bloque no hay nada que firmar, y buscar la
firma primero solo gasta trabajo de un atacante."

**Nota**: este endpoint NO crea transacciones — es
read-only (verifica pruebas ajenas). Requiere:
- Pydantic model `VerifyInference` (request schema).
- `fetch_transaction(txid)` — obtener la tx (del registro
  local, o via SPV/electrumsv). Sin la tx completa no se
  pueden verificar los terminos de pago.
- Tests: prueba valida, prueba invalida, endianness
  invertida (la trampa documentada), header con raiz
  distinta.

## Estado

**IMPLEMENTADO** (`POST /api/inferences/{txid}/verify` en
`smcp/web/api.py`):
- Modelos Pydantic: `VerifyInclusionIn`, `VerifyHeaderIn`,
  `VerifyInferenceIn`.
- El endpoint parsea la tx (`Transaction.parse`), comprueba
  que su txid coincide con el de la URL, construye
  `InclusionProof` + `BlockHeader`, y llama a
  `verify_inscription` (inclusion primero, terminos de
  pago despues).
- Extrae `server_pubkey` de la tx (`extract_inscription`)
  y calcula el `inference_id` (`sha256(txid:mesh:server)`).
- Read-only: no emite, no gasta, no toca el libro.
- **Tests: `tests/test_api_verify_inference.py` (7 tests):**
  prueba valida, raiz forjada, header hostil, txid no
  coincide, tx invalida, endianness volteada, read-only.
  **7/7 passed.** Suite: 1231 passed (12 deselected
  preexistentes: test_serve contrato ACP, test_gates ruff).

