# Adaptador BRC-100 para DELM (HandCash self-custodial)

Archivo: bsv21-bridge/delm-brc100.mjs

## Que es

Surface self-custodial para mover DELM desde la propia
HandCash Desktop/Mobile del usuario (BRC wallet, beta,
BRC-100). NO es el bridge custodial (@1sat/actions via
Connect authToken).

- El usuario firma: createAction/internalizeAction siempre
  piden prompt (la wallet firma con las claves del usuario).
- La app (SMCP) nunca tiene las claves del usuario.
- No hay appSecret ni authToken: el origen (host) es la sesion.

## Contrato verificado contra el codigo fuente REAL

github.com/HandCash/HANDCASH-DESKTOP (rama master):
- src/wallet/token/send.ts — sendBsv21Tokens (flujo de firma)
- src/wallet/token/sendPlan.ts — buildBsv21SendOutputs,
  planBsv21Send, buildBsv21ValueLock, buildBsv21SendRemittance
- src/wallet/token/decode162.ts — encodeBsv21Binary, tokenIdToWire
- src/wallet/token/listTips.ts — decodeListedBsv21Tip
- src/wallet/token/types.ts — bsv21Tags, buildBsv21CustomInstructions
- src/wallet/token/sendEntry.ts — selectFungibleTips

## HALLAZGO CRITICO: BRC-162 BINARIO, no envelope ord JSON

La wallet moderna EMITE BRC-162 binario: "Emits only
BRC-162 locks, never legacy inscription formats" (sendPlan.ts).
El DELM es un token legacy-json (el deploy 8d7f4834 usa el
envelope ord JSON application/bsv-20), que la wallet LEE
(encoding: 'legacy-json') y puede gastar — pero los outputs
NUEVOS se emiten en BRC-162 binario.

El primer adaptador (envelope ord via buildInscriptionScript)
era INCORRECTO para enviar: construia el formato legacy.
Este adaptador emite BRC-162 binario (el wire real).

## Wire BRC-162 (value lock) — verificado offline

    push "BSV21" (5 bytes)
    push tokenIdWire (36 bytes: txid orden interno invertido + uint32 LE vout)
    OP_2DROP
    push amount (numero de script minimo: OP_0..OP_16 o LE)
    OP_0 (payload — solo el deploy lleva CBOR de sym/dec/icon)
    OP_2DROP
    <rest lock: P2PKH del destinatario>

Ejemplo (100000 DELM a mhqo7DfDou6fuS1h3v5BfBCWP8CZ9URbft):

    05 4253563231 24 <36B wire> 6d 03 a08601 00 6d 76a914...88ac
    = push "BSV21" | push wire | OP_2DROP | push 100000 | OP_0
      | OP_2DROP | P2PKH

Decodificado: tag=BSV21, tokenId=8d7f4834..._0, amount=100000,
termina P2PKH. VERIFICADO == DELM_TOKEN_ID.

## BRC-163 remittance (off-chain)

- basket: "bsv21"
- tags: [bsv21, bsv21:<tokenId>, amt:<n>, op:transfer, sym:<s>]
- customInstructions: {"p":"bsv-20","op":"transfer","id":"<txid>_<vout>","amt":"<n>","sym":"<s>","dec":"<d>"}
- El payee EXTERNO no lleva basket (solo el change vuelve a bsv21).
- payeeIsSelf (self-send): el payee SI lleva basket bsv21.

## createAction (la wallet firma)

    wallet.createAction({
      description, inputBEEF,
      inputs: [{ outpoint (wire: punto), inputDescription, unlockingScriptLength: 108 }],
      outputs: [{ lockingScript, satoshis: 1, outputDescription,
                  basket?, tags, customInstructions }],
      options: { trustSelf: 'known', noSend: true,
                 randomizeOutputs: false, signAndProcess: true },
      labels: ['bsv21', 'handcash-send-bsv21'],
    })

- inputBEEF: BRC-176 provenance de los tips gastados (merged).
- unlockingScriptLength: 108 (P2PKH signature script).
- La wallet resuelve el inputBEEF de su beefCache si no se pasa.
- checkBsv21BroadcastValidity: rechaza ancestros invalidos ANTES
  de firmar (el transfer a 1MNF 6b8de05f seria rechazado).

## Flujos

- connect(): isAuthenticated -> waitForAuthentication
  (un prompt por origen, recordado).
- readDelm(): listOutputs basket "p bsv21 id" tags
  [bsv21:<tokenId>] — suma los amt (no hay balance por token).
- transferDelm({recipient, amt, tips, inputBEEF}):
  planBsv21Send (greedy largest-first) -> buildBsv21SendOutputs
  (payee + change BRC-162) -> createAction (prompt).
- receiveDelm({atomicBeef, outputIndex, amt}):
  internalizeAction con basket insertion.

## Invariantes BSV-21 (el wallet los enforcea)

1. Conservacion por token id: out <= in. EXACTA, no redondea
   (assertBsv21AmtConservation).
2. Change obligatorio (si selectedSum > amt).
3. Todo tip es 1 satoshi.
4. El payee externo NO lleva basket del sender; solo el change
   vuelve a bsv21.
5. Padres probables: inputBEEF cubriendo los tips gastados.
6. Tips cosignados no se gastan con unlock plano
   (chooseBsv21BatchSendPath: 'plain' | 'cosigner_required'
   | 'mixed_tips' | 'refuse').

## Estado

- Adaptador BRC-162 creado y **VALIDADO contra el codigo
  compilado real de HandCash Desktop** (v1.3.425,
  AppImage extraida -> resources/app.asar ->
  dist/assets/index-D6d5nUgF.js):
  - El bundle contiene: `Q4t="BSV21"`, `G4t="4253563231"`,
    `MG=(1n<<64n)-1n`, `k9=[66,83,86,50,49]` (= TAG_BYTES).
  - El encode compilado: `writeBin(k9)`, deploy?
    `writeOpCode(OP_0)`:`writeBin([...tokenIdToWire(n)])`,
    `writeOpCode(OP_2DROP)`, `writeAmount`, deploy?
    `writeBin(cbor)`:`writeOpCode(OP_0)`, `writeOpCode(OP_2DROP)`,
    `writeScript(rest)`. **IDENTICO al port de encodeBsv21Binary.**
  - El wire generado offline decodifica == DELM_TOKEN_ID.
  - Errores reales del bridge: USE_PBSV21_SCOPE ("Use BRC-99
    basket p bsv21 all|id"), INVALID_PBSV21_SCOPE,
    MISSING_PBSV21_SCOPE_TAG. El adaptador usa "p bsv21 id".
- Bridge: proxy HTTP `app.all('*')` en https://127.0.0.1:2121
  (TLS) y http://127.0.0.1:3321. Reenvia cualquier METHOD/path
  al renderer via IPC (http-request/http-response). El renderer
  expone: createAction, getPublicKey, internalizeAction,
  isAuthenticated, listOutputs, waitForAuthentication.
- NO probado contra la GUI (la AppImage es Electron: necesita
  display/X11 para que el renderer que firma arranque; en WSL
  sin display no levanta el bridge 2121/3321).
- Para probarlo en vivo: instalar HandCash Desktop en un
  entorno con display, desbloquear, ejecutar readDelm().

## Token DELM

- TokenId canonico: 8d7f4834..._0 (deploy original, legacy-json).
- Supply: 1.000.000 (en el tip del deploy, intacto, bloqueado a 1Eqk).
- El transfer a 1MNF (6b8de05f) es INVALIDO como BSV-21
  (gasto el change, no el tip — no conserva saldo) — ignorado.
