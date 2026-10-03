# Smart contract BSV + protocolo permissionless para DeLM

## Contexto actual (lo que ya hay)

- `anchor.py`: una tx por inferencia, outpoint de atribucion
  (la clave de bloqueo = clave de membresia del nodo). No se
  hashea el contenido (solo se prueba que ocurrio).
- `txbuild.py`: serializador BSV legacy (P2PKH, SIGHASH_ALL).
- `x402.py`: verificador BRC-120/x402 v1.0 (pago por inferencia).
- `arc.py`: broadcast a la red (ARC — whatsonchain).
- `tiers.py`: free / metered / dedicated.

## Objetivo

Protocolo **permissionless**: nadie controla la red, todos
colaboran haciendo inferencia para recibir satoshis. Anclar
al tiempo cada inferencia en BSV via smart contract.

## Diseno del smart contract (sCrypt)

El contract gobierna el **pago por inferencia verificada**.
Un nodo (worker) recibe satoshis solo si su inferencia fue
admitida en el contexto compartido y anclada.

### Estados del contract

```
contract InferenceBounty {
  // parametros inmutables (constructor)
  PubKey     verifier;      // quien verifica gists (la malla)
  PubKey     treasury;      // quien financia (el que publica tareas)
  int        bountyPerInference;  // satoshis por inferencia
  int        dustLimit = 0;       // BSV no tiene umbral de polvo

  // estado mutable
  PubKey     latestAdmittedNode;  // ultimo nodo que admitio
  Sha256     latestGistDigest;    // digest del gist admitido
  int        totalInferences = 0; // contador global
}
```

### Flujo (permissionless)

1. **Treasury** publica una tarea + fondea el contract con
   `bountyPerInference * maxInferences` satoshis.
2. Cualquier nodo (permissionless) resuelve la tarea y
   propone un gist.
3. La malla verifica el gist (n-grams >=4 en el trajectory)
   y lo firma (ed25519).
4. El nodo llama `claim(gistDigest, sig)`:
   - verifica la firma del verifier sobre el gist
   - si es valida: paga `bountyPerInference` al nodo y
     actualiza `latestAdmittedNode` + `totalInferences++`
5. El claim es la **tx de anclaje** (outpoint de atribucion
   al nodo). Una tx por inferencia.

### Por que esto es permissionless

- Nadie controla quien puede ser nodo: cualquiera con una
  clave BSV puede resolver y proponer gists.
- El pago lo gobierna el contract, no un operador: si el
  gist verifica, el contract PAGA (el contract es la ley).
- La red BSV valida la tx (script del contract), no una
  autoridad central.

## Protocolo de anclaje al tiempo (capa E + contract)

Cada inferencia queda anclada con:

```
InferenceAnchor {
  uint8    version = 1;
  Sha256   taskDigest;        // hash de la tarea (publica)
  Sha256   gistDigest;        // hash del gist admitido
  PubKey   nodeKey;           // nodo que resolvio
  int      satoshisPaid;      // lo que pago el contract
  bytes    verifierSig;       // firma del verifier
  uint32   blockHeight;       // altura del anclaje
  bytes32  txid;              // txid de la tx de anclaje
}
```

### Verificacion (cualquiera, offline)

```
verify(anchor):
  1. txid esta en un bloque (InclusionProof vs cabecera
     que elige el verificador) — BRC-96
  2. la tx gasta un output del contract (el bounty)
  3. el script de la tx incluye verifierSig valida
  4. nodeKey = clave del output de atribucion (P2PKH)
  5. blockHeight > altura de membresia del nodo
```

## Integracion con el codigo existente

- `anchor.py` ya produce `InclusionProof` y verifica la
  linea de tiempo — reutilizar para el paso 1 y 5.
- `txbuild.py` ya serializa y firma P2PKH — reutilizar
  para construir la tx del contract (P2SH/P2PKH del
  script del contract).
- `x402.py` ya verifica el pago — el claim del contract
  es el gasto del output x402.
- `arc.py` ya difunde — usar para emitir la tx del
  contract.

## Roadmap

1. [ ] Smart contract sCrypt (InferenceBounty) —
      compilar con sCrypt IDE / sctool
2. [ ] Wrapper Python: construir la tx de claim que
      gasta el output del contract (P2SH) y firma
      con la clave del nodo
3. [ ] Emision: ARC broadcast de la tx de claim
4. [ ] Verificacion offline: InclusionProof + script
      check + linea de tiempo
5. [ ] Mapeo: un nodo (alice) publica tarea + fondea;
      otro (bob) resuelve y cobra via contract

## Decisiones abiertas (para ti)

- **sCrypt vs Script plano**: sCrypt es mas legible pero
  requiere compilador; Script plano (OP_CHECKSIG,
  OP_HASH256) es mas simple y se construye con txbuild.py.
  Para un prototype, Script plano es mas rapido.
- **Financiamiento**: quien fondea el contract? Un
  treasury central (tierno) o un pool decentralizado?
- **Precio del bounty**: fijo o por subasta (los nodos
  pujan por la tarea)?
