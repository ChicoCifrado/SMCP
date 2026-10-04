// Adaptador BRC-100 para el token DELM (BSV-21)
// Surface self-custodial: el usuario firma desde su propia
// HandCash Desktop/Mobile via WalletClient('auto').
//
// Contrato verificado contra el codigo fuente real de
// HandCash Desktop (github.com/HandCash/HANDCASH-DESKTOP):
//   src/wallet/token/send.ts, sendPlan.ts, decode162.ts,
//   listTips.ts, types.ts.
//
// EMITE BRC-162 BINARIO (el formato moderno), no el envelope
// ord JSON legacy. La wallet moderna emite solo BRC-162 locks
// ("Emits only BRC-162 locks, never legacy inscription formats").
// El DELM es un token legacy-json (el deploy 8d7f4834 usa
// JSON), que la wallet lee (encoding: 'legacy-json') y puede
// gastar — pero los outputs nuevos se emiten en BRC-162.
//
// NO hace transacciones por su cuenta: createAction/internalizeAction
// siempre piden prompt al usuario (la wallet firma).

import { WalletClient, P2PKH, LockingScript, OP } from '@bsv/sdk';

// Token DELM canonico (deploy original 8d7f4834..._0).
const DELM_TOKEN_ID =
  '8d7f483498d83358e8c0b61b55334b1650d50ffce1539a482bc245dfc65c4410_0';
const DELM_SYM = 'DELM';
const DELM_DEC = 0; // deploy del DELM: dec "0"
const BSV21_BASKET = 'bsv21';
const BSV21_TAG_HEX = '4253563231'; // "BSV21"

// ---------------------------------------------------------------------------
// BRC-162 encoder (port de src/wallet/token/decode162.ts)
// Wire:
//   push "BSV21" | push tokenIdWire(36B) | OP_2DROP
//   | push amount | OP_0 | OP_2DROP | <rest lock (P2PKH)>
// ---------------------------------------------------------------------------

// Display txid_vout -> 36-byte wire: txid en orden interno
// (invertido) + uint32 LE vout.
function tokenIdToWire(tokenId) {
  const m = /^([0-9a-f]{64})_(\d+)$/i.exec(tokenId.trim().toLowerCase());
  if (!m) throw new Error(`Invalid BSV-21 token id: ${tokenId}`);
  const vout = Number(m[2]);
  if (!Number.isInteger(vout) || vout < 0 || vout > 0xffffffff) {
    throw new Error(`Invalid vout: ${vout}`);
  }
  const internal = [];
  for (let i = 0; i < 32; i++) {
    internal.push(parseInt(m[1].slice(i * 2, i * 2 + 2), 16));
  }
  internal.reverse(); // display -> internal byte order
  const wire = new Uint8Array(36);
  wire.set(internal, 0);
  wire[32] = vout & 0xff;
  wire[33] = (vout >>> 8) & 0xff;
  wire[34] = (vout >>> 16) & 0xff;
  wire[35] = (vout >>> 24) & 0xff;
  return wire;
}

// Numero de script minimamente codificado (0..2^64-1).
// 0 -> OP_0; 1..16 -> OP_1..OP_16; else LE + high-zero sign byte.
function encodeScriptNumber(amount) {
  const amt = BigInt(amount);
  if (amt < 0n || amt > (1n << 64n) - 1n) {
    throw new Error('BSV-21 amount out of range (0..2^64-1)');
  }
  if (amt === 0n) return { op: OP.OP_0 };
  if (amt <= 16n) return { op: OP.OP_1 - 1 + Number(amt) };
  const bytes = [];
  let n = amt;
  while (n > 0n) {
    bytes.push(Number(n & 0xffn));
    n >>= 8n;
  }
  if (bytes[bytes.length - 1] & 0x80) bytes.push(0);
  return { op: bytes.length, data: bytes };
}

// Codifica un value/deploy lock BRC-162.
// tokenId vacio = deploy (OP_0 en lugar del wire de 36B).
function encodeBsv21Binary({ tokenId, amount, rest }) {
  const amt = BigInt(amount);
  if (amt <= 0n) throw new Error('BSV-21 encode refuses amount 0 (authority)');
  const isDeploy = !tokenId || tokenId.trim() === '';
  const idRaw = (tokenId || '').trim().toLowerCase();
  if (!isDeploy && !/^[0-9a-f]{64}_\d+$/.test(idRaw.replace(/\.(\d+)$/, '_$1'))) {
    throw new Error(`Invalid BSV-21 token id: ${tokenId}`);
  }
  const script = new LockingScript();
  // push "BSV21"
  script.writeBin([0x42, 0x53, 0x56, 0x32, 0x31]);
  if (isDeploy) {
    script.writeOpCode(OP.OP_0);
  } else {
    script.writeBin([...tokenIdToWire(idRaw)]);
  }
  script.writeOpCode(OP.OP_2DROP);
  // push amount
  const enc = encodeScriptNumber(amt);
  if (enc.data) script.writeBin(enc.data);
  else script.writeOpCode(enc.op);
  // payload: OP_0 para value outputs (solo el deploy lleva CBOR)
  script.writeOpCode(OP.OP_0);
  script.writeOpCode(OP.OP_2DROP);
  // rest lock (P2PKH del destinatario)
  if (rest) script.writeScript(rest);
  return script;
}

// Lock de valor BRC-162: BRC-162 prefix + P2PKH(address).
function buildBsv21ValueLock({ tokenId, amount, address }) {
  const p2pkhHex = new P2PKH().lock(address).toHex();
  const script = encodeBsv21Binary({
    tokenId,
    amount,
    rest: LockingScript.fromHex(p2pkhHex),
  });
  // Verificacion: decodificar y comprobar el chunk "BSV21"
  // (como isTagChunk en decode162.ts — el hex empieza con
  // el opcode de push, no con los datos).
  const chunks = script.chunks;
  const tag = chunks[0] && chunks[0].data;
  if (!tag || tag.length !== 5) {
    throw new Error('BSV-21 send produced a non-BSV21 lock (no tag)');
  }
  if (!(tag[0] === 0x42 && tag[1] === 0x53 && tag[2] === 0x56 && tag[3] === 0x32 && tag[4] === 0x31)) {
    throw new Error('BSV-21 send produced a non-BSV21 lock (bad tag)');
  }
  return script.toHex().toLowerCase();
}

// ---------------------------------------------------------------------------
// BRC-163 remittance (off-chain: basket + tags + customInstructions)
// ---------------------------------------------------------------------------

function bsv21Tags({ tokenId, amt, sym, op }) {
  const tags = ['bsv21', `bsv21:${tokenId}`, `amt:${amt}`];
  if (op) tags.push(`op:${op}`);
  if (sym) tags.push(`sym:${sym.slice(0, 32).toLowerCase()}`);
  return tags;
}

function buildBsv21CustomInstructions({ tokenId, amt, op, sym, dec }) {
  const body = { p: 'bsv-20', op, id: tokenId, amt: amt.toString() };
  if (sym) body.sym = sym;
  if (dec != null && dec > 0) body.dec = String(dec);
  return JSON.stringify(body);
}

function buildBsv21SendRemittance({ tokenId, amt, sym, dec }) {
  return {
    basket: BSV21_BASKET,
    tags: bsv21Tags({ tokenId, amt, sym, op: 'transfer' }),
    customInstructions: buildBsv21CustomInstructions({
      tokenId,
      amt,
      op: 'transfer',
      sym,
      dec,
    }),
  };
}

// ---------------------------------------------------------------------------
// Planificacion (port de sendPlan.ts / sendEntry.ts)
// ---------------------------------------------------------------------------

// Greedy largest-first hasta cubrir amount. Conservacion exacta.
function planBsv21Send({ tokenId, amount, tips }) {
  const amt = BigInt(amount);
  if (amt <= 0n) throw new Error('Amount must be greater than zero');
  const usable = tips
    .filter((t) => t.tokenId === tokenId && t.amt > 0n)
    .sort((a, b) => (b.amt > a.amt ? 1 : b.amt < a.amt ? -1 : 0));
  const selected = [];
  let selectedSum = 0n;
  for (const tip of usable) {
    if (selectedSum >= amt) break;
    selected.push(tip);
    selectedSum += tip.amt;
  }
  if (selectedSum < amt) {
    throw new Error('Not enough token outputs to cover this send');
  }
  return {
    tokenId,
    selected,
    selectedSum,
    payeeAmt: amt,
    changeAmt: selectedSum - amt,
  };
}

function assertBsv21AmtConservation(inputAmts, outputAmts) {
  const input = inputAmts.reduce((a, b) => a + b, 0n);
  const output = outputAmts.reduce((a, b) => a + b, 0n);
  if (input !== output) {
    throw new Error(`Token amt not conserved (parents ${input} != children ${output})`);
  }
}

// Construye los outputs payee + change (BRC-162 value locks).
function buildBsv21SendOutputs({
  tokenId,
  payeeAmt,
  changeAmt,
  payeeAddress,
  changeAddress,
  sym,
  dec,
  payeeIsSelf,
}) {
  assertBsv21AmtConservation(
    [payeeAmt + changeAmt],
    changeAmt > 0n ? [payeeAmt, changeAmt] : [payeeAmt],
  );
  const payeeRemit = buildBsv21SendRemittance({ tokenId, amt: payeeAmt, sym, dec });
  const { basket: _pb, ...payeeRemitFields } = payeeRemit;
  const outputs = [
    {
      role: 'payee',
      lockingScript: buildBsv21ValueLock({ tokenId, amount: payeeAmt, address: payeeAddress }),
      satoshis: 1,
      ...payeeRemitFields,
      // Solo si el payee es nosotros mismos (self-send): el output
      // vuelve a nuestra basket bsv21. El payee externo NO lleva basket.
      ...(payeeIsSelf ? { basket: BSV21_BASKET } : {}),
      outputDescription: payeeIsSelf ? 'BSV-21 value (self)' : 'BSV-21 value',
      amt: payeeAmt.toString(),
    },
  ];
  if (changeAmt > 0n) {
    const changeRemit = buildBsv21SendRemittance({ tokenId, amt: changeAmt, sym, dec });
    outputs.push({
      role: 'change',
      lockingScript: buildBsv21ValueLock({ tokenId, amount: changeAmt, address: changeAddress }),
      satoshis: 1,
      ...changeRemit,
      basket: BSV21_BASKET,
      outputDescription: 'BSV-21 change',
      amt: changeAmt.toString(),
    });
  }
  return outputs;
}

// ---------------------------------------------------------------------------
// Adaptador
// ---------------------------------------------------------------------------

export class DelmBRC100 {
  constructor() {
    // WalletClient('auto'): encuentra HandCash Desktop en
    // loopback (https://127.0.0.1:2121, fallback 3321).
    // NO requiere appId/appSecret (self-custodial).
    this.wallet = new WalletClient('auto');
  }

  // Conectar (un prompt de aprobacion por origen, recordado).
  async connect() {
    const authed = await this.wallet.isAuthenticated();
    if (authed) return true;
    return this.wallet.waitForAuthentication();
  }

  // Leer el balance DELM de esta wallet.
  // Suma los "amt" de los tips en basket "p bsv21 id" (permiso
  // de lectura). No hay balance por token: hay que sumar tips.
  async readDelm() {
    await this.connect();
    const tokenId = DELM_TOKEN_ID;
    // Basket de permiso de lectura: "p bsv21 id"
    const result = await this.wallet.listOutputs({
      basket: `p ${BSV21_BASKET} id`,
      tags: [`bsv21:${tokenId}`],
      tagQueryMode: 'all',
      includeCustomInstructions: true,
    });
    let total = 0n;
    const tips = [];
    for (const out of result.outputs || []) {
      const ci = this._parseCI(out.customInstructions);
      const amt = ci?.amt ?? this._tagValue(out.tags, 'amt:');
      if (!amt) continue;
      total += BigInt(amt);
      tips.push({
        outpoint: out.outpoint,
        tokenId,
        amt: BigInt(amt),
        satoshis: out.satoshis,
        lockingScript: out.lockingScript,
        customInstructions: out.customInstructions,
        tags: out.tags,
      });
    }
    return { balance: total.toString(), tips, tokenId, sym: DELM_SYM, dec: DELM_DEC };
  }

  // Transferir DELM a una direccion/handle.
  // La wallet firma (createAction pide prompt).
  // tips: los tips a gastar (de readDelm). Si no, greedy de la wallet.
  async transferDelm({ recipient, amt, tips, inputBEEF }) {
    await this.connect();
    const tokenId = DELM_TOKEN_ID;
    const amount = BigInt(amt);
    if (amount <= 0n) throw new Error('Amount must be greater than zero');

    // Seleccionar tips (greedy largest-first) si no los dan.
    const selectedTips = tips && tips.length
      ? tips
      : (await this.readDelm()).tips;
    const plan = planBsv21Send({ tokenId, amount, tips: selectedTips });

    // Direccion propia (para el change) — de la identity key.
    const changeAddress = await this._ownAddress();

    // Construir outputs payee + change (BRC-162 value locks).
    // Conservacion exacta: payeeAmt + changeAmt = selectedSum.
    const outputs = buildBsv21SendOutputs({
      tokenId,
      payeeAmt: plan.payeeAmt,
      changeAmt: plan.changeAmt,
      payeeAddress: recipient,
      changeAddress,
      sym: DELM_SYM,
      dec: DELM_DEC,
      payeeIsSelf: false,
    });

    // Construir el createAction (la wallet firma).
    // inputBEEF: provenance (BRC-176) de los tips gastados.
    // Si no se pasa, la wallet lo resuelve de su beefCache.
    const action = {
      description: `Send ${plan.payeeAmt.toString()} DELM`,
      inputBEEF,
      inputs: plan.selected.map((tip) => ({
        // El outpoint en wire format (punto en lugar de guion bajo).
        outpoint: tip.outpoint.includes('.')
          ? tip.outpoint
          : tip.outpoint.replace(/_(\d+)$/, '.$1'),
        inputDescription: 'BSV-21 value',
        unlockingScriptLength: 108, // P2PKH signature script
      })),
      outputs: outputs.map((o) => ({
        lockingScript: o.lockingScript,
        satoshis: 1,
        outputDescription: o.outputDescription,
        ...(o.basket ? { basket: o.basket } : {}),
        tags: o.tags,
        customInstructions: o.customInstructions,
      })),
      options: {
        trustSelf: 'known',
        noSend: true,
        randomizeOutputs: false,
        signAndProcess: true,
      },
      labels: [BSV21_BASKET, 'handcash-send-bsv21'],
    };

    // createAction: la wallet firma y devuelve el signable.
    // SIEMPRE pide prompt (la wallet no firma sin el usuario).
    const created = await this.wallet.createAction(action);
    return {
      created,
      plan: {
        tipsSpent: plan.selected.length,
        amount: plan.payeeAmt.toString(),
        change: plan.changeAmt.toString(),
      },
      outputs,
    };
  }

  // Recibir DELM (internalizeAction: inserta un output en la
  // basket bsv21 de esta wallet).
  async receiveDelm({ atomicBeef, outputIndex, amt }) {
    await this.connect();
    // atomicBeef: el BEEF atomico de la tx que paga al destinatario.
    // outputIndex: el vout que paga a esta wallet.
    return this.wallet.internalizeAction({
      rawTx: atomicBeef,
      insertions: [
        {
          outputIndex,
          basket: BSV21_BASKET,
          description: `Receive ${amt} DELM`,
          tags: bsv21Tags({ tokenId: DELM_TOKEN_ID, amt, sym: DELM_SYM, op: 'transfer' }),
          customInstructions: buildBsv21CustomInstructions({
            tokenId: DELM_TOKEN_ID,
            amt,
            op: 'transfer',
            sym: DELM_SYM,
            dec: DELM_DEC,
          }),
        },
      ],
    });
  }

  // Dirección propia (para el change) — de listOutputs(default).
  async _ownAddress() {
    const funding = await this.wallet.listOutputs({
      basket: 'default',
      limit: 1,
    });
    const first = funding.outputs && funding.outputs[0];
    if (first && first.deliveryAddress) {
      return first.deliveryAddress;
    }
    throw new Error(
      'own address no disponible: usa listOutputs(default) ' +
      'para obtener una deliveryAddress de la wallet');
  }

  _parseCI(ci) {
    if (!ci) return null;
    try {
      return JSON.parse(ci);
    } catch {
      return null;
    }
  }

  _tagValue(tags, prefix) {
    if (!tags) return undefined;
    for (const tag of tags) {
      if (tag.startsWith(prefix)) {
        const v = tag.slice(prefix.length).trim();
        if (v) return v;
      }
    }
    return undefined;
  }
}

export { DELM_TOKEN_ID, BSV21_BASKET, encodeBsv21Binary, buildBsv21ValueLock };
