// Bridge Node para el token BSV-21 DELM.
// Delega al SDK nativo @1sat/actions (unico SDK
// que opera BSV-21 de forma nativa contra el
// indexer unificado api.1sat.app).
//
// Uso: echo '{"action":"deploy",...}' | node bsv21.mjs
// El WIF viene por env DELM_TOKEN_WIF.
//
// Acciones:
//   deploy    — deployBsv21Mint (supply fijo)
//   send      — sendBsv21 (value-based)
//   balances  — getBsv21Balances
//   list      — listBsv21
//   buy       — buyBsv21

import { createContext } from '@1sat/actions';
import { createNodeWallet } from '@1sat/wallet-node';
import { deployBsv21Mint, sendBsv21, getBsv21Balances, listBsv21, buyBsv21 } from '@1sat/actions';
import { PrivateKey } from '@bsv/sdk';

const WIF = process.env.DELM_TOKEN_WIF || '';
// tokenId canonico del DELM (deploy original 8d7f4834...).
// Los otros dos despliegues quedan como tokens muertos.
const DEFAULT_TOKEN_ID = '8d7f483498d83358e8c0b61b55334b1650d50ffce1539a482bc245dfc65c4410_0';
if (!WIF) {
  console.log(JSON.stringify({ ok: false, error: 'DELM_TOKEN_WIF no definido' }));
  process.exit(0);
}

// leer input (JSON)
let input = '';
process.stdin.setEncoding('utf8');
for await (const chunk of process.stdin) input += chunk;
let req;
try {
  req = JSON.parse(input || '{}');
} catch {
  console.log(JSON.stringify({ ok: false, error: 'input no es JSON' }));
  process.exit(0);
}

const { action } = req;

let wallet;
let services;
let destroy;
try {
  const created = await createNodeWallet({
    chain: 'main',
    privateKey: WIF,
    storage: { provider: 'bun-sqlite', filename: '.delm-wallet.db' },
    storageIdentityKey: 'delm-mesh-token',
    skipInitialMonitor: true,
  });
  wallet = created.wallet;
  services = created.services;
  destroy = created.destroy;
} catch (e) {
  console.log(JSON.stringify({ ok: false, error: 'wallet: ' + e.message }));
  process.exit(0);
}

const ctx = createContext(wallet, { services, chain: 'main' });

try {
  if (action === 'deploy') {
    const result = await deployBsv21Mint.execute(ctx, {
      symbol: req.symbol || 'DELM',
      amount: String(req.amount || '1000000'),
      decimals: Number(req.decimals || 0),
      destination: req.destination ? { address: req.destination } : undefined,
    });
    console.log(JSON.stringify({
      ok: !result.error,
      txid: result.txid || '',
      tokenId: result.tokenId || '',
      error: result.error || '',
    }));
  } else if (action === 'send') {
    const recipients = (req.recipients || []).map((r) => ({
      amount: r.amount,
      destination: r.destination,
    }));
    const result = await sendBsv21.execute(ctx, {
      tokenId: req.tokenId || DEFAULT_TOKEN_ID,
      recipients,
    });
    console.log(JSON.stringify({
      ok: !result.error,
      txid: result.txid || '',
      error: result.error || '',
    }));
  } else if (action === 'balances') {
    const balances = await getBsv21Balances.execute(ctx, {});
    console.log(JSON.stringify({
      ok: true,
      balances: balances.map((b) => ({
        sym: b.sym || b.id,
        amt: String(b.amt),
        dec: b.dec,
      })),
    }));
  } else if (action === 'list') {
    const outputs = await listBsv21.execute(ctx, { limit: Number(req.limit || 100) });
    console.log(JSON.stringify({
      ok: true,
      utxos: outputs.map((o) => ({
        outpoint: o.outpoint,
        tags: o.tags || [],
      })),
    }));
  } else if (action === 'buy') {
    const result = await buyBsv21.execute(ctx, {
      tokenId: req.tokenId || DEFAULT_TOKEN_ID,
      outpoint: req.outpoint,
      amount: String(req.amount),
    });
    console.log(JSON.stringify({
      ok: !result.error,
      txid: result.txid || '',
      error: result.error || '',
    }));
  } else {
    console.log(JSON.stringify({ ok: false, error: 'accion desconocida: ' + action }));
  }
} catch (e) {
  console.log(JSON.stringify({ ok: false, error: e.message }));
} finally {
  try { await destroy(); } catch {}
}
