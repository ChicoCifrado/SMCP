"""Token BSV-21 DELM — economia de la red mesh.

El token DELM es la moneda de la red DeLM: los nodos
(alice, bob, ...) ganan DELM por resolver inferencias
y el DELM se puede listar/vender en 1sat.market.

Este modulo es un **bridge** al SDK nativo
``@1sat/actions`` (Node.js) — el unico SDK que opera
BSV-21 de forma nativa (deploy, send, list, buy) contra
el indexer unificado ``api.1sat.app``. Python no tiene
un SDK BSV-21 equivalente; delegamos via subprocess a
un script Node.

Diseno
------
La capa E (anclaje BSV, :mod:`delm.core.contract`)
cobra el bounty en **satoshis** (P2PKH). Este modulo
anade la **capa F — token**: el pago en DELM.

    Inferencia verificada
        -> contrato BSV: bounty en sats (P2PKH nodo)
        -> token DELM:  pago en DELM (sendBsv21)

El nodo puede:
* cobrar el bounty en sats (contract.py)
* recibir DELM por la inferencia (sendBsv21)
* listar sus DELM en 1sat.market (listBsv21)

El SDK nativo
-------------
``@1sat/actions`` (npm) provee:
* ``deployBsv21Mint``   — deploy supply fijo
* ``deployBsv21Auth``   — deploy mintable + auth
* ``mintBsv21``         — acuñar mas (gasta auth)
* ``sendBsv21``         — enviar (value-based)
* ``getBsv21Balances``  — balances agregados
* ``listBsv21``         — UTXOs de token del wallet
* ``buyBsv21``          — comprar listing OrdLock

Requisitos
----------
* Node.js >= 18
* ``npm i @1sat/actions @1sat/wallet-node @1sat/templates @bsv/sdk``
* WIF de la wallet (env var ``DELM_TOKEN_WIF`` o fichero)

Nota
----
El token DELM se despliega con ``deploy+mint`` (supply
fijo 1.000.000, 0 decimales). El tokenId es
``<deployTxid>_0``. El indexer 1sat solo activa el
token una vez la tx de deploy confirma en bloque.

Se desplego 3 veces por error; el tokenId canonico
es ``TOKEN_ID_CANONICO`` (deploy original ``8d7f4834``).
Los otros dos despliegues quedan como tokens muertos:
no se gastan ni se listan. El supply efectivo de DELM
es 1.000.000 (el del canónico).
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any

#: Simbolo del token.
TOKEN_SYMBOL = "DELM"
#: Suministro total (unidades raw, 0 decimales).
TOKEN_SUPPLY = "1000000"
#: Decimales.
TOKEN_DECIMALS = 0
#: tokenId canonico del DELM (deploy original, confirmado
#: on-chain, con funding parcial en el overlay 1sat).
#: Los otros dos despliegues (5c6c7efb... y 491f8442...)
#: quedan como tokens muertos: no se gastan ni se listan.
TOKEN_ID_CANONICO = (
    "8d7f483498d83358e8c0b61b55334b1650d50ffce"
    "1539a482bc245dfc65c4410_0"
)
#: Direccion que sostiene el 90% del supply (1Eqk).
TOKEN_HOLDER_MAIN = "1EqkBCLhykcHkr7o9AnHwgrgzAsAbGF3Dz"

#: Directorio del bridge Node (junto a este paquete).
_BRIDGE_DIR = os.environ.get(
    "DELM_TOKEN_BRIDGE_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "bsv21-bridge"),
)


@dataclass(frozen=True)
class Bsv21Result:
    """Resultado de una operacion BSV-21."""

    ok: bool
    txid: str = ""
    token_id: str = ""
    error: str = ""
    raw: dict[str, Any] | None = None


def _run_bridge(action: str, **kwargs: Any) -> Bsv21Result:
    """Ejecuta el bridge Node (``node bsv21.mjs <action> <json>``)."""
    payload = json.dumps({"action": action, **kwargs})
    # el WIF se pasa por env (nunca por argv)
    env = os.environ.copy()
    wif = os.environ.get("DELM_TOKEN_WIF") or _read_wif()
    if wif:
        env["DELM_TOKEN_WIF"] = wif
    try:
        proc = subprocess.run(
            ["node", os.path.join(_BRIDGE_DIR, "bsv21.mjs")],
            input=payload,
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
            cwd=_BRIDGE_DIR,
        )
    except FileNotFoundError:
        return Bsv21Result(False, error="node no encontrado (instala Node >= 18)")
    except subprocess.TimeoutExpired:
        return Bsv21Result(False, error="timeout del bridge (120s)")
    out = (proc.stdout or "").strip()
    if not out:
        return Bsv21Result(
            False,
            error=(proc.stderr or "sin salida").strip()[:500],
        )
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return Bsv21Result(False, error=f"salida no JSON: {out[:200]}")
    return Bsv21Result(
        ok=bool(data.get("ok", False)),
        txid=str(data.get("txid", "")),
        token_id=str(data.get("tokenId", "")),
        error=str(data.get("error", "")),
        raw=data,
    )


def _read_wif() -> str:
    """Lee el WIF de ``~/.delm/token.wif`` si existe."""
    for p in (
        os.path.expanduser("~/.delm/token.wif"),
        os.path.expanduser("~/.hermes/token.wif"),
    ):
        try:
            with open(p) as f:
                wif = f.read().strip()
                if wif:
                    return wif
        except OSError:
            continue
    return ""


# ---------------------------------------------------------------------------
# Operaciones publicas
# ---------------------------------------------------------------------------


def deploy(
    *,
    symbol: str = TOKEN_SYMBOL,
    amount: str = TOKEN_SUPPLY,
    decimals: int = TOKEN_DECIMALS,
    destination_address: str = "",
) -> Bsv21Result:
    """Despliega el token BSV-21 (supply fijo).

    ``deployBsv21Mint`` — crea el token con todo el
    suministro y lo envia a ``destination_address``
    (o a la propia wallet si se omite).
    """
    return _run_bridge(
        "deploy",
        symbol=symbol,
        amount=amount,
        decimals=decimals,
        destination=destination_address,
    )


def send(
    *,
    token_id: str,
    recipients: list[dict[str, Any]],
) -> Bsv21Result:
    """Envia DELM a uno o mas destinatarios.

    ``sendBsv21`` — value-based. ``recipients`` es una
    lista de ``{"amount": "<raw>", "destination":
    {"address": "<addr>"}}``.
    """
    if not recipients:
        return Bsv21Result(False, error="sin destinatarios")
    return _run_bridge("send", tokenId=token_id, recipients=recipients)


def balances() -> Bsv21Result:
    """Balances BSV-21 agregados de la wallet.

    ``getBsv21Balances`` — lista todos los tokens que
    la wallet posee, con su simbolo y saldo.
    """
    return _run_bridge("balances")


def list_token_utxos(*, token_id: str = "", limit: int = 100) -> Bsv21Result:
    """Lista los UTXOs de token de la wallet.

    ``listBsv21`` — devuelve los outpoints de token
    (con tags ``bsv21:{tokenId}``, ``amt:{n}``).
    """
    return _run_bridge("list", limit=limit, tokenId=token_id)


def buy(
    *,
    token_id: str,
    outpoint: str,
    amount: str,
) -> Bsv21Result:
    """Compra un listing de 1sat.market.

    ``buyBsv21`` — gasta sats para adquirir DELM de un
    listing OrdLock en el marketplace.
    """
    return _run_bridge(
        "buy", tokenId=token_id, outpoint=outpoint, amount=amount
    )


# ---------------------------------------------------------------------------
# Comodines DeLM
# ---------------------------------------------------------------------------


def pay_for_inference(
    *,
    token_id: str,
    node_address: str,
    amount: str,
) -> Bsv21Result:
    """Paga a un nodo en DELM por una inferencia.

    Es la contrapartida en token del :func:`build_claim_tx`
    (que paga en sats). El nodo recibe ``amount`` DELM
    en su direccion.
    """
    return send(
        token_id=token_id,
        recipients=[
            {"amount": amount, "destination": {"address": node_address}}
        ],
    )


def token_id_from_deploy(deploy_txid: str) -> str:
    """El tokenId BSV-21 es ``<deployTxid>_<outputIndex>``.

    El deploy acuna el token en el output 0 (la
    inscripcion de 1 sat), por lo que el tokenId es
    ``<deployTxid>_0``.
    """
    return f"{deploy_txid}_0"
