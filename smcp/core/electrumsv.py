"""Integracion ElectrumSV headless — la wallet SPV del proyecto.

Por qué esta capa
------------------
El proyecto necesita una wallet SPV real (sin confiar las claves a
un tercero) para la infraestructura de pagos en BSV. HandCash ya
está probado (pagos con `note`, UTXOs via WhatsOnChain), pero es
una wallet custodial: las claves las gestiona HandCash. ElectrumSV
es lo contrario: el daemon firma **localmente** con las claves del
fichero wallet (sqlite, cifrado con password local) y valida contra
ElectrumX sin entregarle nada secreto.

Arquitectura de dos piezas
---------------------------
* **ElectrumSV headless** (`smcp/core/electrumsv.py`, este módulo)
  — la wallet SPV: UTXOs, balance, construir+emitir txs P2PKH y
  con scripts arbitrarios (`script_pubkey` en hex). Firma local.
* **Bridge `@1sat/actions`** (`bsv21-bridge/bsv21.mjs`)
  — la lógica BSV-21 (DELM): despliega/mueve el token contra el
  overlay 1sat (inscripciones + ARC). Lo construye el SDK; este
  módulo no toca inscripciones.

La separación es deliberada: ElectrumSV puede gastar sats y crear
outputs con cualquier `script_pubkey`, pero la semántica BSV-21
(deploy+mint, transfer, el indexer 1sat, el funding BRC-0062/BEEF)
la implementa `@1sat/actions`. No reinventarla aquí.

Trazabilidad (el requisito central)
------------------------------------
Toda tx pasa por ``create_tx`` (construir SIN emitir) -> inspeccionar
inputs/outputs -> ``broadcast`` -> registrar la txid en un log
append-only. El log es ``~/.smcp/electrumsv.txs.jsonl`` (una línea
por tx: txid, wallet, account, propósito, timestamp). Así cada gasto
es trazable on-chain (la txid es el anclaje) y localmente.

Seguridad de claves
-------------------
* El WIF/seed NUNCA se pide por chat ni se imprime.
* Se carga desde ``~/.smcp/token.wif`` (0600) o fichero equivalente.
* La password del fichero wallet es local al daemon (cifra las claves
  dentro del sqlite); este cliente solo habla con un daemon ya
  desbloqueado.
* Lección aprendida (SMCP): un WIF que vivió solo en ``/tmp``
  (pruning 72h) se perdió. Regla: persistir en ``~/.smcp/``.

Lo que este módulo NO hace
---------------------------
* No arranca el daemon (eso es ``electrumsv-sdk``; ver
  ``references/daemon-rest.md`` del skill ``electrumsv-wallet``).
* No mueve DELM/BSV-21 (eso es el bridge).
* No elige fee (la aritmética entra/salida es del que llama).
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)

#: Base URL del daemon restapi (el "dapp" de ejemplo de ElectrumSV).
DAEMON_BASE = "http://127.0.0.1:9999"

#: Red por defecto. main | test | regtest.
NETWORK = os.environ.get("SMCP_ELECTRUMSV_NETWORK", "main")

#: Log append-only de txs (trazabilidad local).
DEFAULT_TX_LOG = Path.home() / ".smcp" / "electrumsv.txs.jsonl"

#: Fichero de clave privada del proyecto (WIF, 0600).
TOKEN_WIF_PATH = Path.home() / ".smcp" / "token.wif"


class ElectrumSVError(RuntimeError):
    """Error del daemon o de la respuesta."""


class ElectrumSV:
    """Cliente REST del daemon ElectrumSV (SPV wallet).

    Todas las lecturas (``wallets``, ``utxos``, ``balance``,
    ``history``) son read-only y no requieren clave. Las escrituras
    (``create_tx``, ``broadcast``) las firma el daemon con las
    claves del fichero wallet — este cliente solo las orquesta.
    """

    def __init__(self, base_url: str = DAEMON_BASE,
                 network: str = NETWORK) -> None:
        self.base_url = base_url.rstrip("/")
        self.network = network

    # ------------------------------------------------------------------ bajo
    def _url(self, path: str) -> str:
        return f"{self.base_url}/v1/{self.network}/dapp{path}"

    def _call(self, method: str, path: str,
              body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self._url(path)
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read().decode("utf-8"))
            except Exception:  # pragma: no cover
                err = {"error": f"HTTP {e.code}"}
            raise ElectrumSVError(
                f"{method} {path}: {err}") from e
        except urllib.error.URLError as e:
            raise ElectrumSVError(
                f"daemon no alcanzable en {self.base_url}: {e.reason}"
            ) from e

    @staticmethod
    def _wallet_path(wallet: str, account: str = "") -> str:
        p = f"/wallets/{wallet}"
        if account:
            p += f"/{account}"
        return p

    # ----------------------------------------------------------------- lectura
    def list_wallets(self) -> dict[str, Any]:
        """Wallets cargados en el daemon."""
        return self._call("GET", "/wallets")

    def load_wallet(self, wallet: str) -> dict[str, Any]:
        """Cargar/sincronizar una wallet (suscribir a ElectrumX)."""
        return self._call("POST", self._wallet_path(wallet))

    def account(self, wallet: str, account: str) -> dict[str, Any]:
        """Resumen de una cuenta."""
        return self._call("GET", self._wallet_path(wallet, account))

    def utxos(self, wallet: str, account: str,
              confirmed_only: bool = False) -> dict[str, Any]:
        """UTXOs de una cuenta (con filtro confirmados)."""
        path = self._wallet_path(wallet, account) + "/utxos"
        body = {"confirmed_only": confirmed_only} if confirmed_only else None
        return self._call("GET", path, body)

    def balance(self, wallet: str, account: str) -> dict[str, Any]:
        """Balance (sats confirmados) de una cuenta."""
        return self._call(
            "GET", self._wallet_path(wallet, account) + "/utxos/balance")

    def history(self, wallet: str, account: str) -> dict[str, Any]:
        """Historial de txs de una cuenta."""
        return self._call(
            "GET", self._wallet_path(wallet, account) + "/txs/history")

    def fetch_transaction(self, wallet: str, account: str,
                          txid: str) -> dict[str, Any]:
        """Detalle de una tx por txid."""
        return self._call(
            "POST", self._wallet_path(wallet, account) + "/txs/fetch",
            {"txid": txid})

    # -------------------------------------------------------------- escritura
    def create_tx(self, wallet: str, account: str,
                  outputs: list[dict[str, Any]],
                  password: str = "") -> dict[str, Any]:
        """Construir una tx firmada SIN emitir (trazabilidad).

        ``outputs`` es una lista de dicts. Dos formas admitidas
        (ver la REST API):

        * P2PKH por dirección: ``{"address": "1...", "value": N}``
        * Script arbitrario (hex): ``{"script_pubkey": "<hex>",
          "value": N}`` — para inscripciones, OP_RETURN, etc.

        El daemon firma con las claves del fichero wallet (cifrado
        con ``password``). Devuelve ``{"txid", "rawtx"}``. Los UTXOs
        usados quedan asignados (no se pueden gastar en otra tx)
        hasta emitir o limpiar.

        **Inspeccionar el rawtx antes de emitir.**
        """
        body: dict[str, Any] = {"outputs": outputs}
        if password:
            body["password"] = password
        return self._call(
            "POST", self._wallet_path(wallet, account) + "/txs/create",
            body)

    def broadcast(self, wallet: str, account: str,
                  rawtx: str) -> dict[str, Any]:
        """Emitir un rawtx (hex) ya firmado. Devuelve ``{"txid"}``."""
        return self._call(
            "POST", self._wallet_path(wallet, account) + "/txs/broadcast",
            {"rawtx": rawtx})

    def create_and_broadcast(self, wallet: str, account: str,
                             outputs: list[dict[str, Any]],
                             password: str = "") -> dict[str, Any]:
        """Construir y emitir atómicamente (revertible ante error)."""
        body: dict[str, Any] = {"outputs": outputs}
        if password:
            body["password"] = password
        return self._call(
            "POST",
            self._wallet_path(wallet, account) + "/txs/create_and_broadcast",
            body)

    # ------------------------------------------------------------ trazabilidad
    def send_tracked(self, wallet: str, account: str,
                     outputs: list[dict[str, Any]],
                     purpose: str = "",
                     password: str = "",
                     tx_log: Path = DEFAULT_TX_LOG) -> dict[str, Any]:
        """Construir SIN emitir -> inspeccionar -> emitir -> registrar.

        El flujo trazable completo. Devuelve ``{"txid", "rawtx",
        "purpose", "logged"}``. Lanza si el daemon falla.
        """
        created = self.create_tx(wallet, account, outputs, password)
        txid = created.get("txid", "")
        rawtx = created.get("rawtx", "")
        if not txid or not rawtx:
            raise ElectrumSVError(f"create_tx incompleto: {created}")
        # Emitir solo si la tx se construyó bien.
        self.broadcast(wallet, account, rawtx)
        # Registrar en el log append-only (trazabilidad local).
        self._log_tx(tx_log, wallet, account, txid, purpose, outputs)
        return {"txid": txid, "rawtx": rawtx,
                "purpose": purpose, "logged": True}

    @staticmethod
    def _log_tx(path: Path, wallet: str, account: str, txid: str,
                purpose: str, outputs: list[dict[str, Any]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "txid": txid,
            "wallet": wallet,
            "account": account,
            "purpose": purpose,
            "outputs": outputs,
            "timestamp": int(time.time()),
        }
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")


def read_wif(path: Path = TOKEN_WIF_PATH) -> str:
    """Leer el WIF del proyecto (``~/.smcp/token.wif``, 0600).

    No imprime la clave. Levanta ``FileNotFoundError`` si no existe
    (recordatorio: no hay backup = no hay wallet).
    """
    if not path.exists():
        raise FileNotFoundError(
            f"WIF no encontrado en {path}. "
            "Sin él no hay wallet que importar en ElectrumSV.")
    wif = path.read_text(encoding="utf-8").strip()
    if not wif:
        raise ValueError(f"WIF vacío en {path}")
    return wif


__all__ = [
    "ElectrumSV", "ElectrumSVError", "DAEMON_BASE", "NETWORK",
    "DEFAULT_TX_LOG", "TOKEN_WIF_PATH", "read_wif",
]
