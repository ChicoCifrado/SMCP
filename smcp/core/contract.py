"""Smart contract BSV (Script plano) + protocolo permissionless.

Diseno
------
El "smart contract" en BSV no es un programa que se ejecuta
en la cadena (BSV no tiene EVM). Es un **locking script**
que gobierna quien puede gastar un output. El contract de
DeLM es simple y se construye con :mod:`smcp.core.txbuild`:

    P2PKH(nodeKey)   --  OP_DUP OP_HASH160 <20> OP_EQUALVERIFY
                         OP_CHECKSIG

El output del contract solo lo gasta el nodo cuya clave
esta en el locking script. Eso es el "contract": la
cadena garantiza que el bounty lo cobra el nodo que
resolvio la tarea, y nadie mas.

Protocolo permissionless
------------------------
Nadie controla la red; todos colaboran haciendo inferencia
para recibir satoshis:

1. **Treasury** (quien publica tareas) fondea un output
   P2PKH(nodeKey) con ``bounty`` satoshis.
2. Cualquier nodo (permissionless) resuelve la tarea y
   propone un gist.
3. La malla verifica el gist (n-grams >=4 en el
   trajectory) y lo firma (ed25519).
4. El nodo **gasta** el output del contract: la tx de
   gasto es la **tx de anclaje** (outpoint de atribucion
   al nodo). El gasto prueba que el nodo cobro.
5. La tx se difunde via ARC (:mod:`smcp.core.arc`).

Verificacion (cualquiera, offline)
----------------------------------
* InclusionProof: el txid esta en un bloque (BRC-96).
* El output gastado es P2PKH(nodeKey) -> atribucion.
* Linea de tiempo: la tx es posterior a la membresia.

Lo que este modulo NO hace
--------------------------
* No emite a la red (eso es ARC).
* No es sCrypt (Script plano, construible con txbuild).
* No hashea el contenido (decision de diseno de
  :mod:`smcp.core.anchor`: se prueba que ocurrio, no
  que decia).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from smcp.core.bsv_keys import Secp256k1KeyPair

if TYPE_CHECKING:  # pragma: no cover - solo tipos
    from smcp.core.anchor import AnchorRecord
    from smcp.core.txbuild import Transaction


#: Un inferencia que se puede anclar y cobrar.
@dataclass(frozen=True)
class InferenceBounty:
    """Una inferencia verificada, lista para anclar.

    Es el vínculo entre la capa D (la inferencia repartida)
    y la capa E (el anclaje BSV). La malla ya verifico el
    gist; aqui solo queda anclar y cobrar.
    """

    #: digest del gist admitido (SHA-256 del gist).
    gist_digest: str
    #: clave publica del nodo que resolvio (hex, 33 bytes
    #: comprimida). Es la que ata el output P2PKH.
    node_pubkey: str
    #: clave publica del verifier que firmo el gist.
    verifier_pubkey: str
    #: satoshis que paga el bounty por esta inferencia.
    satoshis: int
    #: tarea (digest publico; la tarea no es secreta).
    task_digest: str = ""

    def __post_init__(self) -> None:
        if len(self.gist_digest) != 64:
            raise ValueError("gist_digest debe ser 32 bytes hex")
        if len(self.node_pubkey) not in (66, 130):
            raise ValueError("node_pubkey debe ser 33/65 bytes hex")
        if self.satoshis < 0:
            raise ValueError("satoshis negativos")

    def to_dict(self) -> dict[str, object]:
        return {
            "gist_digest": self.gist_digest,
            "node_pubkey": self.node_pubkey,
            "verifier_pubkey": self.verifier_pubkey,
            "satoshis": self.satoshis,
            "task_digest": self.task_digest,
        }

    @classmethod
    def from_dict(cls, d: dict[str, object]) -> "InferenceBounty":
        return cls(
            gist_digest=str(d["gist_digest"]),
            node_pubkey=str(d["node_pubkey"]),
            verifier_pubkey=str(d["verifier_pubkey"]),
            satoshis=int(d["satoshis"]),  # type: ignore[arg-type]
            task_digest=str(d.get("task_digest", "")),
        )


def p2pkh_lock(node_pubkey_hex: str) -> bytes:
    """El locking script del contract: ``P2PKH(nodeKey)``.

    Es el "smart contract" en BSV: la cadena solo deja
    gastar este output a quien tenga la clave privada
    correspondiente a ``node_pubkey_hex``.
    """
    import hashlib

    raw = bytes.fromhex(node_pubkey_hex)
    # BSV usa hash160 = RIPEMD160(SHA256(pubkey)).
    sha = hashlib.sha256(raw).digest()
    rip = hashlib.new("ripemd160", sha).digest()
    # OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    return (
        bytes([0x76, 0xA9, 0x14]) + rip + bytes([0x88, 0xAC])
    )


def claim_anchor(bounty: InferenceBounty,
                 node_key: Secp256k1KeyPair) -> "AnchorRecord":
    """Construye el registro de anclaje (sin emitir).

    La tx de gasto del output P2PKH(nodeKey) es la tx de
    anclaje: su outpoint ata la inferencia al nodo. Aqui
    se devuelve el :class:`~smcp.core.anchor.AnchorRecord`
    que describe esa tx; la construccion y emision real
    de la tx es responsabilidad de :mod:`smcp.core.txbuild`
    y :mod:`smcp.core.arc`.
    """
    # El outpoint de atribucion es P2PKH(nodeKey): el
    # gasto de ese output prueba que el nodo cobro.
    # (La tx real se construye con txbuild; aqui solo
    #  describimos el registro que la cadena registrara.)
    from smcp.core.anchor import AnchorRecord  # noqa: F401

    raise NotImplementedError(
        "La construccion de la tx real va en txbuild + arc; "
        "este metodo describe el registro que se anclara. "
        "Ver build_claim_tx() para la tx firmada."
    )


def build_claim_tx(
    bounty: InferenceBounty,
    node_key: Secp256k1KeyPair,
    *,
    prev_txid: str,
    prev_vout: int,
    prev_satoshis: int,
    change_address_pubkey: bytes,
    fee_satoshis: int = 500,
) -> tuple["Transaction", dict[str, object]]:
    """Construye y firma la tx que cobra el bounty.

    Gasta el output del contract (``P2PKH(nodeKey)``) y
    paga el bounty al nodo. El gasto de ese output es la
    **tx de anclaje**: su outpoint ata la inferencia al
    nodo, y su existencia prueba que ocurrio.

    Parametros
    ----------
    bounty:
        La inferencia verificada (gist + nodo + satoshis).
    node_key:
        La clave privada del nodo (debe ser la que el
        output del contract paga).
    prev_txid, prev_vout, prev_satoshis:
        El UTXO del contract que se gasta.
    change_address_pubkey:
        Clave publica para el cambio (lo que sobra del
        UTXO tras pagar el bounty y la fee).
    fee_satoshis:
        Fee de la tx (por defecto 500 sats).

    Devuelve
    --------
    (tx, registro)
        La tx firmada (lista para difundir via ARC) y el
        registro de anclaje (outpoint, satoshis, digests).
    """
    from smcp.core.txbuild import (
        Transaction, TxIn, TxOut,
    )
    import hashlib

    def _lock_from_pubkey(pubkey_hex: str) -> bytes:
        """``P2PKH(pubkey)`` = OP_DUP OP_HASH160 <hash160> ..."""
        raw = bytes.fromhex(pubkey_hex)
        sha = hashlib.sha256(raw).digest()
        rip = hashlib.new("ripemd160", sha).digest()
        return bytes([0x76, 0xA9, 0x14]) + rip + bytes([0x88, 0xAC])

    # Validar: el UTXO debe cubrir bounty + fee.
    total_out = bounty.satoshis + fee_satoshis
    if prev_satoshis < total_out:
        raise ValueError(
            f"UTXO de {prev_satoshis} sats no cubre "
            f"bounty {bounty.satoshis} + fee {fee_satoshis}"
        )

    # Input: el output del contract (P2PKH del nodo).
    tx = Transaction(
        inputs=[TxIn(prev_txid, prev_vout)],
        outputs=[
            # Output 0: el bounty al nodo (P2PKH del nodo).
            TxOut(bounty.satoshis,
                  _lock_from_pubkey(bounty.node_pubkey)),
        ],
    )
    # Cambio: lo que sobra vuelve al nodo.
    change = prev_satoshis - total_out
    if change > 0:
        tx.outputs.append(
            TxOut(change, _lock_from_pubkey(
                change_address_pubkey.hex()))
        )

    # Firmar el input 0 con la clave del nodo.
    # El script_code es el locking script del UTXO
    # que se gasta (P2PKH del nodo).
    script_code = _lock_from_pubkey(bounty.node_pubkey)
    tx.sign_input(0, node_key, script_code)

    registro = {
        "txid": tx.txid(),
        "gist_digest": bounty.gist_digest,
        "task_digest": bounty.task_digest,
        "node_pubkey": bounty.node_pubkey,
        "verifier_pubkey": bounty.verifier_pubkey,
        "satoshis": bounty.satoshis,
        "prev_outpoint": f"{prev_txid}:{prev_vout}",
        "outpoint": f"{tx.txid()}:0",
        "fee_satoshis": fee_satoshis,
        "raw_hex": tx.serialize().hex(),
    }
    return tx, registro
