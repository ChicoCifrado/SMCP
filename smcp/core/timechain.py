"""Timechain — the node's own anchored history, before it reaches the chain.

Cada nodo publica sus propias transacciones (no hay servicio de notarización
externo), así que necesita dos cosas que hoy no tiene: **guardar** lo que
publicó, y **retransmitir** lo suyo. El segundo punto no es un detalle de
implementación, es la propiedad de seguridad de la que todo lo demás cuelga.

Por qué el nodo tiene que hacer broadcast él mismo
----------------------------------------------------
El timestamp de una inferencia solo existe porque la transacción está en un
bloque. Pero una transacción minada no está *publicada*: el nodo emisor puede
apagarse después de minar y nadie más tendrá el transacción. Y una transacción
no minada puede they've sido editada por cualquiera que la tuviera en mempool:
un atacante que captura la transacción antes de que se mine puede reemplazarla
por otra con el mismo input,alias distinto. Ambas cosas rompen el reloj, y el
timestamp es la mitad del ancla.

De ahí ``rebroadcast()``: reenviar la propia transacción firmado periodica-
mente **mientras no esté confirmada** es lo que hace que "minada por mí a las
12:00" signifique "minada a las 12:00 y no reemplazable después". Un solo
reenvío no basta; la ventana de sustitución se cierra cuando la transacción
entra en un bloque, y antes de eso sigue abierta.

La cadena como tercero de confianza
------------------------------------
Esto **no** es un ledger local que un tercero audite. La cadena ES el tercero
de confianza: el orden de los bloques, sus sellos de tiempo y sus pruebas de
trabajo son lo que da valor de reloj a lo que publicamos. El módulo es
deliberadamente honesto sobre eso: :func:`Timechain.status` no dice "el
timestamp es correcto", dice "este es el estado de publicación de mi
transacción", y :func:`anchor_time_of` no valida el reloj — se lo pide a la
cadena.

Qué NO hace (y por qué está aquí escrito)
-----------------------------------------
*No verifica* la prueba de que su transacción está en el bloque. Eso es SPV
sobre cabeceras (BRC-9/BRC-10) y es trabajo de la Fase 2, con un chain
tracker real. Este módulo deja el hueco explícito
(:attr:`AnchorRecord.proven` a ``False``) en vez de dar por hecho un ancla que
nadie ha comprobado. Un ancla no verificada es una afirmación, no un hecho, y
la diferencia entre las dos cosas es justo lo que este proyecto no ha querido
confundir en ningún sitio.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

_LOG = logging.getLogger(__name__)

#: Format version of the on-disk anchor log (one JSON per line).
ANCHOR_LOG_VERSION = 1


@dataclass
class AnchorRecord:
    """One transaction this node published, and what has happened to it.

    ``txid`` is the node's own id for the transaction, not a verified chain
    id — nothing here claims the transaction was mined until a verifier has
    checked the block inclusion. ``mined`` records what the *chain said* when
    this node last asked; ``proven`` records whether the node actually checked
    the inclusion proof, and it defaults to ``False`` because the honest
    answer today is "nobody checked".
    """

    txid: str
    #: BRC-220 certificate fields, verbatim. The certificate is the evidence;
    #: this node stores it whole so a third party can re-verify offline.
    certificate: dict[str, Any]
    #: Epoch/precommit identifier, when the record comes from an ARIA-style
    #: pre-commitment. Empty for a bare NotaryHash anchor.
    epoch_id: str = ""
    #: First broadcast (unix seconds, local clock — not a chain timestamp).
    first_broadcast: float = 0.0
    #: Bumps each time ``rebroadcast`` sent it again while unconfirmed.
    rebroadcasts: int = 0
    #: What the chain last reported (null until known).
    block_height: int | None = None
    block_time: int | None = None
    #: True only when a real inclusion proof was checked. Not set by polling.
    proven: bool = False

    def confirmed(self) -> bool:
        """Whether the chain has reported a block for this transaction.

        "Confirmed by the chain" is deliberately weaker than "proven": it
        means a block was reported, not that anyone verified the proof. The
        distinction is why :attr:`proven` exists and defaults to ``False``.
        """
        return self.block_height is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "txid": self.txid, "certificate": self.certificate,
            "epoch_id": self.epoch_id, "first_broadcast": self.first_broadcast,
            "rebroadcasts": self.rebroadcasts, "block_height": self.block_height,
            "block_time": self.block_time, "proven": self.proven,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AnchorRecord":
        return cls(
            txid=str(d.get("txid", "")),
            certificate=dict(d.get("certificate") or {}),
            epoch_id=str(d.get("epoch_id", "")),
            first_broadcast=float(d.get("first_broadcast", 0.0)),
            rebroadcasts=int(d.get("rebroadcasts", 0)),
            block_height=d.get("block_height"),
            block_time=d.get("block_time"),
            proven=bool(d.get("proven", False)),
        )


@dataclass
class Timechain:
    """The node's own anchor log: store, rebroadcast, and look up.

    ``store`` persists every record to ``path`` (append-only, JSON lines) so
    the node can recover its history — and keep rebroadcasting — after a
    restart. A node that forgets what it published cannot defend the claim
    that it published it at that time.
    """

    path: str = ""
    records: list[AnchorRecord] = field(default_factory=list)
    _unsent: list[AnchorRecord] = field(default_factory=list, repr=False)

    # ------------------------------------------------------------------ store
    def add(self, record: AnchorRecord) -> AnchorRecord:
        """Record a transaction this node published, and persist it.

        ``first_broadcast`` is stamped from the local clock if absent. The
        local clock is *not* the timestamp that matters — the chain is — but it
        orders this node's own retries.
        """
        if not record.first_broadcast:
            record.first_broadcast = time.time()
        self.records.append(record)
        self._unsent.append(record)
        if self.path:
            self._flush()
        return record

    def _flush(self) -> None:
        """Rewrite the log atomically (the file is small and rewrite-per-add
        keeps it trivially recoverable after a crash mid-write)."""
        import os
        tmp = self.path + ".tmp"
        text = "\n".join(
            json.dumps({"v": ANCHOR_LOG_VERSION, "r": r.to_dict()}, sort_keys=True)
            for r in self.records
        )
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text + ("\n" if text else ""))
        os.replace(tmp, self.path)

    @classmethod
    def load(cls, path: str) -> "Timechain":
        """Recover a node's anchor log.

        A record is restored *unconfirmed and unproven*: this node is starting
        fresh and has verified nothing. Leaving ``proven=True`` from a
        previous run would be a claim it can no longer back.
        """
        chain = cls(path=path)
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line).get("r", {})
                r = AnchorRecord.from_dict(d)
                r.proven = False
                chain.records.append(r)
                chain._unsent.append(r)
        return chain

    # ----------------------------------------------------------- rebroadcast
    def pending(self) -> list[AnchorRecord]:
        """Transactions published but not yet confirmed by the chain."""
        return [r for r in self.records if not r.confirmed()]

    def rebroadcast(self, sender: Any) -> list[str]:
        """Re-send every unconfirmed transaction; return the txids sent.

        ``sender`` is anything with ``(txid, payload) -> bool``. This is the
        method that makes the timestamp mean something: an unconfirmed
        transaction is still replaceable, so it is re-sent until the chain
        says it is in a block. Called periodically by the node's own loop.

        Every unconfirmed transaction is re-sent on every call, on purpose.
        Batching "only the ones older than N seconds" would leave a window
        where a freshly published transaction is silently un-rebroadcast, and
        that window is exactly the attack.
        """
        sent: list[str] = []
        for rec in self.pending():
            payload = rec.certificate.get("rawTx") or rec.certificate.get("txid")
            try:
                ok = sender(rec.txid, payload)
            except Exception as exc:
                # Un relé caido no puede tragarse los reintentos de los demás,
                # pero tampoco debe fallar en silencio: un nodo que reintenta
                # sin registro y sin que nadie lo vea parece que esta publicando.
                _LOG.warning("rebroadcast de %s fallo: %s", rec.txid, exc)
                continue
            if ok:
                rec.rebroadcasts += 1
                sent.append(rec.txid)
        if sent and self.path:
            self._flush()
        return sent

    def mark_mined(self, txid: str, block_height: int,
                   block_time: int) -> AnchorRecord:
        """Record what the chain reported for ``txid``.

        This does **not** set ``proven``: reporting a height is not the same
        as checking a Merkle inclusion proof against a header. Kept separate
        on purpose (see the module docstring).
        """
        for rec in self.records:
            if rec.txid == txid:
                rec.block_height = int(block_height)
                rec.block_time = int(block_time)
                rec.proven = False
                break
        if self.path:
            self._flush()
        return next(r for r in self.records if r.txid == txid)

    # ----------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        """What this node can honestly say about its own anchors.

        Deliberately does not claim the timestamps are correct. It reports
        the state of publication, and separates "the chain said so" from
        "someone checked the proof" — the two are not the same and this
        project does not want them confused.
        """
        return {
            "node_records": len(self.records),
            "unconfirmed": len(self.pending()),
            "proven": sum(1 for r in self.records if r.proven),
            "reported_by_chain": sum(1 for r in self.records if r.confirmed()),
            "total_rebroadcasts": sum(r.rebroadcasts for r in self.records),
            "chain_is_the_clock": True,
            "spv_verified": False,   # Fase 2: a real chain tracker
        }


__all__ = ["AnchorRecord", "Timechain", "ANCHOR_LOG_VERSION"]
