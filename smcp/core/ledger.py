"""Admission ledger and trust gate.

Two pieces close the loop on *who may write to the shared context* and *what
happened*:

* :class:`AdmissionLedger` — an append-only, hash-chained record of every
  admission decision (accept/reject). Each entry links to the previous one's
  hash, so a tamper is detectable (``verify_chain``). This is the audit trail
  a peer can replay to reconstruct the shared context's provenance.

* :class:`TrustGate` — the admission policy. It encodes the trust model:
  which ``author_id``s are admitted (``allowlist`` / ``denylist`` /
  ``require-signed``), and it is the single choke point an agent must pass
  before its gist enters the shared context.

The ledger is deliberately in-memory and synchronous so it can be unit-tested
and replayed without I/O; :class:`LedgerFile` provides **opt-in** append-only
persistence (``dump``/``load``/audit export) over the same canonical line
format, so the default path stays I/O-free.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from smcp.core import ledger_canon as canon

#: Versión por defecto del formato de línea de ``LedgerFile`` (un JSON por
#: entrada). 1 = el hash original sobre ``json.dumps``; 2 = bytes canónicos
#: con prefijo de longitud (:mod:`smcp.core.ledger_canon`). Los ledgers ya
#: emitidos siguen en 1 y se siguen verificando con su hash original.
LEDGER_FORMAT_VERSION = 1


class TrustPolicy(str, Enum):
    ALLOWLIST = "allowlist"          # only listed authors
    DENYLIST = "denylist"           # everyone except listed authors
    REQUIRE_SIGNED = "require-signed"  # any author, but a valid signature is mandatory


@dataclass
class LedgerEntry:
    seq: int
    ts: float
    author_id: str
    label: str
    digest: str
    signature: bytes
    sig_kind: str
    accepted: bool
    reason: str
    prev_hash: str
    entry_hash: str
    #: Formato con el que se calculó ``entry_hash``. Viaja con la entrada para
    #: que un fichero mixto (líneas v1 junto a líneas v2) se verifique
    #: entrada por entrada en vez de rechazarse entero por estar "corrupto".
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq, "ts": self.ts, "author": self.author_id,
            "label": self.label, "digest": self.digest,
            "sig": self.signature.hex(), "sig_kind": self.sig_kind,
            "accepted": self.accepted, "reason": self.reason,
            "prev_hash": self.prev_hash,
        }


class AdmissionLedger:
    """Append-only, hash-chained admission log.

    ``version`` selects the canonical byte encoding of ``entry_hash``
    (see :mod:`smcp.core.ledger_canon`):

    * ``1`` — the original ``sha256(json.dumps(sort_keys) + "|" + prev)``.
      Still supported byte for byte, because ledgers already on disk carry
      these hashes; recomputing them "cleanly" would invalidate every audit
      trail in the field.
    * ``2`` — length-prefixed binary, specified and reproducible outside this
      repo. Required before a BSV anchor is worth anything, since the anchor
      commits to this digest.

    A ledger is single-version for its whole life: a chain cannot mix
    encodings, because every entry links to the previous one. Reading is
    version-agnostic — :meth:`from_file` takes each line's own ``v``.
    """

    def __init__(self, version: int = 1) -> None:
        if version not in (1, 2):
            raise ValueError(
                f"formato de ledger {version} no implementado (solo 1 y 2)")
        self._entries: list[LedgerEntry] = []
        self.version = version

    # -- append ------------------------------------------------------------
    def append(self, author_id: str, label: str, digest: str,
               signature: bytes, sig_kind: str, accepted: bool,
               reason: str) -> LedgerEntry:
        prev = self._entries[-1].entry_hash if self._entries else "0" * 64
        entry = LedgerEntry(
            seq=len(self._entries), ts=time.time(), author_id=author_id,
            label=label, digest=digest, signature=signature, sig_kind=sig_kind,
            accepted=accepted, reason=reason, prev_hash=prev, entry_hash="",
            version=self.version,
        )
        entry.entry_hash = self._hash(entry)
        self._entries.append(entry)
        return entry

    @classmethod
    def _hash_for(cls, to_dict: dict, version: int) -> str:
        """The ``entry_hash`` of ``to_dict`` under format ``version``."""
        return canon.digest_for_version(to_dict, version)

    @classmethod
    def _hash(cls, e: "LedgerEntry") -> str:
        return cls._hash_for(e.to_dict(), e.version)

    # -- read / verify ------------------------------------------------------
    def entries(self) -> list[LedgerEntry]:
        return list(self._entries)

    def by_label(self, label: str) -> list[LedgerEntry]:
        return [e for e in self._entries if e.label == label]

    def verify_chain(self) -> bool:
        """Re-compute every link; return False on any tamper.

        Uses *each entry's own* version rather than the ledger's, so a mixed
        file still verifies per-entry — a v1 line replayed next to v2 lines
        keeps its original hash instead of being rejected as corrupt.
        """
        prev = "0" * 64
        for e in self._entries:
            if e.prev_hash != prev:
                return False
            if AdmissionLedger._hash_for(e.to_dict(), e.version) != e.entry_hash:
                return False
            prev = e.entry_hash
        return True

    def __len__(self) -> int:
        return len(self._entries)

    # -- persistence (opt-in) ----------------------------------------------
    def dump(self, path: str) -> str:
        """Escribe el ledger a ``path`` (append-only, una línea por entrada).

        Devuelve el *hash de artefacto* (``sha256`` del contenido), útil para
        verificar idempotencia: dos dumps del mismo estado dan el mismo hash.
        El formato es una línea por entrada (el ``to_dict`` + ``entry_hash``),
        el mismo cálculo de hash que la cadena en memoria.
        """
        text = "\n".join(
            json.dumps({"v": e.version, "d": e.to_dict(),
                        "h": e.entry_hash}, sort_keys=True)
            for e in self._entries
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @classmethod
    def from_file(cls, path: str) -> "AdmissionLedger":
        """Reconstruye un ledger desde ``path`` (replay).

        Verifica la cadena al reconstruir (``verify_chain``); si el archivo
        está corrupto o truncado, lanza ``ValueError`` (no se silencia).

        Cada línea lleva su propio ``v``, así que un fichero escrito a mitad en v1
        y luego en v2 se lee correctamente: es la razón de que la versión
        viaje *en la entrada* y no solo en el ledger. Una versión desconocida
        se rechaza en vez de asumir la más nueva — dar por bueno un formato
        que no se conoce es exactamente cómo se acepta una cadena manipulada.
        """
        ledger = cls()
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                d, h = rec["d"], rec["h"]
                v = int(rec.get("v", LEDGER_FORMAT_VERSION))
                if v not in (1, 2):
                    raise ValueError(
                        f"formato de ledger {v} desconocido: no se puede "
                        "verificar, y asumir otro sería aceptar una cadena "
                        "sin comprobarla")
                prev = "0" * 64 if not ledger._entries else \
                    ledger._entries[-1].entry_hash
                # Re-verificar el entry_hash contra el contenido, con el
                # formato que la propia línea declara.
                if AdmissionLedger._hash_for(d, v) != h:
                    raise ValueError(
                        f"entry_hash no coincide con el contenido (corrupto) "
                        f"[formato v{v}]"
                    )
                if d["prev_hash"] != prev:
                    raise ValueError(
                        "prev_hash no enlaza con la cadena (truncado/corrupto)"
                    )
                ledger._entries.append(LedgerEntry(
                    seq=d["seq"], ts=d["ts"], author_id=d["author"],
                    label=d["label"], digest=d["digest"],
                    signature=bytes.fromhex(d["sig"]), sig_kind=d["sig_kind"],
                    accepted=d["accepted"], reason=d["reason"],
                    prev_hash=d["prev_hash"], entry_hash=h, version=v,
                ))
        return ledger


class LedgerFile:
    """Persistencia append-only del :class:`AdmissionLedger` (opt-in).

    Un wrapper sobre un archivo que mantiene la cadena en memoria y expone
    ``append``/``flush``/``load``/``export_audit``. El archivo es append-only:
    ``append`` escribe la nueva línea al final; ``load`` relee y verifica la
    cadena; ``export_audit`` produce un dump JSON idempotente para auditoría
    externa (entradas + hash de cadena + ``policy_hash``).

    Un archivo corrupto se rechaza (``load`` lanza), no se reescribe.
    """

    def __init__(self, path: str, version: int = LEDGER_FORMAT_VERSION) -> None:
        self.path = path
        self.ledger = AdmissionLedger(version=version)

    def append(self, author_id: str, label: str, digest: str,
               signature: bytes, sig_kind: str, accepted: bool,
               reason: str) -> LedgerEntry:
        """Añade una entrada (la cadena en memoria; ``flush`` la persiste)."""
        return self.ledger.append(author_id, label, digest, signature,
                                   sig_kind, accepted, reason)

    def flush(self) -> str:
        """Persiste la cadena al archivo (idempotente). Devuelve el hash."""
        return self.ledger.dump(self.path)

    def load(self) -> AdmissionLedger:
        """Recarga el archivo y verifica la cadena (rechaza corrupto)."""
        self.ledger = AdmissionLedger.from_file(self.path)
        return self.ledger

    def export_audit(self, policy_hash: str = "") -> dict:
        """Dump JSON de auditoría (idempotente): entradas + hash de cadena
        + ``policy_hash``. Determinista: el mismo estado da el mismo dict."""
        return {
            "format": LEDGER_FORMAT_VERSION,
            "count": len(self.ledger._entries),
            "policy_hash": policy_hash,
            "chain": [
                {"seq": e.seq, "author": e.author_id, "label": e.label,
                 "digest": e.digest, "accepted": e.accepted,
                 "reason": e.reason, "prev_hash": e.prev_hash,
                 "entry_hash": e.entry_hash}
                for e in self.ledger._entries
            ],
        }


class TrustGate:
    """The admission policy an agent must pass before writing to C."""

    def __init__(self, policy: TrustPolicy = TrustPolicy.REQUIRE_SIGNED,
                 allowlist: set[str] | None = None,
                 denylist: set[str] | None = None) -> None:
        self.policy = policy
        self.allowlist = set(allowlist or ())
        self.denylist = set(denylist or ())

    def permit(self, author_id: str, has_signature: bool) -> tuple[bool, str]:
        if author_id in self.denylist:
            return False, "author is on the denylist"
        if self.policy == TrustPolicy.ALLOWLIST:
            if author_id not in self.allowlist:
                return False, "author not in allowlist"
        if self.policy == TrustPolicy.REQUIRE_SIGNED and not has_signature:
            return False, "a valid signature is required by policy"
        return True, "ok"
