"""Registro — el libro de inferencias: cuando ocurrio y quien la sirvio.

La pieza que une el flujo de inferencia (``intercambio``) con
el anclaje (``inscripcion``) y el token (``token_bsv21``).

Por que existe
--------------
``contrib.record_inference`` **cuenta** una inferencia (reputacion),
pero no **registra** *cual*: no guarda el txid con su timestamp,
su mesh, su nodo, ni su metodo de pago. Sin ese libro, no se
puede responder "identifica la inferencia X y confirma que
ocurrio" — solo "el nodo sirvo N inferencias".

Este modulo es ese libro. Cada **completion exitosa** (status 200
de la inferencia) produce un :class:`InferenceRecord` con:

* ``txid`` — el ancla en cadena (la prueba de que ocurrio);
* ``completed_at`` — el timestamp local de la completion (reloj
  del nodo; la cadena da el *bloque*, el reloj da el *momento*);
* ``mesh_id``, ``server_pubkey``, ``requester_pubkey`` — las
  identidades (sus compromisos ``H`` y ``hash160`` viajan en
  la tx; aqui se guardan para consulta off-chain);
* ``satoshis`` y ``token`` — lo que se cobro, en BSV y/o en
  DELM (la red de incentivos: el nodo elige cobrar en sats,
  en DELM, o en ambos).

Que NO hace
-----------
* No hashea el contenido de la inferencia. Es la decision de
  :mod:`delm.core.anchor`: se prueba que ocurrio, no que decia.
  Aqui tampoco viaja el prompt ni la respuesta.
* No emite a la red (eso es ARC/transporte).
* No firma nada (la firma es del servidor sobre ``H``).
* No es la cadena: es un libro local, consultable, que el nodo
  puede exportar. La prueba definitiva sigue siendo el txid en
  un bloque (``verify_inscription``).

Identificar una inferencia especifica
--------------------------------------
Tres claves, de mas a menos especifica:

1. **txid** — la unica prueba en cadena (el ordinal viaja a
   Alice; quien posee el outpoint posee el registro);
2. **inference_id** — ``sha256(txid:mesh_id:server)`` — el id
   estable del libro (el mismo txid en otro mesh es otra
   inferencia);
3. **(mesh_id, server, completed_at)** — la consulta por rango
   temporal.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any

#: Metodos de pago que puede elegir el nodo.
PAY_BSV = "bsv"        #: solo satoshis (el flujo v3 actual)
PAY_DELM = "delm"      #: solo token DELM (capa F)
PAY_BOTH = "both"      #: sats + DELM
PAY_METHODS = frozenset({PAY_BSV, PAY_DELM, PAY_BOTH})


@dataclass(frozen=True)
class InferenceRecord:
    """Una inferencia completada (status 200) y su cobro.

    El txid es la prueba en cadena; el resto es el libro local
    que explica *cual* es esa tx y *cuando* ocurrio.
    """

    #: txid de la tx de inscripcion (el ancla en cadena).
    txid: str
    #: timestamp de la completion (unix, reloj del nodo).
    completed_at: float
    #: mesh donde ocurrio.
    mesh_id: str
    #: clave publica del nodo que sirvio (hex, 33 bytes).
    server_pubkey: str
    #: clave publica del solicitante (hex, 33 bytes).
    requester_pubkey: str
    #: metodo de pago (bsv / delm / both).
    pay_method: str = PAY_BSV
    #: satoshis cobrados (0 si no cobro en BSV).
    satoshis: int = 0
    #: unidades DELM cobradas (0 si no cobro en DELM).
    delm_amount: int = 0
    #: tokenId DELM (el canonico por defecto).
    delm_token_id: str = ""

    @property
    def inference_id(self) -> str:
        """Id estable del libro: ``sha256(txid:mesh:server)``.

        El mismo txid en otro mesh es otra inferencia; el id
        del libro lo distingue sin tocar la cadena.
        """
        pre = f"{self.txid}:{self.mesh_id}:{self.server_pubkey}"
        return hashlib.sha256(pre.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "InferenceRecord":
        return cls(
            txid=str(d["txid"]),
            completed_at=float(d["completed_at"]),
            mesh_id=str(d["mesh_id"]),
            server_pubkey=str(d["server_pubkey"]),
            requester_pubkey=str(d["requester_pubkey"]),
            pay_method=str(d.get("pay_method", PAY_BSV)),
            satoshis=int(d.get("satoshis", 0)),
            delm_amount=int(d.get("delm_amount", 0)),
            delm_token_id=str(d.get("delm_token_id", "")),
        )


class InferenceRegistry:
    """El libro de inferencias del nodo (append-only, persistente).

    Cada completion (status 200) produce un registro. El libro
    es local y consultable; la prueba en cadena es el txid.
    """

    def __init__(self, path: str = "") -> None:
        self.path = path
        self.records: list[InferenceRecord] = []
        # txid -> registro (el mismo txid no se registra dos veces,
        # igual que contrib no lo cuenta dos veces).
        self._by_txid: dict[str, InferenceRecord] = {}
        if path and os.path.exists(path):
            self._load()

    def _load(self) -> None:
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                r = InferenceRecord.from_dict(d)
                self.records.append(r)
                self._by_txid.setdefault(r.txid, r)

    def _flush(self) -> None:
        if not self.path:
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for r in self.records:
                fh.write(json.dumps(r.to_dict(), sort_keys=True) + "\n")
        os.replace(tmp, self.path)

    def record(self, *, txid: str, mesh_id: str,
               server_pubkey: str, requester_pubkey: str,
               completed_at: float = 0.0,
               pay_method: str = PAY_BSV,
               satoshis: int = 0,
               delm_amount: int = 0,
               delm_token_id: str = "") -> tuple[InferenceRecord, bool]:
        """Registra una inferencia completada.

        Devuelve ``(registro, es_nuevo)``. Si el txid ya estaba,
        devuelve el registro existente con ``es_nuevo=False`` (no
        se duplica — igual que la cadena no gasta un input dos
        veces). ``completed_at`` se estampa del reloj si es 0.
        """
        if pay_method not in PAY_METHODS:
            raise ValueError(f"metodo de pago {pay_method!r} (validos: {sorted(PAY_METHODS)})")
        existing = self._by_txid.get(txid)
        if existing is not None:
            return existing, False
        if not completed_at:
            completed_at = time.time()
        r = InferenceRecord(
            txid=txid, completed_at=completed_at, mesh_id=mesh_id,
            server_pubkey=server_pubkey,
            requester_pubkey=requester_pubkey, pay_method=pay_method,
            satoshis=satoshis, delm_amount=delm_amount,
            delm_token_id=delm_token_id,
        )
        self.records.append(r)
        self._by_txid[txid] = r
        self._flush()
        return r, True

    # -- consulta ------------------------------------------------------
    def by_txid(self, txid: str) -> InferenceRecord | None:
        """El registro de un txid (la prueba en cadena)."""
        return self._by_txid.get(txid)

    def by_inference_id(self, inference_id: str) -> InferenceRecord | None:
        """El registro de un id de libro (txid:mesh:server)."""
        for r in self.records:
            if r.inference_id == inference_id:
                return r
        return None

    def by_mesh(self, mesh_id: str) -> list[InferenceRecord]:
        """Todas las inferencias de un mesh, por tiempo."""
        return sorted(
            (r for r in self.records if r.mesh_id == mesh_id),
            key=lambda r: r.completed_at,
        )

    def by_server(self, server_pubkey: str) -> list[InferenceRecord]:
        """Las inferencias que sirvio un nodo (su historial de cobro)."""
        return sorted(
            (r for r in self.records if r.server_pubkey == server_pubkey),
            key=lambda r: r.completed_at,
        )

    def in_window(self, *, start: float, end: float) -> list[InferenceRecord]:
        """Inferencias en una ventana temporal (identificar por cuando)."""
        return sorted(
            (r for r in self.records if start <= r.completed_at <= end),
            key=lambda r: r.completed_at,
        )

    def totals(self) -> dict[str, Any]:
        """Totales del libro: inferencias, sats y DELM cobrados."""
        return {
            "inferences": len(self.records),
            "unique_txids": len(self._by_txid),
            "satoshis": sum(r.satoshis for r in self.records),
            "delm": sum(r.delm_amount for r in self.records),
            "by_method": {
                m: sum(1 for r in self.records if r.pay_method == m)
                for m in sorted(PAY_METHODS)
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [r.to_dict() for r in self.records],
            "totals": self.totals(),
        }


#: Ruta por defecto del libro (junto a la identidad del nodo).
DEFAULT_REGISTRY_PATH = os.path.expanduser("~/.delm/inferences.jsonl")

__all__ = [
    "InferenceRecord", "InferenceRegistry", "DEFAULT_REGISTRY_PATH",
    "PAY_BSV", "PAY_DELM", "PAY_BOTH", "PAY_METHODS",
]
