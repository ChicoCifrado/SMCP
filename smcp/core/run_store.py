"""Persistencia de runs en disco (SQLite).

Un reinicio del proceso pierde el historial de runs y el
contexto compartido: RunManager los guarda en memoria
(api.py). Este modulo es el camino de salida — cada run
terminado se archiva en SQLite y vuelve a cargarse al
arrancar, asi el historial y el contexto sobreviven a un
reinicio.

Diseno:
  * ``runs`` — una fila por run: header (JSON), outcome
    (JSON, nullable), events (JSON), gists (JSON, el
    contexto admitido por ese run).
  * El contexto vivo sigue en memoria; aqui se guarda lo
    que cada run aporto, para reconstruirlo o auditarlo.
  * El cerrojo es de proceso (threading.Lock): el IPC
    entre procesos es responsabilidad de reservation_ipc,
    no de este store.

Solo escritura: append de runs terminados; no se muta un
run archivado (el historial es append-only por diseno).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id           TEXT PRIMARY KEY,
    header       TEXT NOT NULL,
    outcome      TEXT,
    events       TEXT NOT NULL,
    gists        TEXT NOT NULL,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL
);
"""


def default_path() -> Path:
    """Ruta por defecto del archivo de runs."""
    base = Path.home() / ".smcp"
    base.mkdir(parents=True, exist_ok=True)
    return base / "runs.db"


@dataclass
class StoredRun:
    """Un run tal como vive en disco."""
    id: str
    header: dict[str, Any]
    outcome: dict[str, Any] | None
    events: list[dict[str, Any]]
    gists: list[dict[str, Any]]
    created_at: float
    updated_at: float

    def to_row(self) -> tuple[str, str, str | None, str, str, float, float]:
        return (
            self.id,
            json.dumps(self.header, default=str),
            json.dumps(self.outcome, default=str) if self.outcome else None,
            json.dumps(self.events, default=str),
            json.dumps(self.gists, default=str),
            self.created_at,
            self.updated_at,
        )

    @classmethod
    def from_row(cls, row: tuple) -> "StoredRun":
        (rid, header, outcome, events, gists, created, updated) = row
        return cls(
            id=rid,
            header=json.loads(header),
            outcome=json.loads(outcome) if outcome else None,
            events=json.loads(events),
            gists=json.loads(gists),
            created_at=created,
            updated_at=updated,
        )


class RunStore:
    """Append-only de runs en SQLite."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = str(path) if path else str(default_path())
        self._lock = threading.Lock()
        with self._lock, sqlite3.connect(self.path) as con:
            con.executescript(SCHEMA)

    def save(self, run: StoredRun) -> None:
        """Archiva un run (insert or replace por id)."""
        row = run.to_row()
        with self._lock, sqlite3.connect(self.path) as con:
            con.execute(
                "INSERT INTO runs (id, header, outcome, events, gists, "
                "created_at, updated_at) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET "
                "header=excluded.header, outcome=excluded.outcome, "
                "events=excluded.events, gists=excluded.gists, "
                "updated_at=excluded.updated_at",
                row,
            )

    def get(self, run_id: str) -> StoredRun | None:
        with self._lock, sqlite3.connect(self.path) as con:
            cur = con.execute(
                "SELECT id, header, outcome, events, gists, "
                "created_at, updated_at FROM runs WHERE id = ?",
                (run_id,),
            )
            row = cur.fetchone()
        return StoredRun.from_row(row) if row else None

    def history(self, limit: int = 100) -> list[StoredRun]:
        """Runs archivados, del mas reciente al mas antiguo."""
        with self._lock, sqlite3.connect(self.path) as con:
            cur = con.execute(
                "SELECT id, header, outcome, events, gists, "
                "created_at, updated_at FROM runs "
                "ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (limit,),
            )
            return [StoredRun.from_row(r) for r in cur.fetchall()]

    def drop(self, run_id: str) -> bool:
        with self._lock, sqlite3.connect(self.path) as con:
            cur = con.execute("DELETE FROM runs WHERE id = ?", (run_id,))
            return cur.rowcount > 0

    def clear(self) -> int:
        with self._lock, sqlite3.connect(self.path) as con:
            cur = con.execute("DELETE FROM runs")
            return cur.rowcount
