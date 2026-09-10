"""Tests de persistencia append-only del ``AdmissionLedger`` (Capa 2).

Cubre la issue #3 (persistencia + replay/auditoría):

- **Round-trip**: append en memoria -> ``dump`` -> ``from_file`` ->
  ``verify_chain`` verde (la cadena reconstruida es idéntica).
- **Detección**: corromper el archivo (byte flip) -> ``from_file`` falla
  (no se silencia); truncar (quitar la última línea) -> el replay es un
  prefijo estricto (detectable por conteo, no un silencio).
- **Idempotencia**: dos ``dump`` del mismo estado dan el mismo hash de
  artefacto (y el mismo contenido de archivo).
- **Opt-in**: el path por defecto (``SecureSharedContext``) sigue siendo un
  ``AdmissionLedger`` en memoria, sin I/O (la persistencia es opt-in).

La persistencia es **opt-in**: ``dump``/``from_file``/``LedgerFile`` se
activan explícitamente; el path por defecto no toca disco.
"""
from __future__ import annotations

import json

import pytest

from delm.core.ledger import AdmissionLedger, LedgerFile
from delm.core.secure_context import SecureSharedContext


# ------------------------------------------------------------------ helpers
def _ledger_with_entries(n: int = 3) -> AdmissionLedger:
    """Un ledger con ``n`` entradas válidas (cadena íntegra)."""
    ledger = AdmissionLedger()
    for i in range(n):
        ledger.append(
            author_id=f"author-{i % 2}",
            label=f"label-{i}",
            digest=f"digest-{i}",
            signature=f"sig-{i}".encode(),
            sig_kind="ed25519",
            accepted=(i % 2 == 0),
            reason=f"reason-{i}",
        )
    return ledger


# ------------------------------------------------------------------ round-trip
def test_roundtrip_dump_reload_verifies(tmp_path):
    """Append en memoria -> dump -> from_file -> verify_chain verde."""
    ledger = _ledger_with_entries(5)
    path = str(tmp_path / "ledger.jsonl")
    ledger.dump(path)

    reloaded = AdmissionLedger.from_file(path)
    # La cadena reconstruida es íntegra.
    assert reloaded.verify_chain()
    # Es idéntica: mismo largo y mismo hash de cada entrada.
    assert len(reloaded) == len(ledger)
    for a, b in zip(ledger.entries(), reloaded.entries()):
        assert a.entry_hash == b.entry_hash
        assert a.to_dict() == b.to_dict()


def test_from_file_reconstructs_full_entry(tmp_path):
    """El replay reconstruye cada campo (no solo el hash)."""
    ledger = _ledger_with_entries(3)
    path = str(tmp_path / "ledger.jsonl")
    ledger.dump(path)

    reloaded = AdmissionLedger.from_file(path)
    orig = ledger.entries()
    for i, e in enumerate(orig):
        r = reloaded.entries()[i]
        assert (r.seq, r.author_id, r.label, r.digest) == \
               (e.seq, e.author_id, e.label, e.digest)
        assert r.signature == e.signature
        assert r.sig_kind == e.sig_kind
        assert r.accepted == e.accepted
        assert r.reason == e.reason
        assert r.prev_hash == e.prev_hash


# ------------------------------------------------------------------ detección
def test_corrupted_file_rejected(tmp_path):
    """Corromper el archivo (byte flip) -> from_file falla (no se silencia)."""
    ledger = _ledger_with_entries(4)
    path = str(tmp_path / "ledger.jsonl")
    ledger.dump(path)

    # Corrompe un byte del contenido de una entrada (no del hash): el
    # entry_hash ya no coincide con el to_dict -> from_file debe rechazar.
    lines = [json.loads(l) for l in open(path) if l.strip()]
    lines[1]["d"]["digest"] = "TAMPERED"  # altera el contenido
    with open(path, "w") as f:
        for l in lines:
            f.write(json.dumps(l) + "\n")

    with pytest.raises(ValueError):
        AdmissionLedger.from_file(path)


def test_truncated_file_is_detectable_prefix(tmp_path):
    """Truncar (quitar la última línea) -> el replay es un prefijo estricto.

    Un archivo truncado es un *prefijo válido* de la cadena: ``verify_chain``
    sigue verde, pero el conteo cae. La detección es por conteo (el dump
    original tenía ``n`` entradas; el replay tiene menos). No es un silencio:
    el replay no puede fabricar la entrada perdida.
    """
    ledger = _ledger_with_entries(5)
    path = str(tmp_path / "ledger.jsonl")
    ledger.dump(path)

    # Trunca: quita la última línea (simula una escritura rota / cola perdida).
    with open(path) as f:
        lines = [l for l in f if l.strip()]
    with open(path, "w") as f:
        f.writelines(lines[:-1])

    reloaded = AdmissionLedger.from_file(path)
    # El prefijo sigue siendo íntegro...
    assert reloaded.verify_chain()
    # ...pero el conteo cae: la entrada perdida no se puede reconstruir.
    assert len(reloaded) == len(ledger) - 1
    # Las entradas que sí están son idénticas (prefijo estricto).
    for a, b in zip(ledger.entries()[:-1], reloaded.entries()):
        assert a.entry_hash == b.entry_hash


# ------------------------------------------------------------------ idempotencia
def test_dump_is_idempotent_same_artifact_hash(tmp_path):
    """Dos dumps del mismo estado dan el mismo hash de artefacto."""
    ledger = _ledger_with_entries(4)
    p1 = str(tmp_path / "a.jsonl")
    p2 = str(tmp_path / "b.jsonl")
    h1 = ledger.dump(p1)
    h2 = ledger.dump(p2)
    assert h1 == h2  # mismo estado -> mismo hash de artefacto
    # Y el contenido de archivo es idéntico.
    assert open(p1).read() == open(p2).read()


def test_dump_hash_changes_with_state(tmp_path):
    """El hash de artefacto cambia si el estado cambia (no es constante)."""
    ledger = _ledger_with_entries(3)
    p = str(tmp_path / "a.jsonl")
    h1 = ledger.dump(p)
    # Una entrada más -> otro estado -> otro hash.
    ledger.append(author_id="x", label="x", digest="x",
                  signature=b"x", sig_kind="ed25519",
                  accepted=True, reason="x")
    h2 = ledger.dump(p)
    assert h1 != h2


# ------------------------------------------------------------------ LedgerFile
def test_ledger_file_append_flush_load_roundtrip(tmp_path):
    """LedgerFile: append -> flush -> load reconstruye la cadena."""
    path = str(tmp_path / "ledger.jsonl")
    lf = LedgerFile(path)
    for i in range(3):
        lf.append(author_id=f"a{i}", label=f"l{i}", digest=f"d{i}",
                  signature=f"s{i}".encode(), sig_kind="ed25519",
                  accepted=True, reason=f"r{i}")
    lf.flush()
    reloaded = lf.load()
    assert reloaded.verify_chain()
    assert len(reloaded) == 3


def test_ledger_file_export_audit_idempotent(tmp_path):
    """export_audit es idempotente: el mismo estado da el mismo dump."""
    path = str(tmp_path / "ledger.jsonl")
    lf = LedgerFile(path)
    lf.append(author_id="a", label="l", digest="d",
              signature=b"s", sig_kind="ed25519", accepted=True, reason="r")
    lf.flush()
    audit1 = lf.export_audit(policy_hash="pol-1")
    audit2 = lf.export_audit(policy_hash="pol-1")
    assert audit1 == audit2  # idempotente
    # El dump lleva las entradas + el policy_hash.
    assert audit1["count"] == 1
    assert audit1["policy_hash"] == "pol-1"
    assert audit1["chain"][0]["label"] == "l"


def test_ledger_file_rejects_corrupt_on_load(tmp_path):
    """LedgerFile.load rechaza un archivo corrupto (no lo reescribe)."""
    path = str(tmp_path / "ledger.jsonl")
    lf = LedgerFile(path)
    lf.append(author_id="a", label="l", digest="d",
              signature=b"s", sig_kind="ed25519", accepted=True, reason="r")
    lf.flush()
    # Corrompe el archivo por detrás de LedgerFile.
    lines = [json.loads(l) for l in open(path) if l.strip()]
    lines[0]["d"]["digest"] = "TAMPERED"
    with open(path, "w") as f:
        for l in lines:
            f.write(json.dumps(l) + "\n")
    with pytest.raises(ValueError):
        lf.load()


# ------------------------------------------------------------------ opt-in
def test_default_path_is_in_memory_no_io():
    """Opt-in: el path por defecto es un AdmissionLedger en memoria (sin I/O).

    ``SecureSharedContext`` crea un ``AdmissionLedger`` plano (no un
    ``LedgerFile``), así el path por defecto no toca disco. La persistencia
    se activa explícitamente con ``LedgerFile`` / ``dump`` / ``from_file``.
    """
    c = SecureSharedContext()
    # El ledger por defecto es el tipo plano (no el de archivo).
    assert type(c.ledger) is AdmissionLedger
    assert not isinstance(c.ledger, LedgerFile)
    # Aceptar no crea ningún archivo.
    from delm.core.gist import Gist
    g = Gist(label="x", gist="hi")
    # (sin firma/autor: se rechaza, pero sin I/O en el camino)
    # Un append directo también es sin I/O.
    c.ledger.append(author_id="a", label="l", digest="d",
                    signature=b"s", sig_kind="ed25519",
                    accepted=True, reason="r")
    assert c.ledger.verify_chain()
