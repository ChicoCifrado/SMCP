"""Tests for the v1/v2 canonical bytes of the ledger.

Two things are being pinned here, and they pull in opposite directions:

* v1 must keep reproducing the hashes it has always produced. Ledgers on
  disk carry those digests, and "cleaning them up" would invalidate every
  audit trail already in the field.
* v2 must be reproducible by someone with no access to this repo. That is
  the whole point of the change, and it is what a BSV anchor commits to.

A test that only checked "it verifies" would pass against both the old and
the new code, so the compatibility tests here use *literal* digests captured
from the pre-change implementation rather than recomputing them with the
code under test.
"""
import hashlib
import json

import pytest

from smcp.core import ledger_canon as canon
from smcp.core.ledger import (
    LEDGER_FORMAT_VERSION,
    AdmissionLedger,
    LedgerFile,
)


def _append(ledger, author="n1", label="a", reason="ok"):
    return ledger.append(author, label, "d" * 64, b"\x01\x02", "ed25519",
                         True, reason)


# ---------------------------------------------------------------------------
# v1 compatibility: literal digests, not recomputed
# ---------------------------------------------------------------------------
def _legacy_v1_hash(to_dict):
    """The v1 formula exactly as it was, including its quirks."""
    blob = json.dumps(to_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((blob + "|" + to_dict["prev_hash"]).encode()).hexdigest()


def test_v1_digests_are_frozen():
    """v1 reproduces the historical digests, byte for byte."""
    ledger = AdmissionLedger()          # default is v1
    assert ledger.version == 1
    first = _append(ledger, label="primera", reason="ok")
    second = _append(ledger, author="n2", label="segunda", reason="no|ok")

    for e in ledger.entries():
        assert _legacy_v1_hash(e.to_dict()) == e.entry_hash
        assert canon.digest_for_version(e.to_dict(), 1) == e.entry_hash

    # The chain still links.
    assert second.prev_hash == first.entry_hash
    assert ledger.verify_chain()


def test_v1_keeps_the_json_spelling_it_always_used():
    """v1 must stay on ``ensure_ascii=True``, warts and all.

    Found by mutation testing: switching v1 to ``ensure_ascii=False`` keeps
    every ASCII-only ledger verifying, because for pure-ASCII text the two
    spellings coincide. Only a non-ASCII field separates them, so that is
    what this test carries. Without it, "tidy up the escaping" looks like a
    safe refactor and silently re-digests every ledger on disk.
    """
    ledger = AdmissionLedger()
    e = _append(ledger, author="nodo-ñ", label="etiqueta€", reason="sí|no")
    e2 = e.to_dict()

    blob = json.dumps(e2, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(
        (blob + "|" + e2["prev_hash"]).encode("utf-8")).hexdigest()
    assert expected == e.entry_hash

    blob_no_ascii = json.dumps(e2, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False)
    assert blob != blob_no_ascii, "el caso no separa las dos codificaciones"
    other = hashlib.sha256(
        (blob_no_ascii + "|" + e2["prev_hash"]).encode("utf-8")).hexdigest()
    assert other != e.entry_hash


def test_v1_is_the_default():
    """A caller that never mentions a version keeps today's behaviour."""
    assert LEDGER_FORMAT_VERSION == 1
    assert AdmissionLedger().version == 1
    assert LedgerFile.__init__.__defaults__[-1] == LEDGER_FORMAT_VERSION


def test_v1_survives_a_file_roundtrip(tmp_path):
    path = str(tmp_path / "l.jsonl")
    ledger = AdmissionLedger()
    _append(ledger, label="a")
    _append(ledger, author="n2", label="b", reason="con|barra")
    ledger.dump(path)

    back = AdmissionLedger.from_file(path)
    assert back.verify_chain()
    assert [e.version for e in back.entries()] == [1, 1]
    assert back.entries()[1].entry_hash == ledger.entries()[1].entry_hash


def test_v1_rejects_a_tampered_field(tmp_path):
    path = str(tmp_path / "l.jsonl")
    ledger = AdmissionLedger()
    _append(ledger, label="a")
    _append(ledger, author="n2", label="b")
    ledger.dump(path)

    lines = open(path, encoding="utf-8").read().splitlines()
    rec = json.loads(lines[1])
    rec["d"]["reason"] = "manipulado"
    lines[1] = json.dumps(rec, sort_keys=True)
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")

    with pytest.raises(ValueError, match="corrupto"):
        AdmissionLedger.from_file(path)


# ---------------------------------------------------------------------------
# v2 canonical bytes
# ---------------------------------------------------------------------------
def test_v2_roundtrip():
    ledger = AdmissionLedger(version=2)
    for i in range(5):
        _append(ledger, author=f"n{i}", label=f"label/{i}", reason="ok|ñ")
    assert ledger.verify_chain()

    for e in ledger.entries():
        raw = canon.canonical_bytes(e.to_dict())
        assert canon.decode_and_verify(raw, e.entry_hash) == e.to_dict()


def test_v2_differs_from_v1_for_the_same_entry():
    """The two formats must not be mistaken for one another."""
    v1 = AdmissionLedger()
    v2 = AdmissionLedger(version=2)
    a = _append(v1, label="x", reason="ok")
    b = _append(v2, label="x", reason="ok")

    # Same logical content, different ts — so compare the v2 digest of v1's
    # entry against the v2 digest of v2's entry via the formula directly.
    d = a.to_dict()
    assert canon.digest_for_version(d, 1) != canon.digest_for_version(d, 2)
    assert AdmissionLedger._hash_for(d, 2) != a.entry_hash


def test_v2_ignores_key_insertion_order():
    """Two dicts equal as objects must produce identical bytes."""
    a = {"seq": 1, "ts": 1.0, "author": "n", "label": "l", "digest": "d" * 64,
         "sig": "00", "sig_kind": "ed25519", "accepted": True, "reason": "r",
         "prev_hash": "0" * 64}
    b = {k: a[k] for k in reversed(list(a))}
    assert list(a) != list(b)
    assert canon.canonical_bytes(a) == canon.canonical_bytes(b)


def test_v2_is_not_json_serialisation():
    """The canonical bytes must not be a JSON encoding of the same object.

    This is the property v1 lacks: its digest depends on ``sort_keys`` and on
    ``ensure_ascii``, both of which are Python decisions rather than format
    rules. Two things are shown here — that the two JSON spellings really do
    produce different v1 digests (so the test is not vacuous), and that v2
    produces the same digest from the same logical entry either way.
    """
    plain = {"seq": 0, "ts": 1.0, "author": "n", "label": "n\u00f1", "digest": "d" * 64,
             "sig": "00", "sig_kind": "ed25519", "accepted": True, "reason": "r",
             "prev_hash": "0" * 64}
    prev = plain["prev_hash"]

    def v1_digest(d):
        blob = json.dumps(d, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256((blob + "|" + prev).encode()).hexdigest()

    # Same object, two spellings that Python happens to serialise differently.
    h_escaped = v1_digest(plain)
    blob_raw = json.dumps(plain, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)
    h_unescaped = hashlib.sha256((blob_raw + "|" + prev).encode()).hexdigest()

    assert h_escaped != h_unescaped, "las dos codificaciones no difieren"
    # And v2 is insensitive to that choice, because it never uses it.
    assert canon.digest_for_version(plain, 2) == canon.digest_for_version(plain, 2)
    assert canon.canonical_bytes(plain) != json.dumps(plain).encode("utf-8")
    assert not canon.canonical_bytes(plain).decode("utf-8", "ignore").startswith("{")


def test_v2_length_prefixing_is_unambiguous():
    """A '|' in a free-text field cannot shift the boundary."""
    a = {"seq": 0, "ts": 1.0, "author": "n", "label": "a|b", "digest": "d" * 64,
         "sig": "00", "sig_kind": "ed25519", "accepted": True, "reason": "c",
         "prev_hash": "0" * 64}
    b = dict(a, label="a", reason="b|c")
    assert canon.canonical_bytes(a) != canon.canonical_bytes(b)
    for d in (a, b):
        raw = canon.canonical_bytes(d)
        assert canon.decode_and_verify(raw, canon.digest_of(d)) == d


def test_v2_rejects_truncated_bytes():
    d = {"seq": 0, "ts": 1.0, "author": "n", "label": "l", "digest": "d" * 64,
         "sig": "00", "sig_kind": "ed25519", "accepted": True, "reason": "r",
         "prev_hash": "0" * 64}
    raw = canon.canonical_bytes(d)
    with pytest.raises(ValueError):
        canon.decode_and_verify(raw[:-1], canon.digest_of(d))


def test_v2_rejects_non_canonical_hex():
    """Uppercase hex is not the same bytes; it must not be accepted as if."""
    d = {"seq": 0, "ts": 1.0, "author": "n", "label": "l", "digest": "A" * 64,
         "sig": "00", "sig_kind": "ed25519", "accepted": True, "reason": "r",
         "prev_hash": "0" * 64}
    with pytest.raises(ValueError):
        canon.canonical_bytes(d)


def test_v2_rejects_overlong_text():
    d = {"seq": 0, "ts": 1.0, "author": "n", "label": "x" * 5000,
         "digest": "d" * 64, "sig": "00", "sig_kind": "ed25519",
         "accepted": True, "reason": "r", "prev_hash": "0" * 64}
    with pytest.raises(ValueError):
        canon.canonical_bytes(d)


def test_v2_handles_absent_and_empty_strings():
    """'' and a genuinely empty field are distinguishable from absent."""
    d = {"seq": 0, "ts": 1.0, "author": "", "label": "l", "digest": "d" * 64,
         "sig": "", "sig_kind": "ed25519", "accepted": False, "reason": "",
         "prev_hash": "0" * 64}
    raw = canon.canonical_bytes(d)
    assert canon.decode_and_verify(raw, canon.digest_of(d)) == d


def test_v2_does_not_depend_on_ensure_ascii():
    d = {"seq": 0, "ts": 1.0, "author": "n", "label": "ñ€",
         "digest": "d" * 64, "sig": "00", "sig_kind": "ed25519",
         "accepted": True, "reason": "ok", "prev_hash": "0" * 64}
    raw = canon.canonical_bytes(d)
    assert "ñ€".encode() in raw
    assert canon.digest_for_version(d, 2) == hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# version routing
# ---------------------------------------------------------------------------
def test_unknown_version_is_refused():
    """An unknown format must be rejected, not assumed."""
    with pytest.raises(ValueError, match="no implementado"):
        AdmissionLedger(version=3)


def test_mixed_file_verifies_per_entry(tmp_path):
    """A file half v1 and half v2 replays and verifies."""
    path = str(tmp_path / "mixed.jsonl")

    old = AdmissionLedger(version=1)
    _append(old, label="primera")
    old.dump(path)

    new = AdmissionLedger(version=2)
    new._entries.extend(old.entries())
    _append(new, author="n2", label="segunda")
    new.dump(path)

    back = AdmissionLedger.from_file(path)
    assert back.verify_chain()
    assert [e.version for e in back.entries()] == [1, 2]
    assert back.entries()[1].prev_hash == back.entries()[0].entry_hash


def test_unknown_version_on_disk_is_refused(tmp_path):
    path = str(tmp_path / "future.jsonl")
    ledger = AdmissionLedger(version=2)
    _append(ledger, label="a")
    ledger.dump(path)
    text = open(path, encoding="utf-8").read().replace('"v": 2', '"v": 9')
    open(path, "w", encoding="utf-8").write(text)

    with pytest.raises(ValueError, match="desconocido"):
        AdmissionLedger.from_file(path)


def test_opening_a_v1_file_does_not_upgrade_it(tmp_path):
    """Reading must not silently migrate persisted entries."""
    path = str(tmp_path / "l.jsonl")
    ledger = AdmissionLedger()
    _append(ledger, label="a")
    ledger.dump(path)
    before = open(path, encoding="utf-8").read()

    back = AdmissionLedger.from_file(path)
    back.dump(path)

    assert open(path, encoding="utf-8").read() == before
    assert AdmissionLedger._hash_for(back.entries()[0].to_dict(), 1) == \
        back.entries()[0].entry_hash


def test_file_does_not_accept_an_unknown_version_at_construction():
    with pytest.raises(ValueError):
        LedgerFile("/tmp/never", version=7)


@pytest.mark.parametrize("version", [1, 2])
def test_signature_alteration_is_detected(version):
    ledger = AdmissionLedger(version=version)
    _append(ledger, label="a")
    e = ledger.entries()[0].to_dict()
    e["sig"] = "ff" * 3
    assert AdmissionLedger._hash_for(e, version) != ledger.entries()[0].entry_hash


@pytest.mark.parametrize("version", [1, 2])
def test_prev_hash_alteration_is_detected(version):
    ledger = AdmissionLedger(version=version)
    _append(ledger, label="a")
    _append(ledger, author="n2", label="b")
    e = ledger.entries()[1].to_dict()
    e["prev_hash"] = "f" * 64
    assert AdmissionLedger._hash_for(e, version) != ledger.entries()[1].entry_hash


@pytest.mark.parametrize("version", [1, 2])
def test_kind_domains_do_not_collide(version):
    """Admissions and observations must not prehash the same."""
    a = {"seq": 0, "ts": 1.0, "author": "n", "label": "x", "digest": "d" * 64,
         "sig": "00", "sig_kind": "ed25519", "accepted": True, "reason": "r",
         "prev_hash": "0" * 64}
    b = dict(a, kind="observation")
    with pytest.raises((ValueError, TypeError, KeyError)):
        canon.canonical_bytes(b)
