"""El CLI del ancla — contrato, errores y el limite de BRC-96.

Por que un fichero propio y no un test mas en test_anchor.py: porque el fallo
que mas cuesta aqui no es del modulo, es de la frontera. Un modulo correcto con
un CLI que se traga un ancla invalida y sale con 0 es peor que no tener CLI,
porque hace que un despliegue automatizado crea que algo se verifico.

Y hay una trampa especifica que este fichero sujeta: ``--header`` es
**obligatorio y separado**. Si el ancla trajera su propia cabecera, se avalaria
a si mismo, y la verificacion entera no valdria nada. Ese es el mismo motivo por
el que la pertenencia lo exige.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from delm.core.anchor import AnchorRecord
from delm.core.bsv_keys import Secp256k1KeyPair
from delm.core.membership import InclusionProof, merkle_root

TXID = "aa" * 32
REPO = "/mnt/d/Hermes/DeLM/delm"


def _key() -> Secp256k1KeyPair:
    return Secp256k1KeyPair.new("n1")


#: El solicitante es **otro** nodo: un ancla con solicitante == nodo es
#: autoacreditacion y no se construye (ver `tests/test_anchor.py`).
REQUESTER = Secp256k1KeyPair.new("quien-pide")


def _write(tmp_path, *, txid: str = TXID, height: int = 100,
           header_root: str | None = None, signature: str | None = None,
           record: dict | None = None):
    """Escribe anchor.json + header.json. Devuelve sus rutas."""
    key = _key()
    rec = AnchorRecord(membership_txid=txid, membership_vout=0,
                       membership_pubkey=key.public_key.hex(),
                       requester_pubkey=REQUESTER.public_key.hex(), satoshis=1,
                       occurred_at=1_700_000_000)
    sig = signature if signature is not None else rec.sign(key)
    leaf = bytes.fromhex(txid)[::-1]
    inc = InclusionProof(txid=txid, index=0, path=[],
                         merkle_root=merkle_root([leaf]).hex(), height=height)
    payload = {"record": record if record is not None else rec.to_dict(),
               "inclusion": {"txid": inc.txid, "index": inc.index,
                             "path": inc.path, "merkle_root": inc.merkle_root,
                             "height": inc.height},
               "signature": sig}
    a = tmp_path / "anchor.json"
    h = tmp_path / "header.json"
    a.write_text(json.dumps(payload), encoding="utf-8")
    h.write_text(json.dumps({"merkle_root": header_root or inc.merkle_root,
                             "height": height}), encoding="utf-8")
    return str(a), str(h)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "delm", "mesh", "anchor", *args],
        cwd=REPO, capture_output=True, text=True, timeout=300)


def test_a_valid_anchor_verifies_and_says_out_that_the_chain_is_not_validated(
        tmp_path):
    """Un ancla buena sale con 0 — y dice que la cadena NO esta validada.

    Las dos cosas a la vez. Si solo dijera "valido", un despliegue automatizado
    leeria "validado" y se creeria que hay prueba contra la cadena, que no la
    hay: la inclusion se comprueba contra la cabecera que el propio llamante
    entrego.
    """
    a, h = _write(tmp_path)
    p = _run("--anchor", a, "--header", h)
    assert p.returncode == 0, p.stderr
    assert "True" in p.stdout
    assert "cadena validada   : False" in p.stdout
    assert "BRC-96" in p.stdout
    assert "publica contenido : False" in p.stdout


def test_a_header_from_somewhere_else_is_rejected_with_code_one(tmp_path):
    """Cabecera ajena -> rc 1 y motivo de inclusion, no una excepcion."""
    a, h = _write(tmp_path, header_root="bb" * 32)
    p = _run("--anchor", a, "--header", h)
    assert p.returncode == 1
    assert "Merkle" in p.stdout
    assert "Traceback" not in p.stderr


def test_a_tampered_signature_is_rejected(tmp_path):
    """Firma manipulada -> rc 1, y el motivo dice que es la firma."""
    a, h = _write(tmp_path, signature="00" * 64)
    p = _run("--anchor", a, "--header", h)
    assert p.returncode == 1
    assert "firma" in p.stdout


def test_json_output_is_machine_readable_and_says_the_same(tmp_path):
    """--json sirve para un gate automatico, no solo para un humano."""
    a, h = _write(tmp_path)
    p = _run("--anchor", a, "--header", h, "--json")
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout)
    assert out["valid"] is True
    assert out["chain_validated"] is False
    assert out["publishes_content"] is False
    assert out["membership_outpoint"] == f"{TXID}:0"


def test_unreadable_input_is_a_controlled_error_with_code_two(tmp_path):
    """JSON roto -> rc 2 con mensaje. Nunca una excepcion."""
    bad = tmp_path / "bad.json"
    bad.write_text("{no json", encoding="utf-8")
    h = tmp_path / "h.json"
    h.write_text(json.dumps({"merkle_root": TXID, "height": 100}),
                 encoding="utf-8")
    p = _run("--anchor", str(bad), "--header", str(h))
    assert p.returncode == 2
    assert "error" in p.stderr.lower()
    assert "Traceback" not in p.stderr


def test_a_missing_field_is_a_controlled_error_not_a_key_error(tmp_path):
    """Un anchor.json sin campos es entrada de red corrupta, no un bug."""
    a, h = _write(tmp_path, record={"membership_txid": TXID})
    p = _run("--anchor", a, "--header", h)
    assert p.returncode == 2
    assert "Traceback" not in p.stderr


def test_an_anchor_that_tries_to_publish_content_is_refused_at_the_gate(tmp_path):
    """Un anchor.json con el hash del contenido se rechaza al construir.

    El campo no se puede rellenar — y el CLI es otra puerta mas por la que no
    se puede. Un despliegue que acepte esto publicaria contenido de inferencias
    sin querer, que es justo lo que la decision excluyo.
    """
    key = _key()
    leaf = bytes.fromhex(TXID)[::-1]
    inc = {"txid": TXID, "index": 0, "path": [],
           "merkle_root": merkle_root([leaf]).hex(), "height": 100}
    payload = {
        "record": {"membership_txid": TXID, "membership_vout": 0,
                   "membership_pubkey": key.public_key.hex(), "satoshis": 1,
                   "method": "p2pkh", "ver": 1,
                   "content_sha256": "cd" * 32, "occurred_at": 0},
        "inclusion": inc, "signature": "00" * 64}
    a = tmp_path / "a.json"
    h = tmp_path / "h.json"
    a.write_text(json.dumps(payload), encoding="utf-8")
    h.write_text(json.dumps({"merkle_root": inc["merkle_root"], "height": 100}),
                 encoding="utf-8")
    p = _run("--anchor", str(a), "--header", str(h))
    assert p.returncode == 2
    assert "contenido" in (p.stdout + p.stderr).lower()
    assert "Traceback" not in p.stderr


def test_the_header_is_required_and_separate(tmp_path):
    """``--header`` es obligatorio. Sin el, el ancla se avalaria a si mismo.

    Es la garantia de que la verificacion no es circular: la cabecera la elige
    el verificador, nunca el que pide la verificacion. Por eso el flag no tiene
    valor por defecto.
    """
    a, _ = _write(tmp_path)
    p = _run("--anchor", a)
    assert p.returncode != 0
    assert "--header" in (p.stdout + p.stderr)
    # y --anchor tambien
    p2 = _run("--header", a)
    assert p2.returncode != 0
    assert "--anchor" in (p2.stdout + p2.stderr)


def test_a_header_without_a_raw_field_still_works(tmp_path):
    """La cabecera puede venir solo con merkle_root y height.

    El raw es opcional en BlockHeader, y el CLI tiene que aguantar las dos
    formas: con raw se puede calcular el hash del bloque, sin raw no. Lo que
    importa para inclusion es la raiz, y esa siempre esta.
    """
    a, h = _write(tmp_path)
    p = _run("--anchor", a, "--header", h)
    assert p.returncode == 0, p.stderr
