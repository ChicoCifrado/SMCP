"""CLI `delm mesh membership verify` — el gate de pertenencia desde fuera.

Lo que importa aqui no es la criptografia (esta probada en
``test_membership.py``) sino el contrato del comando: que el codigo de salida
distinga **rechazo** de **entrada que no entiende**, y que la cabecera la
elija el operador.

Porque si un proof malformado saliera como "rechazado", un cliente no podria
distinguir un atacante de un bug de serializacion — y responder 403 a un bug
es la forma de que un fallo de formato se esconda como si fuera seguridad.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from smcp.cli import main
from smcp.core.bsv_keys import Secp256k1KeyPair
from smcp.core.membership import (
    InclusionProof,
    MembershipLock,
    MembershipOutput,
    MembershipProof,
)


@pytest.fixture()
def trio(tmp_path: Path):
    """Un proof valido, su cabecera, y una cabecera ajena."""
    lock = MembershipLock(script_hash="ab" * 20, deployment_txid="cd" * 32)
    key = Secp256k1KeyPair.new("member")
    txid = "cc" * 32
    out = MembershipOutput(txid=txid, vout=0, satoshis=5000,
                           script_hash=lock.script_hash)
    inc = InclusionProof(txid=txid, index=0, path=[], merkle_root=txid,
                         height=900000)
    proof = MembershipProof.create(out, inc, key, lock)

    pf = tmp_path / "proof.json"
    pf.write_text(json.dumps({
        "output": {"txid": txid, "vout": 0, "satoshis": 5000,
                   "script_hash": lock.script_hash},
        "inclusion": {"txid": txid, "index": 0, "path": [],
                      "merkle_root": txid, "height": 900000},
        "membership_pubkey": key.public_key.hex(),
        "signature": proof.signature,
        "lock": {"script_hash": lock.script_hash,
                 "deployment_txid": lock.deployment_txid},
    }))
    good = tmp_path / "header.json"
    good.write_text(json.dumps({"merkle_root": txid, "height": 900000}))
    bad = tmp_path / "header_bad.json"
    bad.write_text(json.dumps({"merkle_root": "ff" * 32, "height": 900001}))
    return pf, good, bad, key, out


def test_a_valid_proof_verifies_and_says_so(trio, capsys):
    pf, good, _bad, key, out = trio
    rc = main(["mesh", "membership", "verify", "--proof", str(pf),
               "--header", str(good)])
    assert rc == 0
    text = capsys.readouterr().out
    assert out.outpoint() in text
    assert key.public_key.hex() in text


def test_the_json_output_admits_that_spv_is_not_chain_validation(trio, capsys):
    """El comando dice que no valida la cadena, en la salida y en el JSON.

    Un gate de pertenencia que-presenta su exito sin decir esto invites a
    confiarle decisiones que no puede sostener. Va en ``chain_validated: false``
    para que un cliente no tenga que leer prosa para enterarse.
    """
    pf, good, _bad, _key, _out = trio
    rc = main(["mesh", "membership", "verify", "--proof", str(pf),
               "--header", str(good), "--json"])
    assert rc == 0
    d = json.loads(capsys.readouterr().out)
    assert d["ok"] is True
    assert d["chain_validated"] is False
    assert d["membership_fee_sats"] == 5000


def test_a_proof_against_another_header_is_rejected_with_exit_1(trio, capsys):
    """Rechazo son 1, no 0 y no 2. El codigo de salida es parte del contrato."""
    pf, _good, bad, _key, _out = trio
    rc = main(["mesh", "membership", "verify", "--proof", str(pf),
               "--header", str(bad)])
    assert rc == 1
    assert "rechazado" in capsys.readouterr().err


def test_a_malformed_proof_is_exit_2_and_says_it_is_not_a_rejection(
        trio, capsys, tmp_path):
    """Entrada que no entiende -> 2. Un "rechazado" seria un 403 a un bug."""
    pf, good, _bad, _key, _out = trio
    bad = tmp_path / "broken.json"
    bad.write_text('{"output": {"txid": 1}}')
    rc = main(["mesh", "membership", "verify", "--proof", str(bad),
               "--header", str(good)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "malformado" in err
    assert "No es un rechazo" in err


def test_a_tampered_signature_is_rejected_not_accepted(trio, capsys, tmp_path):
    """La firma manipulada se rechaza, y el motivo lo dice."""
    pf, good, _bad, _key, _out = trio
    d = json.loads(pf.read_text())
    d["signature"] = "ab" * 64
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(d))
    rc = main(["mesh", "membership", "verify", "--proof", str(tampered),
               "--header", str(good)])
    assert rc == 1
    assert "firma" in capsys.readouterr().err


def test_a_missing_file_is_exit_2_not_a_traceback(trio, capsys, tmp_path):
    """Un fichero que no existe es un error de invocacion, no una excepcion."""
    pf, good, _bad, _key, _out = trio
    rc = main(["mesh", "membership", "verify", "--proof",
               str(tmp_path / "no-existe.json"), "--header", str(good)])
    assert rc == 2
    assert "no se pudo leer" in capsys.readouterr().err


def test_the_header_is_a_separate_input_not_something_the_proof_carries(
        trio, capsys):
    """La cabecera no viaja en el proof: es la eleccion del verificador.

    Si el proof trajera su propia cabecera, el proof se avalaria a si mismo y
    el gate no seria un gate. Aqui la misma prueba falla cambiando solo el
    fichero de cabecera, sin tocar el proof.
    """
    pf, good, bad, _key, _out = trio
    assert main(["mesh", "membership", "verify", "--proof", str(pf),
                 "--header", str(good)]) == 0
    capsys.readouterr()
    assert main(["mesh", "membership", "verify", "--proof", str(pf),
                 "--header", str(bad)]) == 1
