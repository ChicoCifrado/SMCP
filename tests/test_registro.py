"""test_registro: el libro de inferencias (timestamp + cobro).

Sujeta:
1. registrar una completion (txid + timestamp + identidades);
2. el txid no se duplica (como la cadena);
3. el inference_id es estable (txid:mesh:server);
4. consulta por txid, mesh, servidor y ventana;
5. el libro persiste (jsonl) y se recupera;
6. totales: inferencias, sats y DELM;
7. metodos de pago (bsv / delm / both) y rechazo de invalidos.
"""
from __future__ import annotations

import json
import os

import pytest

from smcp.core.registro import (
    DEFAULT_REGISTRY_PATH,
    PAY_BOTH,
    PAY_BSV,
    PAY_DELM,
    InferenceRecord,
    InferenceRegistry,
)

TXID = "a" * 64
SERVER = "02" + "b" * 64  # 33 bytes hex
REQUESTER = "03" + "c" * 64
MESH = "malla-registro"


def _reg(**kw) -> InferenceRegistry:
    return InferenceRegistry(path=kw.pop("path", ""))


def test_registra_completion_con_timestamp():
    r = _reg()
    rec, nuevo = r.record(
        txid=TXID, mesh_id=MESH,
        server_pubkey=SERVER, requester_pubkey=REQUESTER,
        satoshis=99,
    )
    assert nuevo is True
    assert rec.txid == TXID
    assert rec.mesh_id == MESH
    assert rec.completed_at > 0  # estampado del reloj
    assert rec.satoshis == 99
    assert rec.pay_method == PAY_BSV


def test_txid_no_se_duplica():
    r = _reg()
    rec1, n1 = r.record(
        txid=TXID, mesh_id=MESH,
        server_pubkey=SERVER, requester_pubkey=REQUESTER,
        satoshis=99,
    )
    rec2, n2 = r.record(
        txid=TXID, mesh_id=MESH,
        server_pubkey=SERVER, requester_pubkey=REQUESTER,
        satoshis=100,  # distinto monto: no importa
    )
    assert n1 is True and n2 is False
    assert rec1 is rec2  # el mismo registro, no duplicado
    assert len(r.records) == 1


def test_inference_id_es_estable():
    r1 = InferenceRecord(
        txid=TXID, completed_at=1.0, mesh_id=MESH,
        server_pubkey=SERVER, requester_pubkey=REQUESTER,
    )
    r2 = InferenceRecord(
        txid=TXID, completed_at=9.0, mesh_id=MESH,
        server_pubkey=SERVER, requester_pubkey=REQUESTER,
    )
    assert r1.inference_id == r2.inference_id  # el tiempo no lo cambia
    # el mismo txid en otro mesh es otra inferencia
    r3 = InferenceRecord(
        txid=TXID, completed_at=1.0, mesh_id="otro",
        server_pubkey=SERVER, requester_pubkey=REQUESTER,
    )
    assert r3.inference_id != r1.inference_id


def test_consulta_por_mesh_servidor_ventana():
    r = _reg()
    r.record(txid="1" * 64, mesh_id=MESH, server_pubkey=SERVER,
             requester_pubkey=REQUESTER, completed_at=100.0, satoshis=10)
    r.record(txid="2" * 64, mesh_id="otro", server_pubkey=SERVER,
             requester_pubkey=REQUESTER, completed_at=200.0, satoshis=20)
    r.record(txid="3" * 64, mesh_id=MESH, server_pubkey="04" + "d" * 64,
             requester_pubkey=REQUESTER, completed_at=300.0, satoshis=30)
    # por mesh
    assert len(r.by_mesh(MESH)) == 2
    # por servidor
    assert len(r.by_server(SERVER)) == 2
    # por ventana temporal
    assert len(r.in_window(start=150.0, end=250.0)) == 1
    # por txid
    assert r.by_txid("1" * 64).completed_at == 100.0


def test_persiste_y_recupera(tmp_path):
    path = str(tmp_path / "inferences.jsonl")
    r1 = InferenceRegistry(path=path)
    r1.record(txid=TXID, mesh_id=MESH, server_pubkey=SERVER,
              requester_pubkey=REQUESTER, satoshis=99,
              pay_method=PAY_BOTH, delm_amount=50,
              delm_token_id="tok_0")
    # nuevo libro sobre el mismo fichero
    r2 = InferenceRegistry(path=path)
    assert len(r2.records) == 1
    rec = r2.by_txid(TXID)
    assert rec is not None
    assert rec.pay_method == PAY_BOTH
    assert rec.satoshis == 99
    assert rec.delm_amount == 50
    assert rec.delm_token_id == "tok_0"


def test_totales():
    r = _reg()
    r.record(txid="1" * 64, mesh_id=MESH, server_pubkey=SERVER,
             requester_pubkey=REQUESTER, pay_method=PAY_BSV, satoshis=99)
    r.record(txid="2" * 64, mesh_id=MESH, server_pubkey=SERVER,
             requester_pubkey=REQUESTER, pay_method=PAY_DELM, delm_amount=100)
    r.record(txid="3" * 64, mesh_id=MESH, server_pubkey=SERVER,
             requester_pubkey=REQUESTER, pay_method=PAY_BOTH,
             satoshis=50, delm_amount=25)
    t = r.totals()
    assert t["inferences"] == 3
    assert t["satoshis"] == 149  # 99 + 50
    assert t["delm"] == 125  # 100 + 25
    assert t["by_method"][PAY_BSV] == 1
    assert t["by_method"][PAY_DELM] == 1
    assert t["by_method"][PAY_BOTH] == 1


def test_metodo_pago_invalido():
    r = _reg()
    with pytest.raises(ValueError):
        r.record(txid=TXID, mesh_id=MESH, server_pubkey=SERVER,
                 requester_pubkey=REQUESTER, pay_method="nope")


def test_roundtrip_dict():
    rec = InferenceRecord(
        txid=TXID, completed_at=42.0, mesh_id=MESH,
        server_pubkey=SERVER, requester_pubkey=REQUESTER,
        pay_method=PAY_DELM, delm_amount=7, delm_token_id="t_0",
    )
    d = rec.to_dict()
    rec2 = InferenceRecord.from_dict(d)
    assert rec2 == rec
    assert rec2.inference_id == rec.inference_id
    # el fichero es jsonl valido
    assert json.loads(json.dumps(d)) == d


def test_default_path_esta_en_home():
    assert DEFAULT_REGISTRY_PATH.endswith("inferences.jsonl")
