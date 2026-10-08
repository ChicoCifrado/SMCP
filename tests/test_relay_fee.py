"""Fee de relay — la medición que cierra el abierto 3 de la spec.

La plantilla v3.0 paga 250 sats: 1 al ordinal, ``fee_sats``
al minero y el resto al servidor. La pregunta del abierto 3
(``docs/inscripcion-v3.md``): **¿la fee que le queda a la tx
la hace pasar el relay de BSV?**

La respuesta es aritmética, no opinión: se construye una
tx real (flujo DPP completo, firma ECDSA incluida), se serializa
y se mide. El tamaño varía un byte por la firma DER (71 u
72 bytes), así que el test **mide** la tx y verifica la
relación, en lugar de pinchar un número mágico.

Con el precio de 250 sats el presupuesto de fee son 249, y
la tx (~386 bytes) cierra hasta ~0.65 sat/vB — la banda
objetivo de 0.1 a 0.5 sat/vB entera.
"""
from __future__ import annotations

from smcp.core.bsv_keys import Secp256k1KeyPair
from smcp.core.inscripcion import (
    BSV_RELAY_POOL_SAT_PER_BYTE,
    BSV_RELAY_SOFTWARE_SAT_PER_BYTE,
    BSV_RELAY_TARGET_SAT_PER_BYTE,
    ORDINAL_SATOSHIS,
    PER_INFERENCE_SATOSHIS,
    build_inscription,
    relay_budget,
)
from smcp.core.txbuild import TxIn


def _tx(fee_sats: int = 10):
    alice = Secp256k1KeyPair.new("alice")
    bob = Secp256k1KeyPair.new("bob")
    return build_inscription(
        mesh_id="m",
        requester_key=alice,
        server_key=bob,
        funding=TxIn("ab" * 32, 0),
        funding_sats=PER_INFERENCE_SATOSHIS,
        fee_sats=fee_sats,
    )


def test_el_presupuesto_mide_la_tx_real() -> None:
    tx = _tx(fee_sats=10)
    b = relay_budget(tx, fee_sats=10)
    assert b.size_bytes == len(tx.serialize())
    # la firma DER mide 71 u 72 bytes: el tamaño de la
    # plantilla es ~386, nunca una estimación fija
    assert 383 <= b.size_bytes <= 388


def test_el_techo_es_fee_entre_tamano() -> None:
    b = relay_budget(_tx(fee_sats=10), fee_sats=10)
    assert b.max_rate_sat_per_byte == 10 / b.size_bytes
    assert b.cierra_a(0) is True
    assert b.cierra_a(b.max_rate_sat_per_byte) is True
    assert b.cierra_a(b.max_rate_sat_per_byte + 0.001) is False


def test_el_default_del_software_no_cierra() -> None:
    # minrelaytxfee de BSV = 1 sat/vB: ni con la fee
    # máxima construible (248, dejan 1 sat al servidor)
    # la plantilla paga su relay (~386 B > 248).
    b = relay_budget(_tx(fee_sats=248), fee_sats=248)
    assert b.cierra_a(BSV_RELAY_SOFTWARE_SAT_PER_BYTE) is False


def test_la_banda_objetivo_cierra_entera() -> None:
    # La decisión de precio: 250 sats (presupuesto 249)
    # cierran la banda de 0.1 a 0.5 sat/vB con margen —
    # a 0.1 bastan ~46 sats, a 0.5 ~227, y el techo
    # real es 249/size ≈ 0.55.
    b = relay_budget(_tx(fee_sats=227), fee_sats=227)
    assert b.cierra_a(0.1) is True
    assert b.cierra_a(BSV_RELAY_TARGET_SAT_PER_BYTE) is True
    assert b.max_rate_sat_per_byte > BSV_RELAY_TARGET_SAT_PER_BYTE
    # el rango común de los pools (0.05-0.25) cierra con
    # margen: a 0.25 la fee son ~113 sats.
    assert b.cierra_a(BSV_RELAY_POOL_SAT_PER_BYTE) is True
    # una fee de 0 sats no paga relay alguno — solo
    # la minan pools sin fee. Por eso el default del
    # intercambio ya no es 0, sino la fee media.
    gratis = relay_budget(_tx(fee_sats=0), fee_sats=0)
    assert gratis.max_rate_sat_per_byte == 0
    assert gratis.cierra_a(0.05) is False
    # la fee no se come al ordinal: el precio sigue intacto.
    assert PER_INFERENCE_SATOSHIS - ORDINAL_SATOSHIS == 249
