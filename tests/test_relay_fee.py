"""Fee de relay — la medición que cierra el abierto 3 de la spec.

La plantilla v3.0 paga 100 sats: 1 al ordinal, ``fee_sats``
al minero y el resto al servidor. La pregunta del abierto 3
(``docs/inscripcion-v3.md``): **¿la fee que le queda a la tx
la hace pasar el relay de BSV?**

La respuesta es aritmética, no opinión: se construye una tx
real (flujo DPP completo, firma ECDSA incluida), se serializa
y se mide. El tamaño varía un byte por la firma DER (71 u
72 bytes), así que el test **mide** la tx y verifica la
relación, en lugar de pinchar un número mágico.
"""
from __future__ import annotations

from smcp.core.bsv_keys import Secp256k1KeyPair
from smcp.core.inscripcion import (
    BSV_RELAY_POOL_SAT_PER_BYTE,
    BSV_RELAY_SOFTWARE_SAT_PER_BYTE,
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
    # plantilla es ~453, nunca una estimación fija
    assert 450 <= b.size_bytes <= 455


def test_el_techo_es_fee_entre_tamano() -> None:
    b = relay_budget(_tx(fee_sats=10), fee_sats=10)
    assert b.max_rate_sat_per_byte == 10 / b.size_bytes
    assert b.cierra_a(0) is True
    assert b.cierra_a(b.max_rate_sat_per_byte) is True
    assert b.cierra_a(b.max_rate_sat_per_byte + 0.001) is False


def test_el_default_del_software_no_cierra() -> None:
    # minrelaytxfee de BSV = 1 sat/vB: ni con la fee
    # máxima construible (98, dejan 1 sat al servidor)
    # la plantilla paga su relay (~453 B > 98).
    b = relay_budget(_tx(fee_sats=98), fee_sats=98)
    assert b.cierra_a(BSV_RELAY_SOFTWARE_SAT_PER_BYTE) is False


def test_el_mercado_de_pools_cierra_solo_en_su_mitad_baja() -> None:
    # A 0.05 sat/vB bastan ~23 sats; a 0.25 (techo del rango
    # común) no alcanzan ni los 98 máximos. El techo real es
    # fee/size ≈ 0.216 sat/vB.
    barato = relay_budget(_tx(fee_sats=23), fee_sats=23)
    assert barato.cierra_a(0.05) is True
    caro = relay_budget(_tx(fee_sats=98), fee_sats=98)
    assert caro.cierra_a(BSV_RELAY_POOL_SAT_PER_BYTE) is False
    assert caro.max_rate_sat_per_byte < BSV_RELAY_POOL_SAT_PER_BYTE
    # con la fee por defecto del intercambio (0), la tx no
    # paga relay alguno — solo la minan pools sin fee.
    gratis = relay_budget(_tx(fee_sats=0), fee_sats=0)
    assert gratis.max_rate_sat_per_byte == 0
    assert gratis.cierra_a(0.05) is False
    # la fee no se come al ordinal: el precio sigue intacto.
    assert PER_INFERENCE_SATOSHIS - ORDINAL_SATOSHIS == 99
