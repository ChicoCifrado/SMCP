"""Test del demo RSI (el loop L1 mide su avance con HCI).

Verifica que el demo corre de punta a punta y cierra headroom > 0, con la
mejora aceptada por el verifier y el ledger íntegro.
"""
from __future__ import annotations

import asyncio

import pytest

from delm.demo import run_rsi_demo


def _run():
    return asyncio.run(run_rsi_demo.run(verbose=False))


def test_demo_runs_and_closes_headroom():
    out = _run()
    # la mejora cierra headroom (0-100)
    assert out["headroom_closed"] > 0.0
    # la mejora fue aceptada por el verifier
    assert out["rule_accepted"] is True
    # el sucesor consume la mejora (max_burst sube)
    assert out["successor_value"] > 2
    # el ledger queda íntegro
    assert out["ledger_chain_ok"] is True


def test_demo_hci_improves_monotonically():
    out = _run()
    # el HCI tras la mejora > el de la línea base
    assert out["improved_hci"] > out["base_hci"]
    # y el delta coincide con headroom_closed
    assert abs((out["improved_hci"] - out["base_hci"])
               - out["headroom_closed"]) < 1e-6


def test_demo_improvement_summary_is_serializable():
    out = _run()
    imp = out["improvement"]
    # el summary es JSON-serializable
    import json
    json.dumps(imp)
    # y refleja el cierre de headroom
    assert imp["closed"] > 0.0
    assert imp["hci_after"] > imp["hci_before"]
