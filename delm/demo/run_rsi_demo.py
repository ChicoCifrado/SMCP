"""RSI end-to-end demo — el loop L1 mide su avance con la métrica HCI.

Integra el P0 (``RSILoop``) con el P1 (``HCIMeter``):

1. Mide el **HCI de la línea base** (el sistema sin mejoras).
2. El sistema **propone una mejora a sí mismo** (auto-propuesta L1): una
   ``Rule`` que sube un parámetro (``max_burst``) motivada por una
   experiencia.
3. La mejora pasa el **pipeline verificado** (digest + ed25519 +
   ``RuleVerifier`` + ``AdmissionLedger``) y se retiene.
4. Mide el **HCI tras la mejora** y muestra los **puntos de headroom
   cerrados** (la métrica del paper RSI, 0-100).

El punto: la mejora no se asume, se *mide* (HCI) y se *audita* (ledger).
El HCI es la métrica que cuantifica cuánto cierra el hueco cada mejora RSI.

Run:  ``python -m delm.demo.run_rsi_demo``
"""
from __future__ import annotations

import asyncio


# ---------------------------------------------------------------------- scorer
def _base_scores(config: dict) -> dict[str, float]:
    """Scorer determinista: mapea un config a scores de la familia.

    La familia de SMCP tiene dos benchmarks:

    - ``swe-style``  (resolve-rate): mejora con ``max_burst`` (el parámetro
      que la mejora RSI sube). Basa en 0.30 (la frontera) y sube con el
      burst.
    - ``multi-doc-qa`` (accuracy): mejora con ``context_depth`` (otro
      parámetro, estable aquí). Basa en 0.55.

    Es una función pura del config (DeterministicScorer): misma entrada,
    misma salida.
    """
    max_burst = config.get("max_burst", 2)
    context_depth = config.get("context_depth", 1)
    # swe-style: 0.30 + 0.05 * max_burst, tope 0.95
    swe = min(0.95, 0.30 + 0.05 * max_burst)
    # multi-doc-qa: 0.55 + 0.03 * context_depth, tope 0.90
    qa = min(0.90, 0.55 + 0.03 * context_depth)
    return {"swe-style": round(swe, 4), "multi-doc-qa": round(qa, 4)}


# ---------------------------------------------------------------------- demo
async def run(verbose: bool = True) -> dict:
    from delm.core.rsi import RSILoop, Rule
    from delm.core.hci import (
        BenchFamily,
        Benchmark,
        DeterministicScorer,
        HCIMeter,
        RSIImprovement,
        SMCP_FAMILY,
    )

    # --- familia de SMCP (el dominio a medir) ------------------------
    family = SMCP_FAMILY
    scorer = DeterministicScorer(_base_scores)
    meter = HCIMeter(family, scorer)

    # --- 1. HCI de la línea base --------------------------------------
    base_config = {"max_burst": 2, "context_depth": 1}
    base_scores = scorer(base_config)
    base_hci = meter.measure(base_scores)

    # --- 2. el sistema propone una mejora a sí mismo (L1) -----------
    loop = RSILoop("agent-0")
    # La experiencia motiva subir max_burst (la cola se vacía lento).
    experience = (
        "the queue drained slowly across three runs; raising max_burst "
        "from two to five cleared pending tasks within the budget window "
        "and reduced tail latency on the swe-style benchmark"
    )
    out = await loop.propose(
        experience, scope="expansion", param="max_burst", value=5,
        name="auto-max-burst",
    )
    # La mejora pasa el pipeline verificado (digest + ed25519 + verifier +
    # ledger) y se retiene.
    assert out.accepted, "la mejora RSI debe ser aceptada por el verifier"
    succ = loop.apply(out)  # el sucesor consume la mejora (max_burst=5)

    # --- 3. HCI tras la mejora ---------------------------------------
    # El sucesor aplica la mejora: max_burst sube a 5.
    improved_config = {"max_burst": succ.value, "context_depth": 1}
    improved_scores = scorer(improved_config)
    improved_hci = meter.measure(improved_scores)

    # --- 4. puntos de headroom cerrados ------------------------------
    # La métrica del paper RSI: cuánto cierra el hueco la mejora (0-100).
    closed = improved_hci - base_hci
    # El RSIImprovement auditable (antes/después + closed) para el ledger.
    improvement = RSIImprovement.from_scores(
        family, base_scores, improved_scores,
    )

    out_dict = {
        "base_config": base_config,
        "base_scores": base_scores,
        "base_hci": round(base_hci, 4),
        "improved_config": improved_config,
        "improved_scores": improved_scores,
        "improved_hci": round(improved_hci, 4),
        "headroom_closed": round(closed, 4),
        "improvement": improvement.summary(),
        "rule_accepted": out.accepted,
        "successor_value": succ.value,
        "ledger_chain_ok": loop.verify_chain(),
    }

    if verbose:
        print("=== RSI demo: el loop L1 mide su avance (HCI) ===")
        print(f"línea base   : {base_config}")
        print(f"  scores     : {base_scores}")
        print(f"  HCI        : {base_hci:.2f}")
        print(f"mejora RSI   : {improved_config}  (propuesta auto, aceptada={out.accepted})")
        print(f"  scores     : {improved_scores}")
        print(f"  HCI        : {improved_hci:.2f}")
        print(f"headroom     : {closed:+.2f} puntos cerrados (0-100)")
        print(f"ledger       : cadena OK = {loop.verify_chain()}")
        print("=== RSI demo OK ===")
    return out_dict


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
