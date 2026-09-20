"""Headroom-Closed Index (HCI) — métrica del paper RSI (arXiv:2609.11873).

Normaliza el desempeño de un benchmark a la escala 0-100:

- ``0``   = la *frontera* del año de entrada: el mejor score conocido al
  publicar el benchmark. Es el punto de partida (el "headroom" total empieza
  aquí).
- ``100`` = la puntuación *perfecta* (el tope teórico).

El *headroom* de un benchmark es el hueco entre la frontera y el tope.
Cada mejora RSI cierra parte de ese hueco; el **HCI** cuantifica, en una
escala 0-100 comparable, cuánto cierra cada mejora. Así se puede comparar el
avance de una mejora RSI contra la línea base, y entre benchmarks distintos.

La normalización es lineal y por benchmark::

    hci = 100 * (score - frontier) / (perfect - frontier)

clamp a ``[0, 100]``: un score por debajo de la frontera da 0; uno por encima
del tope da 100. El HCI de la *familia* (varios benchmarks) es la media
ponderada de los HCI individuales.

Uso en el loop RSI (P1):

    family = SMCP_FAMILY            # SWE-bench-style + Multi-Doc QA
    scorer = DeterministicScorer(fn)  # o un Scorer real (evalúa un config)
    meter  = HCIMeter(family)
    base   = meter.measure(scorer(config_base))     # HCI de la línea base
    after  = meter.measure(scorer(config_improved)) # HCI tras una mejora RSI
    gained = after - base                          # puntos de headroom cerrados

Módulo de solo lectura sobre la infra existente: no re-implementa verificación
ni proveniencia; solo normaliza scores y mide el avance de una mejora RSI
(midiendo el :class:`~delm.core.rsi.Successor` que el P0 ya produce).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping


# --------------------------------------------------------------------------- Benchmark
@dataclass(frozen=True)
class Benchmark:
    """Un benchmark con su frontera y su tope perfecto.

    ``frontier`` es el mejor score conocido al publicar el benchmark (el
    punto de partida, HCI = 0). ``perfect`` es el tope teórico (HCI = 100).
    Ambos en la misma unidad que el score que se mide (p. ej. ``0.0-1.0``
    para un resolve-rate o una accuracy).
    """
    id: str
    frontier: float
    perfect: float = 1.0
    unit: str = "rate"

    def __post_init__(self):
        if self.perfect <= self.frontier:
            raise ValueError(
                f"benchmark {self.id!r}: perfect ({self.perfect}) debe ser "
                f"> frontier ({self.frontier})"
            )
        if not (0.0 <= self.frontier <= self.perfect):
            raise ValueError(
                f"benchmark {self.id!r}: frontier fuera de [0, perfect]"
            )

    # ------------------------------------------------------------ hci
    def hci(self, score: float) -> float:
        """Normaliza ``score`` a la escala HCI (0-100).

        ``frontier`` -> 0, ``perfect`` -> 100. Clamp a ``[0, 100]``.
        """
        span = self.perfect - self.frontier
        frac = (score - self.frontier) / span
        return max(0.0, min(100.0, 100.0 * frac))

    # ------------------------------------------------------------ headroom
    def headroom(self, score: float) -> float:
        """Puntos de headroom *cerrados* por ``score`` (0-100).

        Igual que :meth:`hci` para un score único: cuánto ha cerrado el hueco
        desde la frontera.
        """
        return self.hci(score)

    # ------------------------------------------------------------ closed_by
    def closed_by(self, before: float, after: float) -> float:
        """Puntos de headroom cerrados por una mejora ``before -> after``.

        Es la diferencia de HCI: ``hci(after) - hci(before)``. Positivo si
        la mejora avanza, negativo si regresa.
        """
        return self.hci(after) - self.hci(before)


# --------------------------------------------------------------------------- BenchFamily
@dataclass(frozen=True)
class BenchFamily:
    """Una familia de benchmarks (el dominio a medir).

    El HCI de la familia es la media ponderada de los HCI individuales
    (pesos uniformes por defecto).
    """
    id: str
    benchmarks: tuple[Benchmark, ...]
    weights: tuple[float, ...] = ()

    def __post_init__(self):
        if self.weights and len(self.weights) != len(self.benchmarks):
            raise ValueError(
                f"familia {self.id!r}: {len(self.weights)} pesos para "
                f"{len(self.benchmarks)} benchmarks"
            )
        if not self.benchmarks:
            raise ValueError(f"familia {self.id!r}: sin benchmarks")

    def _w(self, i: int) -> float:
        if self.weights:
            return self.weights[i]
        return 1.0 / len(self.benchmarks)

    # ------------------------------------------------------------ hci
    def hci(self, scores: Mapping[str, float]) -> float:
        """HCI agregado de la familia para un mapa ``benchmark.id -> score``.

        Media ponderada de los HCI individuales. Si falta un score, se usa la
        frontera (HCI = 0) para ese benchmark.
        """
        total = 0.0
        for i, b in enumerate(self.benchmarks):
            s = scores.get(b.id, b.frontier)
            total += self._w(i) * b.hci(s)
        return total

    # ------------------------------------------------------------ closed_by
    def closed_by(self, before: Mapping[str, float],
                  after: Mapping[str, float]) -> float:
        """Puntos de headroom cerrados por una mejora (mapa antes/después)."""
        return self.hci(after) - self.hci(before)


# --------------------------------------------------------------------------- HCIMeter
class HCIMeter:
    """Mide el HCI de una familia y el headroom cerrado por mejoras RSI.

    Envuelve una :class:`BenchFamily` y un :data:`Scorer` (que evalúa un
    config y devuelve ``benchmark.id -> score``). :meth:`measure` devuelve el
    HCI 0-100 de un config; :meth:`improve` mide una mejora RSI (antes/
    después) y devuelve los puntos de headroom cerrados.
    """

    def __init__(self, family: BenchFamily, scorer: "Scorer | None" = None):
        self.family = family
        self.scorer = scorer

    # ------------------------------------------------------------ measure
    def measure(self, scores: Mapping[str, float]) -> float:
        """HCI 0-100 de un mapa ``benchmark.id -> score``."""
        return self.family.hci(scores)

    # ------------------------------------------------------------ score
    def score(self, config) -> float:
        """HCI 0-100 de un ``config`` (lo evalúa con el :data:`Scorer`)."""
        if self.scorer is None:
            raise ValueError("HCIMeter sin Scorer: usa measure() con scores")
        return self.family.hci(self.scorer(config))

    # ------------------------------------------------------------ improve
    def improve(self, before, after) -> "RSIImprovement":
        """Mide una mejora RSI ``before -> after`` (dos configs).

        Evalúa ambos configs con el :data:`Scorer` y devuelve un
        :class:`RSIImprovement` con el HCI antes/después y los puntos de
        headroom cerrados.
        """
        if self.scorer is None:
            raise ValueError("HCIMeter sin Scorer: usa closed_by() con scores")
        return RSIImprovement.from_scores(
            self.family, self.scorer(before), self.scorer(after),
        )


# --------------------------------------------------------------------------- RSIImprovement
@dataclass
class RSIImprovement:
    """El resultado de medir una mejora RSI contra una familia.

    ``before``/``after`` son los mapas ``benchmark.id -> score``; ``closed``
    son los puntos de headroom cerrados (``after.hci - before.hci``).
    """
    family_id: str
    before: Mapping[str, float]
    after: Mapping[str, float]
    hci_before: float
    hci_after: float
    closed: float

    @staticmethod
    def from_scores(family: BenchFamily,
                    before: Mapping[str, float],
                    after: Mapping[str, float]) -> "RSIImprovement":
        hb = family.hci(before)
        ha = family.hci(after)
        return RSIImprovement(
            family_id=family.id,
            before=dict(before),
            after=dict(after),
            hci_before=hb,
            hci_after=ha,
            closed=ha - hb,
        )

    # ------------------------------------------------------------ summary
    def summary(self) -> dict:
        """Vista JSON-serializable (para el ledger / la web)."""
        return {
            "family": self.family_id,
            "hci_before": round(self.hci_before, 4),
            "hci_after": round(self.hci_after, 4),
            "closed": round(self.closed, 4),
            "before": {k: round(v, 4) for k, v in self.before.items()},
            "after": {k: round(v, 4) for k, v in self.after.items()},
        }


# --------------------------------------------------------------------------- Scorer (protocol)
class Scorer:
    """Protocolo: evalúa un ``config`` y devuelve ``benchmark.id -> score``.

    Un :data:`Scorer` es la función que, dado un config del sistema (p. ej.
    ``{"max_burst": 4}``), ejecuta la familia de benchmarks y devuelve el
    score de cada uno. En producción, un :data:`Scorer` envuelve la suite de
    tests real; en tests/demos, un :class:`DeterministicScorer` mapea
    deterministamente.
    """

    def __call__(self, config) -> "dict[str, float]":  # pragma: no cover
        raise NotImplementedError


# --------------------------------------------------------------------------- DeterministicScorer
class DeterministicScorer(Scorer):
    """Un :data:`Scorer` determinista para tests y demos (sin modelo real).

    Mapea un ``config`` a ``benchmark.id -> score`` vía una función
    ``fn(config) -> dict``. Permite medir el HCI de una mejora RSI sin
    infraestructura: basta con que ``fn`` sea una función pura del config.
    """

    def __init__(self, fn: Callable):
        self._fn = fn

    def __call__(self, config) -> "dict[str, float]":
        return dict(self._fn(config))


# --------------------------------------------------------------------------- SMCP_FAMILY
#: Familia por defecto de SMCP: su dominio (SWE-bench-style + Multi-Doc QA).
#:
#: Los ``frontier`` son orientativos (el mejor score publicado al escribir
#: esto); el ``perfect`` es 1.0 (resolve-rate / accuracy a tope). Ajustar
#: los ``frontier`` cuando se publique el score real de la línea base.
SMCP_FAMILY = BenchFamily(
    id="smcp-core",
    benchmarks=(
        Benchmark(id="swe-style", frontier=0.30, perfect=1.00,
                  unit="resolve-rate"),
        Benchmark(id="multi-doc-qa", frontier=0.55, perfect=1.00,
                  unit="accuracy"),
    ),
)


__all__ = [
    "Benchmark",
    "BenchFamily",
    "HCIMeter",
    "RSIImprovement",
    "Scorer",
    "DeterministicScorer",
    "SMCP_FAMILY",
]
