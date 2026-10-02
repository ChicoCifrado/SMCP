"""Layer placement across a mesh: run a model bigger than any single node.

This is where the three pieces of SMCP meet:

* **llmfit** (:mod:`delm.core.llmfit`) answers *how much memory does this model
  need, and does it fit this box* — for one host;
* **the exchange** (:mod:`delm.core.contrib`) answers *which peers have capacity
  the mesh has admitted, and who is entitled to spend it*;
* **DeLM** keeps sharing the verified context ``C`` across those same peers, so
  the agents reasoning over a jointly-hosted model also share what they learn.

The division of labour is deliberate and worth stating plainly: **SMCP plans and
admits, MeshLLM executes.** A :class:`PlacementPlan` says how the weights are
split across peers and whether that split is admissible; the actual
pipeline-parallel run is served by MeshLLM's OpenAI-compatible endpoint, which
this module only *points at*. Building a tensor-transport runtime here would
duplicate (and lose to) vLLM/MeshLLM — and would be untestable without GPUs,
which is exactly the kind of thing this repo does not do.

What "admissible" means here, and what it does not:

* **Checked:** total admitted VRAM covers the model's requirement; every stage
  fits in its host's *admitted* VRAM minus a reserve; no peer is overcommitted
  by two concurrent plans; every contributing peer is currently observed and
  publishes VRAM to the mesh.
* **Not checked:** that the weights can actually be fetched, that the hosts are
  bandwidth-connected, or that a specific layer→stage mapping is efficient. The
  plan is a *decision record* — deterministic, replayable, and the thing you
  would log and later audit — not a guarantee about the network.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Sequence

from delm.core.contrib import ContributionLedger, capacity_is_intact

__all__ = [
    "PlanReject",
    "ModelSpec",
    "Stage",
    "PlacementPlan",
    "plan_placement",
    "plan_from_dict",
    "plan_json",
    "DEFAULT_MESH_ENDPOINT",
]

#: Where a MeshLLM seed (or any mesh-hosted OpenAI-compatible server) listens.
DEFAULT_MESH_ENDPOINT = "http://127.0.0.1:9337/v1"


class PlanReject(str, Enum):
    """Machine-readable placement outcomes, same discipline as ``RejectReason``."""

    OK = "ok"
    NO_ADMITTED_PEERS = "no_admitted_peers"
    INSUFFICIENT_MESH_VRAM = "insufficient_mesh_vram"
    PEER_TOO_SMALL = "peer_too_small"
    PEER_NOT_OBSERVED = "peer_not_observed"
    NO_PROVIDERS = "no_providers"
    NOT_A_PROVIDER = "not_a_provider"
    SPEC_MISSING_MEMORY = "spec_missing_memory"
    SPEC_NOT_FITTABLE = "spec_not_fittable"   # even an unbounded mesh can't
    #: capacidad admitida que no supera el digest firmado al admitirla
    NO_VERIFIED_PEERS = "no_verified_peers"


@dataclass(frozen=True)
class ModelSpec:
    """What placement needs to know about a model. Sized by llmfit."""

    name: str
    memory_required_gb: float
    n_layers: int = 0            # 0 = unknown; plan by memory share, not layers
    quant: str = ""
    fit_level: str = ""
    estimated_tps: float | None = None
    endpoint_hint: str = ""      # per-model serving hint, if the caller has one

    @classmethod
    def from_fit_row(cls, row: Any, *, name: str = "") -> "ModelSpec":
        """Build from a :class:`delm.core.llmfit.FitRow`.

        ``memory_required_gb`` is what llmfit computed *for a single host*; that
        is the number the mesh has to cover collectively, so it is reused
        verbatim rather than re-estimated.
        """
        return cls(
            name=name or getattr(row, "name", ""),
            memory_required_gb=float(getattr(row, "memory_required_gb", 0.0) or 0.0),
            quant=getattr(row, "best_quant", "") or "",
            fit_level=getattr(row, "fit_level", "") or "",
            estimated_tps=getattr(row, "estimated_tps", None),
        )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ModelSpec":
        return cls(name=str(d.get("name", "")),
                   memory_required_gb=float(d.get("memory_required_gb", 0.0) or 0.0),
                   n_layers=int(d.get("n_layers", 0) or 0),
                   quant=str(d.get("quant", "")),
                   fit_level=str(d.get("fit_level", "")),
                   estimated_tps=(float(d["estimated_tps"])
                                  if d.get("estimated_tps") is not None else None),
                   endpoint_hint=str(d.get("endpoint_hint", "")))

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "memory_required_gb": self.memory_required_gb,
                "n_layers": self.n_layers, "quant": self.quant,
                "fit_level": self.fit_level, "estimated_tps": self.estimated_tps,
                "endpoint_hint": self.endpoint_hint}


@dataclass(frozen=True)
class Stage:
    """One peer's slice of the model."""

    peer_id: str
    memory_gb: float
    #: physical maximum, for display and the detection cross-check
    peer_vram_gb: float
    #: what the node offers, and what this slice was planned against
    peer_advertised_gb: float = 0.0
    #: what the mesh is using right now
    peer_shared_gb: float = 0.0
    peer_ram_gb: float = 0.0
    first_layer: int | None = None
    last_layer: int | None = None

    @property
    def utilization(self) -> float:
        """Fraction of the peer's admitted VRAM this stage consumes."""
        if self.peer_vram_gb <= 0:
            return 1.0
        return round(self.memory_gb / self.peer_vram_gb, 4)

    @property
    def peer_vram_available_gb(self) -> float:
        """What was actually available to plan this slice against.

        Mirrors :attr:`delm.core.contrib.PeerContribution.vram_available_gb`
        rather than recomputing from placement's own numbers, so a stage can
        never report a different figure than the peer it came from. Kept as a
        property because the two must never drift apart.
        """
        return max(0.0, min(self.peer_advertised_gb, self.peer_vram_gb)
                   - self.peer_shared_gb)

    def to_dict(self) -> dict[str, Any]:
        return {"peer_id": self.peer_id, "memory_gb": round(self.memory_gb, 3),
                "peer_vram_gb": self.peer_vram_gb,
                "peer_advertised_gb": self.peer_advertised_gb,
                "peer_shared_gb": self.peer_shared_gb,
                "peer_vram_available_gb": self.peer_vram_available_gb,
                "peer_ram_gb": self.peer_ram_gb,
                "first_layer": self.first_layer, "last_layer": self.last_layer,
                "utilization": self.utilization}


@dataclass(frozen=True)
class PlacementPlan:
    """The decision record: where the model goes, or why it cannot go."""

    model: str
    ok: bool
    reason: str
    memory_required_gb: float = 0.0
    total_vram_gb: float = 0.0
    stages: tuple[Stage, ...] = ()
    endpoint: str = DEFAULT_MESH_ENDPOINT
    single_node: bool = False
    notes: tuple[str, ...] = ()
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def peers(self) -> tuple[str, ...]:
        return tuple(s.peer_id for s in self.stages)

    @property
    def node_count(self) -> int:
        return len(self.stages)

    def to_dict(self) -> dict[str, Any]:
        return {"model": self.model, "ok": self.ok, "reason": self.reason,
                "memory_required_gb": round(self.memory_required_gb, 3),
                "total_vram_gb": round(self.total_vram_gb, 3),
                "stages": [s.to_dict() for s in self.stages],
                "endpoint": self.endpoint, "single_node": self.single_node,
                "notes": list(self.notes), "detail": dict(self.detail),
                "node_count": self.node_count}

    def render(self) -> str:
        """Deterministic text — the CLI's default output for `delm mesh plan`."""
        head = "=== smcp placement ===" if self.ok else "=== smcp placement (rechazado) ==="
        out = [head, f"modelo   : {self.model}",
               f"memoria  : {self.memory_required_gb:.1f}G requeridos · "
               f"{self.total_vram_gb:.1f}G verificados en la malla",
               f"endpoint : {self.endpoint}"]
        if not self.ok:
            out.append(f"veredicto : {self.reason}")
            for note in self.notes:
                out.append(f"  - {note}")
            return "\n".join(out)
        out.append(f"veredicto : {self.reason} · {self.node_count} nodo(s)")
        out.append("")
        out.append("  nodo                 memoria  vmax  ofrece  usa  disp    uso    layers")
        for s in self.stages:
            layers = ("-" if s.first_layer is None
                      else f"{s.first_layer}-{s.last_layer}")
            out.append(f"  {s.peer_id[:20]:<20} {s.memory_gb:>6.1f}G "
                       f"{s.peer_vram_gb:>5.0f}G {s.peer_advertised_gb:>5.1f}G "
                       f"{s.peer_shared_gb:>4.1f}G "
                       f"{s.peer_vram_available_gb:>5.1f}G "
                       f"{s.utilization:>5.0%} {layers:>8}")
        for note in self.notes:
            out.append(f"  · {note}")
        out.append("=== plan OK ===")
        return "\n".join(out)


def _assign_layers(spec: ModelSpec, sizes: Sequence[float]) -> list[tuple[int | None, int | None]]:
    """Map memory shares onto layer ranges when the layer count is known.

    Returns ``(first, last)`` per stage, or ``(None, None)`` when the model
    does not publish a layer count (llmfit does not) — in which case the plan is
    "split by verified VRAM share" and the executor owns the layer mapping.
    """
    if spec.n_layers <= 0 or not sizes:
        return [(None, None)] * len(sizes)
    total = sum(sizes) or 1.0
    out: list[tuple[int | None, int | None]] = []
    cursor = 0
    for i, size in enumerate(sizes):
        if i == len(sizes) - 1:
            out.append((cursor, spec.n_layers - 1))
            break
        # Largest-remainder-free, deterministic: proportional, floor, and the
        # last stage absorbs the rounding so the ranges always tile [0, n-1].
        n = int((size / total) * spec.n_layers)
        n = max(1, min(n, spec.n_layers - cursor - 1))
        out.append((cursor, cursor + n - 1))
        cursor += n
    return out


def plan_placement(spec: ModelSpec, ledger: ContributionLedger, *,
                   reserve_gb: float = 0.0,
                   require_provider: bool = True,
                   observed_only: bool = True,
                   endpoint: str | None = None,
                   ) -> PlacementPlan:
    """Decide how *spec* is split across the mesh's admitted capacity.

    The algorithm is deliberately greedy and boring — biggest verified VRAM
    first, take peers until the model is covered, split each peer's slice in
    proportion to its share. Boring is the point: given the same ledger, the
    plan is byte-identical, so a plan can be logged, replayed and compared
    between observers (see :meth:`ContributionLedger.state_digest`).

    ``require_provider`` is what keeps the mesh honest about what it places:
    a peer that offers no VRAM is a **consumer** (see
    :mod:`delm.core.tiers`), and giving it a stage would mean scheduling work
    on a machine that never offered capacity. The old rule was "must have
    credit", which was the same idea wearing a currency it did not need.
    """
    total_vram = ledger.total_vram_gb(observed_only=observed_only)
    # Anotacion explicita: sin ella pyright infiere `dict[str, str | float]`
    # (el valor comun de los literales) y cada `PlacementPlan(**base)` de la
    # funcion se convierte en 7 reportArgumentType distintos — 41 errores de
    # tipado que son UNO solo, aqui.
    base: dict[str, Any] = dict(
        model=spec.name,
        memory_required_gb=spec.memory_required_gb,
        total_vram_gb=total_vram,
        endpoint=endpoint or spec.endpoint_hint or DEFAULT_MESH_ENDPOINT,
    )

    if spec.memory_required_gb <= 0:
        return PlacementPlan(ok=False, reason=PlanReject.SPEC_MISSING_MEMORY.value,
                             notes=("llmfit no devolvió memoria para este modelo; "
                                    "no se puede planear sin ella.",),
                             **base)

    candidates = ledger.admitted_peers(observed_only=observed_only)
    # Integridad: una capacidad admitida está anclada a un digest firmado al
    # admitirla. Si alguien reescribió `vram_gb` en el ledger (o el ledger vino
    # de una versión sin el campo), el número ya no es una afirmación firmada
    # y no se puede colocar carga sobre él. Se descarta aquí, antes de que
    # `total_vram_gb` de arriba lo haya contado — ese total es un dato
    # informativo, la decisión la toman los candidatos que pasan este filtro.
    intact = [p for p in candidates if capacity_is_intact(p, ledger.mesh_id)]
    tampered = [p for p in candidates if not capacity_is_intact(p, ledger.mesh_id)]
    if tampered and not intact:
        return PlacementPlan(
            ok=False, reason=PlanReject.NO_VERIFIED_PEERS.value,
            notes=("la capacidad admitida no supera la verificación de firma: "
                   + ", ".join(sorted(p.peer_id for p in tampered))
                   + " (atribución de capacidad manipulada tras admitirla; "
                     "re-admite con un report firmado nuevo).",),
            detail={"tampered_peers": sorted(p.peer_id for p in tampered)},
            **base)
    candidates = intact
    if not candidates:
        # Distinguish "nobody joined" from "joined but not observed": the fix is
        # different in each case and the operator needs to know which.
        joined = ledger.admitted_peers(observed_only=False)
        # `notes` es `tuple[str, ...]` en el dataclass. La declaracion va
        # ANTES de las ramas: mas abajo la misma variable se construye como
        # lista, y sin esto pyright la fijaba como `list` desde aqui y luego
        # rechazaba cada rama, o al reves.
        notes: tuple[str, ...]
        if not joined:
            reason = PlanReject.NO_ADMITTED_PEERS.value
            notes = (
                "ningún nodo ha admitido capacidad todavía: `delm mesh contribute`.",
            )
        else:
            reason = PlanReject.PEER_NOT_OBSERVED.value
            notes = (
                f"{len(joined)} nodo(s) admitidos pero ninguno observado ahora mismo: "
                "el crédito solo se acumula con el nodo vivo.",
            )
        return PlacementPlan(ok=False, reason=reason, notes=notes, **base)

    # The three VRAM numbers meet here. Routing plans against what is
    # *available* — advertised minus what the mesh is already using — never
    # against the physical maximum, which would be planning against hardware
    # the owner never offered. reserve_gb then comes off the top, per node, as
    # an operator-level keep-out rather than the node's own decision.
    # La puerta de proveedor va ANTES que la de tamaño. "No ofrece VRAM" y
    # "ofrece muy poca" son arreglos distintos —publicar capacidad, o
    # esperar a un nodo más grande— y si el filtro de tamaño se come al
    # primero, el operador recibe un diagnóstico que no le sirve.
    if require_provider:
        providers = [p for p in candidates if p.vram_advertised_gb > 0]
        non_providers = [p for p in candidates if p.vram_advertised_gb <= 0]
    else:
        providers, non_providers = candidates, []

    usable = [(p, max(0.0, p.vram_available_gb - reserve_gb))
              for p in providers]
    usable = [(p, v) for p, v in usable if v > 0]
    if not usable and non_providers:
        _sin_proveedores = ("ningún nodo ofrece VRAM a la malla: "
                            + ", ".join(sorted(p.peer_id
                                               for p in non_providers))
                            + ". Un nodo que consume no puede alojar carga.")
        return PlacementPlan(ok=False, reason=PlanReject.NOT_A_PROVIDER.value,
                             notes=(_sin_proveedores,),
                             detail={"blocked": sorted(p.peer_id
                                                      for p in non_providers)},
                             **base)
    if not usable:
        return PlacementPlan(ok=False, reason=PlanReject.PEER_TOO_SMALL.value,
                             notes=(f"todos los nodos están por debajo del usable "
                                    f"tras reservar {reserve_gb:.1f}G.",), **base)

    # Greedy cover, biggest first, peers that cannot pay are skipped.
    picked: list[tuple[Any, float]] = []
    covered = 0.0
    blocked: list[str] = []
    for peer, free in usable:
        if covered >= spec.memory_required_gb:
            break
        picked.append((peer, free))
        covered += free
    if not picked:
        # La rama ya no tiene dos motivos: la puerta de proveedor se resolvio
        # antes, asi que llegar aqui es "todo el mundo es demasiado pequeño".
        _notas_bloqueo: tuple[str, ...] = ()
        return PlacementPlan(ok=False,
                             reason=PlanReject.PEER_TOO_SMALL.value,
                             notes=_notas_bloqueo,
                             detail={"blocked": blocked}, **base)

    if covered + 1e-9 < spec.memory_required_gb:
        missing = round(spec.memory_required_gb - covered, 3)
        # Nombre propio: `notes` arriba ya existe como `tuple[str, ...]` en las
        # ramas tempranas (que retornan antes). Reutilizarlo aqui lo convertia
        # en `list` para pyright y rompia la unificacion de tipo.
        _notas = [f"faltan {missing:.1f}G de VRAM verificada para este modelo."]
        if blocked:
            _notas.append("nodos con VRAM pero sin crédito (excluidos): "
                          + ", ".join(blocked))
        return PlacementPlan(ok=False, reason=PlanReject.INSUFFICIENT_MESH_VRAM.value,
                             notes=tuple(_notas), detail={"blocked": blocked},
                             **base)

    # Trim the tail: the last picked peer may not need its whole capacity.
    free_total = sum(f for _, f in picked)
    scale = spec.memory_required_gb / free_total if free_total else 1.0
    stages: list[Stage] = []
    for peer, free in picked:
        memory = round(spec.memory_required_gb * (free / free_total), 4)
        if memory <= 0:
            continue
        stages.append(Stage(
            peer_id=peer.peer_id,
            memory_gb=memory,
            peer_vram_gb=peer.vram_gb,
            peer_advertised_gb=peer.vram_advertised_gb,
            peer_shared_gb=peer.vram_shared_gb,
            peer_ram_gb=peer.ram_gb,
        ))
    # Absorb rounding into the largest stage so the sum is exact.
    if stages:
        drift = round(spec.memory_required_gb - sum(s.memory_gb for s in stages), 4)
        if abs(drift) > 1e-9:
            biggest = max(range(len(stages)), key=lambda i: stages[i].memory_gb)
            stages[biggest] = replace(
                stages[biggest],
                memory_gb=round(stages[biggest].memory_gb + drift, 4))

    layers = _assign_layers(spec, [s.memory_gb for s in stages])
    stages = [replace(s, first_layer=lay[0], last_layer=lay[1])
              for s, lay in zip(stages, layers)]

    # Se acumulan en lista y se convierten a tupla al construir el plan
    # (`notes` es `tuple[str, ...]`). Nombre `_ok_notes` y no `notes` para no
    # colisionar con el `notes: tuple[str, ...]` de las ramas de rechazo
    # de rechazo tempranas de esta misma funcion.
    _ok_notes: list[str] = []
    if len(stages) == 1:
        _ok_notes.append(f"cabe entero en {stages[0].peer_id}: no hace falta repartir.")
    else:
        _ok_notes.append("reparto por cuota de VRAM verificada; "
                         "el mapeo capa→stage lo resuelve el executor (MeshLLM).")
    if spec.n_layers <= 0:
        _ok_notes.append("el modelo no publica nº de capas: el plan es por memoria.")
    if blocked:
        _ok_notes.append("nodos excluidos por falta de crédito: " + ", ".join(blocked))

    return PlacementPlan(ok=True, reason=PlanReject.OK.value,
                         stages=tuple(stages),
                         single_node=len(stages) == 1, notes=tuple(_ok_notes),
                         detail={"blocked": blocked}, **base)


def plan_from_dict(d: dict[str, Any]) -> PlacementPlan:
    """Rebuild a plan from :meth:`PlacementPlan.to_dict` (audit replay)."""
    return PlacementPlan(
        model=str(d.get("model", "")), ok=bool(d.get("ok", False)),
        reason=str(d.get("reason", "")),
        memory_required_gb=float(d.get("memory_required_gb", 0.0) or 0.0),
        total_vram_gb=float(d.get("total_vram_gb", 0.0) or 0.0),
        stages=tuple(Stage(
            peer_id=str(s.get("peer_id", "")),
            memory_gb=float(s.get("memory_gb", 0.0) or 0.0),
            peer_vram_gb=float(s.get("peer_vram_gb", 0.0) or 0.0),
            peer_advertised_gb=float(s.get("peer_advertised_gb", 0.0) or 0.0),
            peer_shared_gb=float(s.get("peer_shared_gb", 0.0) or 0.0),
            peer_ram_gb=float(s.get("peer_ram_gb", 0.0) or 0.0),
            first_layer=s.get("first_layer"), last_layer=s.get("last_layer"))
            for s in d.get("stages", [])),
        endpoint=str(d.get("endpoint", DEFAULT_MESH_ENDPOINT)),
        single_node=bool(d.get("single_node", False)),
        notes=tuple(d.get("notes", [])), detail=dict(d.get("detail", {})))


def plan_json(plan: PlacementPlan) -> str:
    return json.dumps(plan.to_dict(), indent=2, sort_keys=True)
