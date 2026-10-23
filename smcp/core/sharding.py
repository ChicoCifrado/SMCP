"""Sharding strategies for MoE models across a mesh.

Two complementary strategies, chosen per model and per mesh:

* ``EXPERT_ASSIGNMENT`` — MeshLLM style: each node hosts a *subset* of
  whole experts. Zero cross-node expert traffic, but imbalanced load
  (sticky routing mitigates misses).

* ``TENSOR_SHARDING`` — MoEShard style (Balmau et al., arXiv:2503.08467):
  every node holds a contiguous *shard* (columns of ``W_i``, rows of ``W_o``)
  of **every** expert. All nodes process all tokens with their shards and
  the partial outputs are summed. Perfect load balance by construction,
  at the cost of an all-to-all scatter/gather of tokens.

This module is the *planning* half (pure, deterministic, no GPU, no network):
it decides which shard goes where and estimates the communication cost. The
actual scatter/gather and kernel fusion live in the inference runtime
(MeshLLM / llama.cpp / PyTorch), which SMCP only points at.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Sequence


class ShardingStrategy(str, Enum):
    EXPERT_ASSIGNMENT = "expert_assignment"
    TENSOR_SHARDING = "tensor_sharding"


class DType(str, Enum):
    """Element size for communication-cost estimation."""
    FP32 = "fp32"
    FP16 = "fp16"
    BF16 = "bf16"
    FP8 = "fp8"
    INT8 = "int8"


DTYPE_BYTES: dict[DType, int] = {
    DType.FP32: 4,
    DType.FP16: 2,
    DType.BF16: 2,
    DType.FP8: 1,
    DType.INT8: 1,
}


def bytes_for(dtype: DType | str) -> int:
    """Bytes per element for a given dtype (string or enum)."""
    if isinstance(dtype, str):
        try:
            dtype = DType(dtype)
        except ValueError:
            return 4
    return DTYPE_BYTES.get(dtype, 4)


@dataclass(frozen=True, order=True)
class ShardRange:
    """A half-open index range ``[start, end)`` along one matrix axis."""
    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class TensorShard:
    """One peer's shard of one expert matrix.

    ``expert_idx == -1`` means "all experts" (the common MoEShard case,
    where every expert is sharded the same way across peers).
    """
    peer_id: str
    expert_idx: int
    matrix: str          # "W_i" or "W_o"
    axis: str            # "col" (W_i) or "row" (W_o)
    rng: ShardRange


@dataclass(frozen=True)
class ShardPlan:
    """The decision record for sharding one MoE model across the mesh."""
    strategy: ShardingStrategy
    model: str
    ok: bool = True
    reason: str = ""
    n_peers: int = 0
    n_expert: int = 0
    n_expert_used: int = 0
    hidden_in: int = 0
    hidden_out: int = 0
    # peer -> list of shards it holds
    peer_shards: dict[str, list[TensorShard]] = field(default_factory=dict)
    # peer -> set of whole-expert indices (expert assignment only)
    peer_experts: dict[str, frozenset[int]] = field(default_factory=dict)
    # estimated bytes for one forward pass
    scatter_bytes: int = 0
    gather_bytes: int = 0
    redundancy: int = 0
    dtype: str = "fp32"
    notes: tuple[str, ...] = ()

    @property
    def total_comm_bytes(self) -> int:
        return self.scatter_bytes + self.gather_bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "model": self.model,
            "ok": self.ok,
            "reason": self.reason,
            "n_peers": self.n_peers,
            "n_expert": self.n_expert,
            "n_expert_used": self.n_expert_used,
            "hidden_in": self.hidden_in,
            "hidden_out": self.hidden_out,
            "peer_shards": {
                pid: [
                    {"expert": s.expert_idx, "matrix": s.matrix,
                     "axis": s.axis, "start": s.rng.start, "end": s.rng.end}
                    for s in shards
                ]
                for pid, shards in self.peer_shards.items()
            },
            "peer_experts": {pid: sorted(v) for pid, v in self.peer_experts.items()},
            "scatter_bytes": self.scatter_bytes,
            "gather_bytes": self.gather_bytes,
            "total_comm_bytes": self.total_comm_bytes,
            "notes": list(self.notes),
        }


def _contiguous_ranges(n: int, parts: int) -> list[ShardRange]:
    """Split ``[0, n)`` into ``parts`` contiguous ranges (last absorbs remainder)."""
    if parts <= 0:
        return []
    base = n // parts
    rem = n % parts
    out: list[ShardRange] = []
    cur = 0
    for i in range(parts):
        size = base + (1 if i < rem else 0)
        out.append(ShardRange(cur, cur + size))
        cur += size
    return out


def plan_tensor_sharding(
    model: str,
    peers: Sequence[str],
    *,
    n_expert: int = 0,
    n_expert_used: int = 0,
    hidden_in: int = 0,
    hidden_out: int = 0,
    batch_size: int = 1,
    seq_len: int = 1,
    bytes_per_elem: int = 0,
    dtype: DType | str = DType.FP32,
    redundancy: int = 0,
    **_ignored: Any,
) -> ShardPlan:
    """Plan a MoEShard-style tensor sharding across ``peers``.

    Every peer gets a contiguous, disjoint shard of the columns of ``W_i``
    and the rows of ``W_o`` for *all* experts. The shards tile ``[0, hidden_out)``
    exactly. Communication cost is estimated for one forward pass.
    """
    peers = list(peers)
    n = len(peers)
    if n == 0:
        return ShardPlan(strategy=ShardingStrategy.TENSOR_SHARDING, model=model,
                        ok=False, reason="no_peers", n_peers=0)
    if hidden_out <= 0:
        return ShardPlan(strategy=ShardingStrategy.TENSOR_SHARDING, model=model,
                        ok=False, reason="missing_hidden_out", n_peers=n)
    if hidden_out < n:
        return ShardPlan(strategy=ShardingStrategy.TENSOR_SHARDING, model=model,
                        ok=False, reason="hidden_out_smaller_than_peers",
                        n_peers=n, hidden_out=hidden_out)

    ranges = _contiguous_ranges(hidden_out, n)
    # sanity: tile check
    assert ranges[0].start == 0
    assert ranges[-1].end == hidden_out
    for a, b in zip(ranges, ranges[1:]):
        assert a.end == b.start

    peer_shards: dict[str, list[TensorShard]] = {}
    for pid in peers:
        peer_shards.setdefault(pid, [])

    bpe = bytes_per_elem if bytes_per_elem > 0 else bytes_for(dtype)

    for pid, rng in zip(peers, ranges):
        shards = [
            TensorShard(peer_id=pid, expert_idx=-1, matrix="W_i",
                        axis="col", rng=rng),
            TensorShard(peer_id=pid, expert_idx=-1, matrix="W_o",
                        axis="row", rng=rng),
        ]
        peer_shards[pid].extend(shards)

    # redundancy: replicate each shard on `redundancy` extra peers (cyclic)
    if redundancy > 0:
        for i, (pid, rng) in enumerate(zip(peers, ranges)):
            for r in range(1, redundancy + 1):
                replica_peer = peers[(i + r) % n]
                peer_shards[replica_peer].extend([
                    TensorShard(peer_id=replica_peer, expert_idx=-1,
                                matrix="W_i", axis="col", rng=rng),
                    TensorShard(peer_id=replica_peer, expert_idx=-1,
                                matrix="W_o", axis="row", rng=rng),
                ])

    tokens = batch_size * seq_len
    input_bytes = tokens * hidden_in * bpe if hidden_in > 0 else 0
    # Each peer sends its full input to all others (scatter) and receives
    # partial outputs back (gather). Output shape matches input (h_i).
    scatter_bytes = n * input_bytes
    gather_bytes = n * input_bytes

    notes = (
        f"tensor sharding across {n} peer(s): W_i col-wise, W_o row-wise, "
        f"shard size ~{ranges[0].size} of {hidden_out}, dtype={dtype}, "
        f"redundancy={redundancy}.",
    )
    if hidden_out % n != 0:
        notes = notes + (f"hidden_out={hidden_out} not divisible by {n}: "
                         f"last shard absorbs remainder.",)

    return ShardPlan(
        strategy=ShardingStrategy.TENSOR_SHARDING,
        model=model,
        ok=True,
        n_peers=n,
        n_expert=n_expert,
        n_expert_used=n_expert_used,
        hidden_in=hidden_in,
        hidden_out=hidden_out,
        peer_shards=peer_shards,
        scatter_bytes=scatter_bytes,
        gather_bytes=gather_bytes,
        redundancy=redundancy,
        dtype=str(dtype),
        notes=notes,
    )


def plan_expert_assignment(
    model: str,
    peers: Sequence[str],
    *,
    n_expert: int = 0,
    n_expert_used: int = 0,
    min_experts_per_node: int = 0,
    overlap: int = 0,
    **_ignored: Any,
) -> ShardPlan:
    """Plan MeshLLM-style expert assignment: subset of whole experts per peer.

    ``overlap`` extra experts are added to every peer (solape) so that a
    token's required expert is likely local. Union must cover all experts.
    """
    peers = list(peers)
    n = len(peers)
    if n == 0:
        return ShardPlan(strategy=ShardingStrategy.EXPERT_ASSIGNMENT, model=model,
                        ok=False, reason="no_peers", n_peers=0)
    if n_expert <= 0:
        return ShardPlan(strategy=ShardingStrategy.EXPERT_ASSIGNMENT, model=model,
                        ok=False, reason="missing_n_expert", n_peers=n)
    if min_experts_per_node > 0 and min_experts_per_node * n < n_expert:
        # even with no overlap, must cover all experts
        pass

    # base partition: contiguous chunks of experts
    base = n_expert // n
    rem = n_expert % n
    peer_experts: dict[str, frozenset[int]] = {}
    cur = 0
    for i, pid in enumerate(peers):
        size = base + (1 if i < rem else 0)
        chunk = set(range(cur, cur + size))
        cur += size
        # add overlap: next `overlap` experts (wrapping)
        if overlap > 0:
            for k in range(overlap):
                chunk.add((cur + k) % n_expert)
        peer_experts[pid] = frozenset(chunk)

    # verify coverage
    union: set[int] = set()
    for v in peer_experts.values():
        union |= set(v)
    covered = len(union)
    ok = covered == n_expert
    reason = "" if ok else f"coverage_gap:{n_expert - covered}"

    # min experts per node check
    if ok and min_experts_per_node > 0:
        for pid, v in peer_experts.items():
            if len(v) < min_experts_per_node:
                ok = False
                reason = f"peer_{pid}_below_min:{len(v)}<{min_experts_per_node}"
                break

    notes = (f"expert assignment across {n} peer(s): "
             f"{n_expert} experts, overlap={overlap}.",)
    if overlap > 0:
        notes = notes + (f"solape de {overlap} expertos por nodo.",)

    return ShardPlan(
        strategy=ShardingStrategy.EXPERT_ASSIGNMENT,
        model=model,
        ok=ok,
        reason=reason,
        n_peers=n,
        n_expert=n_expert,
        n_expert_used=n_expert_used,
        peer_experts=peer_experts,
        notes=notes,
    )


def plan_sharding(
    model: str,
    peers: Sequence[str],
    *,
    strategy: ShardingStrategy = ShardingStrategy.TENSOR_SHARDING,
    **kwargs: Any,
) -> ShardPlan:
    """Dispatch to the chosen strategy planner."""
    if strategy == ShardingStrategy.TENSOR_SHARDING:
        return plan_tensor_sharding(model, peers, **kwargs)
    if strategy == ShardingStrategy.EXPERT_ASSIGNMENT:
        return plan_expert_assignment(model, peers, **kwargs)
    return ShardPlan(strategy=strategy, model=model, ok=False,
                    reason=f"unknown_strategy:{strategy}")


def recommend_strategy(
    *,
    n_peers: int,
    batch_size: int = 1,
    latency_ms: float = 0.0,
    n_expert: int = 0,
) -> ShardingStrategy:
    """Heuristic selector between the two strategies.

    Tensor sharding wins when the mesh is fast and batches are large enough
    to amortize the all-to-all communication. Expert assignment wins on slow
    or small meshes.
    """
    if n_peers < 2:
        return ShardingStrategy.EXPERT_ASSIGNMENT
    if latency_ms > 50.0:
        return ShardingStrategy.EXPERT_ASSIGNMENT
    if batch_size < 8:
        return ShardingStrategy.EXPERT_ASSIGNMENT
    if n_expert > 0 and n_expert < 8:
        return ShardingStrategy.EXPERT_ASSIGNMENT
    return ShardingStrategy.TENSOR_SHARDING


@dataclass(frozen=True)
class LayerShard:
    """One contiguous layer range with its chosen sharding strategy."""
    layer_start: int
    layer_end: int          # exclusive
    strategy: ShardingStrategy
    plan: ShardPlan


@dataclass(frozen=True)
class LayeredShardPlan:
    """Sharding plan split by layer ranges, possibly mixed strategies."""
    model: str
    n_layers: int
    layers: tuple[LayerShard, ...] = ()
    ok: bool = True
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "n_layers": self.n_layers,
            "ok": self.ok,
            "reason": self.reason,
            "layers": [
                {"start": ls.layer_start, "end": ls.layer_end,
                 "strategy": ls.strategy.value, "plan": ls.plan.to_dict()}
                for ls in self.layers
            ],
        }


def plan_layered_sharding(
    model: str,
    peers: Sequence[str],
    n_expert_per_layer: Sequence[int],
    *,
    strategy_threshold: int = 8,
    hidden_in: int = 0,
    hidden_out: int = 0,
    **kwargs: Any,
) -> LayeredShardPlan:
    """Mixed-strategy sharding: tensor sharding for layers with many experts,
    expert assignment for layers with few. Consecutive same-strategy layers
    are grouped into one chunk (one ShardPlan per chunk).
    """
    peers = list(peers)
    n = len(n_expert_per_layer)
    if n == 0:
        return LayeredShardPlan(model=model, n_layers=0, ok=False,
                                reason="no_layers")
    if not peers:
        return LayeredShardPlan(model=model, n_layers=n, ok=False,
                                reason="no_peers")

    # decide strategy per layer
    layer_strategy: list[ShardingStrategy] = []
    for cnt in n_expert_per_layer:
        if cnt >= strategy_threshold:
            layer_strategy.append(ShardingStrategy.TENSOR_SHARDING)
        else:
            layer_strategy.append(ShardingStrategy.EXPERT_ASSIGNMENT)

    # group consecutive same-strategy layers
    chunks: list[tuple[int, int, ShardingStrategy, int]] = []
    start = 0
    for i in range(1, n + 1):
        if i == n or layer_strategy[i] != layer_strategy[start]:
            cnt_max = max(n_expert_per_layer[start:i])
            chunks.append((start, i, layer_strategy[start], cnt_max))
            start = i

    layers: list[LayerShard] = []
    for (ls, le, strat, cnt) in chunks:
        plan = plan_sharding(
            model, peers, strategy=strat,
            n_expert=cnt, n_expert_used=0,
            hidden_in=hidden_in, hidden_out=hidden_out,
            **kwargs,
        )
        layers.append(LayerShard(layer_start=ls, layer_end=le,
                                strategy=strat, plan=plan))

    ok = all(ls.plan.ok for ls in layers)
    reason = "" if ok else "some_chunks_failed"
    return LayeredShardPlan(model=model, n_layers=n, layers=tuple(layers),
                            ok=ok, reason=reason)


def replan_sharding(
    previous: ShardPlan,
    *,
    peers: Sequence[str] | None = None,
    latency_ms: float = 0.0,
    **kwargs: Any,
) -> ShardPlan:
    """Re-plan a sharding with updated peers/metrics (dynamic rebalancing).

    Pure: returns a new plan; the caller decides whether to apply it.
    """
    new_peers = list(peers) if peers is not None else []
    if not new_peers:
        # fall back to the peers implied by the previous plan
        new_peers = list(previous.peer_shards.keys())
    merged = dict(kwargs)
    merged.setdefault("n_expert", previous.n_expert)
    merged.setdefault("n_expert_used", previous.n_expert_used)
    merged.setdefault("hidden_in", previous.hidden_in)
    merged.setdefault("hidden_out", previous.hidden_out)
    merged.setdefault("redundancy", previous.redundancy)
    merged.setdefault("dtype", previous.dtype)
    return plan_sharding(previous.model, new_peers,
                         strategy=previous.strategy, **merged)


def plan_speculative(
    model: str,
    draft_model: str,
    peers: Sequence[str],
    *,
    strategy: ShardingStrategy = ShardingStrategy.TENSOR_SHARDING,
    **kwargs: Any,
) -> tuple[ShardPlan, ShardPlan]:
    """Plan sharding for a model + its speculative draft model.

    Returns (main_plan, draft_plan). Both use the same strategy by default.
    """
    main = plan_sharding(model, peers, strategy=strategy, **kwargs)
    draft = plan_sharding(draft_model, peers, strategy=strategy, **kwargs)
    return main, draft


__all__ = [
    "ShardingStrategy",
    "DType",
    "DTYPE_BYTES",
    "bytes_for",
    "ShardRange",
    "TensorShard",
    "ShardPlan",
    "LayerShard",
    "LayeredShardPlan",
    "plan_tensor_sharding",
    "plan_expert_assignment",
    "plan_sharding",
    "plan_layered_sharding",
    "replan_sharding",
    "plan_speculative",
    "recommend_strategy",
]
