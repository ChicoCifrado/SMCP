"""Core primitives of the DELM framework."""

from smcp.core.gist import Gist, Summary, RefTag, GistKind
from smcp.core.shared_context import SharedContext
from smcp.core.task_queue import TaskQueue, Task
from smcp.core.admission import AdmissionPipeline, AdmissionOutcome
from smcp.core.unfolding import Unfolding
from smcp.core.verifier import Verifier
from smcp.core.sharding import (
    ShardingStrategy, DType, DTYPE_BYTES, bytes_for,
    ShardRange, TensorShard, ShardPlan, LayerShard, LayeredShardPlan,
    plan_tensor_sharding, plan_expert_assignment, plan_sharding,
    plan_layered_sharding, replan_sharding, plan_speculative,
    recommend_strategy,
)
from smcp.core.llm import LLMClient, OpenAICompatibleClient, FakeLLMClient

__all__ = [
    "Gist",
    "Summary",
    "RefTag",
    "GistKind",
    "SharedContext",
    "TaskQueue",
    "Task",
    "AdmissionPipeline",
    "AdmissionOutcome",
    "Unfolding",
    "Verifier",
    "LLMClient",
    "OpenAICompatibleClient",
    "FakeLLMClient",
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
