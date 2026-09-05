"""DELM — Decentralized Language Models (clean-room implementation).

Core idea (paper: Mao & Mirhoseini, "Decentralized Multi-Agent Systems with
Shared Context", arXiv:2606.10662):

    Instead of a central orchestrator that routes every intermediate result
    through itself (a communication bottleneck), agents coordinate
    *decentrally* through two global structures:

      * a **shared context**  C : compact, *verified* gists of accumulated
        progress, visible to every agent; and
      * a **task queue**     T : pending subtasks that agents claim
        asynchronously.

    An agent claims a task from T, reads the shared context C, does local
    reasoning, and writes back a compact update. That update is *compressed,
    verified against its supporting evidence, and admitted* into C only if
    it passes — turning intermediate progress into reusable problem state.
"""

__version__ = "0.1.0"

from delm.core.gist import Gist, Summary, RefTag, GistKind
from delm.core.shared_context import SharedContext
from delm.core.task_queue import TaskQueue, Task
from delm.core.admission import AdmissionPipeline, AdmissionOutcome
from delm.core.unfolding import Unfolding
from delm.core.verifier import Verifier
from delm.core.llm import LLMClient, OpenAICompatibleClient, FakeLLMClient

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
]
