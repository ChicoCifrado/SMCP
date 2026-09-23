"""LLMClient abstraction — model-agnostic completion.

DELM is model-agnostic: the same pipeline runs against any OpenAI-compatible
endpoint (OpenRouter, direct provider, a local server, etc.). Two clients ship:

  * :class:`FakeLLMClient` — deterministic, no network. Used by the demo and
    tests so the whole pipeline (queue -> agent -> compress -> verify ->
    admit -> unfold -> finalize) runs end-to-end with zero API cost.
  * :class:`OpenAICompatibleClient` — real calls to an OpenAI-compatible
    ``/chat/completions`` endpoint via the ``openai`` SDK.
"""

from __future__ import annotations

import abc
import json
from dataclasses import dataclass, field


class LLMClient(abc.ABC):
    """Async completion interface. ``complete`` returns the raw text."""

    @abc.abstractmethod
    async def complete(self, prompt: str, system: str = "", **kwargs) -> str:
        ...

    async def complete_json(self, prompt: str, system: str = "") -> dict:
        """Complete and parse the response as JSON (robust to code fences)."""
        raw = await self.complete(prompt, system)
        return parse_json_lenient(raw)


class FakeLLMClient(LLMClient):
    """Deterministic stand-in for an LLM.

    Routes on simple markers in the prompt so the demo can exercise every
    branch of the pipeline (summarize / verify / solve / finalize) without a
    model. Outputs are short and structured so downstream parsing is trivial.
    """

    def __init__(self, transcript: dict[str, str] | None = None) -> None:
        # transcript: optional override map from prompt-marker -> response.
        self.transcript = transcript or {}
        self.calls: list[str] = []

    async def complete(self, prompt: str, system: str = "", **kwargs) -> str:
        self.calls.append(prompt)
        # 1) explicit override wins
        for marker, resp in self.transcript.items():
            if marker in prompt:
                return resp
        # 2) default routing by the role tag we prepend to prompts
        if "[ROLE:SUMMARIZER]" in prompt:
            # Trajectory compression: the prompt embeds the result text
            # between "trajectory result:\n" and "\nCompress". Return it as a
            # faithful 1:1 gist so the admission n-gram check passes.
            if "trajectory result:" in prompt and "\nCompress" in prompt:
                start = prompt.index("trajectory result:\n") + len("trajectory result:\n")
                end = prompt.index("\nCompress")
                return prompt[start:end].strip()
            # Source compression: a generic compact gist (verified via RefTags,
            # not n-grams), so any faithful text is fine.
            return (
                "Gist: source unit covers the core claim relevant to the task; "
                "key figures and constraints are stated plainly."
            )
        if "[ROLE:VERIFIER]" in prompt:
            return json.dumps({"ok": True, "reasons": ["grounded"]})
        if "[ROLE:SOLVER]" in prompt:
            return (
                "SOLUTION: applied the minimal change that resolves the issue; "
                "verified by the reproduction test passing. "
                "PATCH_SUMMARY files=src/target.py idea=apply_minimal_fix "
                "evidence=repro PASSED"
            )
        if "[ROLE:FINALIZER]" in prompt:
            return (
                "ANSWER: The task is resolved by the verified change recorded in "
                "the shared context; all constraints are satisfied."
            )
        return "OK"


class OpenAICompatibleClient(LLMClient):
    """Real client for any OpenAI-compatible ``/chat/completions`` API.

    Parameters mirror the reference repo's ``config/model_config.yaml``:
    ``model`` (e.g. ``google/gemini-3-flash``), ``base_url`` (e.g.
    ``https://openrouter.ai/api/v1``), ``api_key``.
    """

    def __init__(self, model: str, base_url: str | None = None,
                 api_key: str | None = None, temperature: float = 0.0,
                 **kwargs) -> None:
        # Imported laz so the package is importable without the SDK installed.
        from openai import AsyncOpenAI  # type: ignore
        self.model = model
        self.temperature = temperature
        # Endpoints that need no auth (local servers) reject any
        # Authorization header (401 "Invalid token payload"). Only send a
        # Bearer token when a real key is configured; otherwise strip it
        # via an httpx request hook so AsyncOpenAI still gets a non-empty
        # api_key (it refuses api_key=None without OPENAI_API_KEY).
        key = (api_key or "").strip()
        if key:
            self._client = AsyncOpenAI(
                base_url=base_url, api_key=key, **kwargs
            )
            return
        # No auth: endpoint local rejects any Authorization (401). Use a
        # placeholder key (SDK refuses api_key=None) and strip the header
        # on the wire. openai 3.x ships httpx2; older used httpx.
        self._client = AsyncOpenAI(
            base_url=base_url, api_key="delm-no-auth", **kwargs
        )
        try:
            import httpx2  # type: ignore
        except ImportError:  # pragma: no cover
            import httpx as httpx2  # type: ignore

        async def _strip_auth(request):
            request.headers.pop("Authorization", None)
            request.headers.pop("authorization", None)
            return request

        # Inject the hook into the SDK's transport without building a
        # whole new AsyncClient (timeout/base_url/limits would be lost).
        transport = getattr(self._client, "_custom_http_client", None)
        if transport is None:
            transport = getattr(self._client, "_client", None)
        inner = getattr(transport, "_client", transport)
        if inner is not None and hasattr(inner, "event_hooks"):
            inner.event_hooks["request"] = list(
                inner.event_hooks.get("request", [])
            ) + [_strip_auth]
        else:  # pragma: no cover — openai layout change
            import copy
            hc = copy.deepcopy(getattr(inner, "_transport", None))
            self._client._custom_http_client = httpx2.AsyncClient(
                event_hooks={"request": [_strip_auth]},
                timeout=kwargs.get("timeout", 60),
            )

    async def complete(self, prompt: str, system: str = "", **kwargs) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = await self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
        )
        return resp.choices[0].message.content or ""


def parse_json_lenient(text: str) -> dict:
    """Parse a JSON object out of an LLM reply, tolerating code fences."""
    t = text.strip()
    if t.startswith("```"):
        # strip the fence
        t = t.strip("`")
        if t.lower().startswith("json"):
            t = t[4:]
        t = t.strip()
    # find the first {...} block
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        t = t[start:end + 1]
    return json.loads(t)
