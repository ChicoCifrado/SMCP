"""DeepSeek Harness adapter — agent turns behind the LLMClient interface.

DELM is already model-agnostic: ``OpenAICompatibleClient`` talks to any
OpenAI-compatible endpoint. That covers a single completion. What it does
*not* cover is an **agent runtime** — tool use, sub-agents, plan mode,
persistent sessions.

This module bridges DELM into the `DeepSeek Harness` SDK, which provides
exactly that. It exposes the same :class:`delm.core.llm.LLMClient` interface,
so a worker can swap in a harness-backed agent without changing its call
sites.

Design (Phase A — the thin adapter)
-----------------------------------

* **Lazy SDK import.** ``deepseek_harness`` is imported only inside
  :meth:`HarnessLLMClient._ensure`, so the package stays importable — and the
  default test suite stays green — without the SDK (or its 268 MB runtime)
  installed.
* **One subprocess per client.** The harness runtime (``dsh``) is launched
  once per :class:`HarnessLLMClient` and reused across turns.
* **Sync SDK, async surface.** The SDK is synchronous (it drives a
  subprocess); :meth:`HarnessLLMClient.complete` dispatches the blocking call
  off the event loop via :func:`asyncio.to_thread`.
* **Route injection.** The ``sdk`` profile ships ``llm-pi-ai`` dormant. A
  generated patch activates an OpenAI-compatible route (``llm-pi-ai``)
  pointing at the same local model server DELM already runs, so the agent
  uses the *same* model — no second model to manage.

The adapter is **opt-in**: nothing imports it at module load. A worker that
wants agent turns constructs one explicitly (or via :func:`build_harness_client`).
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from delm.core.llm import LLMClient

__all__ = [
    "HarnessLLMClient",
    "build_harness_client",
    "HARNESS_ROUTE_ID",
    "DEFAULT_KEY_FILE",
]

#: Route id (the ``provider`` the SDK requests) of the OpenAI-compatible
#: route the generated patch activates inside ``llm-pi-ai``.
HARNESS_ROUTE_ID = "qwen-local"

#: The env var the generated route reads the model key from. Must match the
#: ``apiKeyEnv`` the patch writes.
_KEY_ENV = "DELM_HARNESS_KEY"

#: Default location of the local model server's API key (minted by
#: Unsloth Studio). Overridable per client.
DEFAULT_KEY_FILE = Path(
    os.environ.get(
        "DELM_HARNESS_KEY_FILE",
        "/home/cifrado/.unsloth/studio/auth/agent_api_key.json",
    )
)


def _read_key(key_file: Path) -> str:
    """Read the local model server's API key from ``key_file``.

    The file is the JSON Unsloth Studio mints; the key lives under
    ``servers[<host>][minted][0]``. The first entry that carries a minted key
    is returned, so the exact host spelling need not match.
    """
    data = json.loads(Path(key_file).read_text())
    for entry in (data.get("servers") or {}).values():
        minted = entry.get("minted") or []
        if minted:
            return minted[0]
    raise ValueError(f"no minted API key found in {key_file}")


@dataclass
class _Turn:
    final_response: str
    finish_reason: str | None
    events: list[dict]


class HarnessLLMClient(LLMClient):
    """An :class:`LLMClient` backed by the DeepSeek Harness agent runtime.

    Parameters
    ----------
    model, base_url:
        The OpenAI-compatible model + endpoint the agent runs against
        (defaults to the local Qwen server).
    api_key:
        Explicit key. If ``None``, it is read from ``key_file``.
    key_file:
        Where to read the key when ``api_key`` is ``None``.
    dsh_home:
        State dir for the harness runtime (sessions). A tempdir is created
        when ``None``.
    timeout:
        Per-turn request timeout (seconds).
    """

    def __init__(
        self,
        model: str = "unsloth/Qwen3.8-27B-GGUF",
        base_url: str = "http://127.0.0.1:8888/v1",
        api_key: str | None = None,
        key_file: Path = DEFAULT_KEY_FILE,
        dsh_home: str | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.timeout = timeout
        self._api_key = api_key
        self._key_file = Path(key_file)
        self._dsh_home = dsh_home
        self._harness: Any = None
        self._patch_path: str | None = None
        self._closed = False
        self._ensure_lock = threading.Lock()

    # ------------------------------------------------------------- key
    def _resolve_key(self) -> str:
        if self._api_key:
            return self._api_key
        return _read_key(self._key_file)

    # ---------------------------------------------------------- patch
    def _write_patch(self) -> str:
        """Materialise the ``llm-pi-ai`` route patch; return its path.

        The patch activates a single OpenAI-compatible route (``llm-pi-ai``)
        pointing at ``base_url``/``model``. The key is read by the route from
        ``_KEY_ENV``, which the SDK injects into the runtime subprocess.
        """
        if self._patch_path is not None:
            return self._patch_path
        base = Path(self._dsh_home) if self._dsh_home else Path(tempfile.gettempdir())
        base.mkdir(parents=True, exist_ok=True)
        patch = base / "patch_local.yml"
        if not patch.exists():
            model_line = self.model.replace(" ", " ")
            patch.write_text(
                "- id: llm-pi-ai\n"
                "  name: '@deepseek-ai/dsh-llm-pi-ai'\n"
                "  config:\n"
                "    providers:\n"
                f"      {HARNESS_ROUTE_ID}:\n"
                f"        displayName: {model_line}\n"
                f"        apiKeyEnv: {_KEY_ENV}\n"
                "        api: openai-completions\n"
                f"        baseURL: {self.base_url}\n"
                "        models:\n"
                f"          - id: {model_line}\n"
                f"            name: {model_line}\n"
                "            contextWindow: 131072\n"
                "            maxTokens: 8192\n"
            )
        self._patch_path = str(patch)
        return self._patch_path

    # ------------------------------------------------------- runtime
    def _ensure(self) -> None:
        """Import the SDK and launch the harness runtime (once)."""
        if self._harness is not None:
            return
        with self._ensure_lock:
            if self._harness is not None:
                return
            # Lazy: the SDK is a heavy, optional dependency (Rust runtime).
            from deepseek_harness import (  # type: ignore
                DeepSeekHarness,
                DeepSeekHarnessConfig,
            )
            dsh_home = self._dsh_home or tempfile.gettempdir()
            self._harness = DeepSeekHarness(
                DeepSeekHarnessConfig(
                    provider=HARNESS_ROUTE_ID,
                    model=self.model,
                    dsh_home=dsh_home,
                    patches=(self._write_patch(),),
                    env={_KEY_ENV: self._resolve_key()},
                    request_timeout_seconds=self.timeout,
                )
            )

    # ---------------------------------------------------------- sync core
    def _run_sync(self, prompt: str, system: str) -> _Turn:
        """Blocking agent turn; runs off the event loop."""
        self._ensure()
        # The SDK's run() takes a single text input; the system prompt is
        # prepended (the SDK exposes no separate system channel in this build).
        text = f"{system}\n\n{prompt}" if system else prompt
        res = self._harness.run(text)
        return _Turn(
            final_response=res.final_response,
            finish_reason=res.finish_reason,
            events=list(res.events),
        )

    # ---------------------------------------------------------- async api
    async def complete(self, prompt: str, system: str = "", **kwargs) -> str:
        """Run one agent turn and return its final text response.

        The call is blocking (it drives the harness subprocess), so it is
        dispatched off the event loop.
        """
        if self._closed:
            raise RuntimeError("HarnessLLMClient is closed")
        return (await asyncio.to_thread(self._run_sync, prompt, system)).final_response

    # ---------------------------------------------------------- lifecycle
    def close(self) -> None:
        if self._harness is not None:
            self._harness.close()
            self._harness = None
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def build_harness_client(
    config,
    *,
    api_key: str | None = None,
    key_file: Path = DEFAULT_KEY_FILE,
    dsh_home: str | None = None,
    timeout: float = 120.0,
) -> HarnessLLMClient:
    """Build a :class:`HarnessLLMClient` from a :class:`~delm.config.ModelConfig`.

    Mirrors :func:`delm.config.build_client` so a worker picks the agent
    runtime with the same config object it already uses for the plain model.
    """
    return HarnessLLMClient(
        model=config.model,
        base_url=config.base_url,
        api_key=api_key,
        key_file=key_file,
        dsh_home=dsh_home,
        timeout=timeout,
    )
