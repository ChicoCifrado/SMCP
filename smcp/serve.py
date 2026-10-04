"""``smcp-serve`` — SMCP as an ACP agent (the missing protocol loop).

This is the piece that turns SMCP from "a FastAPI endpoint" into **an agent**
for any ACP client (OpenDesign, Zed, VS Code, JetBrains). See
``DESIGNCOMPAT.md`` — via A, the canonical integration path.

Why this file exists
--------------------

The protocol shape of a shared, verified agent context is already implemented
and tested (the admission pipeline, the secure context, the mesh). What was
missing is a **receiver**: something that speaks a *client* protocol on stdio
and drives that loop, so a third party can run SMCP as one more agent in its
catalogue rather than reimplementing the loop. The precedent is Hermes' own
``hermes acp`` (``acp_adapter/`` in the hermes-agent repo) — this file is the
same shape, wired to SMCP's pipeline instead of Hermes'.

The shape (verified against the real SDK, ``agent-client-protocol==0.9.0``)
-----------------------------------------------------------------------------

ACP is JSON-RPC 2.0 over stdio. The **agent** implements server methods and
the SDK wires a ``Client`` in via :meth:`on_connect`, which the agent uses to
push output back (``session/update``). Every agent method is **async**, and
``acp.run_agent(agent)`` owns the stdio loop.

Each ACP ``session`` maps to a SMCP run: an editor prompt becomes one or more
:class:`~smcp.core.task_queue.Task` objects, they go through the real
:class:`~smcp.core.pipeline.DelmPipeline` (compress → verify → admit into the
signed shared context), and the result streams back as ``session/update``
chunks. Nothing here re-implements the pipeline — it is the same code path the
HTTP API uses (:mod:`smcp.web.api`), so an ACP run and an ``/api/runs`` run are the
same pipeline over the same admission gate.

Contract invariants
-------------------

- **stdout is reserved for JSON-RPC.** All logging goes to stderr. Any stray
  ``print`` to stdout corrupts the protocol stream — this is the single most
  common way an ACP adapter dies.
- **No secrets over the wire**: the model config is read server-side
  (env > YAML > default); the ACP client never sees the API key.
- **The default backend is deterministic** (``FakeLLMClient``) so an ACP smoke
  test runs with no model and no network. ``--backend real`` opts into a live
  endpoint.
- Cancellation is real: ``session/cancel`` aborts the in-flight run task
  (mirrors ``RunManager.cancel`` in the HTTP API).

Usage
-----

    pip install "delm[acp]"        # agent-client-protocol
    smcp-serve                      # deterministic (FakeLLMClient), no key
    smcp-serve --backend real       # a real endpoint (DELM_MODEL/BASE_URL)
    python -m smcp.serve            # == smcp-serve

Register with an ACP client (OpenDesign): ``bin: 'smcp-serve'``,
``streamFormat: 'acp-json-rpc'``.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import uuid
from typing import TYPE_CHECKING, Any

# ACP is an OPTIONAL dependency: importing this module must not break the base
# install or the test suite. The import happens in ``_require_acp()``.
ACP_HINT = (
    "smcp-serve needs the optional ACP dependency. Install it with:\n"
    "    pip install 'delm[acp]'    # agent-client-protocol\n"
)

logger = logging.getLogger("smcp.acp")

# Type-only imports of the ACP schema. The SDK is an optional extra, so these
# must not run at import time — but the annotations on the Agent overrides
# below are string literals precisely so that a type checker can resolve them
# against the real protocol types. Without this block pyright cannot see
# ``NewSessionResponse`` and reports every override as incompatible, which is
# the same error it reported for the *order* of the parameters before the
# signatures were annotated at all.
if TYPE_CHECKING:  # pragma: no cover
    from acp.schema import (
        AcpMcpServer,
        ForkSessionResponse,
        HttpMcpServer,
        SseMcpServer,
        McpServerStdio,
        ListSessionsResponse,
        NewSessionResponse,
        PromptResponse,
        ResumeSessionResponse,
        SetSessionModeResponse,
    )
    from acp.schema import (
        AudioContentBlock,
        EmbeddedResourceContentBlock,
        ImageContentBlock,
        ResourceContentBlock,
        TextContentBlock,
    )

#: Model id reported to ACP clients. SMCP is model-agnostic; this is the
#: *backend* label, and the concrete model is resolved server-side.
AGENT_NAME = "smcp"
AGENT_VERSION = "1"


def _require_acp():
    """Import the ACP SDK lazily so the base install stays ACP-free.

    Returns the ``acp`` module only; the content blocks live in ``acp.schema``
    (not the top-level package) and are imported where they are used.
    """
    try:
        import acp
    except ImportError as exc:  # pragma: no cover - depends on the extra
        raise SystemExit(ACP_HINT) from exc
    return acp


# ----------------------------------------------------------------- helpers
def log_setup() -> None:
    """Route logging to stderr — stdout belongs to the JSON-RPC stream."""
    handler = logging.StreamHandler(__import__("sys").stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                          datefmt="%Y-%m-%d %H:%M:%S")
    )
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    for noisy in ("httpx", "httpcore", "openai", "aiohttp", "websockets"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def prompt_text(prompt: list) -> str:
    """Flatten an ACP prompt (a list of content blocks) into plain text.

    Only text blocks are read; image/audio/resource blocks are skipped rather
    than guessed at (SMCP reasons over text).
    """
    parts: list[str] = []
    for block in prompt or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(str(text))
    return "\n".join(parts).strip()


def split_tasks(prompt: str) -> list[str]:
    """Split one editor prompt into pipeline tasks.

    The natural mapping for a shared-context protocol: a prompt is *one* task
    per line, so the pipeline's workers claim them concurrently and their gists
    meet in the shared context. A single-line prompt stays a single task (the
    common case) — the split only matters for multi-part requests.
    """
    lines = [ln.strip() for ln in (prompt or "").splitlines()]
    tasks = [ln for ln in lines if ln]
    return tasks or ["(empty prompt)"]


# ------------------------------------------------------------------ agent
def build_agent(backend: str = "fake", n_workers: int = 4,
                max_rounds: int = 3) -> Any:
    """Build the ACP agent object bound to the SMCP pipeline.

    A factory returning an ``acp.Agent`` subclass instance: the SDK is only
    touched at runtime, and the class body can reference the SDK's types
    without a module-level import.
    """
    acp = _require_acp()

    from smcp.core.llm import FakeLLMClient, LLMClient

    def _make_llm() -> tuple[LLMClient, dict[str, Any]]:
        if backend == "fake":
            return FakeLLMClient(), {"backend": "fake", "model": "fake"}
        # Real endpoint: same resolution as the HTTP API (env > YAML > default).
        from smcp.config import build_client, load_config

        cfg = load_config()
        if not cfg.model or not cfg.base_url:
            raise ValueError(
                "backend=real requires DELM_MODEL and DELM_BASE_URL "
                "(or a config/model_config.yaml)"
            )
        info = {"backend": "real", "model": cfg.model,
                "timeout_s": cfg.timeout_s, "use_harness": cfg.use_harness}
        return build_client(cfg), info

    class SmcpAgent(acp.Agent):
        """SMCP exposed as an ACP agent.

        One ACP session == one SMCP run: a prompt becomes tasks, the real
        :class:`DelmPipeline` runs them against a signed shared context, and
        the output streams back as ``session/update`` chunks.

        **Los overrides repiten la firma de :class:`acp.Agent` tal cual**
        (``session_id`` antes que ``prompt``, ``cwd`` antes que ``cursor``, …),
        aunque el SDK despacha por keyword (`func(**params)` en
        `acp/router.py`) y nuestra versión anterior funcionara con el orden
        invertido. Es deliberado: el orden de una firma pública es parte del
        contrato LSP, y un orden distinto rompe en silencio a cualquier
        llamador posicional (o a un SDK que despache posicionalmente) asignando
        ``cwd`` donde va ``session_id``. Los parámetros que SMCP ignora a
        propósito (``additional_directories``) se **declaran** en vez de
        tragarse en ``**kwargs``, para que la decisión se lea y no se deduzca.
        `tests/test_serve.py::test_overrides_match_the_acp_contract` lo fija.
        """

        def __init__(self) -> None:
            super().__init__()
            # session_id -> the in-flight run task (for session/cancel).
            self._runs: dict[str, Any] = {}
            self._sessions: dict[str, str] = {}   # session_id -> cwd

        # -- the SDK injects the Client here (that is how we push updates)
        def on_connect(self, conn) -> None:
            self.client = conn
            logger.info("ACP client connected")

        # -- lifecycle -------------------------------------------------
        async def initialize(self, protocol_version, client_capabilities=None,
                             client_info=None, **kwargs):
            from acp.schema import Implementation

            logger.info("ACP initialize: protocol_version=%s client=%s",
                        protocol_version, client_info)
            return acp.InitializeResponse(
                protocol_version=acp.PROTOCOL_VERSION,
                agent_info=Implementation(name=AGENT_NAME,
                                          version=AGENT_VERSION),
                # SMCP's capability surface: it reasons over a shared verified
                # context. It does not touch the filesystem or spawn terminals
                # itself, so those client capabilities stay unclaimed.
                agent_capabilities=None,
                auth_methods=[],
            )

        async def new_session(
            self,
            cwd: str,
            additional_directories: list[str] | None = None,
            mcp_servers: list[HttpMcpServer | SseMcpServer | AcpMcpServer | McpServerStdio] | None = None,
            **kwargs: Any,
        ) -> "NewSessionResponse":
            # `additional_directories` se acepta y se **ignora a propósito**:
            # SMCP no toca el filesystem (no es una herramienta de agente), así
            # que no hay directorio que abrir. Se declara explícitamente en vez
            # de dejarlo caer en **kwargs para que la decisión sea legible y no
            # un efecto colateral del `**kwargs`.
            session_id = str(uuid.uuid4())
            self._sessions[session_id] = cwd
            logger.info("ACP new_session: %s (cwd=%s)", session_id, cwd)
            return acp.NewSessionResponse(session_id=session_id)

        async def load_session(self, cwd, session_id, mcp_servers=None,
                               additional_directories=None, **kwargs):
            # SMCP runs are ephemeral (the shared context persists, the run
            # does not), so a resume starts clean rather than faking history.
            self._sessions[session_id] = cwd
            logger.info("ACP load_session: %s (fresh run)", session_id)
            return acp.LoadSessionResponse()

        async def close_session(self, session_id, **kwargs):
            task = self._runs.pop(session_id, None)
            if task is not None and not task.done():
                task.cancel()
            self._sessions.pop(session_id, None)
            return None

        async def list_sessions(
            self,
            cwd: str | None = None,
            cursor: str | None = None,
            **kwargs: Any,
        ) -> "ListSessionsResponse":
            """SMCP runs are ephemeral: there is nothing to enumerate.

            An empty list (not an error) is the honest answer — the shared
            *context* persists across runs, the run history does not.
            """
            from acp.schema import ListSessionsResponse

            return ListSessionsResponse(sessions=[])

        async def fork_session(
            self,
            session_id: str,
            cwd: str,
            additional_directories: list[str] | None = None,
            mcp_servers: list[HttpMcpServer | SseMcpServer | AcpMcpServer | McpServerStdio] | None = None,
            **kwargs: Any,
        ) -> "ForkSessionResponse":
            # Forking would mean cloning admitted state; SMCP's shared context
            # IS the fork mechanism (a new run reads the same C), so a forked
            # session is just a new session.
            from acp.schema import ForkSessionResponse

            self._sessions.pop(session_id, None)
            return ForkSessionResponse(session_id=str(uuid.uuid4()))

        async def resume_session(
            self,
            session_id: str,
            cwd: str,
            additional_directories: list[str] | None = None,
            mcp_servers: list[HttpMcpServer | SseMcpServer | AcpMcpServer | McpServerStdio] | None = None,
            **kwargs: Any,
        ) -> "ResumeSessionResponse":
            from acp.schema import ResumeSessionResponse

            self._sessions[session_id] = cwd
            return ResumeSessionResponse()

        async def authenticate(self, method_id, **kwargs):
            """No auth: SMCP's trust anchor is the owner's key, not a login."""
            return None

        async def set_session_mode(
            self, session_id: str, mode_id: str, **kwargs: Any,
        ) -> "SetSessionModeResponse | None":
            # No modes declared in new_session, so a mode set is a no-op.
            return None

        async def set_session_model(self, model_id, session_id, **kwargs):
            # The model is resolved server-side (env > YAML > default) and
            # declared as None in the session, so there is nothing to switch.
            return None

        async def set_config_option(self, config_id, session_id, value, **kwargs):
            return None

        async def ext_method(self, method, params):
            """No SMCP extensions over ACP: unknown method = -32601."""
            from acp.exceptions import RequestError

            raise RequestError(-32601, f"unknown method: {method}")

        async def ext_notification(self, method, params):
            """Unknown notifications are ignored (fire-and-forget)."""
            logger.debug("ignoring unknown ACP notification: %s", method)

        async def cancel(self, session_id, **kwargs):
            """``session/cancel`` — abort the in-flight run, keep the session."""
            task = self._runs.get(session_id)
            if task is not None and not task.done():
                task.cancel()
                logger.info("ACP cancel: %s", session_id)
            return None

        # -- the loop --------------------------------------------------
        async def prompt(
            self,
            session_id: str,
            prompt: list[TextContentBlock | ImageContentBlock
                         | AudioContentBlock | ResourceContentBlock
                         | EmbeddedResourceContentBlock],
            **kwargs: Any,
        ) -> "PromptResponse":
            text = prompt_text(prompt)
            logger.info("ACP prompt: session=%s chars=%d tasks=%d",
                        session_id, len(text), len(split_tasks(text)))
            # The run happens in the background: `prompt` returns a
            # stop_reason immediately and the output arrives as
            # session/update notifications (that is the ACP contract).
            self._runs[session_id] = asyncio.ensure_future(
                self._run_prompt(session_id, text))
            return acp.PromptResponse(stop_reason="end_turn")

        async def _run_prompt(self, session_id: str, text: str) -> None:
            """Drive one SMCP pipeline run and stream it to the client."""
            from smcp.core.pipeline import DelmPipeline
            from smcp.core.task_queue import Task

            try:
                llm, info = _make_llm()
            except ValueError as exc:
                await self._emit_thought(session_id, str(exc))
                await self._emit_message(session_id, f"error: {exc}")
                return

            await self._emit_thought(
                session_id,
                f"SMCP run: backend={info.get('backend')} "
                f"model={info.get('model')} workers={n_workers} "
                f"rounds={max_rounds}",
            )

            tasks = [
                Task(label=f"acp{idx}", body=body, kind="solve")
                for idx, body in enumerate(split_tasks(text))
            ]

            try:
                pipe = DelmPipeline(llm=llm, n_workers=n_workers)
                outcome = await pipe.run(tasks, max_rounds=max_rounds)
            except asyncio.CancelledError:
                await self._emit_message(session_id, "run cancelled")
                raise
            finally:
                close = getattr(llm, "close", None)
                if callable(close):
                    close()

            # Report what actually got *admitted* to the shared context first
            # — that is the protocol's whole point (verified state, not
            # attempted state) — then the final answer.
            if outcome.admitted_gists:
                await self._emit_thought(
                    session_id,
                    f"admitted {outcome.admitted_gists} gist(s) to the shared "
                    f"context over {outcome.rounds} round(s)",
                )
            await self._emit_message(session_id, outcome.answer or "(no answer)")

        # -- client callbacks -----------------------------------------
        async def _emit_message(self, session_id: str, text: str) -> None:
            from acp.schema import AgentMessageChunk, TextContentBlock

            await self.client.session_update(
                session_id=session_id,
                update=AgentMessageChunk(
                    session_update="agent_message_chunk",
                    content=TextContentBlock(type="text", text=text)),
            )

        async def _emit_thought(self, session_id: str, text: str) -> None:
            from acp.schema import AgentThoughtChunk, TextContentBlock

            await self.client.session_update(
                session_id=session_id,
                update=AgentThoughtChunk(
                    session_update="agent_thought_chunk",
                    content=TextContentBlock(type="text", text=text)),
            )

    return SmcpAgent()


# ------------------------------------------------------------------- serve
def serve(backend: str = "fake", n_workers: int = 4,
          max_rounds: int = 3) -> int:
    """Run the ACP agent on stdio until the client disconnects."""
    acp = _require_acp()
    log_setup()

    agent = build_agent(backend=backend, n_workers=n_workers,
                        max_rounds=max_rounds)
    logger.info("smcp-serve: backend=%s workers=%d rounds=%d",
                backend, n_workers, max_rounds)

    # The SDK owns the stdio JSON-RPC loop; stdout stays untouched by us.
    asyncio.run(acp.run_agent(agent))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="smcp-serve",
        description="Run SMCP as an ACP agent over stdio (the canonical "
                    "integration path; see DESIGNCOMPAT.md via A).",
    )
    ap.add_argument("--backend", choices=("fake", "real"), default="fake",
                    help="fake = deterministic FakeLLMClient (default, no "
                         "key/network); real = a live OpenAI-compatible "
                         "endpoint (DELM_MODEL / DELM_BASE_URL)")
    ap.add_argument("--workers", type=int, default=4,
                    help="parallel workers in the pipeline (default: 4)")
    ap.add_argument("--rounds", type=int, default=3,
                    help="max pipeline rounds (default: 3)")
    ap.add_argument("--check", action="store_true",
                    help="verify the ACP dependency is importable and exit")
    args = ap.parse_args(argv)

    if args.check:
        try:
            acp = _require_acp()
        except SystemExit as exc:
            print(str(exc), file=__import__("sys").stderr)
            return 1
        print(f"smcp-serve OK: agent-client-protocol present "
              f"(PROTOCOL_VERSION={acp.PROTOCOL_VERSION})")
        return 0

    return serve(backend=args.backend, n_workers=args.workers,
                 max_rounds=args.rounds)


if __name__ == "__main__":
    raise SystemExit(main())
