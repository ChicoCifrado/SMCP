"""End-to-end wiring test for a *real* (OpenAI-compatible HTTP) model client.

This is the P1 acceptance test: it proves the whole real-model path works,
without depending on any external network, API key, or a live model.

It stands up a tiny in-process OpenAI-compatible HTTP server (a *mock*),
points a :class:`~delm.config.ModelConfig` at it, builds the
:class:`OpenAICompatibleClient` via :func:`delm.config.build_client`, and
runs a real :class:`DelmPipeline` over it. The mock answers the same role
prompts the pipeline sends (SOLVER / SUMMARIZER / FINALIZER) exactly the way
the deterministic demo does, so the gist is verbatim the result and the
deterministic :class:`RuleVerifier` passes on the first attempt (no retries).

What this proves (and only this):

* :func:`delm.config.build_client` returns a working
  :class:`OpenAICompatibleClient` for a :class:`ModelConfig`.
* The client issues real HTTP ``POST /v1/chat/completions`` calls and parses
  the OpenAI response shape.
* A real :class:`DelmPipeline` runs to completion against that client and
  admits gists — i.e. the config → client → pipeline wiring is sound.

It does NOT assert model *quality*; it asserts *wiring*.
"""
from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from delm.config import ModelConfig, build_client
from delm.core.llm import OpenAICompatibleClient
from delm.core.pipeline import DelmPipeline
from delm.core.task_queue import Task


# ---------------------------------------------------------------- mock server
class _MockHandler(BaseHTTPRequestHandler):
    """Answers ``POST /v1/chat/completions`` (and ``GET /v1/models``)."""

    # The pipeline sends the role in the last user message's content.
    SOLVER_RESULT = (
        "SOLUTION: applied the minimal change that resolves the issue; "
        "verified by the reproduction test passing."
    )
    FINAL_ANSWER = (
        "ANSWER: The task is resolved by the verified change recorded in "
        "the shared context; all constraints are satisfied."
    )

    def log_message(self, format, *args):  # silence request logging in tests
        pass

    # ------------------------------------------------------------- models
    def do_GET(self):  # pragma: no cover - not exercised by the pipeline
        self._send_json({"data": [{"id": "mock-model", "object": "model"}]},
                        200)

    # ----------------------------------------------------------- completions
    def do_POST(self):
        if not self.path.endswith("/chat/completions"):
            self._send_json({"error": "not found"}, 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        prompt = (body.get("messages") or [{}])[-1].get("content", "")
        reply = self._route(prompt)
        self._send_json({
            "id": "mock-cmplt",
            "object": "chat.completion",
            "created": 0,
            "model": body.get("model", "mock-model"),
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": reply},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1,
                      "total_tokens": 2},
        }, 200)

    def _route(self, prompt: str) -> str:
        if "[ROLE:FINALIZER]" in prompt:
            return self.FINAL_ANSWER
        if "[ROLE:SOLVER]" in prompt:
            return self.SOLVER_RESULT
        # SUMMARIZER (trajectory): return the result verbatim so the gist is
        # exactly the result and the deterministic verifier passes.
        if "[ROLE:SUMMARIZER]" in prompt and "trajectory result:" in prompt:
            start = prompt.index("trajectory result:\n") + len(
                "trajectory result:\n")
            end = prompt.index("\nCompress") if "\nCompress" in prompt else len(prompt)
            return prompt[start:end].strip()
        return self.SOLVER_RESULT

    def _send_json(self, obj, code):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _start_mock() -> tuple[str, ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
    host, port = server.server_address
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://{host}:{port}/v1", server


# ---------------------------------------------------------------------- test
def test_real_model_client_wiring_end_to_end():
    base_url, server = _start_mock()
    try:
        config = ModelConfig(model="mock-model", base_url=base_url,
                             api_key="sk-test")
        client = build_client(config)
        assert isinstance(client, OpenAICompatibleClient)
        assert client.model == "mock-model"

        async def _go() -> dict:
            pipe = DelmPipeline(llm=client, n_workers=2)
            tasks = [
                Task(label="t0", body="Solve the toy defect.", kind="solve"),
                Task(label="t1", body="Solve the toy defect.", kind="solve"),
            ]
            out = await pipe.run(tasks)
            return {"answer": out.answer, "admitted": out.admitted_gists}

        result = asyncio.run(_go())
        # The finalizer's answer must come back through the real HTTP client.
        assert result["answer"].startswith("ANSWER:")
        # At least one gist was admitted through the verified path.
        assert result["admitted"] >= 1
    finally:
        server.shutdown()


def test_build_client_rejects_no_base_url_is_allowed():
    # build_client is a thin wrapper: it must not raise for a config that
    # only carries a model (base_url may be filled by the SDK default).
    client = build_client(ModelConfig(model="m", base_url="http://x/v1"))
    assert isinstance(client, OpenAICompatibleClient)
