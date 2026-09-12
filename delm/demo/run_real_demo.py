"""Real-model demo — run the pipeline against a concrete endpoint.

The no-API-key :mod:`run_demo` proves the pipeline is wired; this one proves
it runs against a *real* model. It loads a :class:`~delm.config.ModelConfig`
(file + environment), builds an :class:`OpenAICompatibleClient`, and drives a
small :class:`DelmPipeline` over a handful of tasks, printing the final answer
and the cost/latency aggregate.

Configuration comes from :mod:`delm.config`, so the API key is *never* in
source: it is read from the environment (``DELM_API_KEY``) or a local,
git-ignored ``config/model_config.yaml``.

Run:

    # point at a local server (no key needed)
    DELM_BASE_URL=http://127.0.0.1:8888/v1 DELM_MODEL=unsloth/Qwen3.8-27B \
        python -m delm.demo.run_real_demo --tasks 2

    # or a hosted provider
    DELM_BASE_URL=https://openrouter.ai/api/v1 DELM_MODEL=google/gemini-3-flash \
        DELM_API_KEY=sk-... python -m delm.demo.run_real_demo --tasks 4

    # dry-run: show the resolved config, call nothing
    python -m delm.demo.run_real_demo --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time

from delm.config import ModelConfig, build_client, load_config
from delm.core.pipeline import DelmPipeline
from delm.core.task_queue import Task


# ---------------------------------------------------------------------- tasks
def _toy_tasks(n: int) -> list[Task]:
    """A few self-contained tasks the pipeline can solve.

    They are deliberately tiny so a *thinking* model (which emits a long
    reasoning pass before the answer) still finishes in reasonable time.
    """
    base = (
        "SWE-style micro-task: state the single minimal change that fixes the "
        "described defect, in one sentence, with the evidence that it works."
    )
    bodies = [
        "A function opens a file but never closes it on the error path; the "
        "defect leaks the handle. State the minimal fix.",
        "A retry loop sleeps a constant delay, so a burst of failures "
        "throttles the caller; the defect is missing backoff. State the "
        "minimal fix.",
        "A cache stores values by key but never evicts them, so memory grows "
        "unbounded; the defect is no eviction. State the minimal fix.",
        "A parser treats a missing optional field as an error; the defect is "
        "it should default instead. State the minimal fix.",
        "A connection pool reuses a closed socket; the defect is it does not "
        "check liveness before handing one out. State the minimal fix.",
    ]
    return [
        Task(label=f"rt{i}", body=base + " " + bodies[i % len(bodies)],
             kind="solve")
        for i in range(n)
    ]


# ---------------------------------------------------------------------- run
async def run(config: ModelConfig, tasks: int = 2, workers: int = 2,
              verbose: bool = True) -> dict:
    client = build_client(config)
    t0 = time.perf_counter()
    try:
        pipe = DelmPipeline(llm=client, n_workers=workers)
        outcome = await pipe.run(_toy_tasks(tasks))
    finally:
        # The harness backend owns a subprocess; release it (plain HTTP client
        # close() is a no-op, so calling it unconditionally is safe).
        close = getattr(client, "close", None)
        if callable(close):
            close()
    wall = time.perf_counter() - t0

    out = {
        "model": config.model,
        "base_url": config.base_url,
        "tasks": tasks,
        "workers": workers,
        "wall_s": round(wall, 2),
        "final_answer": outcome.answer,
        "admitted_gists": outcome.admitted_gists,
        "rounds": outcome.rounds,
        "metrics": outcome.metrics,
    }

    if verbose:
        print("=== DELM real-model demo ===")
        print(f"model       : {config.model}")
        print(f"base_url    : {config.base_url}")
        print(f"tasks/workers: {tasks}/{workers}")
        print(f"wall        : {out['wall_s']}s")
        print(f"admitted    : {out['admitted_gists']} gist(s)")
        agg = outcome.metrics
        if agg:
            print(f"cost usd    : {agg.get('total_cost_usd', 0)}")
            print(f"tokens      : in={agg.get('total_tokens_in', 0)} "
                  f"out={agg.get('total_tokens_out', 0)}")
        print("--- final answer ---")
        print(outcome.answer)
        print("=== real-model demo OK ===")
    return out


def _mask_key(key: str) -> str:
    if not key:
        return "(unset)"
    if len(key) <= 8:
        return "***"
    return key[:4] + "***" + key[-4:]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the DELM pipeline against "
                                             "a real model endpoint.")
    ap.add_argument("--config", default=None,
                    help="path to a YAML model config (default: "
                         "config/model_config.yaml if present)")
    ap.add_argument("--tasks", type=int, default=2,
                    help="number of micro-tasks to solve (default: 2)")
    ap.add_argument("--workers", type=int, default=2,
                    help="number of parallel workers (default: 2)")
    ap.add_argument("--harness", action="store_true",
                    help="use the DeepSeek Harness agent runtime backend "
                         "(overrides the DELM_HARNESS env flag for this run)")
    ap.add_argument("--dry-run", action="store_true",
                    help="resolve the config and print it; call no model")
    args = ap.parse_args(argv)

    cfg_path = args.config
    if cfg_path is None:
        # Default to the committed example if it exists, else env-only.
        from pathlib import Path
        default = Path("config/model_config.yaml")
        cfg_path = default if default.exists() else None

    config = load_config(cfg_path)
    if args.harness:
        from dataclasses import replace
        config = replace(config, use_harness=True)

    if args.dry_run:
        print("=== dry-run (no model called) ===")
        print(f"model     : {config.model or '(unset)'}")
        print(f"base_url  : {config.base_url or '(unset)'}")
        print(f"api_key   : {_mask_key(config.api_key)}")
        print(f"temperature: {config.temperature}")
        print(f"backend   : {'harness' if config.use_harness else 'openai-compatible'}")
        if not config.model or not config.base_url:
            print("note      : model/base_url unset — set DELM_MODEL / "
                  "DELM_BASE_URL or pass --config")
            return 2
        print("=== dry-run OK ===")
        return 0

    if not config.model or not config.base_url:
        print("error: no model/base_url configured. Set DELM_MODEL / "
              "DELM_BASE_URL (and DELM_API_KEY if needed) or pass --config.",
              file=sys.stderr)
        return 2

    try:
        asyncio.run(run(config, tasks=args.tasks, workers=args.workers))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
