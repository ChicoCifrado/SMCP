"""SMCP interactive API — sessions, inspection, demos (in-process).

Mounts under /api/* from api_server.py. Localhost-only by design; the
frontend never receives api_key values.
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import time
import uuid
from pathlib import Path
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from delm.config import DEFAULT_CONFIG_PATH, build_client, load_config
from delm.core.gist import Gist, GistKind, RefTag, Summary
from delm.core.injection import detect_injection
from delm.core.injection_hardened import detect_injection_hardened
from delm.core.llm import FakeLLMClient, LLMClient
from delm.core.metrics import TaskMetrics
from delm.core.pipeline import DelmPipeline, PipelineOutcome, WorkerResult
from delm.core.task_queue import Task, TaskState
from delm.core.taint import TaintLevel
from delm.core.unfolding import Unfolding, Unfolded
from delm.core.verifier import RuleVerifier

router = APIRouter(prefix="/api")

MAX_TASKS = 32
MAX_HISTORY = 10
RUN_TIMEOUT_S = 600.0


# ------------------------------------------------------------------ helpers
def _mask_key(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return "***"
    return key[:4] + "…" + key[-2:]


def _gist_dict(g: Gist) -> dict[str, Any]:
    refs = [{"head": r.head, "tail": r.tail, "n_words": r.n_words}
            for r in (g.refs or [])]
    summary = None
    if g.summary is not None:
        claims = []
        for b in g.summary.claims:
            ref = b.get("ref")
            claims.append({
                "claim": b.get("claim", ""),
                "ref": ({"head": ref.head, "tail": ref.tail,
                         "n_words": ref.n_words} if ref else None),
            })
        summary = {"claims": claims, "raw_unit": g.summary.raw_unit}
    kind = g.kind.value if isinstance(g.kind, GistKind) else str(g.kind)
    sig = g.signature.hex() if isinstance(g.signature, (bytes, bytearray)) else str(g.signature or "")
    return {
        "label": g.label,
        "gist": g.gist,
        "kind": kind,
        "refs": refs,
        "summary": summary,
        "raw": g.raw,
        "meta": dict(g.meta or {}),
        "author_id": g.author_id,
        "digest": g.digest,
        "signature": sig,
        "sig_kind": g.sig_kind,
    }


def _worker_dict(w: WorkerResult) -> dict[str, Any]:
    return {
        "worker_id": w.worker_id,
        "solved": w.solved,
        "failed": w.failed,
        "admitted": w.admitted,
        "notes": list(w.notes),
    }


def _task_metrics_dict(m: TaskMetrics) -> dict[str, Any]:
    return dataclasses.asdict(m)


def _unfolded_dict(u: Unfolded) -> dict[str, Any]:
    return {
        "label": u.label,
        "gist": _gist_dict(u.gist) if u.gist else None,
        "summary_claims": (
            [{"claim": b.get("claim", "")} for b in u.summary.claims]
            if u.summary else None
        ),
        "raw": u.raw,
        "neighbors": list(u.neighbors or []),
    }


def _ref_from_dict(d: dict[str, Any] | None) -> RefTag | None:
    if not d:
        return None
    return RefTag(head=d.get("head", ""), tail=d.get("tail", ""),
                  n_words=int(d.get("n_words", 5)))


# ------------------------------------------------------------------ schemas
class TaskIn(BaseModel):
    label: str | None = Field(default=None, max_length=64)
    body: str = Field(min_length=1, max_length=4000)
    kind: str = Field(default="solve", max_length=32)
    deps: list[str] = Field(default_factory=list, max_length=8)


class RunCreate(BaseModel):
    tasks: list[TaskIn] = Field(min_length=1, max_length=MAX_TASKS)
    n_workers: int = Field(default=2, ge=1, le=16)
    max_rounds: int = Field(default=8, ge=1, le=16)
    backend: str = Field(default="fake", pattern="^(fake|real)$")


class UnfoldIn(BaseModel):
    label: str = Field(min_length=1, max_length=64)
    deep: bool = False
    run: str | None = Field(default=None, max_length=64)


class VerifyIn(BaseModel):
    kind: str = Field(pattern="^(source|trajectory)$")
    raw: str = Field(default="", max_length=20000)
    result: str = Field(default="", max_length=20000)
    gist: str = Field(default="", max_length=8000)
    claims: list[dict[str, Any]] = Field(default_factory=list, max_length=64)


class ProbeIn(BaseModel):
    check_completion: bool = False


class ScanIn(BaseModel):
    text: str = Field(min_length=1, max_length=50000)
    hardened: bool = True


class TaintIn(BaseModel):
    label: str = Field(min_length=1, max_length=64)
    action: str = Field(pattern="^(escalate|clear)$")
    level: int | None = Field(default=None, ge=1, le=2)
    reason: str = Field(default="", max_length=200)
    run: str | None = Field(default=None, max_length=64)


class ConfigUpdate(BaseModel):
    model: str | None = Field(default=None, max_length=200)
    base_url: str | None = Field(default=None, max_length=500)
    api_key: str | None = Field(default=None, max_length=500)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    timeout_s: float | None = Field(default=None, gt=0.0, le=3600.0)
    use_harness: bool | None = None
    clear_api_key: bool = False


# ------------------------------------------------------------------ sessions
class RunSession:
    def __init__(self, *, backend: str, n_workers: int, max_rounds: int,
                 tasks: list[Task]) -> None:
        self.id = "run_" + uuid.uuid4().hex[:12]
        self.backend = backend
        self.n_workers = n_workers
        self.max_rounds = max_rounds
        self.task_specs = [
            {"label": t.label, "body": t.body, "kind": t.kind, "deps": list(t.deps)}
            for t in tasks
        ]
        self.tasks = tasks
        self.status = "queued"
        self.error: str | None = None
        self.created_at = time.time()
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self.pipeline: DelmPipeline | None = None
        self.outcome: PipelineOutcome | None = None
        self.events: list[dict[str, Any]] = []
        self._task: asyncio.Task | None = None
        self._llm: LLMClient | None = None
        self.model_info: dict[str, Any] = {}
        self.rounds = 0

    def header(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "backend": self.backend,
            "n_workers": self.n_workers,
            "max_rounds": self.max_rounds,
            "tasks": self.task_specs,
            "task_count": len(self.task_specs),
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "wall_s": (
                round((self.finished_at or time.time()) - (self.started_at or self.created_at), 2)
                if self.started_at else None
            ),
            "rounds": self.rounds,
            "model": self.model_info,
        }


class RunManager:
    def __init__(self) -> None:
        self._active: RunSession | None = None
        self._history: list[RunSession] = []

    @property
    def active(self) -> RunSession | None:
        return self._active

    def get(self, run_id: str) -> RunSession:
        if self._active and self._active.id == run_id:
            return self._active
        for s in self._history:
            if s.id == run_id:
                return s
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")

    def resolve(self, run_id: str | None = None) -> RunSession:
        if run_id:
            return self.get(run_id)
        if self._active:
            return self._active
        if self._history:
            return self._history[-1]
        raise HTTPException(status_code=404, detail="no runs yet")

    def list_headers(self) -> list[dict[str, Any]]:
        items = list(self._history)
        if self._active:
            items = [self._active] + items
        return [s.header() for s in items[:MAX_HISTORY]]

    def begin(self, session: RunSession) -> None:
        if self._active and self._active.status in ("queued", "starting", "running"):
            raise HTTPException(
                status_code=409,
                detail=f"run already active: {self._active.id} ({self._active.status})",
            )
        self._active = session

    def _archive(self, session: RunSession) -> None:
        if self._active is session:
            self._active = None
        self._history = [s for s in self._history if s is not session]
        self._history.append(session)
        del self._history[:-MAX_HISTORY]

    async def cancel(self, run_id: str) -> dict[str, Any]:
        s = self.get(run_id)
        if s.status not in ("queued", "starting", "running"):
            return s.header()
        if s._task and not s._task.done():
            s._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(asyncio.shield(s._task), timeout=5)
        if s.status not in ("done", "error", "cancelled"):
            s.status = "cancelled"
            s.finished_at = time.time()
            s.error = s.error or "cancelled by client"
        self._archive(s)
        return s.header()

    def drop(self, run_id: str) -> None:
        s = self.get(run_id)
        if s.status in ("queued", "starting", "running"):
            raise HTTPException(status_code=409, detail="cannot delete an active run")
        if self._active is s:
            self._active = None
        self._history = [x for x in self._history if x is not s]


MANAGER = RunManager()


def _push(session: RunSession, type_: str, **payload: Any) -> None:
    session.events.append({"type": type_, "ts": time.time(), **payload})
    if len(session.events) > 200:
        del session.events[: len(session.events) - 200]


def _build_tasks(items: list[TaskIn]) -> list[Task]:
    out: list[Task] = []
    for i, t in enumerate(items, start=1):
        label = t.label or f"t-{i:03d}"
        out.append(Task(label=label, body=t.body, kind=t.kind, deps=list(t.deps)))
    return out


def _build_llm(backend: str) -> tuple[LLMClient, dict[str, Any]]:
    if backend == "fake":
        return FakeLLMClient(), {"backend": "fake", "model": "fake"}
    cfg = _load_cfg()
    if not cfg.model or not cfg.base_url:
        raise HTTPException(
            status_code=400,
            detail="backend=real requires DELM_MODEL and DELM_BASE_URL (or YAML config)",
        )
    llm = build_client(cfg)
    info = {
        "backend": "real",
        "model": cfg.model,
        "base_url": cfg.base_url,
        "timeout_s": cfg.timeout_s,
        "use_harness": cfg.use_harness,
    }
    return llm, info


async def _run_pipeline(session: RunSession) -> None:
    session.status = "starting"
    session.started_at = time.time()
    try:
        llm, info = _build_llm(session.backend)
        session._llm = llm
        session.model_info = info
        pipe = DelmPipeline(llm=llm, n_workers=session.n_workers)
        session.pipeline = pipe
        session.status = "running"
        _push(session, "started", backend=session.backend, **{k: v for k, v in info.items() if k not in ("base_url", "backend")})

        base_reason: Callable[[Task], Awaitable[str]] | None = None

        async def hooked_reason(task: Task) -> str:
            _push(session, "reason", label=task.label, kind=task.kind)
            # Default path: pipeline Worker._default_reason uses llm.complete
            # when reason is None; here we always hook so we emit events.
            prompt = (
                f"[ROLE:SOLVER]\n"
                f"task {task.label} ({task.kind}): {task.body}\n"
                f"shared context so far:\n{pipe.ctx.render()}\n"
                "Solve the task. Be concise; state the concrete finding or the "
                "minimal change and its evidence."
            )
            return await llm.complete(prompt)

        # Use default reason (no hook) for fake so transcripts stay intact?
        # FakeLLMClient routes on ROLE tags in the prompt, so default_reason
        # is fine; we still wrap for events.
        outcome = await asyncio.wait_for(
            pipe.run(
                session.tasks,
                max_rounds=session.max_rounds,
                reason=hooked_reason,
                yield_between=True,
            ),
            timeout=RUN_TIMEOUT_S,
        )
        session.outcome = outcome
        session.rounds = outcome.rounds
        session.status = "done"
        _push(session, "done", admitted=outcome.admitted_gists, rounds=outcome.rounds)
    except asyncio.CancelledError:
        session.status = "cancelled"
        session.error = session.error or "cancelled"
        _push(session, "cancelled")
        raise
    except HTTPException:
        session.status = "error"
        session.error = "build failed"
        _push(session, "error", error=session.error)
        raise
    except Exception as e:  # noqa: BLE001
        session.status = "error"
        session.error = f"{type(e).__name__}: {e}"
        _push(session, "error", error=session.error)
    finally:
        session.finished_at = time.time()
        close = getattr(session._llm, "close", None)
        if callable(close):
            with contextlib.suppress(Exception):
                close()
        MANAGER._archive(session)


def session_state(s: RunSession) -> dict[str, Any]:
    queue_labels: list[dict[str, Any]] = []
    ctx_labels: list[str] = []
    taint: dict[str, int] = {}
    metrics: dict[str, Any] = {}
    if s.pipeline is not None:
        q = s.pipeline.queue
        for lbl in q.all_labels():
            try:
                t = q.get(lbl)
            except KeyError:
                continue
            st = t.state.value if isinstance(t.state, TaskState) else str(t.state)
            queue_labels.append({"label": lbl, "state": st, "error": t.error})
        ctx = s.pipeline.ctx
        ctx_labels = list(ctx.labels())
        if hasattr(ctx, "taint_report"):
            with contextlib.suppress(Exception):
                taint = ctx.taint_report()
        metrics = s.pipeline.metrics.aggregate()
    gists = []
    if s.pipeline is not None:
        for lbl in ctx_labels:
            g = s.pipeline.ctx.get(lbl)
            if g:
                gd = _gist_dict(g)
                gists.append({
                    "label": gd["label"],
                    "kind": gd["kind"],
                    "gist": (gd["gist"] or "")[:200],
                    "author_id": gd["author_id"],
                    "digest": gd["digest"],
                    "taint": taint.get(lbl, 0),
                })
    workers = []
    if s.outcome:
        workers = [_worker_dict(w) for w in s.outcome.workers]
    return {
        "id": s.id,
        "status": s.status,
        "error": s.error,
        "rounds": s.rounds,
        "backend": s.backend,
        "model": s.model_info,
        "queue": queue_labels,
        "pending": sum(1 for x in queue_labels if x["state"] != "done"),
        "ctx_labels": ctx_labels,
        "gists": gists,
        "taint": taint,
        "metrics": metrics,
        "events": s.events[-50:],
        "workers": workers,
        "wall_s": (
            round((s.finished_at or time.time()) - (s.started_at or s.created_at), 2)
            if s.started_at else None
        ),
    }


def outcome_dict(s: RunSession) -> dict[str, Any]:
    if s.outcome is None:
        raise HTTPException(status_code=409, detail=f"run {s.id} has no outcome (status={s.status})")
    o = s.outcome
    return {
        "answer": o.answer,
        "admitted_gists": o.admitted_gists,
        "rounds": o.rounds,
        "workers": [_worker_dict(w) for w in o.workers],
        "queue_exhausted": o.queue_exhausted,
        "metrics": o.metrics,
        "header": s.header(),
    }


# ------------------------------------------------------------------ config
def _load_cfg():
    """Load config from the resolved YAML path (env still wins)."""
    path = _config_path()
    return load_config(path if path.exists() else None)


def _config_path() -> Path:
    # Resolve relative to CWD so api_server's ROOT layout is respected.
    p = Path(DEFAULT_CONFIG_PATH)
    if p.is_absolute():
        return p
    # Prefer the copy under the server package root when present.
    root_cfg = Path(__file__).resolve().parent / p
    if root_cfg.exists() or root_cfg.parent.exists():
        return root_cfg
    return p


def _write_yaml(data: dict[str, Any]) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Local model config (this file is git-ignored; never commit real keys).",
        "# Written by PUT /api/config. Override via DELM_* env vars.",
    ]
    for key in ("model", "base_url", "api_key", "temperature", "timeout_s", "use_harness"):
        if key not in data:
            continue
        val = data[key]
        if isinstance(val, bool):
            lines.append(f"{key}: {'true' if val else 'false'}")
        elif isinstance(val, (int, float)):
            lines.append(f"{key}: {val}")
        else:
            s = str(val).replace('"', '\\"')
            lines.append(f'{key}: "{s}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@router.get("/config")
def get_config() -> dict[str, Any]:
    cfg = _load_cfg()
    d = cfg.as_dict()
    key = d.pop("api_key", "")
    d["api_key_set"] = bool(key)
    d["api_key_masked"] = _mask_key(key)
    d["has_model"] = bool(d.get("model"))
    d["has_base_url"] = bool(d.get("base_url"))
    d["config_path"] = str(_config_path())
    return d


@router.put("/config")
def put_config(body: ConfigUpdate) -> dict[str, Any]:
    """Persist model settings to the local YAML (never echoes api_key)."""
    path = _config_path()
    current: dict[str, Any] = {}
    if path.exists():
        current = _read_yaml_flat(path)
    updates: dict[str, Any] = {}
    if body.model is not None:
        updates["model"] = body.model
    if body.base_url is not None:
        updates["base_url"] = body.base_url
    if body.temperature is not None:
        updates["temperature"] = body.temperature
    if body.timeout_s is not None:
        updates["timeout_s"] = body.timeout_s
    if body.use_harness is not None:
        updates["use_harness"] = body.use_harness
    if body.clear_api_key:
        updates["api_key"] = ""
    elif body.api_key is not None:
        updates["api_key"] = body.api_key
    if not updates:
        raise HTTPException(status_code=400, detail="no fields to update")
    merged = {**current, **updates}
    try:
        _write_yaml(merged)
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"cannot write config: {e}") from e
    cfg = _load_cfg()
    d = cfg.as_dict()
    key = d.pop("api_key", "")
    return {
        "ok": True,
        "path": str(path),
        "updated": sorted(updates.keys()),
        "model": d.get("model", ""),
        "base_url": d.get("base_url", ""),
        "temperature": d.get("temperature"),
        "timeout_s": d.get("timeout_s"),
        "use_harness": d.get("use_harness"),
        "api_key_set": bool(key),
        "api_key_masked": _mask_key(key),
        "has_model": bool(d.get("model")),
        "has_base_url": bool(d.get("base_url")),
    }


def _read_yaml_flat(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        pass
    out: dict[str, Any] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if val.lower() in ("true", "false"):
            out[key] = val.lower() == "true"
        else:
            try:
                out[key] = float(val) if "." in val else int(val)
            except ValueError:
                out[key] = val
    return out


async def _probe_endpoint(base_url: str, api_key: str,
                          check_completion: bool = False) -> dict[str, Any]:
    try:
        import httpx  # type: ignore
    except ModuleNotFoundError:
        import httpx2 as httpx  # type: ignore

    base = (base_url or "").rstrip("/")
    if not base:
        return {"reachable": False, "error": "no base_url configured"}
    t0 = time.perf_counter()
    headers = {}
    key = (api_key or "").strip()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    try:
        async with httpx.AsyncClient(timeout=8.0, headers=headers) as client:
            r = await client.get(f"{base}/models")
            latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            if r.status_code >= 400:
                return {"reachable": False, "error": f"HTTP {r.status_code}",
                        "latency_ms": latency_ms}
            data = r.json() or {}
            items = data.get("data") or []
            model_id = items[0].get("id") if items else None
            out: dict[str, Any] = {
                "reachable": True,
                "latency_ms": latency_ms,
                "model_id": model_id,
                "models": [m.get("id") for m in items[:12]],
            }
            if check_completion:
                t1 = time.perf_counter()
                payload = {
                    "model": model_id or "",
                    "messages": [{"role": "user", "content": "Reply with exactly OK"}],
                    "max_tokens": 16,
                    "temperature": 0,
                }
                cr = await client.post(f"{base}/chat/completions", json=payload)
                out["completion_ms"] = round((time.perf_counter() - t1) * 1000, 1)
                out["completion_status"] = cr.status_code
                if cr.status_code == 200:
                    body = cr.json()
                    choice = (body.get("choices") or [{}])[0]
                    msg = choice.get("message") or {}
                    out["completion_content"] = (msg.get("content") or "")[:120]
                    out["completion_ok"] = True
                else:
                    out["completion_ok"] = False
                    out["completion_error"] = cr.text[:200]
            return out
    except Exception as e:  # noqa: BLE001
        return {
            "reachable": False,
            "error": f"{type(e).__name__}: {e}",
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
        }


@router.post("/config/probe")
async def post_probe(body: ProbeIn | None = None) -> dict[str, Any]:
    cfg = _load_cfg()
    body = body or ProbeIn()
    result = await _probe_endpoint(cfg.base_url, cfg.api_key, body.check_completion)
    return {
        "base_url": cfg.base_url,
        "model": cfg.model,
        "api_key_set": bool(cfg.api_key),
        **result,
    }


@router.get("/health")
async def get_health() -> dict[str, Any]:
    cfg = _load_cfg()
    probe = await _probe_endpoint(cfg.base_url, cfg.api_key, False)
    return {
        "api": True,
        "model": {
            "base_url": cfg.base_url,
            "model": cfg.model,
            "configured": bool(cfg.model and cfg.base_url),
            "reachable": probe.get("reachable", False),
            "model_id": probe.get("model_id"),
            "error": probe.get("error"),
            "latency_ms": probe.get("latency_ms"),
        },
        "active_run": MANAGER.active.id if MANAGER.active else None,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }


# ------------------------------------------------------------------ runs
@router.post("/runs")
async def create_run(body: RunCreate) -> dict[str, Any]:
    if body.backend == "real":
        cfg = _load_cfg()
        if not cfg.model or not cfg.base_url:
            raise HTTPException(
                status_code=400,
                detail="backend=real requires DELM_MODEL and DELM_BASE_URL",
            )
        probe = await _probe_endpoint(cfg.base_url, cfg.api_key, False)
        if not probe.get("reachable"):
            raise HTTPException(
                status_code=400,
                detail=f"model endpoint not reachable: {probe.get('error')}",
            )
    tasks = _build_tasks(body.tasks)
    session = RunSession(
        backend=body.backend,
        n_workers=body.n_workers,
        max_rounds=body.max_rounds,
        tasks=tasks,
    )
    MANAGER.begin(session)
    session._task = asyncio.get_running_loop().create_task(_run_pipeline(session))
    return session.header()


@router.get("/runs")
def list_runs() -> dict[str, Any]:
    return {"runs": MANAGER.list_headers(),
            "active": MANAGER.active.id if MANAGER.active else None}


@router.get("/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    return MANAGER.get(run_id).header()


@router.get("/runs/{run_id}/state")
def get_run_state(run_id: str) -> dict[str, Any]:
    return session_state(MANAGER.get(run_id))


@router.get("/runs/{run_id}/outcome")
def get_run_outcome(run_id: str) -> dict[str, Any]:
    return outcome_dict(MANAGER.get(run_id))


@router.post("/runs/{run_id}/cancel")
async def cancel_run(run_id: str) -> dict[str, Any]:
    return await MANAGER.cancel(run_id)


@router.delete("/runs/{run_id}")
def delete_run(run_id: str) -> dict[str, Any]:
    MANAGER.drop(run_id)
    return {"ok": True, "id": run_id}


# ------------------------------------------------------------------ inspect
@router.get("/context")
def get_context(run: str | None = None) -> dict[str, Any]:
    s = MANAGER.resolve(run)
    if s.pipeline is None:
        raise HTTPException(status_code=409, detail=f"run {s.id} has no pipeline yet")
    ctx = s.pipeline.ctx
    taint: dict[str, int] = {}
    if hasattr(ctx, "taint_report"):
        with contextlib.suppress(Exception):
            taint = ctx.taint_report()
    gists = [_gist_dict(g) for g in ctx.snapshot()]
    # strip huge raw from list view
    for g in gists:
        if g.get("raw") and len(g["raw"]) > 4000:
            g["raw"] = g["raw"][:4000] + "…"
    return {
        "run": s.header(),
        "labels": list(ctx.labels()),
        "gists": gists,
        "taint": taint,
        "render": ctx.render(),
        "size": len(ctx),
    }


@router.get("/context/{label:path}")
def get_context_label(label: str, run: str | None = None) -> dict[str, Any]:
    s = MANAGER.resolve(run)
    if s.pipeline is None:
        raise HTTPException(status_code=409, detail="no pipeline")
    g = s.pipeline.ctx.get(label)
    if g is None:
        raise HTTPException(status_code=404, detail=f"gist not found: {label}")
    return {"run": s.id, "gist": _gist_dict(g)}


@router.get("/ledger")
def get_ledger(run: str | None = None) -> dict[str, Any]:
    s = MANAGER.resolve(run)
    if s.pipeline is None:
        raise HTTPException(status_code=409, detail="no pipeline")
    ledger = getattr(s.pipeline.ctx, "ledger", None)
    if ledger is None:
        raise HTTPException(status_code=409, detail="context has no ledger")
    entries = [e.to_dict() for e in ledger.entries()]
    return {
        "run": s.header(),
        "count": len(entries),
        "chain_ok": ledger.verify_chain(),
        "entries": entries,
    }


@router.get("/metrics")
def get_metrics(run: str | None = None) -> dict[str, Any]:
    s = MANAGER.resolve(run)
    if s.pipeline is None:
        raise HTTPException(status_code=409, detail="no pipeline")
    agg = s.pipeline.metrics.aggregate()
    recs = [_task_metrics_dict(r) for r in s.pipeline.metrics.records()]
    return {"run": s.header(), "aggregate": agg, "records": recs}


@router.post("/unfold")
def post_unfold(body: UnfoldIn) -> dict[str, Any]:
    s = MANAGER.resolve(body.run)
    if s.pipeline is None:
        raise HTTPException(status_code=409, detail="no pipeline")
    unf = Unfolding(s.pipeline.ctx)
    u = unf.deep_unfold(body.label) if body.deep else unf.unfold(body.label)
    if u.gist is None and body.label not in s.pipeline.ctx.labels():
        raise HTTPException(status_code=404, detail=f"label not found: {body.label}")
    return {"run": s.id, "unfolded": _unfolded_dict(u)}


@router.post("/verifier/check")
async def post_verifier(body: VerifyIn) -> dict[str, Any]:
    vr = RuleVerifier()
    if body.kind == "source":
        from delm.core.gist import Summary
        claims = []
        for c in body.claims:
            claims.append({"claim": c.get("claim", ""), "ref": _ref_from_dict(c.get("ref"))})
        payload = {"raw": body.raw, "summary": Summary(claims=claims, raw_unit=body.raw)}
    else:
        payload = {"result": body.result, "gist": body.gist}
    result = await vr.verify(body.kind, payload)
    return result.to_dict()


# ------------------------------------------------------------------ demos
@router.post("/demo/{name}")
async def post_demo(name: str) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        if name == "pipeline":
            from delm.demo.run_demo import run as demo_run
            data = await demo_run(verbose=False)
            return {"ok": True, "secs": round(time.perf_counter() - t0, 2),
                    "demo": name, "data": data}
        if name == "security":
            from delm.demo.run_security_demo import run as sec_run
            code = await sec_run(verbose=True)
            return {"ok": code == 0, "secs": round(time.perf_counter() - t0, 2),
                    "demo": name, "exit": code,
                    "data": {"ok": code == 0}}
        if name == "rsi":
            from delm.demo.run_rsi_demo import run as rsi_run
            data = await rsi_run(verbose=False)
            return {"ok": True, "secs": round(time.perf_counter() - t0, 2),
                    "demo": name, "data": data}
        if name == "real":
            from delm.demo.run_real_demo import run as real_run
            cfg = _load_cfg()
            if not cfg.model or not cfg.base_url:
                raise HTTPException(status_code=400,
                                    detail="real demo needs DELM_MODEL + DELM_BASE_URL")
            probe = await _probe_endpoint(cfg.base_url, cfg.api_key, False)
            if not probe.get("reachable"):
                raise HTTPException(
                    status_code=400,
                    detail=f"endpoint not reachable: {probe.get('error')}",
                )
            data = await real_run(cfg, tasks=2, workers=2, verbose=False)
            return {"ok": True, "secs": round(time.perf_counter() - t0, 2),
                    "demo": name, "data": data}
        if name == "taint":
            import io
            from contextlib import redirect_stdout
            from delm.demo.run_taint_demo import main as taint_main
            buf = io.StringIO()
            with redirect_stdout(buf):
                taint_main()
            return {"ok": True, "secs": round(time.perf_counter() - t0, 2),
                    "demo": name,
                    "data": {"ok": True, "stdout": buf.getvalue()}}
        if name == "multihost":
            # Keep subprocess (opens sockets); reuse /api/run via client-side.
            raise HTTPException(
                status_code=400,
                detail="multihost uses POST /api/run/multihost (subprocess)",
            )
        raise HTTPException(status_code=404, detail=f"unknown demo: {name}")
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}") from e


# ------------------------------------------------------------------ actions
def _require_pipeline(run: str | None) -> RunSession:
    s = MANAGER.resolve(run)
    if s.pipeline is None:
        raise HTTPException(status_code=409, detail=f"run {s.id} has no pipeline yet")
    return s


@router.post("/scan")
def post_scan(body: ScanIn) -> dict[str, Any]:
    """Deterministic prompt-injection scan (baseline + hardened A/B)."""
    baseline = detect_injection(body.text)
    out: dict[str, Any] = {
        "ok": True,
        "baseline": {
            "clean": baseline.clean,
            "matched": list(baseline.matched),
            "snippets": list(baseline.snippets),
            "reasons": baseline.reasons,
        },
    }
    if body.hardened:
        h = detect_injection_hardened(body.text)
        out["hardened"] = {
            "clean": h.clean,
            "matched": list(h.matched),
            "snippets": list(h.snippets),
            "reasons": h.reasons,
            "evasion_detected": h.evasion_detected,
            "baseline_clean": h.baseline_clean,
            "region_hits": list(h.region_hits),
            "normalized_text": h.normalized_text[:4000],
        }
        out["clean"] = h.clean
    else:
        out["clean"] = baseline.clean
    return out


@router.get("/taint")
def get_taint(run: str | None = None) -> dict[str, Any]:
    s = _require_pipeline(run)
    ctx = s.pipeline.ctx
    if not hasattr(ctx, "taint"):
        raise HTTPException(status_code=409, detail="context has no taint registry")
    reg = ctx.taint
    report = ctx.taint_report() if hasattr(ctx, "taint_report") else {}
    sources = [
        {
            "label": src.label,
            "level": int(src.level),
            "level_name": TaintLevel(src.level).name,
            "reason": src.reason,
            "derived_from": src.derived_from,
        }
        for src in reg.sources()
    ]
    return {
        "run": s.header(),
        "report": report,
        "sources": sources,
        "quarantined": sorted(reg.quarantined()),
        "blocked": sorted(reg.blocked()),
        "labels": list(ctx.labels()),
    }


@router.post("/taint")
def post_taint(body: TaintIn) -> dict[str, Any]:
    """Operator action: escalate or clear taint on a label in the run."""
    s = _require_pipeline(body.run)
    ctx = s.pipeline.ctx
    if not hasattr(ctx, "taint"):
        raise HTTPException(status_code=409, detail="context has no taint registry")
    reg = ctx.taint
    label = body.label
    if body.action == "clear":
        reg.clear(label)
        action_note = "cleared"
    else:
        level = body.level if body.level is not None else int(TaintLevel.SUSPICIOUS)
        try:
            lvl = TaintLevel(level)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=f"bad taint level: {level}") from e
        if lvl < TaintLevel.SUSPICIOUS:
            raise HTTPException(status_code=422, detail="escalate requires level 1 or 2")
        reg.escalate(label, lvl, reason=body.reason or "manual:operator")
        action_note = f"escalated to {lvl.name}"
    report = ctx.taint_report() if hasattr(ctx, "taint_report") else {}
    _push(s, "taint", label=label, action=body.action, note=action_note)
    return {
        "ok": True,
        "run": s.id,
        "label": label,
        "action": body.action,
        "note": action_note,
        "level": report.get(label, 0),
        "report": report,
    }


@router.get("/ledger/export")
def export_ledger(run: str | None = None) -> dict[str, Any]:
    """Idempotent audit dump of the run's AdmissionLedger."""
    s = MANAGER.resolve(run)
    if s.pipeline is None:
        raise HTTPException(status_code=409, detail="no pipeline")
    ledger = getattr(s.pipeline.ctx, "ledger", None)
    if ledger is None:
        raise HTTPException(status_code=409, detail="context has no ledger")
    chain = []
    for e in ledger.entries():
        d = e.to_dict()
        d["entry_hash"] = getattr(e, "entry_hash", "")
        chain.append(d)
    return {
        "format": 1,
        "run": s.header(),
        "count": len(chain),
        "chain_ok": ledger.verify_chain(),
        "chain": chain,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }


@router.get("/runs/{run_id}/events")
async def stream_run_events(run_id: str, after: int = 0) -> StreamingResponse:
    """SSE: live event feed for a run (replays from ``after``)."""
    session = MANAGER.get(run_id)
    cursor = max(0, after)

    async def gen():
        nonlocal cursor
        # Replay backlog first.
        while cursor < len(session.events):
            ev = session.events[cursor]
            cursor += 1
            yield f"data: {json.dumps(ev, default=str)}\n\n"
        # Follow until terminal status and no more events.
        while True:
            if cursor < len(session.events):
                ev = session.events[cursor]
                cursor += 1
                yield f"data: {json.dumps(ev, default=str)}\n\n"
                continue
            if session.status in ("done", "error", "cancelled"):
                final = {"type": "end", "ts": time.time(),
                         "status": session.status, "cursor": cursor}
                yield f"data: {json.dumps(final)}\n\n"
                break
            await asyncio.sleep(0.12)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/meshllm")
async def get_meshllm() -> dict[str, Any]:
    """Probe the local MeshLLM OpenAI-compatible endpoint (:9337)."""
    result = await _probe_endpoint("http://127.0.0.1:9337/v1", "", False)
    return {"endpoint": "http://127.0.0.1:9337/v1", **result}
