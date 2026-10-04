"""SMCP interactive API — sessions, inspection, demos (in-process).

Mounted under ``/api/*`` by :mod:`smcp.web.app`. Localhost-only by design; the
frontend never receives ``api_key`` values.
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

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from smcp.config import DEFAULT_CONFIG_PATH, build_client, load_config
from smcp.web import REPO_ROOT
from smcp.core.benchmark import scale_sweep, summarize
from smcp.core.contract import InferenceBounty, build_claim_tx
from smcp.core.contrib import (
    default_identity_path,
    default_state_path,
)
from smcp.core.gist import Gist, GistKind, RefTag, Summary
from smcp.core.injection import detect_injection
from smcp.core.injection_hardened import detect_injection_hardened
from smcp.core.llm import FakeLLMClient, LLMClient
from smcp.core.metrics import TaskMetrics
from smcp.core.placement import DEFAULT_MESH_ENDPOINT
from smcp.core.registro import (
    DEFAULT_REGISTRY_PATH,
    InferenceRegistry,
)
from smcp.core.pipeline import DelmPipeline, PipelineOutcome, WorkerResult
from smcp.core.run_store import RunStore, StoredRun
from smcp.core.task_queue import Task, TaskState
from smcp.core.taint import TaintLevel
from smcp.core.unfolding import Unfolding, Unfolded
from smcp.core.verifier import RuleVerifier

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
        # Header exacto archivado (runs recuperados de disco):
        # si existe, header() lo sirve tal cual.
        self._stored: dict[str, Any] | None = None

    def header(self) -> dict[str, Any]:
        if self._stored is not None:
            return self._stored
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
        self._persist(session)

    def _persist(self, session: RunSession) -> None:
        """Archiva el run en disco (append-only por id).

        El pipeline lleva el contexto vivo; aqui se guardan
        los gists que ese run aporto, para reconstruir el
        contexto o auditarlo despues de un reinicio.
        """
        gists = []
        pipe = session.pipeline
        if pipe is not None:
            for g in pipe.ctx.snapshot():
                gists.append({
                    "label": g.label,
                    "gist": g.gist,
                    "kind": getattr(g.kind, "value", str(g.kind)),
                    "author_id": getattr(g, "author_id", None),
                    "digest": getattr(g, "digest", None),
                    "taint": getattr(g, "taint", None),
                })
        try:
            RUN_STORE.save(StoredRun(
                id=session.id,
                header=session.header(),
                outcome=(dataclasses.asdict(session.outcome)
                         if session.outcome else None),
                events=list(session.events),
                gists=gists,
                created_at=session.created_at,
                updated_at=time.time(),
            ))
        except Exception:  # noqa: BLE001 — nunca fallar el run por persistir
            pass

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


# Persistencia en disco: el historial sobrevive a un reinicio.
RUN_STORE = RunStore()
MANAGER = RunManager()
# Recuperar el historial archivado (sin estado vivo, solo header+gists).
for _stored in RUN_STORE.history(MAX_HISTORY):
    _sess = RunSession(
        backend=_stored.header.get("backend", "fake"),
        n_workers=_stored.header.get("n_workers", 1),
        max_rounds=_stored.header.get("max_rounds", 1),
        tasks=[],
    )
    _sess.id = _stored.id
    _sess._stored = _stored.header
    _sess.status = _stored.header.get("status", "done")
    _sess.error = _stored.header.get("error")
    _sess.created_at = _stored.created_at
    _sess.started_at = _stored.header.get("started_at")
    _sess.finished_at = _stored.header.get("finished_at")
    _sess.rounds = _stored.header.get("rounds", 0)
    _sess.model_info = _stored.header.get("model", {})
    _sess.events = _stored.events
    _sess.outcome = None
    MANAGER._history.append(_sess)


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
        taint = _taint_report(ctx)
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


def _taint_report(ctx: Any) -> dict[str, int]:
    """El reporte de taint de ``ctx``, o ``{}`` si el contexto no lo tiene.

    ``taint`` / ``taint_report`` existen en :class:`SecureSharedContext` (con
    su registro de taint) pero no en el :class:`SharedContext` base: el
    endpoint tiene que servir ambos. Se resuelve con ``getattr`` — y no con
    ``hasattr`` seguido de acceso — porque el type-checker no estrecha el
    tipo con ``hasattr``, y el patron ya es la convencion del archivo (ver el
    ``getattr(s.pipeline.ctx, "ledger", None)`` de /api/ledger).
    """
    fn = getattr(ctx, "taint_report", None)
    if fn is None:
        return {}
    try:
        return fn()
    except Exception:  # noqa: BLE001 - un reporte que falla no tumba la vista
        return {}


# ------------------------------------------------------------------ config
def _load_cfg():
    """Load config from the resolved YAML path (env still wins)."""
    path = _config_path()
    return load_config(path if path.exists() else None)


def _config_path() -> Path:
    # `config/model_config.yaml` es relativo al CWD por defecto. Con un
    # checkout se prefiere la copia junto a la raiz del repo; en una
    # instalacion sin checkout se usa la del CWD (o la que ya exista), que es
    # donde un usuario de un `pip install` espera tenerla.
    p = Path(DEFAULT_CONFIG_PATH)
    if p.is_absolute():
        return p
    if REPO_ROOT is not None:
        root_cfg = REPO_ROOT / p
        if root_cfg.exists() or root_cfg.parent.exists():
            return root_cfg
    return p


def _write_yaml(data: dict[str, Any], notes: list[str] | None = None) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Local model config (this file is git-ignored; never commit real keys).",
        "# Written by PUT /api/config. Override via DELM_* env vars.",
    ]
    for note in notes or []:
        lines.append(f"# {note}")
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


def _persist_config(updates: dict[str, Any],
                    notes: list[str] | None = None) -> dict[str, Any]:
    """Merge *updates* into the local YAML and return the resulting view.

    Single writer for the model config: both ``PUT /api/config`` and
    ``POST /api/fit/apply`` go through here, so there is exactly one place that
    knows the file layout and one place that masks the key on the way out.
    """
    path = _config_path()
    current: dict[str, Any] = {}
    if path.exists():
        current = _read_yaml_flat(path)
    merged = {**current, **updates}
    try:
        _write_yaml(merged, notes)
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


@router.put("/config")
def put_config(body: ConfigUpdate) -> dict[str, Any]:
    """Persist model settings to the local YAML (never echoes api_key)."""
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
    return _persist_config(updates)



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
    taint: dict[str, int] = _taint_report(ctx)
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


@router.post("/benchmark")
async def run_benchmark(
    workers: str = "1,2,4",
    tasks_per_worker: int = 1,
    body: str = "State one concrete fact.",
) -> dict[str, Any]:
    """Benchmark de la malla: throughput vs nodos y latencia.

    Barre niveles de workers (nodos) y mide, para cada uno,
    throughput (tareas/s), latencia p50/p95 y tokens/s. La
    carga por nodo es constante (tasks_per_worker * W), asi
    el throughput es comparable entre niveles de paralelismo.
    Requiere backend=real configurado.
    """
    counts = [int(w) for w in workers.split(",") if w.strip().isdigit()]
    if not counts:
        raise HTTPException(status_code=400, detail="workers invalido")
    llm, _info = _build_llm("real")
    try:
        points = await scale_sweep(
            llm, worker_counts=counts,
            tasks_per_worker=tasks_per_worker, body=body,
        )
        return summarize(points)
    finally:
        close = getattr(llm, "close", None)
        if callable(close):
            with contextlib.suppress(Exception):
                res = close()
                if asyncio.iscoroutine(res):
                    await res


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
        from smcp.core.gist import Summary
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
            from smcp.demo.run_demo import run as demo_run
            data = await demo_run(verbose=False)
            return {"ok": True, "secs": round(time.perf_counter() - t0, 2),
                    "demo": name, "data": data}
        if name == "security":
            from smcp.demo.run_security_demo import run as sec_run
            code = await sec_run(verbose=True)
            return {"ok": code == 0, "secs": round(time.perf_counter() - t0, 2),
                    "demo": name, "exit": code,
                    "data": {"ok": code == 0}}
        if name == "rsi":
            from smcp.demo.run_rsi_demo import run as rsi_run
            data = await rsi_run(verbose=False)
            return {"ok": True, "secs": round(time.perf_counter() - t0, 2),
                    "demo": name, "data": data}
        if name == "real":
            from smcp.demo.run_real_demo import run as real_run
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
            from smcp.demo.run_taint_demo import main as taint_main
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


def _ctx_of(s: RunSession) -> Any:
    """El contexto de una sesión que ya pasó por :func:`_require_pipeline`.

    Existe para el type-checker: ``s.pipeline`` es opcional en el dataclass y
    pyright no sabe que :func:`_require_pipeline` ya asegura que no lo es. El
    ``assert`` no cambia el comportamiento en runtime (la condición es
    invariante tras el helper, y si algún día dejara de serlo, prefiero un
    AssertionError explícito que un ``AttributeError`` en un endpoint).
    """
    assert s.pipeline is not None, "_require_pipeline garantiza pipeline"
    return s.pipeline.ctx


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
    ctx = _ctx_of(s)
    # `taint` existe solo en SecureSharedContext, no en el SharedContext base:
    # por eso la interogacion. Se hace con getattr (y no hasattr + acceso) para
    # que el type-checker tambien lo vea.
    reg = getattr(ctx, "taint", None)
    if reg is None:
        raise HTTPException(status_code=409, detail="context has no taint registry")
    report = _taint_report(ctx)
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
    ctx = _ctx_of(s)
    # `taint` existe solo en SecureSharedContext, no en el SharedContext base:
    # por eso la interogacion. Se hace con getattr (y no hasattr + acceso) para
    # que el type-checker tambien lo vea.
    reg = getattr(ctx, "taint", None)
    if reg is None:
        raise HTTPException(status_code=409, detail="context has no taint registry")
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
    report = _taint_report(ctx)
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


# ------------------------------------------------------------------- llmfit
# Web surface of `delm fit` (delm/core/llmfit.py). Same three views as the
# CLI — table, verdict, persist — so the browser and the shell answer the same
# question with the same rules.
_FIT_LEVELS = ("perfect", "good", "marginal", "too_tight")
_FIT_RUNTIMES = ("mlx", "llamacpp", "vllm", "bitnetcpp")
_FIT_SORTS = ("score", "tps", "params", "mem", "ctx", "name")
_FIT_USE_CASES = ("general", "coding", "reasoning", "chat", "multimodal",
                  "embedding")


def _verdict_dict(v) -> dict[str, Any]:
    """Serializable view of a :class:`~smcp.core.llmfit.ModelFitVerdict`."""
    return {
        "model": v.model,
        "matched": v.matched,
        "runnable": v.runnable,
        "fit_level": v.fit_level,
        "fit_label": v.fit_label,
        "best_quant": v.best_quant,
        "memory_required_gb": v.memory_required_gb,
        "estimated_tps": v.estimated_tps,
        "runtime": v.runtime,
        "row_name": v.row_name,
        "exit_code": v.exit_code(),
        "suggestions": list(v.suggestions),
    }


@router.get("/fit")
def get_fit(
    limit: int = Query(default=10, ge=1, le=50),
    use_case: str | None = Query(default=None),
    min_fit: str | None = Query(default=None),
    runtime: str | None = Query(default=None),
    search: str = Query(default="", max_length=120),
    sort: str | None = Query(default=None),
    include_too_tight: bool = Query(default=False),
    memory: str | None = Query(default=None, max_length=16),
    ram: str | None = Query(default=None, max_length=16),
    cpu_cores: int | None = Query(default=None, ge=1, le=1024),
    max_context: int | None = Query(default=None, ge=256, le=1048576),
    llmfit_bin: str | None = Query(default=None, max_length=400),
    timeout_s: float = Query(default=120.0, gt=0.0, le=600.0),
) -> dict[str, Any]:
    """What fits *this* host (llmfit) + the verdict on the configured model.

    A missing or broken llmfit is **not** an HTTP error: the UI has to be able
    to render the install hint, so the failure is reported in the body
    (``available: false`` + ``hint``) and the verdict comes back *unknown*
    rather than blocking the page.
    """
    from smcp.core.llmfit import (
        FitReport, LlmfitError, LlmfitRunner, verdict_for,
    )

    bad = []
    if min_fit and min_fit not in _FIT_LEVELS:
        bad.append(f"min_fit: usa {'|'.join(_FIT_LEVELS)}")
    if runtime and runtime not in _FIT_RUNTIMES:
        bad.append(f"runtime: usa {'|'.join(_FIT_RUNTIMES)}")
    if sort and sort not in _FIT_SORTS:
        bad.append(f"sort: usa {'|'.join(_FIT_SORTS)}")
    if use_case and use_case not in _FIT_USE_CASES:
        bad.append(f"use_case: usa {'|'.join(_FIT_USE_CASES)}")
    if bad:
        raise HTTPException(status_code=400, detail="; ".join(bad))

    runner = LlmfitRunner(llmfit_bin, timeout_s=timeout_s)
    t0 = time.time()
    try:
        # Unnarrowed fetch: the verdict must see the rows the table hides (a
        # model that does not fit is exactly the one `--all` would show).
        raw = runner.catalog(limit=None, memory=memory, ram=ram,
                             cpu_cores=cpu_cores, max_context=max_context)
        view = raw.filtered(min_fit=min_fit, runtime=runtime,
                            use_case=use_case or None,
                            search=search or None, sort_by=sort,
                            include_too_tight=include_too_tight).top(limit)
    except LlmfitError as e:
        # Sin llmfit no hay veredicto posible, pero tampoco es un error HTTP:
        # la UI tiene que poder pintar el hint de instalación.
        return {
            "available": False,
            "hint": str(e),
            "secs": round(time.time() - t0, 2),
            "system": {},
            "total_models": 0,
            "models": [],
            "check": _verdict_dict(verdict_for(_load_cfg().model, FitReport())),
        }

    verdict = verdict_for(_load_cfg().model, raw)
    return {
        "available": True,
        "secs": round(time.time() - t0, 2),
        **view.to_payload(),
        "check": _verdict_dict(verdict),
    }


class FitApply(BaseModel):
    model: str = Field(min_length=1, max_length=200)
    base_url: str | None = Field(default=None, max_length=500)
    timeout_s: float | None = Field(default=None, gt=0.0, le=3600.0)
    api_key: str | None = Field(default=None, max_length=500)



@router.post("/fit/apply")
def post_fit_apply(body: FitApply) -> dict[str, Any]:
    """Adopt a model from the fit table as the pipeline's model.

    Same commit rule as ``delm fit --write-config``: the operator presses the
    button, and the llmfit verdict that justified the pick (quant, sizes, tok/s)
    travels into the YAML as comments instead of being lost.
    """
    from smcp.core.llmfit import LlmfitError, LlmfitRunner

    notes: list[str] = []
    row_name = body.model
    try:
        raw = LlmfitRunner().catalog(limit=None)
    except LlmfitError:
        raw = None            # sin llmfit no hay notas, pero el apply sigue
    if raw is not None:
        row = raw.by_name(body.model)
        if row is not None:
            row_name = row.name
            if row.best_quant:
                notes.append(f"quant elegido por llmfit: {row.best_quant}")
            if row.disk_size_gb is not None:
                notes.append(f"tamaño en disco: {row.disk_size_gb:.1f}G")
            if row.estimated_tps:
                notes.append(
                    f"velocidad estimada: {row.estimated_tps:.1f} tok/s "
                    f"({row.estimate_confidence or 'sin estimar'})")
            notes.append("elegido con delm fit / POST /api/fit/apply")

    updates: dict[str, Any] = {"model": row_name}
    if body.base_url:
        updates["base_url"] = body.base_url
    if body.timeout_s is not None:
        updates["timeout_s"] = body.timeout_s
    if body.api_key is not None:
        updates["api_key"] = body.api_key
    return _persist_config(updates, notes)


# ------------------------------------------------------------- la malla
# Superficie web de `delm mesh` (delm/core/contrib.py + delm/core/placement.py).
# Mismo contrato que la CLI, action por action, y **el mismo fichero de estado**:
# `smcp.core.contrib.default_state_path()` lo resuelve para las dos, porque una
# malla cuya CLI y su UI vieran estados distintos serían dos mallas.
#: Re-exported from the core so both surfaces resolve the same files.
_mesh_state_path = default_state_path
_mesh_identity_path = default_identity_path
DEFAULT_MESH_ID = "smcp-local"


def _load_mesh(mesh_id: str) -> Any:
    """Load the exchange state (empty ledger when absent)."""
    from smcp.core.contrib import ContributionLedger

    path = _mesh_state_path()
    if path.exists():
        try:
            led = ContributionLedger.load(str(path))
            return led if led.mesh_id == mesh_id else ContributionLedger(mesh_id)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            pass
    return ContributionLedger(mesh_id=mesh_id)


def _save_mesh(led: Any) -> str:
    path = _mesh_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    return led.save(str(path))


def _mesh_view(led: Any, mesh_id: str, endpoint: str) -> dict[str, Any]:
    """The exchange as the UI wants it: peers, totals, chain, endpoint."""
    peers = led.admitted_peers(observed_only=False)
    return {
        "mesh_id": mesh_id,
        "state_path": str(_mesh_state_path()),
        "identity_path": str(_mesh_identity_path()),
        "endpoint": endpoint,
        "chain_entries": len(led),
        "chain_ok": led.verify_chain(),
        "state_digest": led.state_digest(),
        "vram_verified_gb": led.total_vram_gb(observed_only=True),
        "vram_declared_gb": led.total_vram_gb(observed_only=False),
        "rejections": sum(1 for r in led.records if not r.accepted),
        "peers": [
            {"peer_id": p.peer_id, "vram_gb": p.vram_gb,
        "vram_advertised_gb": p.vram_advertised_gb,
        "vram_shared_gb": p.vram_shared_gb,
        "vram_available_gb": p.vram_available_gb, "ram_gb": p.ram_gb,
             "cpu_cores": p.cpu_cores, "backend": p.backend,
             "alive": p.alive, "seconds_observed": p.seconds_observed,
             # Historial, no saldo: se cuenta, no se gasta.
             "inferences_served": p.inferences_served,
             "satoshis_earned": p.satoshis_earned,
             "rejections": p.rejections}
            for p in peers],
    }



# ------------------------------------------------------- reservations (tier 2)
#: One book per mesh, held for the process lifetime. Deliberately module-level
#: and *not* persisted, mirroring :class:`smcp.core.reservation.ReservationBook`:
#: a reservation is a promise about the next few minutes of local scheduling.
#: Building one per request would make the endpoint meaningless — every call
#: would see an empty book and could take the same GiB twice, which is the exact
#: oversubscription the module exists to prevent.
_RESERVATION_BOOKS: dict[str, Any] = {}


def _reservation_book(led: Any, mesh_id: str) -> Any:
    """The mesh's book, freshly baselined from the ledger.

    The snapshot is taken on every call because the ledger's available figures
    move as peers report usage, and a book baselined once would keep promoting
    memory that is already committed.
    """
    from smcp.core.reservation import ReservationBook

    book = _RESERVATION_BOOKS.get(mesh_id)
    if book is None:
        book = ReservationBook()
        _RESERVATION_BOOKS[mesh_id] = book
    book.publish_snapshot(led.peers)
    return book


@router.get("/mesh")
def get_mesh(mesh_id: str = Query(default=DEFAULT_MESH_ID, max_length=80),
             endpoint: str = Query(default=DEFAULT_MESH_ENDPOINT, max_length=200),
             ) -> dict[str, Any]:
    """Exchange state: who contributes verified VRAM, and what they are owed."""
    return _mesh_view(_load_mesh(mesh_id), mesh_id, endpoint)



class MeshReserve(BaseModel):
    peer_id: str = Field(min_length=1, max_length=80)
    memory_gb: float = Field(gt=0.0, le=100_000.0)
    ttl_s: float = Field(default=0.0, ge=0.0, le=30 * 86400.0)
    tier: str = Field(default="paid", max_length=32)
    order_id: str = Field(default="", max_length=200)


@router.post("/mesh/reserve")
def post_mesh_reserve(body: MeshReserve,
                      mesh_id: str = Query(default=DEFAULT_MESH_ID,
                                           max_length=80)) -> dict[str, Any]:
    """Hold dedicated VRAM on one node (the paid single-shot tier).

    Atomic under the book's lock: the check and the accounting happen together,
    so two callers cannot be told the same GiB is free. That is the whole reason
    this endpoint is not a read-modify-write over the mesh view.
    """
    from smcp.core.reservation import NOT_ENOUGH, RESERVED, UNKNOWN_PEER

    led = _load_mesh(mesh_id)
    book = _reservation_book(led, mesh_id)
    res, why = book.reserve(body.peer_id, body.memory_gb, ttl_s=body.ttl_s,
                            tier=body.tier,
                            meta={"order_id": body.order_id} if body.order_id
                            else None)
    view = book.snapshot()
    node = view["nodes"].get(body.peer_id, {})
    if why != RESERVED or res is None:
        status = 404 if why == UNKNOWN_PEER else 409
        raise HTTPException(
            status_code=status,
            detail={"reason": why, "free_gb": node.get("free_gb", 0.0),
                    "requested_gb": body.memory_gb, "peer_id": body.peer_id})
    return {"reason": why, "reservation": res.to_dict(),
            "free_gb_after": book.free_gb(body.peer_id),
            "generation": view["generation"]}


@router.post("/mesh/release")
def post_mesh_release(reservation_id: str = Query(min_length=1, max_length=200),
                      mesh_id: str = Query(default=DEFAULT_MESH_ID,
                                           max_length=80)) -> dict[str, Any]:
    """Give back a reservation. Idempotent by outcome, never by silent success."""
    from smcp.core.reservation import NOT_HELD_ALIAS, RELEASED, Reservation

    led = _load_mesh(mesh_id)
    book = _reservation_book(led, mesh_id)
    peer_id = reservation_id.split("#", 1)[0]
    res = Reservation(reservation_id=reservation_id, peer_id=peer_id,
                      memory_gb=0.0, generation=book.generation, taken_at=0.0)
    out = book.release(res)
    if out == NOT_HELD_ALIAS:
        raise HTTPException(status_code=404,
                            detail={"reason": out, "reservation_id": reservation_id})
    return {"reason": out, "reservation_id": reservation_id,
            "released": out == RELEASED}


@router.get("/mesh/reservations")
def get_mesh_reservations(
        mesh_id: str = Query(default=DEFAULT_MESH_ID, max_length=80),
) -> dict[str, Any]:
    """Per-node reservation state: what is promised, and what is still free."""
    led = _load_mesh(mesh_id)
    book = _reservation_book(led, mesh_id)
    view = book.snapshot()
    return {**view,
            "reservations": [r.to_dict() for r in book.all_reservations()],
            "note": ("las reservas son en memoria de este proceso; un "
                     "reinicio las pierde a propósito")}


class MeshContribute(BaseModel):
    peer_id: str = Field(default="local", min_length=1, max_length=80)
    #: physical maximum of the host. Optional now, so ``detect`` can fill it.
    vram_gb: float = Field(default=0.0, ge=0.0, le=100_000.0)
    #: what this node offers the mesh — the owner's policy, and the number
    #: routing may plan against. Defaults to the physical maximum.
    vram_advertised_gb: float | None = Field(default=None, ge=0.0, le=100_000.0)
    #: what the mesh is using right now. Telemetry; unsigned by design.
    vram_shared_gb: float = Field(default=0.0, ge=0.0, le=100_000.0)
    ram_gb: float = Field(default=0.0, ge=0.0, le=1_000_000.0)
    cpu_cores: int = Field(default=0, ge=0, le=1024)
    backend: str = Field(default="cuda", max_length=32)
    ttl_s: float = Field(default=86400.0, gt=0.0, le=30 * 86400.0)
    #: fill vram_gb from local hardware detection instead of trusting the caller
    detect: bool = False


@router.post("/mesh/contribute")
def post_mesh_contribute(body: MeshContribute,
                         mesh_id: str = Query(default=DEFAULT_MESH_ID,
                                              max_length=80)) -> dict[str, Any]:
    """Sign this node's capacity and admit it (the web form of `delm mesh contribute`).

    Uses the same identity file as the CLI, so contributing from the browser
    and from the shell are the *same* identity, not two.
    """
    import time as _time

    from smcp.core.contrib import CapacityReport
    from smcp.core.provenance import KeyPair

    led = _load_mesh(mesh_id)
    path = _mesh_identity_path()
    if path.exists():
        key = KeyPair.load(str(path))
    else:
        key = KeyPair.new(body.peer_id, "ed25519")
        path.parent.mkdir(parents=True, exist_ok=True)
        key.save(str(path))
    now = _time.time()
    challenge = led.issue_challenge(body.peer_id, now=now)
    # Detection is opt-in and clearly labelled: a caller that sends its own
    # number gets its own number signed, which is what a remote node must do.
    # ``detect`` exists so a node standing on its own hardware does not have to
    # type a figure it cannot check.
    physical = body.vram_gb
    detected = None
    if body.detect or physical <= 0:
        from smcp.core.capability import local_report
        detected = round(
            local_report(body.peer_id).total_vram_bytes / (1024 ** 3), 3)
        physical = detected or physical
    advertised = (body.vram_advertised_gb
                  if body.vram_advertised_gb is not None else physical)
    if advertised > physical:
        raise HTTPException(
            status_code=422,
            detail=("vram_advertised_gb exceeds vram_gb: offering more VRAM "
                    "than the node reports is refused (capacity_overstated)"))
    report = CapacityReport(
        mesh_id=mesh_id, peer_id=body.peer_id, vram_gb=physical,
        vram_advertised_gb=advertised, vram_shared_gb=body.vram_shared_gb,
        ram_gb=body.ram_gb, cpu_cores=body.cpu_cores, backend=body.backend,
        nonce=challenge.nonce, issued_at=now, expires_at=now + body.ttl_s,
    ).sign(key)
    ok, reason = led.admit(report, now=now)
    # El rechazo se persiste antes de responder 400: si no, el intento
    # desaparecería del audit trail y `check` no podría listarlo.
    _save_mesh(led)
    if not ok:
        raise HTTPException(status_code=400,
                            detail=f"la malla rechazó la contribución: {reason}")
    return {"ok": True, "reason": reason, "digest": report.digest,
            "sig_kind": report.sig_kind, "identity_path": str(path),
            ** _mesh_view(led, mesh_id, DEFAULT_MESH_ENDPOINT)}


class MeshObserve(BaseModel):
    peer_id: str = Field(default="local", min_length=1, max_length=80)
    seconds: float = Field(gt=0.0, le=365 * 86400.0)


@router.post("/mesh/observe")
def post_mesh_observe(body: MeshObserve,
                      mesh_id: str = Query(default=DEFAULT_MESH_ID,
                                           max_length=80)) -> dict[str, Any]:
    """Mark a peer as observed for *seconds*.

    It does **not** credit anything: earning used to be a function of uptime
    times VRAM, which meant a machine accumulated value by being plugged in.
    The only thing that counts an inference now is `POST /api/mesh/infer`, and
    only with a verified anchor.
    """
    import time as _time

    led = _load_mesh(mesh_id)
    peer = led.observe(body.peer_id, _time.time(), dt_s=body.seconds)
    if peer is None:
        raise HTTPException(
            status_code=400,
            detail=f"{body.peer_id} no está admitido: usa /api/mesh/contribute antes")
    _save_mesh(led)
    return {"ok": True, "peer_id": peer.peer_id,
            "seconds_observed": peer.seconds_observed,
            "inferences_served": peer.inferences_served,
            "credits_accrued": False,   # explicito: observar no acredita
            **_mesh_view(led, mesh_id, DEFAULT_MESH_ENDPOINT)}


class MeshInfer(BaseModel):
    peer_id: str = Field(default="local", min_length=1, max_length=80)
    txid: str = Field(min_length=8, max_length=200)
    satoshis: int = Field(default=0, ge=0, le=21_000_000)


@router.post("/mesh/infer")
def post_mesh_infer(body: MeshInfer,
                    mesh_id: str = Query(default=DEFAULT_MESH_ID,
                                         max_length=80)) -> dict[str, Any]:
    """Count one verified inference in a peer's history.

    The only way a node's count goes up, and it is deliberately narrow: the peer
    must publish VRAM (a consumer is not a provider), the record must carry a
    txid, and the same txid cannot be counted twice. The satoshis are recorded
    as *history* — the balance is on the chain, and this is only what the mesh
    watched go by.
    """
    led = _load_mesh(mesh_id)
    ok, reason = led.record_inference(body.peer_id, txid=body.txid,
                                      satoshis=body.satoshis)
    if not ok:
        raise HTTPException(status_code=400,
                            detail=f"la inferencia no cuenta ({reason})")
    _save_mesh(led)
    peer = led.peers[body.peer_id]
    return {"ok": True, "reason": reason,
            "peer_id": peer.peer_id,
            "inferences_served": peer.inferences_served,
            "satoshis_earned": peer.satoshis_earned,
            **_mesh_view(led, mesh_id, DEFAULT_MESH_ENDPOINT)}


@router.get("/mesh/reputation")
def get_mesh_reputation(mesh_id: str = Query(default=DEFAULT_MESH_ID,
                                            max_length=80)) -> dict[str, Any]:
    """The ranking: how much each node has actually served.

    It is a counter, not a balance: it cannot be spent, transferred, or bought,
    and it only moves on an anchored record. See :mod:`smcp.core.reputation`.
    """
    from smcp.core.reputation import board_from_counters

    led = _load_mesh(mesh_id)
    board = board_from_counters(led)
    return {"ok": True, **board.to_dict(),
            "mesh_id": mesh_id,
            "total_inferences": sum(e.inferences_served for e in board)}


@router.get("/mesh/plan")
def get_mesh_plan(
    model: str = Query(min_length=1, max_length=200),
    memory_gb: float | None = Query(default=None, ge=0.0, le=10_000_000.0),
    layers: int = Query(default=0, ge=0, le=100_000),
    quant: str = Query(default="", max_length=32),
    reserve_gb: float = Query(default=0.0, ge=0.0, le=100_000.0),
    require_provider: bool = Query(default=True),
    observed_only: bool = Query(default=True),
    mesh_id: str = Query(default=DEFAULT_MESH_ID, max_length=80),
    endpoint: str = Query(default=DEFAULT_MESH_ENDPOINT, max_length=200),
    llmfit_bin: str | None = Query(default=None, max_length=400),
    timeout_s: float = Query(default=120.0, gt=0.0, le=600.0),
) -> dict[str, Any]:
    """Plan a model across the mesh (the web form of `delm mesh plan`).

    With ``memory_gb`` the plan needs nothing external; without it, llmfit sizes
    the model — and its absence is reported in the body, not as an HTTP error,
    so the page can still show the mesh and explain the missing piece.
    """
    from smcp.core.placement import ModelSpec, plan_placement

    led = _load_mesh(mesh_id)
    spec: ModelSpec | None = None
    llmfit_note = ""
    if memory_gb:
        spec = ModelSpec(name=model, memory_required_gb=memory_gb,
                         n_layers=layers, quant=quant)
    else:
        from smcp.core.llmfit import LlmfitError, LlmfitRunner
        try:
            raw = LlmfitRunner(llmfit_bin, timeout_s=timeout_s).catalog(limit=None)
        except LlmfitError as e:
            return {"available": False, "hint": str(e), "mesh_id": mesh_id,
                    **_mesh_view(led, mesh_id, endpoint)}
        row = raw.by_name(model)
        if row is None:
            raise HTTPException(
                status_code=400,
                detail=(f"{model!r} no está en el catálogo de llmfit; usa "
                        f"memory_gb para planear sin él"))
        spec = ModelSpec.from_fit_row(row, name=row.name)
        llmfit_note = f"dimensionado por llmfit: {row.memory_required_gb:.1f}G " \
                      f"({row.best_quant or 'sin quant'})"

    plan = plan_placement(spec, led,
                          reserve_gb=reserve_gb,
                          require_provider=require_provider,
                          observed_only=observed_only, endpoint=endpoint)
    payload = {"available": True, "llmfit": llmfit_note,
               **_mesh_view(led, mesh_id, endpoint), **plan.to_dict()}
    payload.pop("mesh_id", None)
    payload["mesh_id"] = mesh_id
    return payload


@router.get("/mesh/check")
def get_mesh_check(mesh_id: str = Query(default=DEFAULT_MESH_ID, max_length=80),
                   ) -> dict[str, Any]:
    """Audit the exchange: chain, rejections, balances, and what it cannot prove."""
    led = _load_mesh(mesh_id)
    view = _mesh_view(led, mesh_id, DEFAULT_MESH_ENDPOINT)
    served = sum(p.inferences_served for p in led.peers.values())
    view.update({
        "ok": bool(view["chain_ok"]),
        "inferences_served": served,
        "counted_anchors": len(led.counted_txids()),
        "refusals": [{"seq": r.seq, "peer_id": r.peer_id, "reason": r.reason}
                     for r in led.records if not r.accepted][-20:],
        "not_proven": ("que la VRAM declarada exista: no hay atestación de "
                       "hardware; es una afirmación firmada y auditable"),
    })
    return view


# ---------------------------------------------------------------------------
# Smart contract BSV (protocolo permissionless)
# ---------------------------------------------------------------------------

class ContractClaim(BaseModel):
    """Una inferencia verificada, lista para cobrar el bounty.

    La malla ya admitio el gist (n-grams >=4 en el
    trajectory). Aqui se construye la tx que gasta el
    output del contract (P2PKH del nodo) y paga el
    bounty al nodo.
    """

    gist_digest: str = Field(min_length=64, max_length=64)
    node_pubkey: str = Field(min_length=66, max_length=66)
    verifier_pubkey: str = Field(min_length=66, max_length=66)
    satoshis: int = Field(gt=0, le=100_000_000)
    task_digest: str = Field(default="", max_length=64)
    #: UTXO del contract que se gasta.
    prev_txid: str = Field(min_length=64, max_length=64)
    prev_vout: int = Field(ge=0)
    prev_satoshis: int = Field(gt=0)
    #: Clave privada del nodo (para firmar el gasto).
    node_privkey: str = Field(min_length=64, max_length=64)
    fee_satoshis: int = Field(default=500, ge=0, le=100_000)


@router.post("/contract/claim")
def post_contract_claim(body: ContractClaim) -> dict[str, Any]:
    """Cobra el bounty de una inferencia verificada.

    Construye y firma la tx que gasta el output del
    contract (``P2PKH(nodeKey)``) y paga el bounty al
    nodo. El gasto de ese output es la **tx de anclaje**:
    su outpoint ata la inferencia al nodo, y su existencia
    prueba que ocurrio. La tx esta lista para difundir
    via ARC.

    Permissionless: cualquier nodo con su clave BSV puede
    cobrar; la cadena garantiza (via el locking script)
    que solo el nodo que resolvio la tarea recibe los
    satoshis.
    """
    from smcp.core.bsv_keys import Secp256k1KeyPair

    # clave del nodo (para firmar el gasto del UTXO)
    node_key = Secp256k1KeyPair.from_private_bytes(
        "claim", bytes.fromhex(body.node_privkey))

    bounty = InferenceBounty(
        gist_digest=body.gist_digest,
        node_pubkey=body.node_pubkey,
        verifier_pubkey=body.verifier_pubkey,
        satoshis=body.satoshis,
        task_digest=body.task_digest,
    )
    # el cambio vuelve a la clave del nodo
    tx, registro = build_claim_tx(
        bounty, node_key,
        prev_txid=body.prev_txid,
        prev_vout=body.prev_vout,
        prev_satoshis=body.prev_satoshis,
        change_address_pubkey=node_key.public_key,
        fee_satoshis=body.fee_satoshis,
    )
    return {
        "ok": True,
        "reason": "claim firmado (listo para ARC)",
        "txid": registro["txid"],
        "outpoint": registro["outpoint"],
        "satoshis": registro["satoshis"],
        "fee_satoshis": registro["fee_satoshis"],
        "gist_digest": registro["gist_digest"],
        "raw_hex": registro["raw_hex"],
    }


# Token BSV-21 DELM (capa F — economia tokenizada)
# ---------------------------------------------------------------------------

class TokenPay(BaseModel):
    """Pago a un nodo en DELM por una inferencia.

    Es la contrapartida en token del bounty en sats
    (``/contract/claim``). El nodo recibe ``amount``
    DELM en su direccion BSV.
    """

    #: tokenId BSV-21 (<deployTxid>_0).
    token_id: str = Field(min_length=65, max_length=66)
    #: direccion BSV del nodo que resolvio.
    node_address: str = Field(min_length=26, max_length=34)
    #: cantidad de DELM (unidades raw, 0 decimales).
    amount: str = Field(min_length=1, max_length=20)


@router.post("/token/pay")
def post_token_pay(body: TokenPay) -> dict[str, Any]:
    """Paga a un nodo en DELM por una inferencia.

    Envuelve ``smcp.core.token_bsv21.pay_for_inference``
    (``sendBsv21`` del SDK nativo ``@1sat/actions``).
    El bridge Node se ejecuta via subprocess; el WIF
    viene de ``DELM_TOKEN_WIF`` o ``~/.delm/token.wif``.

    Requiere el token DELM activo (la tx de deploy
    confirmada en bloque) y el indexer 1sat operativo.
    """
    from smcp.core.token_bsv21 import pay_for_inference

    res = pay_for_inference(
        token_id=body.token_id,
        node_address=body.node_address,
        amount=body.amount,
    )
    return {
        "ok": res.ok,
        "txid": res.txid,
        "token_id": res.token_id,
        "error": res.error,
        "reason": "DELM enviado al nodo" if res.ok else "error del bridge",
    }


# ------------------------------------------------------------------ libro de inferencias
def _inference_registry() -> InferenceRegistry:
    """El libro de inferencias del nodo (persistente)."""
    return InferenceRegistry(path=DEFAULT_REGISTRY_PATH)


@router.get("/inferences")
def list_inference_registry(
    mesh_id: str = Query(default="", max_length=80),
    server: str = Query(default="", max_length=66),
    start: float = Query(default=0.0),
    end: float = Query(default=0.0),
) -> dict[str, Any]:
    """El libro de inferencias del nodo.

    Cada completion (status 200) produce un registro con
    txid (la prueba en cadena), timestamp (cuando ocurrio),
    identidades (mesh, servidor, solicitante) y el cobro
    (sats y/o DELM). Filtra por mesh, servidor y ventana.
    """
    reg = _inference_registry()
    if mesh_id:
        recs = reg.by_mesh(mesh_id)
    elif server:
        recs = reg.by_server(server)
    elif start or end:
        recs = reg.in_window(start=start, end=end or time.time())
    else:
        recs = reg.records
    return {
        "ok": True,
        "records": [r.to_dict() for r in recs],
        "totals": reg.totals(),
        "path": DEFAULT_REGISTRY_PATH,
    }


@router.get("/inferences/{txid}")
def get_inference(txid: str) -> dict[str, Any]:
    """Identifica una inferencia especifica y confirma que ocurrio.

    Busca por txid (la prueba en cadena) o por inference_id
    (``sha256(txid:mesh:server)``). Devuelve el registro con
    su timestamp, identidades y cobro — la prueba de que la
    inferencia ocurrio es el txid en un bloque (verificable
    offline con ``verify_inscription``).
    """
    reg = _inference_registry()
    rec = reg.by_txid(txid) or reg.by_inference_id(txid)
    if rec is None:
        raise HTTPException(
            status_code=404,
            detail=f"inferencia no registrada (txid o inference_id: {txid})",
        )
    return {"ok": True, "record": rec.to_dict(),
            "inference_id": rec.inference_id,
            "path": DEFAULT_REGISTRY_PATH}


@router.get("/inferences/totals")
def get_inference_totals() -> dict[str, Any]:
    """Totales del libro: inferencias, sats y DELM cobrados."""
    reg = _inference_registry()
    return {"ok": True, "totals": reg.totals(),
            "path": DEFAULT_REGISTRY_PATH}
