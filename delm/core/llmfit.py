"""llmfit adapter — right-size the *local* model to the host's hardware.

The project is model-agnostic (``OpenAICompatibleClient`` takes any
OpenAI-compatible endpoint), but being model-agnostic is not the same as being
*fitted*. Every local run has to answer one question before anything else:
**which model can this box actually run, and how fast?** Today that question is
answered by hand, from a blog post, or by trial and error — a 27B Q2 GGUF on a
16 GB card is fine, a Q5 of the same model is not, and nothing in this repo can
tell you which.

[`llmfit`](https://github.com/AlexsJones/llmfit) answers exactly that: it reads
the host (RAM, cores, GPU/VRAM, backend) and ranks the model catalog by fit,
speed, quality and context. This module is the seam:

* :class:`LlmfitRunner` — locates and invokes llmfit, returning **parsed JSON**.
  It never raises for a missing tool: it raises :class:`LlmfitNotFound`, which
  the CLI turns into an actionable install hint and a distinct exit code.
* :class:`SystemProfile` / :class:`FitRow` / :class:`FitReport` — typed views of
  llmfit's payload. Only the fields this repo reasons about are parsed; unknown
  keys are ignored, so a newer llmfit stays compatible.
* :func:`verdict_for` — the part that belongs to SMCP: given the model the
  pipeline is *actually configured* to use, say whether it fits this host.
  That closes the loop with :mod:`delm.config` (``delm fit --check``), which is
  the point: llmfit's answer is only useful if it is checked against the
  config that the pipeline will use.
* :func:`local_config_yaml` — the recommendation rendered as a
  ``model_config.yaml`` for a local OpenAI-compatible runtime, so "the model
  that fits" becomes the endpoint SMCP talks to.

Design constraints (same discipline as the rest of ``delm.core``):

* **stdlib only.** llmfit is an *optional external tool*, never a dependency:
  nothing in the base install changes, and the framework runs with zero extras.
* **Deterministic and offline-testable.** The runner is injectable, so tests
  never need the binary (see ``tests/test_llmfit.py``).
* **No network, no side effects on import.** Importing this module runs
  nothing; the subprocess only starts when a command is actually issued.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Sequence

__all__ = [
    "LlmfitError",
    "LlmfitNotFound",
    "LlmfitFailed",
    "LlmfitRunner",
    "SystemProfile",
    "FitRow",
    "FitReport",
    "ModelFitVerdict",
    "verdict_for",
    "local_config_yaml",
    "INSTALL_HINT",
    "LLMFIT_BIN_ENV",
]

#: Env var that overrides llmfit discovery (an explicit path or a command name).
LLMFIT_BIN_ENV = "DELM_LLMFIT_BIN"

#: Shown when llmfit is absent. Kept short and copy-pasteable on purpose: the
#: most common install paths, nothing else.
INSTALL_HINT = (
    "llmfit no esta instalado. Instala el binario o el paquete Python:\n"
    "  brew install AlexsJones/llmfit/llmfit   # macOS\n"
    "  curl -fsSL https://llmfit.axjns.dev/install.sh | sh   # linux/macOS\n"
    "  uv tool install -U llmfit              # via uv/pip\n"
    "  export DELM_LLMFIT_BIN=/ruta/al/llmfit # o apunta al binario a mano\n"
    "Docs: https://github.com/AlexsJones/llmfit"
)

#: Fit levels, worst to best. Order matters: it is the ranking used both for
#: "does it run at all" and for the exit code of ``--check``.
_FIT_ORDER = ("too_tight", "marginal", "good", "perfect")

#: Levels where the model is actually usable locally. ``marginal`` counts: it
#: runs, it is just tight (llmfit's own "runs with swaps/partial offload").
_RUNNABLE = ("perfect", "good", "marginal")


# --------------------------------------------------------------------- errors
class LlmfitError(Exception):
    """Base class for every llmfit adapter failure."""


class LlmfitNotFound(LlmfitError):
    """llmfit is not installed / not discoverable on this host."""


class LlmfitFailed(LlmfitError):
    """llmfit ran but failed, timed out, or emitted unparseable output."""

    def __init__(self, message: str, *, returncode: int | None = None,
                 stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


# ---------------------------------------------------------------- value types
def _f(value: Any) -> float | None:
    """Best-effort float, or ``None`` (``null`` is meaningful in llmfit)."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _i(value: Any) -> int | None:
    f = _f(value)
    return int(f) if f is not None else None


def _s(value: Any) -> str:
    return "" if value is None else str(value)


@dataclass(frozen=True)
class SystemProfile:
    """What llmfit detected about the host (or the simulated profile)."""

    total_ram_gb: float | None = None
    available_ram_gb: float | None = None
    cpu_cores: int | None = None
    cpu_name: str = ""
    has_gpu: bool = False
    gpu_name: str = ""
    gpu_vram_gb: float | None = None
    gpu_available_gb: float | None = None
    gpu_count: int = 0
    unified_memory: bool = False
    backend: str = ""

    @classmethod
    def from_payload(cls, payload: Any) -> "SystemProfile":
        """Parse llmfit's ``system`` object. Unknown keys are ignored."""
        if not isinstance(payload, dict):
            return cls()
        return cls(
            total_ram_gb=_f(payload.get("total_ram_gb")),
            available_ram_gb=_f(payload.get("available_ram_gb")),
            cpu_cores=_i(payload.get("cpu_cores")),
            cpu_name=_s(payload.get("cpu_name")),
            has_gpu=bool(payload.get("has_gpu")),
            gpu_name=_s(payload.get("gpu_name")),
            gpu_vram_gb=_f(payload.get("gpu_vram_gb")),
            gpu_available_gb=_f(payload.get("gpu_available_gb")),
            gpu_count=_i(payload.get("gpu_count")) or 0,
            unified_memory=bool(payload.get("unified_memory")),
            backend=_s(payload.get("backend")),
        )

    def ram_line(self) -> str:
        return _gb(self.total_ram_gb) + " RAM"

    def gpu_line(self) -> str:
        if not self.has_gpu:
            return "sin GPU"
        bits = [self.gpu_name or "GPU"]
        if self.gpu_count > 1:
            bits[0] = f"{self.gpu_count}x {bits[0]}"
        vram = _gb(self.gpu_vram_gb)
        if vram:
            bits.append(f"VRAM {vram}")
        if self.unified_memory:
            bits.append("memoria unificada")
        return " · ".join(bits)

    def render(self) -> str:
        """One-line-ish hardware summary for the CLI header."""
        cores = f"{self.cpu_cores} nucleos" if self.cpu_cores else "nucleos ?"
        lines = [f"cpu     : {self.cpu_name or '(desconocido)'} ({cores})",
                 f"ram     : {self.ram_line()}"]
        if self.available_ram_gb is not None:
            lines[-1] += f" (libre {_gb(self.available_ram_gb)})"
        lines.append(f"gpu     : {self.gpu_line()}")
        if self.backend:
            lines.append(f"backend : {self.backend}")
        return "\n".join(lines)


@dataclass(frozen=True)
class FitRow:
    """One model row: its fit verdict, its cost in memory, its speed."""

    name: str
    provider: str = ""
    params_b: float | None = None
    use_case: str = ""
    fit_level: str = ""            # machine code: perfect|good|marginal|too_tight
    fit_label: str = ""            # human string when llmfit ships one
    run_mode: str = ""             # gpu|cpu_offload|cpu_only
    runtime: str = ""              # llamacpp|vllm|mlx|bitnetcpp
    best_quant: str = ""
    score: float | None = None
    estimated_tps: float | None = None
    memory_required_gb: float | None = None
    memory_available_gb: float | None = None
    disk_size_gb: float | None = None
    effective_context_length: int | None = None
    estimate_confidence: str = ""
    installed: bool = False
    ollama_name: str = ""
    verify_command: str = ""

    @classmethod
    def from_payload(cls, row: Any) -> "FitRow":
        """Parse one ``models[]`` entry; never raises on a partial row."""
        if not isinstance(row, dict):
            return cls(name="")
        return cls(
            name=_s(row.get("name")),
            provider=_s(row.get("provider")),
            params_b=_f(row.get("params_b")),
            use_case=_s(row.get("use_case")),
            fit_level=_s(row.get("fit_level")).lower(),
            fit_label=_s(row.get("fit_label")),
            run_mode=_s(row.get("run_mode")).lower(),
            runtime=_s(row.get("runtime")).lower(),
            best_quant=_s(row.get("best_quant")),
            score=_f(row.get("score")),
            estimated_tps=_f(row.get("estimated_tps")),
            memory_required_gb=_f(row.get("memory_required_gb")),
            memory_available_gb=_f(row.get("memory_available_gb")),
            disk_size_gb=_f(row.get("disk_size_gb")),
            effective_context_length=_i(row.get("effective_context_length")),
            estimate_confidence=_s(row.get("estimate_confidence")).lower(),
            installed=bool(row.get("installed")),
            ollama_name=_s(row.get("ollama_name")),
            verify_command=_s(row.get("verify_command")),
        )

    @property
    def runnable(self) -> bool:
        return self.fit_level in _RUNNABLE

    @property
    def label(self) -> str:
        return self.fit_label or self.fit_level

    def params_text(self) -> str:
        if self.params_b is None:
            return "?"
        return f"{self.params_b:g}B"

    def tps_text(self) -> str:
        return f"{self.estimated_tps:.1f} tok/s" if self.estimated_tps else "?"

    def mem_text(self) -> str:
        if self.memory_required_gb is None:
            return "?"
        return f"{_gb(self.memory_required_gb)}"

    def quant_text(self) -> str:
        return self.best_quant or "-"

    def render(self) -> str:
        """One table row. Fixed column order; missing data renders as '?'."""
        flags = []
        if self.installed:
            flags.append("instalado")
        if self.estimate_confidence in ("measured_local", "measured_community"):
            flags.append("medido")
        suffix = f"  [{', '.join(flags)}]" if flags else ""
        name = self.name if len(self.name) <= 46 else self.name[:43] + "..."
        return (f"{name:<46} {self.params_text():>6} {self.quant_text():<8} "
                f"{self.label:<10} {self.mem_text():>7} {self.tps_text():>13}"
                f"{suffix}")


@dataclass(frozen=True)
class FitReport:
    """A parsed llmfit answer: the hardware it scored against + the rows."""

    system: SystemProfile = field(default_factory=SystemProfile)
    models: tuple[FitRow, ...] = ()
    total_models: int = 0

    @classmethod
    def from_payload(cls, payload: Any) -> "FitReport":
        if not isinstance(payload, dict):
            return cls()
        rows = payload.get("models")
        parsed = tuple(
            FitRow.from_payload(r) for r in (rows if isinstance(rows, list) else [])
        )
        parsed = tuple(r for r in parsed if r.name)
        total = _i(payload.get("total_models")) or len(parsed)
        return cls(system=SystemProfile.from_payload(payload.get("system")),
                   models=parsed, total_models=total)

    def __len__(self) -> int:
        return len(self.models)

    def __iter__(self):
        """Iterating a report iterates its rows: ``for r in report`` reads well."""
        return iter(self.models)

    def runnable(self) -> tuple[FitRow, ...]:
        return tuple(r for r in self.models if r.runnable)

    def top(self, n: int | None = None) -> "FitReport":
        """The first *n* rows, as a new report (llmfit already sorts best-first).

        Returns a report, not a tuple, so it composes with :meth:`filtered`
        and still renders: narrowing is a chain, not a terminal step.
        """
        rows = self.models if n is None else self.models[:max(n, 0)]
        return FitReport(system=self.system, models=rows,
                         total_models=self.total_models)

    def filtered(self, *, min_fit: str | None = None, runtime: str | None = None,
                 search: str | None = None, sort_by: str | None = None,
                 include_too_tight: bool = False) -> "FitReport":
        """Narrow the rows client-side.

        Why filter here and not pass ``--min-fit``/``--runtime``/``--sort`` down
        to the binary: those knobs are documented for llmfit's REST API, and a
        flag the installed build does not know is a hard ``exit 2``. Filtering
        the parsed rows is deterministic, version-proof, and keeps the report
        faithful — the caller decides what a "too tight" row is worth.

        ``sort_by`` accepts the same vocabulary as the API (``tps``, ``params``,
        ``mem``, ``ctx``, ``score``, ``name``); ``score`` is a no-op because
        llmfit already returns rows best-first.
        """
        rows = list(self.models)
        floor = _FIT_ORDER.index(min_fit) if min_fit in _FIT_ORDER else 0
        keep = []
        for row in rows:
            if not include_too_tight and row.fit_level == "too_tight":
                continue
            if min_fit in _FIT_ORDER and _FIT_ORDER.index(row.fit_level) < floor:
                continue
            if runtime and row.runtime and row.runtime != runtime.lower():
                continue
            if search and search.lower() not in row.name.lower() and \
                    search.lower() not in row.provider.lower():
                continue
            keep.append(row)

        keys: dict[str, Any] = {
            "score": lambda r: -(r.score or 0.0),
            "tps": lambda r: -(r.estimated_tps or 0.0),
            "params": lambda r: -(r.params_b or 0.0),
            "mem": lambda r: (r.memory_required_gb if r.memory_required_gb
                              is not None else float("inf")),
            "ctx": lambda r: -(r.effective_context_length or 0),
            "name": lambda r: r.name.lower(),
        }
        if sort_by in keys:
            keep.sort(key=keys[sort_by])
        return FitReport(system=self.system, models=tuple(keep),
                         total_models=self.total_models)

    def by_name(self, needle: str) -> FitRow | None:
        """The row for *needle* (exact, then normalized) — see :func:`_match_row`."""
        return _match_row(needle, self.models)

    def header(self) -> str:
        return (f"modelo".ljust(46) + f" {'params':>6} {'quant':<8} "
                f"{'fit':<10} {'mem':>7} {'velocidad':>13}")

    def render(self, limit: int | None = None,
               title: str = "=== delm fit ===") -> str:
        """Deterministic text report — the CLI's default output."""
        out = [title, "--- hardware (detected by llmfit) ---", self.system.render(),
               f"--- top {len(self.top(limit))} de {self.total_models} modelos ---",
               self.header()]
        if not self.models:
            out.append("(sin filas: ningun modelo cabe con esos filtros)")
        for row in self.top(limit):
            out.append(row.render())
        out.append("=== fit OK ===")
        return "\n".join(out)

    def to_payload(self) -> dict[str, Any]:
        """Serializable view (for ``--json`` and for the web/API)."""
        return {
            "system": {
                "total_ram_gb": self.system.total_ram_gb,
                "available_ram_gb": self.system.available_ram_gb,
                "cpu_cores": self.system.cpu_cores,
                "cpu_name": self.system.cpu_name,
                "has_gpu": self.system.has_gpu,
                "gpu_name": self.system.gpu_name,
                "gpu_vram_gb": self.system.gpu_vram_gb,
                "backend": self.system.backend,
            },
            "total_models": self.total_models,
            "models": [
                {
                    "name": r.name,
                    "provider": r.provider,
                    "params_b": r.params_b,
                    "use_case": r.use_case,
                    "fit_level": r.fit_level,
                    "fit_label": r.label,
                    "run_mode": r.run_mode,
                    "runtime": r.runtime,
                    "best_quant": r.best_quant,
                    "score": r.score,
                    "estimated_tps": r.estimated_tps,
                    "memory_required_gb": r.memory_required_gb,
                    "memory_available_gb": r.memory_available_gb,
                    "disk_size_gb": r.disk_size_gb,
                    "effective_context_length": r.effective_context_length,
                    "estimate_confidence": r.estimate_confidence,
                    "installed": r.installed,
                    "ollama_name": r.ollama_name,
                }
                for r in self.models
            ],
        }


def _gb(value: float | None) -> str:
    if value is None:
        return "?"
    return f"{value:.1f}G"


# -------------------------------------------------------------------- verdict
@dataclass(frozen=True)
class ModelFitVerdict:
    """Does the model SMCP is *configured* to use fit this host?

    ``matched`` is ``False`` when llmfit's catalog has no row for that id — a
    perfectly normal case (a served model id is a local runtime tag like
    ``unsloth/Qwen3.8-27B-GGUF:UD-Q2_K_XL``, not a catalog name). It is
    reported, never treated as a failure: the config is the source of truth,
    llmfit is the advisor.
    """

    model: str
    matched: bool
    runnable: bool = False
    fit_level: str = ""
    fit_label: str = ""
    best_quant: str = ""
    memory_required_gb: float | None = None
    estimated_tps: float | None = None
    runtime: str = ""
    row_name: str = ""
    suggestions: tuple[str, ...] = ()

    def verdict_text(self) -> str:
        """Human line for the CLI: fits, does not fit, or unknown."""
        if not self.matched:
            return f"modelo {self.model!r}: no esta en el catalogo de llmfit"
        head = f"modelo {self.model!r}: {self.fit_label or self.fit_level}"
        if self.runnable:
            return head
        return f"{head} — NO cabe en este host"

    def exit_code(self) -> int:
        """0 = fits (or unknown), 2 = configured model does not fit.

        Same convention as ``config-check``: a shell branches without parsing
        output. Unknown is not a failure — llmfit is an advisor, not a gate.
        """
        return 0 if (self.runnable or not self.matched) else 2


def _normalize(name: str) -> str:
    """Loose key for matching a config model id against catalog names.

    Lowercased, with the org prefix, the ``:tag`` runtime suffix, the ``-GGUF``
    marker and quant noise removed. Deliberately *not* fuzzy: a wrong match
    would be worse than an honest miss.
    """
    n = name.strip().lower()
    if "/" in n:
        n = n.rsplit("/", 1)[1]
    n = n.split(":", 1)[0]
    for junk in ("-gguf", ".gguf", "-unsloth"):
        n = n.replace(junk, "")
    return n.strip("-_ ")


def _match_row(model: str, rows: Sequence[FitRow]) -> FitRow | None:
    """Find the row for *model* among *rows* (exact, then normalized)."""
    for row in rows:
        if row.name == model:
            return row
    target = _normalize(model)
    if not target:
        return None
    hits = [r for r in rows if _normalize(r.name) == target]
    if len(hits) == 1:
        return hits[0]
    # Second pass: the config id usually carries a quant/runner suffix the
    # catalog name lacks ("...-27b-g-ud-q2_k_xl" vs "...-27b"). Require a single
    # row that *starts with* the target to avoid guessing between siblings.
    prefix = [r for r in rows if _normalize(r.name).startswith(target)]
    return prefix[0] if len(prefix) == 1 else None


def verdict_for(model: str, report: FitReport, *,
                limit: int = 3) -> ModelFitVerdict:
    """Judge the configured *model* against *report* and suggest alternatives.

    Suggestions are the best runnable rows that are *not* the configured one —
    the actionable output when the answer is "it does not fit".
    """
    if not model:
        return ModelFitVerdict(model="", matched=False)

    row = _match_row(model, report.models)
    if row is None:
        return ModelFitVerdict(model=model, matched=False)

    suggestions: tuple[str, ...] = ()
    if not row.runnable:
        suggestions = tuple(r.name for r in report.runnable()[:max(limit, 0)])

    return ModelFitVerdict(
        model=model,
        matched=True,
        runnable=row.runnable,
        fit_level=row.fit_level,
        fit_label=row.label,
        best_quant=row.best_quant,
        memory_required_gb=row.memory_required_gb,
        estimated_tps=row.estimated_tps,
        runtime=row.runtime,
        row_name=row.name,
        suggestions=suggestions,
    )


# ------------------------------------------------------------------- the YAML
def local_config_yaml(row: FitRow, *, base_url: str,
                      api_key: str = "dummy", timeout_s: float = 300.0,
                      temperature: float = 0.0) -> str:
    """Render a ``model_config.yaml`` for *row* on a local OpenAI-compatible server.

    The point of the integration: llmfit's top pick should be *one step* away
    from being the endpoint the pipeline uses. The served id is the model's
    catalog name (what a llama.cpp / MeshLLM / vLLM deployment exposes), the
    api_key stays a harmless placeholder because local servers do not
    authenticate, and nothing here is ever written without ``--write-config``
    from the CLI.
    """
    lines = [
        "# Generated by `delm fit --write-config <path>`.",
        "# Local model sized for THIS host by llmfit. This file is "
        "git-ignored.",
        "# Serve it first (llama.cpp / mesh-llm / vllm), then:",
        "#   DELM_BASE_URL/DELM_MODEL/DELM_API_KEY override this file.",
        f'model: "{row.name}"',
        f'base_url: "{base_url}"',
        f'api_key: "{api_key}"',
        f"temperature: {temperature}",
        f"timeout_s: {timeout_s}",
    ]
    if row.best_quant:
        lines.append(f"# quant elegido por llmfit: {row.best_quant} "
                     f"({row.disk_size_gb or 0:.1f}G en disco)")
    if row.ollama_name:
        lines.append(f"# ollama: ollama pull {row.ollama_name}")
    return "\n".join(lines) + "\n"


# -------------------------------------------------------------------- runner
class LlmfitRunner:
    """Locate and run llmfit, returning parsed JSON.

    Discovery order (first hit wins):

    1. an explicit ``binary=`` argument;
    2. ``$DELM_LLMFIT_BIN`` (a path or a command name);
    3. ``llmfit`` on ``$PATH``;
    4. ``python -m llmfit`` (the pip/uv install of the same project).

    Keeping the Python entry as a fallback is what makes this usable from a
    plain ``pip install`` without a second installer, and it is why the runner
    stores the *command prefix* rather than a resolved path.
    """

    def __init__(self, binary: str | None = None, *,
                 python: str | None = None, timeout_s: float = 120.0,
                 env: dict[str, str] | None = None) -> None:
        self.binary = binary
        self.python = python or os.sys.executable
        self.timeout_s = timeout_s
        self.env = env

    # -- discovery
    def _env_binary(self) -> str | None:
        return os.environ.get(LLMFIT_BIN_ENV) or None

    def _python_module_ok(self) -> bool:
        try:
            return importlib.util.find_spec("llmfit") is not None
        except (ImportError, ValueError):
            return False

    def command_prefix(self) -> list[str]:
        """The argv prefix that invokes llmfit, or raise :class:`LlmfitNotFound`."""
        explicit = self.binary or self._env_binary()
        if explicit:
            resolved = shutil.which(explicit) or (
                explicit if os.path.isfile(explicit) and
                os.access(explicit, os.X_OK) else None)
            if resolved:
                return [resolved]
            # An explicit path that does not work is a *configuration* error:
            # silently falling back would hide it.
            raise LlmfitNotFound(
                f"{LLMFIT_BIN_ENV}={explicit!r} no apunta a un ejecutable "
                f"llmfit. Corrigelo o unsetéalo para usar el del PATH."
            )
        on_path = shutil.which("llmfit")
        if on_path:
            return [on_path]
        if self._python_module_ok():
            return [self.python, "-m", "llmfit"]
        raise LlmfitNotFound(INSTALL_HINT)

    # -- invocation
    def run_json(self, argv: Sequence[str]) -> dict[str, Any]:
        """Run llmfit with *argv* plus ``--json`` and parse stdout.

        Raises :class:`LlmfitNotFound` when the tool is absent and
        :class:`LlmfitFailed` on a non-zero exit, a timeout, or output that is
        not a JSON object. The raw stderr is kept on the exception because llmfit
        is the one that knows why it failed.
        """
        cmd = [*self.command_prefix(), *argv, "--json"]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout_s,
                env={**os.environ, **self.env} if self.env else None,
            )
        except subprocess.TimeoutExpired as exc:
            raise LlmfitFailed(
                f"llmfit tardo mas de {self.timeout_s:g}s (subprocess: "
                f"{' '.join(cmd)})", returncode=None,
                stderr=str(exc.stderr or "")) from exc
        except OSError as exc:
            raise LlmfitFailed(
                f"no se pudo ejecutar llmfit ({' '.join(cmd)}): {exc}",
                returncode=None) from exc

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise LlmfitFailed(
                f"llmfit salio con {proc.returncode}"
                + (f": {detail.splitlines()[-1]}" if detail else ""),
                returncode=proc.returncode, stderr=proc.stderr or "")

        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise LlmfitFailed(
                f"llmfit no emitio JSON (linea {exc.lineno}, col {exc.colno}). "
                f"Primeros bytes: {(proc.stdout or '')[:200]!r}",
                returncode=proc.returncode, stderr=proc.stderr or "") from exc
        if not isinstance(payload, dict):
            raise LlmfitFailed(
                f"llmfit emitio {type(payload).__name__}, se esperaba un objeto "
                f"JSON con 'models'",
                returncode=proc.returncode, stderr=proc.stderr or "")
        return payload

    # -- typed commands
    def report(self, *, limit: int | None = None, use_case: str | None = None,
               perfect: bool = False, profile: str | None = None,
               memory: str | None = None, ram: str | None = None,
               cpu_cores: int | None = None, max_context: int | None = None,
               force_runtime: str | None = None) -> FitReport:
        """``llmfit fit`` as a :class:`FitReport`.

        Only flags documented for the *CLI* are passed down: the global
        hardware block (``--profile``/``--memory``/``--ram``/``--cpu-cores``/
        ``--max-context``) **before** the subcommand, and ``-n`` /
        ``--perfect`` / ``--use-case`` / ``--force-runtime`` after it. Flag
        order matters, so this is assembled in two blocks rather than
        flattened.

        The result is the *whole* scored catalog for those settings, unfiltered
        and unsliced. Narrowing (``--min-fit``-style thresholds, search, sort,
        the final cut) is :meth:`FitReport.filtered` and ``.top()`` — kept out
        of here so the caller can filter once and still search the full
        catalog (that is how ``delm fit --check`` finds a model that is too
        tight for this host: it must survive the view filter to be reported).
        """
        argv: list[str] = []
        if profile:
            argv += ["--profile", profile]
        if memory:
            argv += ["--memory", memory]
        if ram:
            argv += ["--ram", ram]
        if cpu_cores is not None:
            argv += ["--cpu-cores", str(cpu_cores)]
        if max_context is not None:
            argv += ["--max-context", str(max_context)]

        argv.append("fit")
        if limit is not None:
            argv += ["-n", str(limit)]
        if use_case:
            argv += ["--use-case", use_case]
        if perfect:
            argv.append("--perfect")
        if force_runtime:
            argv += ["--force-runtime", force_runtime]
        return FitReport.from_payload(self.run_json(argv))

    def plan(self, model: str, *, context: int | None = None,
             quant: str | None = None, target_tps: float | None = None,
             max_context: int | None = None) -> dict[str, Any]:
        """``llmfit plan <model>`` — hardware needed for a *specific* model."""
        argv: list[str] = []
        if max_context is not None:
            argv += ["--max-context", str(max_context)]
        argv += ["plan", model]
        if context is not None:
            argv += ["--context", str(context)]
        if quant:
            argv += ["--quant", quant]
        if target_tps is not None:
            argv += ["--target-tps", str(target_tps)]
        return self.run_json(argv)

    def system(self, *, profile: str | None = None, memory: str | None = None,
               ram: str | None = None, cpu_cores: int | None = None) -> SystemProfile:
        """``llmfit system`` — just the hardware profile."""
        argv: list[str] = []
        if profile:
            argv += ["--profile", profile]
        if memory:
            argv += ["--memory", memory]
        if ram:
            argv += ["--ram", ram]
        if cpu_cores is not None:
            argv += ["--cpu-cores", str(cpu_cores)]
        argv.append("system")
        return SystemProfile.from_payload(self.run_json(argv))
