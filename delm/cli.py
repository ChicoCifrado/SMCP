"""Unified ``delm`` CLI (issue #9).

Until now the package was only reachable through ``python -m delm.demo.*`` and
two console scripts. This module is the single front door: one binary
(``delm``) and one module entry point (``python -m delm``, which is the *same*
parser) with five subcommands:

- ``delm demo <name>``   — run a demo (pipeline, security, taint, multihost,
  rsi, real);
- ``delm test``          — run the test suite (forwards args to pytest);
- ``delm config-check``  — resolve the model config and show it with the API
  key masked;
- ``delm fit``           — size the *local* model to this host (llmfit);
- ``delm version``       — print the version (and the Python it runs on).

Why demos are dispatched as **subprocesses** rather than in-process imports:
each demo module already has its own ``main()``/``run()`` contract, prints its
own report to stdout, and (in the multihost case) spawns child nodes with
``python -m delm.demo.run_multihost_demo``. Dispatching the module keeps the
CLI a thin, honest wrapper: no demo has to be refactored to be callable, the
demo's own exit code is the CLI's exit code, and the demos stay importable for
the in-process API (:mod:`api_server`, :mod:`smcp_api`) and the tests.

``delm fit`` is the one subcommand that talks to something outside the repo
(``llmfit``, an external tool), so it is the one that can fail for a reason
outside our control: missing tool → :data:`EXIT_LLMFIT` with an install hint,
never a traceback. The adapter itself is :mod:`delm.core.llmfit`.

Conventions this module follows (see the project conventions):

- ``argparse`` only — no heavy dependency added to the base install;
- no secrets ever printed: the key is masked via the demo's own ``_mask_key``;
- the CLI resolves *nothing* that the demos don't already resolve (env > YAML
  > default stays in :mod:`delm.config`).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Sequence

__all__ = ["main", "build_parser", "DEMOS", "EXIT_LLMFIT"]

if TYPE_CHECKING:  # pragma: no cover - typing only
    from delm.core.llmfit import ModelFitVerdict

#: Exit code for "llmfit is not usable here" (absent tool, failed run, bad
#: JSON). Distinct from ``2`` (config does not resolve / model does not fit) so
#: a CI step can tell "my setup is broken" from "this host cannot run it".
EXIT_LLMFIT = 3


#: The demos the CLI can run, in the order they are listed. Each entry is
#: ``(id, module, description)`` — the module is what gets executed as
#: ``python -m <module>``, so the demo's own CLI (flags, roles) is untouched.
DEMOS: tuple[tuple[str, str, str], ...] = (
    ("pipeline", "delm.demo.run_demo",
     "Pipeline end-to-end: cola, workers, verificacion, admision, despliegue "
     "selectivo y finalizacion (sin API key)."),
    ("security", "delm.demo.run_security_demo",
     "Capas 1+2: digest, firma ed25519, inmutabilidad y ledger append-only."),
    ("taint", "delm.demo.run_taint_demo",
     "Capa 5: taint + detector de inyeccion; el linaje envenenado queda "
     "cuarentenado."),
    ("multihost", "delm.demo.run_multihost_demo",
     "Capa 3 sobre red: 2 nodos en procesos distintos (QUIC por defecto; "
     "--nostr para relay Nostr)."),
    ("rsi", "delm.demo.run_rsi_demo",
     "Loop RSI L1: proponer/verificar/retener/sucesor, midiendo el HCI."),
    ("real", "delm.demo.run_real_demo",
     "Pipeline contra un endpoint real (requiere DELM_MODEL/DELM_BASE_URL)."),
)

_BY_ID = {d[0]: d for d in DEMOS}


# ------------------------------------------------------------------ helpers
def _mask_key(key: str) -> str:
    """Mask an API key for display. Reused from ``run_real_demo`` (one rule:
    don't re-derive a masking convention per call site)."""
    if not key:
        return "(unset)"
    if len(key) <= 8:
        return "***"
    return key[:4] + "***" + key[-4:]


def _default_config_path() -> str | None:
    """The committed example config, if present (else env-only)."""
    from delm.config import DEFAULT_CONFIG_PATH

    return str(DEFAULT_CONFIG_PATH) if DEFAULT_CONFIG_PATH.exists() else None


def _run_module(module: str, argv: Sequence[str] = ()) -> int:
    """Run ``python -m <module> <argv>`` and return its exit code."""
    cmd = [sys.executable, "-m", module, *argv]
    try:
        # No capture: the demo's report is the CLI's output (a wrapper that
        # swallows stdout would be worse than useless when debugging).
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


# ------------------------------------------------------------- subcommands
def _cmd_version(args: argparse.Namespace) -> int:
    from delm import __version__

    print(f"delm {__version__}")
    print(f"python {sys.version.split()[0]} ({sys.executable})")
    return 0


def _cmd_config_check(args: argparse.Namespace) -> int:
    """Resolve the model config (env > YAML > default) and show it masked.

    Same contract as ``run_real_demo --dry-run``: exit 0 when model and
    base_url are resolvable, 2 when they are not (so a CI step or a shell can
    branch on it without parsing output).
    """
    from delm.config import load_config

    cfg_path = args.config or _default_config_path()
    config = load_config(cfg_path)
    if args.harness:
        from dataclasses import replace

        config = replace(config, use_harness=True)

    print("=== delm config-check ===")
    print(f"config file : {cfg_path or '(none: env-only)'}")
    print(f"model       : {config.model or '(unset)'}")
    print(f"base_url    : {config.base_url or '(unset)'}")
    print(f"api_key     : {_mask_key(config.api_key)}")
    print(f"temperature : {config.temperature}")
    print(f"timeout_s   : {config.timeout_s}")
    print(f"backend     : "
          f"{'harness' if config.use_harness else 'openai-compatible'}")
    if not config.model or not config.base_url:
        print("note        : model/base_url unset — set DELM_MODEL / "
              "DELM_BASE_URL (and DELM_API_KEY if needed) or pass --config")
        return 2
    print("=== config OK ===")
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    if args.list:
        print("demos disponibles (delm demo <nombre>):")
        for did, _mod, desc in DEMOS:
            print(f"  {did:<10} {desc}")
        return 0

    name = args.name or "pipeline"
    if name not in _BY_ID:
        print(f"error: demo desconocida: {name!r}. "
              f"Usa 'delm demo --list' para ver las disponibles.",
              file=sys.stderr)
        return 2
    _id, module, _desc = _BY_ID[name]

    # Per-demo passthrough: the demo owns its own flags, the CLI only routes.
    extra: list[str] = list(args.demo_args)
    if args.nostr and name == "multihost":
        extra.append("--nostr")
    if name == "real":
        if args.config:
            extra += ["--config", args.config]
        if args.tasks is not None:
            extra += ["--tasks", str(args.tasks)]
        if args.workers is not None:
            extra += ["--workers", str(args.workers)]
        if args.harness:
            extra.append("--harness")
        if args.dry_run:
            extra.append("--dry-run")
    return _run_module(module, extra)


def _cmd_test(args: argparse.Namespace) -> int:
    """Run the suite in a subprocess (pytest must own its own process)."""
    cmd = [sys.executable, "-m", "pytest", *args.pytest_args]
    if args.slow:
        # The default addopts exclude `slow`; asking for it explicitly wins
        # because a later -m on the command line overrides an earlier one.
        cmd += ["-m", "slow"]
    print("+ " + " ".join(cmd))
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


# ------------------------------------------------------------------- llmfit
def _cmd_fit(args: argparse.Namespace) -> int:
    """Right-size the local model for this host, via llmfit.

    Three views of the same catalog, in increasing order of commitment:

    * default          — the ranked table of what runs here;
    * ``--check``      — does the model the *config* points to fit this host?
      (exit 2 when it does not, so a script can branch without parsing);
    * ``--write-config`` — persist the top pick as a ``model_config.yaml``,
      the only step that touches the filesystem and it never overwrites
      silently (``--force`` required).

    llmfit is an optional external tool, never a dependency: when it is absent
    the command explains how to install it and exits ``EXIT_LLMFIT``.
    """
    from delm.core.llmfit import LlmfitError, LlmfitRunner, verdict_for

    runner = LlmfitRunner(args.llmfit_bin, timeout_s=args.timeout)
    hardware = dict(profile=args.profile, memory=args.memory, ram=args.ram,
                    cpu_cores=args.cpu_cores, max_context=args.max_context)
    narrow = dict(use_case=args.use_case, min_fit=args.min_fit,
                  runtime=args.runtime, search=args.search, sort_by=args.sort,
                  perfect=args.perfect, include_too_tight=args.all)
    try:
        if args.check:
            # The verdict must see the *whole* catalog: a model that does not
            # fit this host is exactly the row the view hides, and no filter
            # the user typed for choosing a new model may erase it. So the
            # fetch is unnarrowed and the table is cut here, after.
            raw = runner.catalog(limit=None, **hardware)
            view = raw.filtered(**narrow).top(args.limit)
        else:
            view = runner.report(limit=args.limit, **hardware, **narrow)
            raw = view
    except LlmfitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_LLMFIT

    if args.json:
        payload = view.to_payload()
        rc = 0
        if args.check:
            verdict = verdict_for(_configured_model(args), raw)
            payload["check"] = _check_payload(verdict)
            # Mismo contrato de salida que en modo tabla: un script no tiene que
            # cambiar de logica por pedir JSON.
            rc = verdict.exit_code()
        print(json.dumps(payload, indent=2, sort_keys=True))
        return rc

    print(view.render(title="=== delm fit ==="))
    return _fit_followup(args, view, raw)


def _configured_model(args: argparse.Namespace) -> str:
    """The model the pipeline would actually use (env > YAML > default)."""
    from delm.config import load_config

    return load_config(args.config or _default_config_path()).model


def _check_payload(verdict: "ModelFitVerdict") -> dict:
    """``--check --json`` view of a :class:`ModelFitVerdict` (no secrets)."""
    return {
        "model": verdict.model,
        "matched": verdict.matched,
        "runnable": verdict.runnable,
        "fit_level": verdict.fit_level,
        "fit_label": verdict.fit_label,
        "best_quant": verdict.best_quant,
        "memory_required_gb": verdict.memory_required_gb,
        "estimated_tps": verdict.estimated_tps,
        "runtime": verdict.runtime,
        "row_name": verdict.row_name,
        "suggestions": list(verdict.suggestions),
    }


def _fit_followup(args: argparse.Namespace, view, raw) -> int:
    """`--check` and `--write-config`: the two committing steps.

    Split out of :func:`_cmd_fit` so the JSON path can skip it entirely: in
    ``--json`` mode the check is *data* in the payload, not prose after the
    table.
    """
    from delm.core.llmfit import local_config_yaml, verdict_for

    rc = 0

    if args.check:
        verdict = verdict_for(_configured_model(args), raw)
        print("--- check del modelo configurado ---")
        print(f"veredicto : {verdict.verdict_text()}")
        if verdict.matched and verdict.runnable:
            print(f"quant     : {verdict.best_quant or '?'}  "
                  f"velocidad: "
                  f"{verdict.estimated_tps if verdict.estimated_tps else '?'} "
                  f"tok/s  memoria: "
                  f"{verdict.memory_required_gb or '?'}G")
        for name in verdict.suggestions:
            print(f"sugerencia: {name}")
        rc = verdict.exit_code()

    if args.write_config:
        if not view.models:
            print("error: ningun modelo cabe con esos filtros; no se escribe "
                  "la config.", file=sys.stderr)
            return EXIT_LLMFIT
        path = Path(args.write_config)
        if path.exists() and not args.force:
            print(f"error: {path} ya existe. Usa --force para sobrescribir, o "
                  f"otro --write-config.", file=sys.stderr)
            return 2
        top = view.models[0]
        path.parent.mkdir(parents=True, exist_ok=True)
        # No se reusa `args.timeout` (que espera a llmfit) como timeout del
        # cliente: son dos cosas distintas y el default del runtime local es
        # mucho mayor — cargar un GGUF de 27B lleva minutos.
        path.write_text(local_config_yaml(top, base_url=args.base_url),
                        encoding="utf-8")
        print(f"escrito   : {path}  (model={top.name}, quant={top.quant_text()})")
    return rc


# ----------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="delm",
        description="DELM / SMCP — decentralized shared context, verified "
                    "admission and multi-agent meshes.",
        epilog="Ejemplos:\n"
               "  delm demo                 # pipeline end-to-end (sin API key)\n"
               "  delm demo security        # Capas 1+2\n"
               "  delm demo multihost       # 2 nodos sobre QUIC\n"
               "  delm demo real --dry-run  # resuelve la config, no llama al modelo\n"
               "  delm fit                  # que modelos caben en esta maquina\n"
               "  delm fit --check          # el modelo de la config cabe aqui?\n"
               "  delm test                 # la suite (por defecto: -m 'not slow')\n"
               "  delm config-check         # config de modelo con la key oculta\n"
               "  python -m delm version    # == delm version\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("-V", "--version", action="version",
                    version=f"delm {_version()}")

    sub = ap.add_subparsers(dest="command", metavar="<comando>")

    # --- demo
    p_demo = sub.add_parser(
        "demo", help="ejecuta una de las demos (default: pipeline)")
    p_demo.add_argument("name", nargs="?", default=None,
                        choices=sorted(_BY_ID),
                        help="demo a ejecutar (default: pipeline)")
    p_demo.add_argument("--list", action="store_true", dest="list",
                        help="lista las demos disponibles y sale")
    p_demo.add_argument("--nostr", action="store_true",
                        help="demo multihost: relay Nostr en vez de QUIC")
    p_demo.add_argument("--tasks", type=int, default=None,
                        help="demo real: numero de micro-tareas")
    p_demo.add_argument("--workers", type=int, default=None,
                        help="demo real: numero de workers en paralelo")
    p_demo.add_argument("--config", default=None,
                        help="demo real: ruta a un YAML de modelo")
    p_demo.add_argument("--harness", action="store_true",
                        help="demo real: backend DeepSeek Harness (opt-in)")
    p_demo.add_argument("--dry-run", action="store_true",
                        help="demo real: resuelve la config y no llama al modelo")
    p_demo.add_argument("demo_args", nargs=argparse.REMAINDER,
                        help="args extra pasados tal cual a la demo")
    p_demo.set_defaults(func=_cmd_demo)

    # --- test
    p_test = sub.add_parser("test", help="ejecuta la suite de tests")
    p_test.add_argument("--slow", action="store_true",
                        help="corre solo los tests marcados `slow` "
                             "(handshake QUIC, subprocess)")
    p_test.add_argument("pytest_args", nargs=argparse.REMAINDER,
                        help="args extra pasados a pytest")
    p_test.set_defaults(func=_cmd_test)

    # --- config-check
    p_cfg = sub.add_parser("config-check",
                           help="resuelve la config de modelo (key oculta)")
    p_cfg.add_argument("--config", default=None,
                       help="ruta a un YAML de modelo (default: "
                            "config/model_config.yaml si existe)")
    p_cfg.add_argument("--harness", action="store_true",
                       help="resuelve como backend harness (opt-in)")
    p_cfg.set_defaults(func=_cmd_config_check)

    # --- fit (llmfit)
    p_fit = sub.add_parser(
        "fit", help="dimensiona el modelo local a este hardware (llmfit)")
    p_fit.add_argument("-n", "--limit", type=int, default=10,
                       help="cuantas filas mostrar (default: 10)")
    p_fit.add_argument("--use-case", default=None,
                       choices=["general", "coding", "reasoning", "chat",
                                "multimodal", "embedding"],
                       help="filtra por caso de uso (categoría de llmfit)")
    p_fit.add_argument("--perfect", action="store_true",
                       help="solo los que caben perfecto")
    p_fit.add_argument("--min-fit", default=None,
                       choices=["perfect", "good", "marginal", "too_tight"],
                       help="umbral de fit de la tabla (default: descarta "
                            "los que no caben)")
    p_fit.add_argument("--all", action="store_true",
                       help="incluye los modelos que NO caben (too_tight)")
    p_fit.add_argument("--runtime", default=None,
                       choices=["mlx", "llamacpp", "vllm", "bitnetcpp"],
                       help="filtra la tabla por runtime (llama.cpp, vLLM…)")
    p_fit.add_argument("--search", default=None,
                       help="filtra por nombre o proveedor")
    p_fit.add_argument("--sort", default=None,
                       choices=["score", "tps", "params", "mem", "ctx", "name"],
                       help="ordena la tabla (default: el orden de llmfit)")
    p_fit.add_argument("--profile", default=None,
                       help="perfil de hardware de llmfit (simula otra maquina)")
    p_fit.add_argument("--memory", default=None,
                       help="override de VRAM (p.ej. 24G)")
    p_fit.add_argument("--ram", default=None, help="override de RAM (p.ej. 64G)")
    p_fit.add_argument("--cpu-cores", type=int, default=None,
                       help="override de nucleos de CPU")
    p_fit.add_argument("--max-context", type=int, default=None,
                       help="tope de contexto para la estimacion de memoria")
    p_fit.add_argument("--check", action="store_true",
                       help="verifica si el modelo de la config cabe aqui "
                            "(sale 2 si no cabe)")
    p_fit.add_argument("--config", default=None,
                       help="--check: ruta al YAML de modelo (misma "
                            "resolucion que config-check)")
    p_fit.add_argument("--write-config", default=None, metavar="RUTA",
                       help="escribe el primer resultado como model_config.yaml")
    p_fit.add_argument("--force", action="store_true",
                       help="--write-config: sobrescribe un archivo existente")
    p_fit.add_argument("--base-url", default="http://127.0.0.1:8080/v1",
                       help="--write-config: base_url del runtime local")
    p_fit.add_argument("--json", action="store_true",
                       help="salida JSON (para scripts y la API web)")
    p_fit.add_argument("--llmfit-bin", default=None,
                       help="ruta/comando de llmfit (default: $DELM_LLMFIT_BIN, "
                            "el PATH, o python -m llmfit)")
    p_fit.add_argument("--timeout", type=float, default=120.0,
                       help="segundos de espera para llmfit (default: 120)")
    p_fit.set_defaults(func=_cmd_fit)

    # --- version
    p_ver = sub.add_parser("version", help="muestra la version")
    p_ver.set_defaults(func=_cmd_version)

    return ap


def _version() -> str:
    from delm import __version__

    return __version__


def main(argv: list[str] | None = None) -> int:
    """Entry point for both ``delm`` and ``python -m delm``."""
    ap = build_parser()
    args = ap.parse_args(argv)
    if getattr(args, "func", None) is None:
        # No subcommand: show the help (and exit non-zero, like git does for
        # a bare `git` on a repo with no default).
        ap.print_help(sys.stderr)
        return 2
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover - via delm/__main__.py
    raise SystemExit(main())
