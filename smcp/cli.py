"""Unified ``delm`` CLI (issue #9).

Until now the package was only reachable through ``python -m smcp.demo.*`` and
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
``python -m smcp.demo.run_multihost_demo``. Dispatching the module keeps the
CLI a thin, honest wrapper: no demo has to be refactored to be callable, the
demo's own exit code is the CLI's exit code, and the demos stay importable for
the in-process API (:mod:`smcp.web.app`, :mod:`smcp.web.api`) and the tests.

``delm fit`` is the one subcommand that talks to something outside the repo
(``llmfit``, an external tool), so it is the one that can fail for a reason
outside our control: missing tool → :data:`EXIT_LLMFIT` with an install hint,
never a traceback. The adapter itself is :mod:`smcp.core.llmfit`.

Conventions this module follows (see the project conventions):

- ``argparse`` only — no heavy dependency added to the base install;
- no secrets ever printed: the key is masked via the demo's own ``_mask_key``;
- the CLI resolves *nothing* that the demos don't already resolve (env > YAML
  > default stays in :mod:`smcp.config`).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Sequence

__all__ = ["main", "build_parser", "DEMOS", "EXIT_LLMFIT"]

if TYPE_CHECKING:  # pragma: no cover - typing only
    from smcp.core.contrib import ContributionLedger
    from smcp.core.llmfit import ModelFitVerdict
    from smcp.core.provenance import KeyPair
    from smcp.core.reservation import ReservationBook

# ``placement`` is stdlib-only (it imports contrib, which imports provenance),
# so importing the endpoint constant here costs nothing and keeps
# ``build_parser`` free of import-order surprises.
from smcp.core.placement import DEFAULT_MESH_ENDPOINT  # noqa: E402

#: Default mesh id for the local exchange. A mesh is a *view with its own
#: state file*; two meshes never share nonces, chain or balances.
DEFAULT_MESH_ID = "smcp-local"

#: Exit code for "llmfit is not usable here" (absent tool, failed run, bad
#: JSON). Distinct from ``2`` (config does not resolve / model does not fit) so
#: a CI step can tell "my setup is broken" from "this host cannot run it".
EXIT_LLMFIT = 3


#: The demos the CLI can run, in the order they are listed. Each entry is
#: ``(id, module, description)`` — the module is what gets executed as
#: ``python -m <module>``, so the demo's own CLI (flags, roles) is untouched.
DEMOS: tuple[tuple[str, str, str], ...] = (
    ("pipeline", "smcp.demo.run_demo",
     "Pipeline end-to-end: cola, workers, verificacion, admision, despliegue "
     "selectivo y finalizacion (sin API key)."),
    ("security", "smcp.demo.run_security_demo",
     "Capas 1+2: digest, firma ed25519, inmutabilidad y ledger append-only."),
    ("taint", "smcp.demo.run_taint_demo",
     "Capa 5: taint + detector de inyeccion; el linaje envenenado queda "
     "cuarentenado."),
    ("multihost", "smcp.demo.run_multihost_demo",
     "Capa 3 sobre red: 2 nodos en procesos distintos (QUIC por defecto; "
     "--nostr para relay Nostr)."),
    ("rsi", "smcp.demo.run_rsi_demo",
     "Loop RSI L1: proponer/verificar/retener/sucesor, midiendo el HCI."),
    ("real", "smcp.demo.run_real_demo",
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
    from smcp.config import DEFAULT_CONFIG_PATH

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
    from smcp import __version__

    print(f"smcp {__version__}")
    print(f"python {sys.version.split()[0]} ({sys.executable})")
    return 0


def _cmd_config_check(args: argparse.Namespace) -> int:
    """Resolve the model config (env > YAML > default) and show it masked.

    Same contract as ``run_real_demo --dry-run``: exit 0 when model and
    base_url are resolvable, 2 when they are not (so a CI step or a shell can
    branch on it without parsing output).
    """
    from smcp.config import load_config

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
              f"Usa 'smcp demo --list' para ver las disponibles.",
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
    from smcp.core.llmfit import LlmfitError, LlmfitRunner, verdict_for

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
    from smcp.config import load_config

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
    from smcp.core.llmfit import local_config_yaml, verdict_for

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


# ------------------------------------------------------------------- mesh
def _mesh_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    """``(exchange state, node identity)`` paths, resolved like the model config.

    Both live next to ``config/`` so the CLI and the web API share one file, and
    the identity is per-node while the exchange state is per-mesh-view. Only
    ``contribute`` needs the identity, so ``--identity`` is only defined on that
    subcommand — hence the ``getattr``.
    """
    from smcp.core.contrib import default_identity_path, default_state_path

    state = Path(args.state) if args.state else default_state_path()
    identity = getattr(args, "identity", None)
    ident = Path(identity) if identity else default_identity_path()
    return state, ident


def _load_exchange(path: Path, mesh_id: str) -> "ContributionLedger":
    from smcp.core.contrib import ContributionLedger

    if path.exists():
        try:
            led = ContributionLedger.load(str(path))
            if led.mesh_id != mesh_id:
                # Un estado de otra malla no se reusa: mezclarlos sería
                # contabilidad falsa (los nonces y la cadena son por malla).
                led = ContributionLedger(mesh_id=mesh_id)
            return led
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            # Estado corrupto: se empieza de cero en vez de dies — pero nunca
            # se reescribe en silencio sin que el operador lo vea (`check`).
            print(f"aviso: {path} ilegible o corrupto; se empieza de cero",
                  file=sys.stderr)
    return ContributionLedger(mesh_id=mesh_id)


def _node_identity(path: Path, peer_id: str) -> "KeyPair":
    """Load this node's signing key, creating it on first use."""
    from smcp.core.provenance import KeyPair

    if path.exists():
        return KeyPair.load(str(path))
    key = KeyPair.new(peer_id, "ed25519")
    path.parent.mkdir(parents=True, exist_ok=True)
    key.save(str(path))
    print(f"identidad creada: {path} (ed25519, chmod 600) — "
          f"guárdala: es lo que ata tus contribuciones a esta identidad",
          file=sys.stderr)
    return key


def _cmd_mesh(args: argparse.Namespace) -> int:
    """The exchange: verified VRAM in, free inference out (see contrib.py)."""
    action = args.mesh_command or "status"
    if action == "status":
        return _mesh_status(args)
    if action == "contribute":
        return _mesh_contribute(args)
    if action == "observe":
        return _mesh_observe(args)
    if action == "plan":
        return _mesh_plan(args)
    if action == "check":
        return _mesh_check(args)
    if action == "reserve":
        return _mesh_reserve(args)
    if action == "release":
        return _mesh_release(args)
    if action == "membership":
        return _mesh_membership(args)
    if action == "tiers":
        return _mesh_tiers(args)
    if action == "anchor":
        return _mesh_anchor(args)
    if action == "infer":
        return _mesh_infer(args)
    if action == "reputation":
        return _mesh_reputation(args)
    return 2


def _pay_show(args: argparse.Namespace) -> int:
    """La identidad de pago: adónde van los sats."""
    from smcp.core.contrib import default_payments_identity_path
    from smcp.core.handcash import load_identity

    ident = load_identity()
    path = default_payments_identity_path()
    print("=== smcp pay (identidad de pago) ===")
    print(f"fichero    : {path}"
          f"{'' if path.exists() else ' (aún no existe)'}")
    if not ident.configured:
        print("identidad  : sin configurar "
              "(el pago va a la clave local)")
        print()
        print("  delm pay set --handle '$Chicocifrado'")
        print("  # el paymail chicocifrado@handcash.io "
              "enruta a tu billetera")
        return 0
    if ident.handle is not None:
        print(f"handle     : {ident.handle.display}")
        print(f"paymail    : {ident.handle.paymail}")
    if ident.legacy_address:
        print(f"legacy     : {ident.legacy_address} "
              "(no recomendado)")
    print(f"destino    : {ident.recipient}")
    return 0


def _pay_set(args: argparse.Namespace) -> int:
    """Guarda la identidad de pago (handle y/o dirección)."""
    from smcp.core.handcash import (
        PaymentIdentity, parse_handle, save_identity,
        valid_legacy_address,
    )
    from smcp.core.membership import ProtocolError

    handle = (args.handle or "").strip() or None
    legacy = (args.legacy or "").strip() or None
    ident_handle = None
    if handle is not None:
        try:
            ident_handle = parse_handle(handle)
        except ProtocolError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if legacy is not None:
        if not valid_legacy_address(legacy):
            print(f"error: dirección {legacy!r}: no es "
                  "una P2PKH de BSV mainnet válida",
                  file=sys.stderr)
            return 2
        print("aviso: la dirección legacy es estática y "
              "rastreable — el handle es el camino",
              file=sys.stderr)
    try:
        ident = PaymentIdentity(handle=ident_handle,
                                 legacy_address=legacy)
    except ProtocolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    path = save_identity(ident)
    print(f"identidad guardada: {path}")
    print(f"  destino: {ident.recipient}")
    if ident.handle is not None:
        print(f"  los pagos a {ident.handle.paymail} "
              "enrutan a tu billetera HandCash")
    return 0


def _pay_clear(args: argparse.Namespace) -> int:
    """Borra la identidad de pago."""
    from smcp.core.contrib import default_payments_identity_path

    path = default_payments_identity_path()
    if path.exists():
        path.unlink()
        print(f"identidad borrada: {path}")
    else:
        print("no hay identidad que borrar")
    return 0


def _cmd_pay(args: argparse.Namespace) -> int:
    """La identidad de pago: adónde van los sats."""
    action = args.pay_command or "show"
    if action == "show":
        return _pay_show(args)
    if action == "set":
        return _pay_set(args)
    if action == "clear":
        return _pay_clear(args)
    return 2


def _mesh_status(args: argparse.Namespace) -> int:
    state, _ = _mesh_paths(args)
    led = _load_exchange(state, args.mesh_id)
    peers = led.admitted_peers(observed_only=False)
    print(f"=== smcp mesh ({args.mesh_id}) ===")
    print(f"estado     : {state}{'' if state.exists() else ' (aún no existe)'}")
    print(f"cadena     : {len(led)} entradas · "
          f"{'íntegra' if led.verify_chain() else 'ALTERADA'}")
    print(f"vram       : {led.total_vram_gb():.1f}G verificados "
          f"({led.total_vram_gb(observed_only=False):.1f}G declarados)")
    print(f"endpoint   : {args.endpoint}")
    print()
    if not peers:
        print("— ningún nodo ha aportado capacidad todavía —")
        print("  delm mesh contribute --vram-gb 16 --ram-gb 64 --cpu-cores 12")
        return 0
    print("  nodo                 vram    ofrece   observado  inferencias  sats")
    for p in peers:
        print(f"  {p.peer_id[:20]:<20} {p.vram_gb:>5.1f}G "
              f"{p.vram_advertised_gb:>6.1f}G "
              f"{('sí' if p.alive else 'NO'):>9} "
              f"{p.inferences_served:>11} {p.satoshis_earned:>5}")
    print()
    print("no hay saldo ni moneda interna: el valor es el satoshi y se mueve "
          "en la cadena. Las inferencias son historial (delm mesh reputation).")
    print("nota: la capacidad es una afirmación *firmada* de la identidad, no "
          "una atestación de hardware (ver docs/threat-model.md).")
    return 0


def _mesh_contribute(args: argparse.Namespace) -> int:
    from smcp.core.contrib import CapacityReport

    state, ident = _mesh_paths(args)
    led = _load_exchange(state, args.mesh_id)
    key = _node_identity(ident, args.peer_id)
    now = time.time()
    challenge = led.issue_challenge(args.peer_id, now=now, ttl_s=args.challenge_ttl)
    # The owner's decision, not a silent default: offering everything is a real
    # choice and the one that gets overwritten by accident when the flag is
    # forgotten. It is stated in the help and echoed in the output below.
    advertised = (args.vram_advertised_gb if args.vram_advertised_gb is not None
                  else args.vram_gb)
    if advertised > args.vram_gb:
        print(f"error: ofreces {advertised:.1f}G pero el nodo declara "
              f"{args.vram_gb:.1f}G físicos. La malla rechazaría el informe "
              f"(capacity_overstated); corrige uno de los dos números.",
              file=sys.stderr)
        return 2
    report = CapacityReport(
        mesh_id=args.mesh_id, peer_id=args.peer_id,
        vram_gb=args.vram_gb, vram_advertised_gb=advertised,
        vram_shared_gb=max(0.0, args.vram_shared_gb),
        ram_gb=args.ram_gb, cpu_cores=args.cpu_cores,
        backend=args.backend, nonce=challenge.nonce, issued_at=now,
        expires_at=now + args.ttl,
    ).sign(key)
    ok, reason = led.admit(report, now=now)
    # Un rechazo se guarda ANTES de salir: un rechazo que no se registra es un
    # rechazo que nadie puede auditar (y `delm mesh check` lo listaría vacío).
    state.parent.mkdir(parents=True, exist_ok=True)
    led.save(str(state))
    if not ok:
        print(f"error: la malla rechazó la contribución ({reason})",
              file=sys.stderr)
        return 2
    print(f"=== smcp mesh: contribución admitida ===")
    print(f"nodo       : {args.peer_id}")
    print(f"firma      : {report.sig_kind} · digest {report.digest[:16]}…")
    print(f"capacidad  : {report.vram_gb:.1f}G VRAM físicos · "
          f"{report.vram_advertised_gb:.1f}G ofrecidos · "
          f"{report.vram_shared_gb:.1f}G ya usados por la malla")
    print(f"            {report.ram_gb:.0f}G RAM · {report.cpu_cores} núcleos · "
          f"{report.backend}")
    if report.vram_advertised_gb < report.vram_gb:
        print(f"retenido    : {report.vram_gb - report.vram_advertised_gb:.1f}G "
              f"no se ofrecen a la malla (y no generan crédito)")
    print(f"cadena     : {len(led)} entradas")
    print(f"estado     : {state}")
    print("siguiente  : `delm mesh observe` (la malla te ve vivo) y luego "
          "`delm mesh plan <modelo>`")
    return 0


def _mesh_book(args: argparse.Namespace) -> "ReservationBook":
    """Build a book from the ledger on disk.

    Recreated per invocation, which is exactly the process-local scope
    :class:`smcp.core.reservation.ReservationBook` documents. The CLI therefore
    shows what a fresh mesh could reserve and releases nothing across commands —
    the real holder is whatever dispatches work, and it keeps one book for its
    lifetime.
    """
    from smcp.core.reservation import ReservationBook

    state, _ = _mesh_paths(args)
    led = _load_exchange(state, args.mesh_id)
    book = ReservationBook()
    book.publish_snapshot(led.peers)
    return book


def _mesh_reserve(args: argparse.Namespace) -> int:
    from smcp.core.reservation import NOT_ENOUGH, RESERVED, UNKNOWN_PEER

    book = _mesh_book(args)
    peer = book.snapshot()["nodes"].get(args.peer_id)
    res, why = book.reserve(args.peer_id, args.memory_gb, ttl_s=args.ttl_s)
    if args.json:
        print(json.dumps({"reason": why, "reservation": res.to_dict()
                          if res else None}, indent=2, sort_keys=True))
        return 0 if why == RESERVED else 2
    if why != RESERVED or res is None:
        print(f"error: no se pudo reservar {args.memory_gb:.1f}G en "
              f"{args.peer_id} ({why})", file=sys.stderr)
        if peer is not None:
            print(f"        disponible: {peer['free_gb']:.1f}G "
                  f"(físico {peer['physical_gb']:.1f}G · "
                  f"ofrece {peer['advertised_gb']:.1f}G · "
                  f"en uso {peer['reported_used_gb']:.1f}G)",
                  file=sys.stderr)
        elif why == UNKNOWN_PEER:
            print("        ese nodo no está admitido en la malla; "
                  "`delm mesh status` para ver quién está.", file=sys.stderr)
        elif why == NOT_ENOUGH:
            print("        sube `--vram-advertised-gb` en el nodo, o reserva "
                  "menos. La malla no puede prometer lo que no se ofreció.",
                  file=sys.stderr)
        return 2
    print(f"=== smcp mesh: reserva tomada ===")
    print(f"reserva    : {res.reservation_id}")
    print(f"nodo       : {res.peer_id}")
    print(f"memoria    : {res.memory_gb:.1f}G dedicados")
    print(f"generación : {res.generation}")
    print(f"caducidad  : "
          f"{'sin TTL (hasta liberar)' if not res.expires_at else f'{res.expires_at:.0f}'}")
    print(f"libre tras : {book.free_gb(res.peer_id):.1f}G")
    print("nota: las reservas viven en memoria de este proceso. Un reinicio "
          "las pierde a propósito — un disco con VRAM prometida a nadie es peor "
          "que empezar vacío.")
    return 0


def _mesh_release(args: argparse.Namespace) -> int:
    from smcp.core.reservation import NOT_HELD_ALIAS, RELEASED, Reservation

    book = _mesh_book(args)
    # ``release`` matches on the reservation id within a node's book, so the
    # caller needs to say which node. Accepting "peer#seq" keeps the id it
    # printed as the single handle.
    node = args.reservation_id.split("#", 1)[0]
    res = Reservation(reservation_id=args.reservation_id, peer_id=node,
                      memory_gb=0.0, generation=book.generation, taken_at=0.0)
    out = book.release(res)
    if args.json:
        print(json.dumps({"reason": out}, indent=2, sort_keys=True))
        return 0 if out == RELEASED else 2
    if out == NOT_HELD_ALIAS:
        print(f"error: {args.reservation_id} no está en este libro "
              f"(o ya se liberó). Las reservas no sobreviven a un reinicio.",
              file=sys.stderr)
        return 2
    print(f"reserva liberada: {args.reservation_id} ({out})")
    return 0


def _mesh_infer(args: argparse.Namespace) -> int:
    """Cuenta una inferencia verificada en el historial del nodo.

    Es el camino del ingreso, y es el **unico**. No acepta el importe: el
    satoshi no se acredita aqui, se lee de la cadena. Solo el txid, que es lo
    que lets un tercero volver a verificar lo mismo.
    """
    from smcp.core.contrib import ContributionLedger

    state, _ = _mesh_paths(args)
    led = _load_exchange(state, args.mesh_id)
    ok, reason = led.record_inference(args.peer_id, txid=args.txid,
                                      satoshis=args.satoshis)
    if not ok:
        print(f"no cuenta ({reason}): {args.peer_id} / {args.txid[:16] or '(sin ancla)'}…",
              file=sys.stderr)
        return 2
    state.parent.mkdir(parents=True, exist_ok=True)
    led.save(str(state))
    peer = led.peers[args.peer_id]
    print(f"contada   : {args.peer_id} · {peer.inferences_served} inferencias "
          f"· {peer.satoshis_earned} sats acumulados")
    print(f"motivo    : {reason}")
    print("recuerda  : un txid repetido no cuenta dos veces, y una inferencia "
          "local (solicitante == nodo) no se ancla.")
    return 0


def _mesh_reputation(args: argparse.Namespace) -> int:
    """El ranking: cuantosUe ha servido cada nodo, y en que orden."""
    from smcp.core.contrib import ContributionLedger
    from smcp.core.reputation import board_from_counters

    state, _ = _mesh_paths(args)
    led = _load_exchange(state, args.mesh_id)
    board = board_from_counters(led)
    if args.json:
        print(json.dumps(board.to_dict(), indent=2, sort_keys=True))
    else:
        print(board.render())
    pos = board.position(args.peer_id) if args.peer_id else None
    if pos:
        print(f"posicion  : {args.peer_id} es #{pos} de {len(board)}")
    return 0


def _mesh_anchor(args: argparse.Namespace) -> int:
    """Verifica un ancla de inferencia.

    Exige ``--header`` como entrada separada, por el mismo motivo que la
    pertenencia: si el proof trajera su cabecera, se avalaria a si mismo.
    """
    from smcp.core.anchor import AnchorRecord, ProtocolError
    from smcp.core.membership import BlockHeader, InclusionProof

    try:
        payload = json.loads(Path(args.anchor).read_text(encoding="utf-8"))
        hdr_raw = json.loads(Path(args.header).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: no se pudo leer la entrada: {exc}", file=sys.stderr)
        return 2

    try:
        header = (BlockHeader(merkle_root=str(hdr_raw["merkle_root"]),
                              height=int(hdr_raw.get("height", 0)),
                              raw=bytes.fromhex(hdr_raw["raw"]))
                  if "raw" in hdr_raw
                  else BlockHeader(merkle_root=str(hdr_raw["merkle_root"]),
                                   height=int(hdr_raw.get("height", 0))))
        rec = AnchorRecord.from_dict(payload["record"])
        inc = InclusionProof(
            txid=str(payload["inclusion"]["txid"]),
            index=int(payload["inclusion"]["index"]),
            path=[str(x) for x in payload["inclusion"]["path"]],
            merkle_root=str(payload["inclusion"]["merkle_root"]),
            height=int(payload["inclusion"]["height"]))
        signature = str(payload["signature"])
    except (KeyError, TypeError, ValueError) as exc:
        print(f"error: ancla malformada: {exc}", file=sys.stderr)
        return 2
    except ProtocolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ok, why = rec.verify(signature, inc, header)
    result = {"valid": ok, "reason": why,
              "membership_outpoint": rec.membership_outpoint,
              "publishes_content": bool(rec.content_sha256),
              "chain_validated": False}
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("valido            :", ok)
        print("motivo            :", why)
        print("membresia         :", rec.membership_outpoint)
        print("publica contenido :", bool(rec.content_sha256))
        print("cadena validada   : False  (BRC-96: inclusion contra la cabecera "
              "que diste, no validacion de cadena)")
    return 0 if ok else 1


def _mesh_tiers(args: argparse.Namespace) -> int:
    """Muestra los tres niveles, o presupuesta un plan.

    El precio se decide una vez y se muestra, no se recalcula en cada cliente.
    Un endpoint de precios que no existe es como cada quien se inventa el suyo.
    """
    from smcp.core.tiers import levels, quote

    if args.tiers_cmd == "levels":
        data = levels()
        if args.json:
            print(json.dumps(data, indent=2, sort_keys=True))
            return 0
        print("=== niveles de la malla (BSV, satoshis) ===")
        for name, t in data.items():
            print(f"\n{name}: {t['description']}")
            print(f"  entrada          : {t['join_satoshis']} sat")
            print(f"  por inferencia   : {t['per_inference_sats']} sat")
            print(f"  dedicada (unico) : {t['dedicated_satoshis']} sat")
            print(f"  aporta VRAM      : {t['provides_vram']}")
            print(f"  da pertenencia   : {t['grants_membership']}")
            print(f"  x402 adecuado    : {t['x402_suitable']}")
            if not t["x402_suitable"]:
                print(f"                     {t['x402_note']}")
        print("\nEl corte entre pago por uso y pago único son 400 inferencias "
              "(100 000 / 250). En el empate gana el pago único: mismo precio, "
              "capacidad reservada.")
        print("BSV no tiene umbral de polvo: una salida de 1 satoshi es válida "
              "y gastable, que es lo que hace posible 1sat ordinals (el ordinal "
              "de la inscripción viaja dentro de la tx de inferencia). La entrada "
              "es gratis (roster, off-chain): el freno de Sybil es la fee de "
              "servir, lineal con el trabajo.")
        return 0

    # quote
    try:
        q = quote(inferences=args.inferences,
                  wants_dedicated=args.dedicated,
                  offers_vram=args.offers_vram)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(q.to_dict(), indent=2, sort_keys=True))
        return 0
    print(f"nivel    : {q.tier_name}")
    print(f"total    : {q.total_satoshis} sat")
    print(f"equivalente a pago por uso: {q.metered_equivalent_sats} sat")
    delta = q.savings_vs_metered_sats
    if delta > 0:
        print(f"ahorro   : {delta} sat frente a pagar por uso")
    elif delta < 0:
        # Solo hay empate real cuando el nivel elegido ES el metered con el
        # mismo numero. Con 0 inferencias, o cuando el nivel ya es el metered,
        # el delta es 0 por construccion y no porque los precios empaten.
        if q.tier_name == "metered":
            print("coste extra: 0 (ya es el pago por uso)")
        else:
            print(f"coste extra: {-delta} sat frente a pagar por uso "
                  f"(y da capacidad reservada)")
    for r in q.reasons:
        print(f"  - {r}")
    return 0


def _mesh_membership(args: argparse.Namespace) -> int:
    """Verify a BSV membership proof against a block header the caller chose.

    Two files, both operator-supplied: the proof and the header. The header is
    *not* taken from the proof, because that would make the proof vouch for
    itself — the trust in a membership gate is the chain of headers the
    verifier believes, and that has to be an input, not an output of the same
    file. This mirrors what the threat model says about SPV.
    """
    import json as _json
    from smcp.core.membership import (
        BlockHeader, InclusionProof, MembershipLock, MembershipOutput,
        MembershipProof, _canonical_digest,
    )

    if args.membership_cmd != "verify":
        print(f"error: subcomando {args.membership_cmd!r} no soportado.",
              file=sys.stderr)
        return 2
    try:
        with open(args.proof, encoding="utf-8") as fh:
            pd = _json.load(fh)
        with open(args.header, encoding="utf-8") as fh:
            hd = _json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"error: no se pudo leer proof/header: {exc}", file=sys.stderr)
        return 2

    try:
        out_d = pd["output"]
        inc_d = pd["inclusion"]
        lock = MembershipLock(
            script_hash=pd.get("lock", {}).get("script_hash", ""),
            deployment_txid=pd.get("lock", {}).get("deployment_txid", ""))
        proof = MembershipProof(
            output=MembershipOutput(
                txid=str(out_d["txid"]), vout=int(out_d["vout"]),
                satoshis=int(out_d["satoshis"]),
                script_hash=str(out_d["script_hash"])),
            inclusion=InclusionProof(
                txid=str(inc_d["txid"]), index=int(inc_d["index"]),
                path=[str(x) for x in inc_d.get("path", [])],
                merkle_root=str(inc_d["merkle_root"]),
                height=int(inc_d.get("height", 0))),
            membership_pubkey=str(pd["membership_pubkey"]),
            signature=str(pd["signature"]),
            lock=lock if lock.script_hash else None)
    except (KeyError, TypeError, ValueError) as exc:
        print(f"error: proof malformado ({exc}). No es un rechazo: es un "
              f"formato que este comando no entiende.", file=sys.stderr)
        return 2

    header = BlockHeader(merkle_root=str(hd.get("merkle_root", "")),
                         height=int(hd.get("height", 0)),
                         raw=bytes.fromhex(hd["raw"]) if hd.get("raw") else b"")
    ok, why = proof.verify(header)
    if args.json:
        print(_json.dumps({
            "ok": ok, "reason": why,
            "outpoint": proof.output.outpoint(),
            "membership_pubkey": proof.membership_pubkey,
            "membership_fee_sats": proof.output.satoshis,
            "header_merkle_root": header.merkle_root,
            "chain_validated": False,   # SPV: inclusion, not chain ownership
        }, indent=2, sort_keys=True))
        return 0 if ok else 1
    if ok:
        print(f"miembro: {proof.output.outpoint()} "
              f"({proof.output.satoshis} sats) en el bloque "
              f"{header.height or proof.inclusion.height}")
        print(f"  clave : {proof.membership_pubkey}")
        print("  aviso : SPV verifica la inclusión en ESTA cabecera, no que "
              "sea la más larga. La confianza está en la cadena que tú eliges.")
        return 0
    print(f"rechazado: {why}", file=sys.stderr)
    return 1


def _mesh_observe(args: argparse.Namespace) -> int:
    state, _ = _mesh_paths(args)
    led = _load_exchange(state, args.mesh_id)
    now = time.time()
    peer = led.observe(args.peer_id, now, dt_s=args.seconds)
    if peer is None:
        print(f"error: {args.peer_id} no está admitido; usa "
              f"`delm mesh contribute` primero.", file=sys.stderr)
        return 2
    led.save(str(state))
    print(f"{args.peer_id}: +{args.seconds:.0f}s observado · "
          f"inferencias servidas {peer.inferences_served}")
    print("nota: observar NO acredita nada. El historial sube solo con "
          "`delm mesh infer` (una inferencia con ancla verificada).")
    return 0


def _mesh_plan(args: argparse.Namespace) -> int:
    """Size a model with llmfit, then decide who hosts it across the mesh."""
    from smcp.core.llmfit import LlmfitError, LlmfitRunner
    from smcp.core.placement import ModelSpec, plan_placement

    state, _ = _mesh_paths(args)
    led = _load_exchange(state, args.mesh_id)
    spec = _spec_from_args(args)
    if spec is None:
        # Sin spec explícita, la dimensiona llmfit (misma fuente que `delm fit`).
        runner = LlmfitRunner(args.llmfit_bin, timeout_s=args.timeout)
        try:
            raw = runner.catalog(limit=None, memory=args.memory, ram=args.ram,
                                 cpu_cores=args.cpu_cores)
        except LlmfitError as exc:
            print(f"error: {exc}\n"
                  f"(usa --memory-gb para planear sin llmfit)", file=sys.stderr)
            return EXIT_LLMFIT
        row = raw.by_name(args.model)
        if row is None:
            print(f"error: {args.model!r} no está en el catálogo de llmfit. "
                  f"Usa --memory-gb para planear a mano.", file=sys.stderr)
            return 2
        spec = ModelSpec.from_fit_row(row, name=row.name)

    plan = plan_placement(spec, led,
                          reserve_gb=args.reserve_gb,
                          require_provider=not args.no_provider,
                          endpoint=args.endpoint)
    if args.json:
        print(json.dumps(plan.to_dict(), indent=2, sort_keys=True))
    else:
        print(plan.render())
    return 0 if plan.ok else 2


def _spec_from_args(args: argparse.Namespace):
    """A hand-specified spec (`--memory-gb`) short-circuits llmfit."""
    from smcp.core.placement import ModelSpec

    if not args.memory_gb:
        return None
    return ModelSpec(name=args.model, memory_required_gb=args.memory_gb,
                     n_layers=args.layers, quant=args.quant or "")


def _mesh_check(args: argparse.Namespace) -> int:
    """Audit the exchange: chain integrity, balances, and what it does not prove."""
    state, _ = _mesh_paths(args)
    if not state.exists():
        print(f"no hay estado de malla en {state}", file=sys.stderr)
        return 2
    led = _load_exchange(state, args.mesh_id)
    chain_ok = led.verify_chain()
    print(f"=== smcp mesh check ({args.mesh_id}) ===")
    print(f"estado    : {state}")
    print(f"cadena    : {len(led)} entradas · {'íntegra' if chain_ok else 'ALTERADA'}")
    print(f"digest    : {led.state_digest()}")
    rejected = [r for r in led.records if not r.accepted]
    print(f"rechazos  : {len(rejected)}")
    for r in rejected[-5:]:
        print(f"  - seq {r.seq} {r.peer_id}: {r.reason}")
    print(f"historial : {sum(p.inferences_served for p in led.peers.values())} "
          f"inferencias contadas · {len(led.counted_txids())} anclas")
    for p in led.admitted_peers(observed_only=False):
        print(f"  {p.peer_id}: ofrece {p.vram_advertised_gb:.1f}G · observed "
              f"{p.seconds_observed:.0f}s · sirvio {p.inferences_served}")
    print()
    print("lo que esto NO prueba: que la VRAM declarada exista. No hay "
          "atestación de hardware; es una afirmación firmada y auditable.")
    return 0 if chain_ok else 2


# ----------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="smcp",
        description="DELM / SMCP — decentralized shared context, verified "
                    "admission and multi-agent meshes.",
        epilog="Ejemplos:\n"
               "  delm demo                 # pipeline end-to-end (sin API key)\n"
               "  delm demo security        # Capas 1+2\n"
               "  delm demo multihost       # 2 nodos sobre QUIC\n"
               "  delm demo real --dry-run  # resuelve la config, no llama al modelo\n"
               "  delm mesh status           # quien publica VRAM y cuanto ha servido\n"
               "  delm mesh contribute --vram-gb 16 --ram-gb 64 --cpu-cores 12\n"
               "  delm mesh plan <modelo>    # repartir un modelo entre los nodos\n"
               "  delm mesh infer --txid <tx>  # contar una inferencia verificada\n"
               "  delm mesh reputation       # ranking de quien ha servido\n"
               "  delm fit                  # que modelos caben en esta maquina\n"
               "  delm fit --check          # el modelo de la config cabe aqui?\n"
               "  delm test                 # la suite (por defecto: -m 'not slow')\n"
               "  delm config-check         # config de modelo con la key oculta\n"
               "  python -m delm version    # == delm version\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("-V", "--version", action="version",
                    version=f"smcp {_version()}")

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

    # --- mesh (intercambio: VRAM verificada <-> inferencia)
    p_mesh = sub.add_parser(
        "mesh", help="la malla: capacidad verificada a cambio de inferencia")
    msub = p_mesh.add_subparsers(dest="mesh_command", metavar="<acción>")

    def _mesh_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--mesh-id", default=DEFAULT_MESH_ID,
                        help=f"id de malla (default: {DEFAULT_MESH_ID})")
        sp.add_argument("--state", default=None,
                        help="estado del intercambio (default: "
                             "config/mesh_exchange.json)")
        sp.add_argument("--endpoint", default=DEFAULT_MESH_ENDPOINT,
                        help="endpoint OpenAI-compatible de la malla "
                             f"(default: {DEFAULT_MESH_ENDPOINT})")

    m_st = msub.add_parser("status", help="quién contribuye y cuánto tiene "
                                          "de crédito (default)")
    _mesh_common(m_st)

    m_ct = msub.add_parser("contribute", help="firmar y admitir tu capacidad")
    _mesh_common(m_ct)
    m_ct.add_argument("--peer-id", default="local",
                      help="identidad de este nodo (default: local)")
    m_ct.add_argument("--identity", default=None,
                      help="ruta de la clave de firma (default: "
                           "config/mesh_identity.json)")
    m_ct.add_argument("--vram-gb", type=float, required=True,
                      help="VRAM física total del nodo (el máximo del hardware)")
    m_ct.add_argument("--vram-advertised-gb", type=float, default=None,
                      help="cuánta VRAM ofreces a la malla (default: toda la "
                           "física; es la política del dueño del nodo)")
    m_ct.add_argument("--vram-shared-gb", type=float, default=0.0,
                      help="VRAM que la malla ya te está usando ahora "
                           "(telemetría; no va en la firma)")
    m_ct.add_argument("--ram-gb", type=float, default=0.0, help="RAM del nodo")
    m_ct.add_argument("--cpu-cores", type=int, default=0, help="núcleos")
    m_ct.add_argument("--backend", default="cuda",
                      help="backend (cuda, mlx, cpu, rocm, metal…)")
    m_ct.add_argument("--ttl", type=float, default=86400.0,
                      help="validez del informe en segundos (default: 24h)")
    m_ct.add_argument("--challenge-ttl", type=float, default=300.0,
                      help="validez del reto (default: 300s)")

    m_ob = msub.add_parser("observe", help="acumular crédito por tiempo "
                                           "observado vivo")
    _mesh_common(m_ob)
    m_ob.add_argument("--peer-id", default="local")
    m_ob.add_argument("--seconds", type=float, required=True,
                      help="segundos que la malla ha visto al nodo vivo")

    m_pl = msub.add_parser("plan", help="repartir un modelo entre los nodos")
    _mesh_common(m_pl)
    m_pl.add_argument("model", help="modelo a repartir (lo dimensiona llmfit)")
    m_pl.add_argument("--memory-gb", type=float, default=0.0,
                      help="forzar la memoria del modelo (sin llmfit)")
    m_pl.add_argument("--layers", type=int, default=0,
                      help="nº de capas del modelo, si lo sabes (reparte por "
                           "capas; si no, por cuota de VRAM)")
    m_pl.add_argument("--quant", default="", help="quant (nota informativa)")
    m_pl.add_argument("--reserve-gb", type=float, default=0.0,
                      help="VRAM que se reserva por nodo (no se ofrece)")
    m_pl.add_argument("--no-provider", action="store_true",
                      help="planificar también contra nodos que no publican "
                           "VRAM (solo diagnóstico: coloca carga donde no "
                           "hay capacidad ofrecida)")
    m_pl.add_argument("--memory", default=None, help="override de VRAM a llmfit")
    m_pl.add_argument("--ram", default=None, help="override de RAM a llmfit")
    m_pl.add_argument("--cpu-cores", type=int, default=None,
                      help="override de núcleos a llmfit")
    m_pl.add_argument("--llmfit-bin", default=None, help="ruta de llmfit")
    m_pl.add_argument("--timeout", type=float, default=120.0,
                      help="segundos de espera para llmfit")
    m_pl.add_argument("--json", action="store_true", help="plan en JSON")

    m_in = msub.add_parser(
        "infer", help="cuenta una inferencia verificada en el historial")
    _mesh_common(m_in)
    m_in.add_argument("--peer-id", default="local",
                      help="el nodo que la sirvio (default: local)")
    m_in.add_argument("--txid", required=True,
                      help="txid de la transaccion que la ancla: la prueba")
    m_in.add_argument("--satoshis", type=int, default=0,
                      help="satoshis de la ancla (historial; el saldo esta "
                           "en la cadena)")

    m_rep = msub.add_parser(
        "reputation", help="ranking de inferencias servidas por nodo")
    _mesh_common(m_rep)
    m_rep.add_argument("--peer-id", default=None,
                       help="muestra tambien la posicion de este nodo")
    m_rep.add_argument("--json", action="store_true", help="ranking en JSON")

    m_ck = msub.add_parser("check", help="auditar cadena e historial")
    _mesh_common(m_ck)

    # Reservas dedicadas (tier de pago único). Un libro de reservas es
    # deliberadamente efímero — no se persiste — así que estos comandos
    # trabajan contra el estado en memoria de este proceso; sirven para
    # inspeccionar y para probar la aritmética, no para coordinar dispatched
    # work entre procesos. Ver reservation.ReservationBook.
    m_rs = msub.add_parser(
        "reserve", help="reservar VRAM dedicada (tier de pago único)")
    _mesh_common(m_rs)
    m_rs.add_argument("--peer-id", required=True, help="nodo a reservar")
    m_rs.add_argument("--memory-gb", type=float, required=True,
                      help="GiB dedicados a reservar")
    m_rs.add_argument("--ttl-s", type=float, default=0.0,
                      help="duración en segundos (0 = hasta liberar)")
    m_rs.add_argument("--json", action="store_true", help="reserva en JSON")

    m_rl = msub.add_parser("release", help="liberar una reserva")
    _mesh_common(m_rl)
    m_rl.add_argument("--reservation-id", required=True)
    m_rl.add_argument("--json", action="store_true")

    m_an = msub.add_parser(
        "anchor", help="verificar el ancla de una inferencia")
    _mesh_common(m_an)
    m_an.add_argument("--anchor", required=True,
                      help="fichero del ancla (record + inclusion + signature)")
    m_an.add_argument("--header", required=True,
                      help="cabecera del bloque, como entrada separada")
    m_an.add_argument("--json", action="store_true")

    m_ti = msub.add_parser(
        "tiers", help="los tres niveles de precio, y presupuestar un plan")
    msub_t = m_ti.add_subparsers(dest="tiers_cmd", required=True)
    m_tl = msub_t.add_parser("levels", help="mostrar los tres niveles")
    _mesh_common(m_tl)
    m_tl.add_argument("--json", action="store_true")
    m_tq = msub_t.add_parser("quote", help="presupuestar un plan")
    _mesh_common(m_tq)
    m_tq.add_argument("--inferences", type=int, required=True,
                      help="inferencias previstas")
    m_tq.add_argument("--dedicated", action="store_true",
                      help="quiere VRAM dedicada")
    m_tq.add_argument("--offers-vram", action="store_true",
                      help="el nodo publica VRAM propia")
    m_tq.add_argument("--json", action="store_true")

    m_mb = msub.add_parser(
        "membership",
        help="gate de pertenencia anclado en BSV")
    msub_m = m_mb.add_subparsers(dest="membership_cmd", required=True)
    m_mv = msub_m.add_parser(
        "verify", help="verificar una MembershipProof contra una cabecera")
    _mesh_common(m_mv)
    m_mv.add_argument("--proof", required=True,
                      help="fichero JSON de la MembershipProof")
    m_mv.add_argument("--header", required=True,
                      help="fichero JSON de la cabecera (la elige el operador, "
                           "no la recibe del proof: la confianza está en la "
                           "cadena que tú crees)")
    m_mv.add_argument("--json", action="store_true")

    p_mesh.set_defaults(func=_cmd_mesh)

    # --- pay: la identidad de pago (HandCash)
    p_pay = sub.add_parser(
        "pay",
        help="identidad de pago: adónde van los sats "
             "(handle de HandCash o dirección legacy)")
    psub = p_pay.add_subparsers(dest="pay_command",
                                 metavar="<acción>")
    p_sh = psub.add_parser("show", help="la identidad "
                                        "actual (default)")
    p_st = psub.add_parser("set", help="guardar handle "
                                       "y/o dirección")
    p_st.add_argument("--handle", default=None,
                      help="handle de HandCash "
                           "($Chicocifrado) — el paymail "
                           "enruta a tu billetera")
    p_st.add_argument("--legacy", default=None,
                      help="dirección P2PKH de BSV "
                           "(no recomendado: estática "
                           "y rastreable)")
    p_cl = psub.add_parser("clear", help="borrar la "
                                         "identidad")
    p_pay.set_defaults(func=_cmd_pay)

    # --- version
    p_ver = sub.add_parser("version", help="muestra la version")
    p_ver.set_defaults(func=_cmd_version)

    # --- gates
    p_gates = sub.add_parser(
        "gates",
        help="corre los gates de calidad (readme, ruff, pyright, pytest, slow)")
    p_gates.add_argument(
        "names", nargs="*",
        help="gates concretos: readme, ruff, pyright, tests, slow "
             "(por defecto, todos)")
    p_gates.add_argument(
        "--blocking", action="store_true",
        help="solo los que bloquean el commit (excluye `slow`)")
    p_gates.add_argument("--timeout", type=int, default=None,
                         help="timeout por gate, en segundos")
    p_gates.add_argument("--list", action="store_true", dest="list",
                         help="lista los gates y sale")
    p_gates.set_defaults(func=_cmd_gates)

    return ap


def _cmd_gates(args: argparse.Namespace) -> int:
    """Run the project's quality gates.

    The list lives in :mod:`smcp.core.gates` and nowhere else, so the CI
    workflow and this command cannot disagree about what a gate is. The same
    module exposes :func:`~smcp.core.gates.ci_argv` for the workflow to call,
    which is the point: one list, two callers.
    """
    from smcp.core import gates

    if getattr(args, "list", False):
        for gate in gates.BLOCKING if args.blocking else gates.ALL:
            mark = " (bloqueante)" if gate in gates.BLOCKING else ""
            state = "" if gate.available() else "  [no instalado]"
            print(f"  {gate.name:8} {gate.why}{mark}{state}")
        return 0
    return gates.check_all(args.names, only_blocking=args.blocking,
                           timeout=args.timeout)


def _version() -> str:
    from smcp import __version__

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
