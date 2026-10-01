"""The project's quality gates, in one list, in the order they should fail.

The point of this module is that the gate list exists exactly once. It was
scattered across four places that each had to be kept in sync by hand:

* the CI workflow (``.github/workflows/ci.yml``) — which gates run, and in
  what order;
* ``delm test`` — runs pytest and nothing else;
* a bare ``scripts/check_readme_count.py`` the CI invoked by path;
* the README, which documents the count that script reconciles.

Four copies of a list that gates depend on is how a gate quietly stops
running: nothing fails when the list shrinks, the build just gets weaker.
Here the list is data, both the CLI and CI derive from it, and
:func:`check_all` is what both call.

Each gate is a subprocess because that is the only honest way to run them:
ruff, pyright and pytest each own their own process, plugins and exit-code
conventions, and reimplementing any of that in-process would be a worse copy.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent.parent


def _tool(name: str) -> str:
    """Resolve a dev tool against the venv *before* ``PATH``.

    A gate that silently skips because the tool sits in ``.venv/bin`` is worse
    than no gate: the run reports green while checking nothing. ``sys.executable``
    already points inside the venv when delm is installed there, so its sibling
    directory is the right place to look first.
    """
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.exists():
        return str(venv_bin)
    found = shutil.which(name)
    return found or name


@dataclass(frozen=True)
class Gate:
    """One quality gate: what it is, and how to run it.

    ``needs_module`` gates import something optional (``pyright`` may be
    absent, and that is not a failure — it is a gate that cannot run, which
    has to be reported as such rather than silently passing).
    """

    name: str
    why: str
    argv: tuple[str, ...]
    optional: bool = False

    @property
    def executable(self) -> Optional[str]:
        """The tool's binary, or ``None`` when it is not installed.

        The ``argv`` already carries the venv-resolved path, so this checks
        that path and not a bare name that might only exist on another host.
        """
        return shutil.which(self.argv[0]) or (
            self.argv[0] if Path(self.argv[0]).exists() else None)

    def available(self) -> bool:
        if not self.optional:
            return True
        return self.executable is not None

    def render(self) -> str:
        return f"{self.why}  [{' '.join(self.argv)}]"


def _pytest() -> Gate:
    return Gate(
        name="tests",
        why="suite completa (el default de pyproject excluye `slow`)",
        argv=(sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"),
    )


def _slow() -> Gate:
    return Gate(
        name="slow",
        why="tests marcados `slow` (handshake QUIC, subprocess)",
        argv=(sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
              "-m", "slow"),
    )


def _ruff() -> Gate:
    return Gate(
        name="ruff",
        why="lint (config en pyproject.toml: select + ignore justificado)",
        argv=(_tool("ruff"), "check", "."),
        optional=True,
    )


def _pyright() -> Gate:
    return Gate(
        name="pyright",
        why="type-check (config en pyproject.toml)",
        argv=(_tool("pyright"),),
        optional=True,
    )


def _readme() -> Gate:
    return Gate(
        name="readme",
        why="el conteo de tests del README cuadra con la suite real",
        argv=(sys.executable, "scripts/check_readme_count.py"),
    )


#: The gates, in the order they should run. Cheap-and-always-first ordering is
#: deliberate: a lint failure should not cost a 50s test run to discover.
ALL: tuple[Gate, ...] = (_readme(), _ruff(), _pyright(), _pytest(), _slow())

#: Gates that block a commit, in CI terms. ``slow`` is excluded because it
#: needs a real QUIC handshake and is not required to be green.
BLOCKING: tuple[Gate, ...] = tuple(g for g in ALL if g.name != "slow")

BY_NAME: dict[str, Gate] = {g.name: g for g in ALL}


@dataclass
class GateResult:
    gate: Gate
    skipped: bool = False
    code: Optional[int] = None
    seconds: float = 0.0
    output: str = ""

    @property
    def ok(self) -> bool:
        return self.skipped or self.code == 0


def run_gate(gate: Gate, *, stream: bool = True,
             timeout: Optional[int] = None) -> GateResult:
    """Run one gate in its own process and capture what it said."""
    if not gate.available():
        return GateResult(gate=gate, skipped=True, output="no instalado")

    started = time.monotonic()
    try:
        proc = subprocess.run(
            gate.argv, cwd=ROOT, capture_output=not stream, text=True,
            timeout=timeout,
        )
        code, out = proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        code, out = 124, f"timeout tras {timeout}s"
    except FileNotFoundError as exc:
        code, out = 127, str(exc)
    return GateResult(gate=gate, code=code,
                      seconds=time.monotonic() - started, output=out)


def select(names: Sequence[str]) -> list[Gate]:
    """Resolve gate names, keeping the canonical order regardless of input.

    Order is by the list, not by the command line: running the same gates in a
    different order can hide a different first failure, and a gate runner
    whose result depends on argument order is not a gate runner.
    """
    unknown = [n for n in names if n not in BY_NAME]
    if unknown:
        raise KeyError(
            f"gate desconocido: {', '.join(unknown)}. "
            f"Disponibles: {', '.join(BY_NAME)}")
    wanted = set(names)
    return [g for g in ALL if g.name in wanted]


def check_all(names: Sequence[str] = (), *,
              only_blocking: bool = False,
              timeout: Optional[int] = None) -> int:
    """Run the selected gates, stop at the first failure, return its code.

    Stopping early is the point: a contributor who breaks a signature should
    not wait 50s for pytest to tell them something ruff knew in a second.
    """
    chosen = list(BLOCKING if only_blocking else ALL) if not names \
        else select(names)
    results: list[GateResult] = []
    for gate in chosen:
        print(f"==> {gate.name}: {gate.render()}", flush=True)
        result = run_gate(gate, stream=True, timeout=timeout)
        results.append(result)
        if result.skipped:
            print(f"    OMITIDO (no instalado): {gate.argv[0]}")
            continue
        status = "ok" if result.ok else f"FALLO rc={result.code}"
        print(f"    {status} en {result.seconds:.1f}s", flush=True)
        if not result.ok:
            break
    return _summary(results, only_blocking=only_blocking)


def _summary(results: list[GateResult], *, only_blocking: bool) -> int:
    print()
    failed = [r for r in results if not r.ok]
    skipped = [r for r in results if r.skipped]
    ran = len(results) - len(skipped)
    if failed:
        print(f"gates: {len(failed)} fallo de {ran} ejecutados, "
              f"{len(skipped)} omitidos")
        for r in failed:
            print(f"  - {r.gate.name} (rc={r.code})")
        return int(failed[0].code or 1)
    if skipped:
        print(f"gates: {ran} ok, {len(skipped)} OMITIDOS por falta de herramienta "
              "(no es un verde: es un gate que no se pudo ejecutar)")
        for r in skipped:
            print(f"  - {r.gate.name}: instala {r.gate.argv[0]}")
        if only_blocking:
            return 0
        return 0
    print(f"gates: {ran} ok, 0 omitidos")
    return 0


def ci_argv() -> list[str]:
    """The command CI should run, so the workflow and the CLI cannot drift."""
    return [sys.executable, "-m", "delm", "gates", "--blocking"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    """``python -m delm.core.gates`` — the same gates CI runs."""
    import argparse

    ap = argparse.ArgumentParser(
        prog="delm-gates", description="los gates de calidad del proyecto")
    ap.add_argument("names", nargs="*", help="gates concretos (por defecto, todos)")
    ap.add_argument("--blocking", action="store_true",
                    help="solo los que bloquean el commit")
    args = ap.parse_args(list(argv) if argv is not None else None)
    return check_all(args.names, only_blocking=args.blocking)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
