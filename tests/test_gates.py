"""Tests for the gate runner.

The gate list exists once, in :mod:`delm.core.gates`, and both the CLI and CI
read it. These tests pin the parts that make that safe:

* an unknown gate name fails loudly instead of running nothing;
* argument order does not change which gates run or their order;
* a gate whose tool is missing is reported as *skipped*, never as passed;
* a failing gate stops the run and returns that gate's code.
"""
import subprocess
import sys

from pathlib import Path

import pytest

from delm.core import gates


def test_the_list_exists_and_is_ordered():
    names = [g.name for g in gates.ALL]
    assert names == ["readme", "ruff", "pyright", "tests", "slow"]
    # Cheap gates first: a lint failure should not cost a full test run.
    assert names.index("readme") < names.index("tests")


def test_slow_is_not_blocking():
    """``slow`` needs a real QUIC handshake; it is not required to be green."""
    assert "slow" not in [g.name for g in gates.BLOCKING]
    assert len(gates.BLOCKING) == 4


def test_every_gate_says_why_it_exists():
    for gate in gates.ALL:
        assert gate.why, f"{gate.name} no explica para que sirve"
        assert gate.argv, f"{gate.name} no tiene comando"


def test_unknown_gate_name_raises():
    with pytest.raises(KeyError, match="gate desconocido"):
        gates.select(["no-existe"])


def test_selection_keeps_canonical_order():
    """Order comes from the list, not the command line."""
    chosen = gates.select(["tests", "readme"])
    assert [g.name for g in chosen] == ["readme", "tests"]


def test_selecting_a_subset_does_not_add_the_rest():
    assert [g.name for g in gates.select(["ruff"])] == ["ruff"]


def test_missing_tool_is_skipped_not_passed():
    """A gate that cannot run is not a green gate.

    This is the failure mode worth being pedantic about: reporting an absent
    linter as "ok" is how a project stops being linted without anyone
    noticing. The skip has to be visible and distinct from success.
    """
    absent = gates.Gate(name="nope", why="prueba", argv=("definitely-not-installed",),
                       optional=True)
    assert absent.available() is False
    result = gates.run_gate(absent)
    assert result.skipped is True
    assert result.ok is True, "un gate omitido no debe fallar, pero tampoco pasar"
    # And the reason is recorded rather than swallowed.
    assert result.output == "no instalado"


def test_a_failing_gate_reports_its_code():
    failing = gates.Gate(name="falla", why="prueba",
                         argv=(sys.executable, "-c", "raise SystemExit(3)"))
    result = gates.run_gate(failing, stream=False)
    assert result.ok is False
    assert result.code == 3


def test_a_timeout_is_a_failure_not_a_hang():
    slow = gates.Gate(name="lento", why="prueba",
                      argv=(sys.executable, "-c", "import time; time.sleep(30)"))
    result = gates.run_gate(slow, stream=False, timeout=1)
    assert result.ok is False
    assert result.code == 124
    assert "timeout" in result.output


def test_check_all_stops_at_the_first_failure(monkeypatch):
    """A broken signature should not cost a 50s test run to discover."""
    ran: list[str] = []

    def fake(gate, stream=True, timeout=None):
        ran.append(gate.name)
        return gates.GateResult(
            gate=gate, skipped=False,
            code=0 if gate.name != "ruff" else 1)

    monkeypatch.setattr(gates, "run_gate", fake)
    code = gates.check_all(["readme", "ruff", "tests"])

    assert code == 1
    assert ran == ["readme", "ruff"], "tests no deberia correr tras un fallo de lint"


def test_check_all_runs_everything_selected(monkeypatch):
    monkeypatch.setattr(
        gates, "run_gate",
        lambda gate, stream=True, timeout=None:
            gates.GateResult(gate=gate, code=0))
    assert gates.check_all(["readme", "ruff"]) == 0


def test_ci_argv_uses_this_module():
    """The workflow must call the same list the CLI does."""
    argv = gates.ci_argv()
    assert argv[1:] == ["-m", "delm", "gates", "--blocking"]


def test_cli_exposes_gates_and_lists_them():
    out = subprocess.run(
        [sys.executable, "-m", "delm", "gates", "--list"],
        capture_output=True, text=True, timeout=120)
    assert out.returncode == 0
    for name in ("readme", "ruff", "pyright", "tests", "slow"):
        assert name in out.stdout


def test_cli_rejects_an_unknown_gate():
    out = subprocess.run(
        [sys.executable, "-m", "delm", "gates", "inventado"],
        capture_output=True, text=True, timeout=120)
    assert out.returncode != 0
    assert "desconocido" in (out.stdout + out.stderr)


def test_pyright_resolves_the_project_interpreter():
    """The bug that made six *correct* overrides look broken.

    ``agent-client-protocol`` changed its ``Agent`` protocol signatures
    between 0.9 and 0.12: 0.9 has ``prompt(prompt, session_id, message_id)``
    and 0.12 has ``prompt(session_id, prompt)``. Pyright resolved against
    another venv, so it checked the code against a library the project does
    not ship and every override looked incompatible. The fix is the ``venv``
    pin in ``pyproject.toml`` — nothing in the code changed.
    """
    from pathlib import Path

    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    assert 'venv = ".venv"' in text, (
        "pyright debe resolver imports contra el venv del proyecto; "
        "sin esto evalua el ACP de otro venv y da falsos positivos")


def test_gate_tool_is_resolved_against_the_running_interpreter():
    """A gate must find its tool even when PATH does not mention it.

    This is the runner half of the same bug. ``ruff`` and ``pyright`` live in
    ``.venv/bin``, which is not on PATH in most shells, so a runner that only
    asked ``shutil.which`` reported both as "not installed" — and a skipped
    gate is indistinguishable from a passing one unless it says so loudly.

    The resolution happens in :func:`gates._tool` when the canonical list is
    built, so that is what gets checked: a gate named for a tool present in
    this venv must carry a path that exists, not a bare name.
    """
    venv_bin = Path(sys.executable).parent
    for gate in gates.ALL:
        first = gate.argv[0]
        if (venv_bin / Path(first).name).exists():
            # The gate points at this interpreter's venv, so it resolves.
            assert Path(first).exists(), (
                f"{gate.name} no apunta a un binario que exista: {first}")
            assert gate.available() is True, (
                f"{gate.name} esta instalado pero el runner lo daria por ausente")


def test_every_optional_gate_is_findable_or_reported():
    """Optional gates must resolve against the venv, not vanish silently."""
    venv_bin = Path(sys.executable).parent
    optional = [g for g in gates.ALL if g.optional]
    assert optional, "deberia haber gates opcionales (ruff, pyright)"
    for gate in optional:
        assert Path(gate.argv[0]).exists(), (
            f"{gate.name}: {gate.argv[0]} no existe; el gate se omitiria en "
            "silencio y el build se debilitaria sin que nadie lo note")
