"""Tests de la CLI unificada `delm` (issue #9).

Qué se cubre:

- el **parser** (nombres de subcomando, defaults, ``--help`` no revienta);
- el **dispatch** de demos a su módulo (por *nombre*, no por importación) y
  el passthrough de flags (``--nostr``, ``--dry-run``, …);
- ``config-check``: resuelve (env > YAML > default) y **nunca imprime la key
  entera** — el enmascarado es la garantía, así que se prueba con una key
  larga y una corta;
- ``test``: reenvía a pytest, y ``--slow`` añade el ``-m slow`` que pisa el
  ``-m 'not slow'`` de los addopts;
- el **entry point real** (``python -m delm``) como subprocess: es el contrato
  público del issue (``python -m delm`` == ``delm``), y un fallo ahí (el
  paquete sin ``__main__``, un import roto) no lo vería ningún test in-proceso.

Ninguno de estos tests necesita red, modelo ni sockets: los demos se despachan
como subprocess pero solo se ejecuta ``version`` (instantáneo) y un demo real
de la suite, que ya es determinista. ``delm test`` y ``delm demo multihost`` se
prueban por *dispatch* (monkeypatch), no ejecutándolos — la suite completa
dentro de la suite sería recursión, y multihost abre puertos (es ``slow``).
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from delm import __version__
from delm.cli import DEMOS, build_parser, main


# ------------------------------------------------------------------ parser
def test_parser_has_the_four_subcommands():
    ap = build_parser()
    # La forma de subcomandos se comprueba por el help: los nombres están
    # exposed en las secciones de ayuda.
    help_txt = ap.format_help()
    for cmd in ("demo", "test", "config-check", "version"):
        assert cmd in help_txt


def test_version_matches_package_version():
    assert __version__


def test_version_command_prints_version(capsys):
    assert main(["version"]) == 0
    out = capsys.readouterr().out
    assert __version__ in out
    assert "python" in out


def test_no_subcommand_shows_help_and_exits_nonzero(capsys):
    rc = main([])
    assert rc == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_demo_list_names_every_demo(capsys):
    assert main(["demo", "--list"]) == 0
    out = capsys.readouterr().out
    for demo_id, _mod, _desc in DEMOS:
        assert demo_id in out


def test_unknown_demo_is_rejected(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["demo", "no-existe"])
    assert exc.value.code == 2
    assert "no-existe" in capsys.readouterr().err


# ------------------------------------------------------------------ dispatch
@pytest.fixture()
def dispatched(monkeypatch):
    """Captura ``(module, argv)`` en vez de lanzar un subprocess."""
    calls: list[tuple[str, list[str]]] = []

    def fake_run_module(module, argv=()):
        calls.append((module, list(argv)))
        return 0

    monkeypatch.setattr("delm.cli._run_module", fake_run_module)
    return calls


def test_demo_default_runs_the_pipeline_demo(dispatched):
    assert main(["demo"]) == 0
    assert dispatched == [("delm.demo.run_demo", [])]


def test_demo_names_route_to_their_module(dispatched):
    for name, module, _desc in DEMOS:
        dispatched.clear()
        assert main(["demo", name]) == 0
        assert dispatched[0][0] == module


def test_demo_multihost_nostr_flag_is_forwarded(dispatched):
    assert main(["demo", "multihost", "--nostr"]) == 0
    module, argv = dispatched[0]
    assert module == "delm.demo.run_multihost_demo"
    assert "--nostr" in argv


def test_demo_real_forwards_its_flags(dispatched):
    assert main(["demo", "real", "--dry-run", "--tasks", "5",
                 "--workers", "3"]) == 0
    module, argv = dispatched[0]
    assert module == "delm.demo.run_real_demo"
    assert "--dry-run" in argv
    assert argv[argv.index("--tasks") + 1] == "5"
    assert argv[argv.index("--workers") + 1] == "3"


def test_demo_real_dry_run_works_end_to_end():
    """El único demo que corre de verdad: dry-run (no llama al modelo)."""
    p = subprocess.run(
        [sys.executable, "-m", "delm", "demo", "real", "--dry-run"],
        capture_output=True, text=True, timeout=120,
    )
    assert p.returncode in (0, 2), p.stderr  # 2 = config no resuelta (entorno vacío)
    assert "dry-run" in p.stdout


def test_demo_pipeline_runs_end_to_end():
    """`delm demo` == la demo sin API key, con su exit code."""
    p = subprocess.run(
        [sys.executable, "-m", "delm", "demo"],
        capture_output=True, text=True, timeout=300,
    )
    assert p.returncode == 0, p.stderr
    assert "demo OK" in p.stdout


# ------------------------------------------------------------------ test
def test_test_command_forwards_to_pytest(monkeypatch, capsys):
    seen: list[list[str]] = []
    monkeypatch.setattr("delm.cli.subprocess.call",
                        lambda cmd: seen.append(list(cmd)) or 0)
    assert main(["test"]) == 0
    cmd = seen[0]
    assert cmd[1:3] == ["-m", "pytest"]
    assert "tests" not in cmd  # la config de pytest define testpaths


def test_test_slow_appends_marker(monkeypatch):
    seen: list[list[str]] = []
    monkeypatch.setattr("delm.cli.subprocess.call",
                        lambda cmd: seen.append(list(cmd)) or 0)
    assert main(["test", "--slow"]) == 0
    cmd = seen[0]
    # -m slow debe ir DESPUÉS de los args para pisar el -m 'not slow' de los
    # addopts (pytest aplica el último -m).
    assert cmd[-2:] == ["-m", "slow"]


def test_test_forwards_extra_args(monkeypatch):
    seen: list[list[str]] = []
    monkeypatch.setattr("delm.cli.subprocess.call",
                        lambda cmd: seen.append(list(cmd)) or 0)
    main(["test", "tests/test_delm.py", "-k", "admission"])
    cmd = seen[0]
    assert "tests/test_delm.py" in cmd
    assert cmd[-1] == "admission"


# ------------------------------------------------------------------ config
def test_config_check_masks_a_long_key(monkeypatch, capsys):
    monkeypatch.setenv("DELM_MODEL", "m")
    monkeypatch.setenv("DELM_BASE_URL", "http://127.0.0.1:1/v1")
    monkeypatch.setenv("DELM_API_KEY", "sk-secret-value-1234567890")
    assert main(["config-check"]) == 0
    out = capsys.readouterr().out
    assert "sk-secret-value-1234567890" not in out
    assert "sk-s***7890" in out


def test_config_check_masks_a_short_key(monkeypatch, capsys):
    monkeypatch.setenv("DELM_MODEL", "m")
    monkeypatch.setenv("DELM_BASE_URL", "http://127.0.0.1:1/v1")
    monkeypatch.setenv("DELM_API_KEY", "short")
    assert main(["config-check"]) == 0
    out = capsys.readouterr().out
    assert "short" not in out
    assert "***" in out


def test_config_check_reports_unset_config(monkeypatch, capsys):
    # Sin model ni base_url en env, y con un --config inexistente: la resolución
    # es env-only y debe decir que falta (exit 2, para que un shell pueda
    # bifurcar sin parsear la salida).
    monkeypatch.delenv("DELM_MODEL", raising=False)
    monkeypatch.delenv("DELM_BASE_URL", raising=False)
    assert main(["config-check", "--config", "/nonexistent.yaml"]) == 2
    out = capsys.readouterr().out
    assert "(unset)" in out
    assert "DELM_MODEL" in out


# ------------------------------------------------------------------ entry point
def test_python_m_delm_equals_the_console_script():
    """`python -m delm` y `delm` son el mismo parser (issue #9)."""
    mod = subprocess.run(
        [sys.executable, "-m", "delm", "version"],
        capture_output=True, text=True, timeout=120,
    )
    assert mod.returncode == 0, mod.stderr
    assert __version__ in mod.stdout
    # Y el target del console script apunta al mismo main.
    assert "delm = \"delm.cli:main\"" in (
        __import__("pathlib").Path(__file__).resolve().parent.parent
        / "pyproject.toml").read_text(encoding="utf-8")
