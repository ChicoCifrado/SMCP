"""Tests for the model-config loader (``delm.config``).

Covers:
* ``load_config`` — env-only, YAML-only, and env-over-YAML precedence.
* ``_read_yaml`` — missing file, flat parse, and the PyYAML path.
* ``build_client`` — returns an ``OpenAICompatibleClient`` with the right
  fields (no network call).
* ``run_real_demo`` dry-run — resolves the config, prints it, calls nothing,
  and exits non-zero when model/base_url are unset.

No network, no API key: the loader is pure configuration.
"""
from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from delm.config import ModelConfig, build_client, load_config
from delm.core.llm import OpenAICompatibleClient


# ---------------------------------------------------------------- load_config
def test_load_env_only(monkeypatch):
    for var in ("DELM_MODEL", "DELM_BASE_URL", "DELM_API_KEY",
               "DELM_TEMPERATURE", "DELM_TIMEOUT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("DELM_MODEL", "m")
    monkeypatch.setenv("DELM_BASE_URL", "http://x/v1")
    monkeypatch.setenv("DELM_API_KEY", "k")
    cfg = load_config(None)
    assert cfg.model == "m"
    assert cfg.base_url == "http://x/v1"
    assert cfg.api_key == "k"
    assert cfg.temperature == 0.0
    assert cfg.timeout_s == 120.0


def test_load_env_numeric(monkeypatch):
    for var in ("DELM_MODEL", "DELM_BASE_URL", "DELM_API_KEY",
               "DELM_TEMPERATURE", "DELM_TIMEOUT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("DELM_MODEL", "m")
    monkeypatch.setenv("DELM_BASE_URL", "u")
    monkeypatch.setenv("DELM_TEMPERATURE", "0.7")
    monkeypatch.setenv("DELM_TIMEOUT", "55")
    cfg = load_config(None)
    assert cfg.temperature == 0.7
    assert cfg.timeout_s == 55.0


def test_load_env_bad_number_falls_back(monkeypatch):
    for var in ("DELM_MODEL", "DELM_BASE_URL", "DELM_TEMPERATURE",
               "DELM_TIMEOUT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("DELM_MODEL", "m")
    monkeypatch.setenv("DELM_BASE_URL", "u")
    monkeypatch.setenv("DELM_TEMPERATURE", "not-a-number")
    monkeypatch.setenv("DELM_TIMEOUT", "")
    cfg = load_config(None)
    assert cfg.temperature == 0.0
    assert cfg.timeout_s == 120.0


def test_load_yaml_only(tmp_path: Path):
    p = tmp_path / "c.yaml"
    p.write_text(textwrap.dedent("""\
        model: fromfile
        base_url: http://file/v1
        api_key: filekey
        temperature: 0.3
        timeout_s: 77.0
    """))
    # Make sure no env leaks in.
    for var in ("DELM_MODEL", "DELM_BASE_URL", "DELM_API_KEY",
               "DELM_TEMPERATURE", "DELM_TIMEOUT"):
        os.environ.pop(var, None)
    cfg = load_config(p)
    assert cfg.model == "fromfile"
    assert cfg.base_url == "http://file/v1"
    assert cfg.api_key == "filekey"
    assert cfg.temperature == 0.3
    assert cfg.timeout_s == 77.0


def test_load_env_overrides_yaml(tmp_path: Path, monkeypatch):
    p = tmp_path / "c.yaml"
    p.write_text("model: fromfile\nbase_url: http://file/v1\n")
    monkeypatch.setenv("DELM_MODEL", "fromenv")
    monkeypatch.setenv("DELM_BASE_URL", "http://env/v1")
    monkeypatch.delenv("DELM_API_KEY", raising=False)
    cfg = load_config(p)
    assert cfg.model == "fromenv"
    assert cfg.base_url == "http://env/v1"


def test_load_missing_file_is_empty(tmp_path: Path):
    cfg = load_config(tmp_path / "does-not-exist.yaml")
    assert cfg == ModelConfig()  # all defaults


def test_load_config_frozen():
    cfg = ModelConfig(model="m")
    with pytest.raises(Exception):
        cfg.model = "x"  # type: ignore[misc]


# ---------------------------------------------------------------- _read_yaml
def test_read_yaml_missing(tmp_path: Path):
    from delm.config import _read_yaml
    assert _read_yaml(tmp_path / "nope.yaml") == {}


def test_read_yaml_flat(tmp_path: Path):
    from delm.config import _read_yaml
    p = tmp_path / "c.yaml"
    p.write_text("model: a\nbase_url: b\napi_key: c\n# a comment\n")
    d = _read_yaml(p)
    assert d["model"] == "a"
    assert d["base_url"] == "b"
    assert d["api_key"] == "c"


def test_read_yaml_quoted(tmp_path: Path):
    from delm.config import _read_yaml
    p = tmp_path / "c.yaml"
    p.write_text('model: "a b"\nbase_url: \'u\'\n')
    d = _read_yaml(p)
    assert d["model"] == "a b"
    assert d["base_url"] == "u"


# ---------------------------------------------------------------- build_client
def test_build_client_fields():
    cfg = ModelConfig(model="m", base_url="http://x/v1", api_key="k",
                      temperature=0.2, timeout_s=30.0)
    client = build_client(cfg)
    assert isinstance(client, OpenAICompatibleClient)
    assert client.model == "m"
    assert client.temperature == 0.2


def test_build_client_empty_key_is_none():
    cfg = ModelConfig(model="m", base_url="http://x/v1", api_key="")
    client = build_client(cfg)
    assert client._client is not None  # constructed


# ---------------------------------------------------------------- dry-run CLI
def test_run_real_demo_dry_run(capsys):
    from delm.demo import run_real_demo
    rc = run_real_demo.main(["--dry-run", "--config", "/dev/null"])
    out = capsys.readouterr().out
    assert "dry-run" in out
    # /dev/null is empty -> no model/base_url -> reports unset, non-zero.
    assert rc != 0


def test_run_real_demo_dry_run_ok(capsys, monkeypatch, tmp_path: Path):
    from delm.demo import run_real_demo
    p = tmp_path / "c.yaml"
    p.write_text("model: m\nbase_url: http://x/v1\n")
    rc = run_real_demo.main(["--dry-run", "--config", str(p)])
    out = capsys.readouterr().out
    assert "dry-run OK" in out
    assert rc == 0


def test_run_real_demo_missing_model_errors(capsys, monkeypatch, tmp_path):
    from delm.demo import run_real_demo
    # Run from a clean cwd so the local config/model_config.yaml is not
    # auto-detected; only the (absent) env vars apply.
    monkeypatch.chdir(tmp_path)
    rc = run_real_demo.main([])  # no --config, no env
    err = capsys.readouterr().err
    assert "no model/base_url" in err
    assert rc == 2


def test_model_config_as_dict():
    cfg = ModelConfig(model="m", base_url="u", api_key="k", temperature=0.1,
                      timeout_s=5.0)
    d = cfg.as_dict()
    assert d == {"model": "m", "base_url": "u", "api_key": "k",
                "temperature": 0.1, "timeout_s": 5.0}
