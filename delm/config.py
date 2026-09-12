"""Model configuration — point the pipeline at a real model endpoint.

The framework is model-agnostic: :class:`OpenAICompatibleClient` already
accepts any OpenAI-compatible endpoint. What was missing was a *concrete*
way to point the pipeline at one without hard-coding an API key in source.

This module provides that:

* :class:`ModelConfig` — an immutable value object: ``model``, ``base_url``,
  ``api_key``, ``temperature``, ``timeout_s``.
* :func:`load_config` — read a YAML file (optional) and overlay
  environment variables, so a secret never has to live in the repo.
* :func:`build_client` — turn a :class:`ModelConfig` into an
  :class:`~delm.core.llm.OpenAICompatibleClient`.

Precedence (highest wins):

1. environment variables (``DELM_MODEL``, ``DELM_BASE_URL``, ``DELM_API_KEY``,
   ``DELM_TEMPERATURE``, ``DELM_TIMEOUT``);
2. the YAML file, if given and present;
3. empty defaults (an ``api_key`` of ``""`` is legal — it can come from the
   environment at call time).

The YAML file is *optional*: an env-only configuration is first-class. A
committed example lives at ``config/model_config.yaml`` and ships an empty
``api_key`` on purpose.

This module only *produces* a client; it does not run the pipeline, so it
imports nothing from the core at module load (the ``openai`` SDK is imported
lazily inside :func:`build_client` via :mod:`delm.core.llm`).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "ModelConfig",
    "load_config",
    "build_client",
    "ENV_PREFIX",
    "DEFAULT_CONFIG_PATH",
]

ENV_PREFIX = "DELM"

#: Where a committed example config lives (relative to the project root).
DEFAULT_CONFIG_PATH = Path("config") / "model_config.yaml"


@dataclass(frozen=True)
class ModelConfig:
    """One concrete model endpoint the pipeline can run against.

    ``api_key`` is a plain field and is *not* validated here: an empty string
    is allowed so the value can be supplied purely by the environment.

    ``use_harness`` selects the agent runtime backend: when ``True``,
    :func:`build_client` returns a :class:`~delm.core.harness_client
    .HarnessLLMClient` (the DeepSeek Harness) instead of the plain
    OpenAI-compatible client. Opt-in — defaults to ``False`` so nothing
    changes unless the user asks for the harness.
    """

    model: str = ""
    base_url: str = ""
    api_key: str = ""
    temperature: float = 0.0
    timeout_s: float = 120.0
    use_harness: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "base_url": self.base_url,
            "api_key": self.api_key,
            "temperature": self.temperature,
            "timeout_s": self.timeout_s,
            "use_harness": self.use_harness,
        }


def _env() -> dict[str, str]:
    """Read the DELM_* environment variables as raw strings."""
    return {
        "model": os.environ.get(f"{ENV_PREFIX}_MODEL", ""),
        "base_url": os.environ.get(f"{ENV_PREFIX}_BASE_URL", ""),
        "api_key": os.environ.get(f"{ENV_PREFIX}_API_KEY", ""),
        "temperature": os.environ.get(f"{ENV_PREFIX}_TEMPERATURE", ""),
        "timeout": os.environ.get(f"{ENV_PREFIX}_TIMEOUT", ""),
        "harness": os.environ.get(f"{ENV_PREFIX}_HARNESS", ""),
    }


def _flag(raw) -> bool:
    """Parse a truthy ``1/true/yes/on/y`` (or actual bool) as True."""
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in ("1", "true", "yes", "on", "y")


def _coerce(raw: str, cast, default):
    """Parse a numeric env value; bad/empty input falls back to *default*."""
    if raw == "":
        return default
    try:
        return cast(raw)
    except (TypeError, ValueError):
        return default


def load_config(path: str | Path | None = None,
                env: dict[str, str] | None = None) -> ModelConfig:
    """Build a :class:`ModelConfig` from a YAML file and/or the environment.

    ``path`` may be ``None`` (env-only) or a path to a YAML file. A missing
    file is *not* an error: it contributes nothing, so env-only setups and
    partial files behave uniformly.
    """
    file_vals: dict[str, Any] = {}
    if path is not None:
        file_vals = _read_yaml(path)

    e = env if env is not None else _env()

    model = e["model"] or str(file_vals.get("model", ""))
    base_url = e["base_url"] or str(file_vals.get("base_url", ""))
    api_key = e["api_key"] or str(file_vals.get("api_key", ""))
    temperature = _coerce(
        e["temperature"], float, float(file_vals.get("temperature", 0.0)))
    timeout = _coerce(
        e["timeout"], float, float(file_vals.get("timeout_s", 120.0)))
    # Harness backend: explicit env flag wins; else the YAML field; else off.
    use_harness = (
        _flag(e["harness"])
        if e["harness"] != ""
        else bool(file_vals.get("use_harness", False))
    )

    return ModelConfig(
        model=model, base_url=base_url, api_key=api_key,
        temperature=temperature, timeout_s=timeout,
        use_harness=use_harness)


def _read_yaml(path: str | Path) -> dict[str, Any]:
    """Read a YAML config file into a flat dict (best-effort, no hard dep).

    PyYAML is preferred. If it is absent the file is parsed with a minimal
    ``key: value`` scanner that understands only the flat mapping the example
    uses. A parse failure returns ``{}`` so a malformed file degrades to "no
    file values" instead of crashing the caller.
    """
    p = Path(path)
    if not p.exists():
        return {}
    text = p.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except Exception:
        pass
    # Fallback: flat ``key: value`` lines.
    out: dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        out[key] = val
    return out


def build_client(config: ModelConfig):
    """Return the model client for *config*.

    Imported here so :mod:`delm.config` stays free of the client SDK imports
    at module load (``load_config`` is importable with nothing extra
    installed). When ``config.use_harness`` is set, this returns a
    :class:`~delm.core.harness_client.HarnessLLMClient` (the DeepSeek Harness
    agent runtime); otherwise the plain :class:`OpenAICompatibleClient`. Both
    implement :class:`delm.core.llm.LLMClient`, so the pipeline is unchanged.
    """
    if config.use_harness:
        from delm.core.harness_client import HarnessLLMClient
        harness_kwargs: dict[str, Any] = {"timeout": config.timeout_s}
        if config.base_url:
            harness_kwargs["base_url"] = config.base_url
        if config.api_key:
            harness_kwargs["api_key"] = config.api_key
        return HarnessLLMClient(model=config.model, **harness_kwargs)
    from delm.core.llm import OpenAICompatibleClient
    return OpenAICompatibleClient(
        model=config.model,
        base_url=config.base_url or None,
        api_key=config.api_key or None,
        temperature=config.temperature,
        timeout=config.timeout_s,
    )
