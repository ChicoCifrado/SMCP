"""Tests de la integración llmfit (`delm fit`, `delm.core.llmfit`).

Qué se cubre y por qué:

* **El runner nunca depende del binario real.** Los tests inyectan un ejecutable
  *falso* (un script que imprime un JSON fijo) vía ``--llmfit-bin``, así que la
  suite es determinista, sin red y sin máquina con GPU. Un llmfit de verdad solo
  se ejercita en el test opcional marcado ``slow``/``opt-in`` (si el binario
  está instalado), igual que `test_meshllm_wiring.py` con la malla.
* **Los flags se ensamblan en el orden que llmfit exige** (globales *antes* del
  subcomando, opciones *después*). Un orden plano es el bug más fácil de
  colar aquí: llmfit sale con ``2`` y el mensaje no lo dice.
* **Ausencia de llmfit es un estado de primera clase**: exit ``3`` con hint de
  instalación, nunca un traceback — ni cuando ``$DELM_LLMFIT_BIN`` apunta a un
  binario roto (eso es error de configuración, no motivo para caer al PATH).
* **El veredicto `--check`**: el modelo de la config, si cabe o no, y el código
  de salida (0 cabe / 2 no cabe / 0 desconocido). Y el caso que justifica el
  diseño: `--check` debe ver las filas que la tabla *oculta* (`too_tight`).
* **El render y el YAML** son deterministas y no filtran secretos.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest

from delm.cli import EXIT_LLMFIT, main
from delm.core.llmfit import (
    FitReport,
    FitRow,
    LlmfitFailed,
    LlmfitNotFound,
    LlmfitRunner,
    ModelFitVerdict,
    SystemProfile,
    local_config_yaml,
    verdict_for,
)


# ------------------------------------------------------------- payload fake
SYSTEM = {
    "total_ram_gb": 62.2,
    "available_ram_gb": 41.0,
    "cpu_cores": 14,
    "cpu_name": "Intel(R) Core(TM) Ultra 7 165U",
    "has_gpu": True,
    "gpu_name": "NVIDIA GeForce RTX 4060 Ti",
    "gpu_vram_gb": 16.0,
    "gpu_available_gb": 15.1,
    "gpu_count": 1,
    "unified_memory": False,
    "backend": "CUDA",
}

#: The fake payload speaks the *real* llmfit 1.1.16 CLI vocabulary on purpose:
#: human strings under `fit_level`/`run_mode`/`runtime` ("Too Tight" with a
#: space, "CPU+GPU", "llama.cpp", "vLLM") and the use case under `category`.
#: Parsing those is exactly what breaks if the adapter is only ever tested
#: against tidy machine codes.
MODELS = [
    {"name": "Qwen/Qwen2.5-Coder-7B-Instruct", "provider": "Qwen",
     "params_b": 7.0, "use_case": "Code generation and completion",
     "category": "Coding", "fit_level": "Perfect",
     "fit_label": "Perfect", "run_mode": "GPU", "runtime": "llama.cpp",
     "best_quant": "Q5_K_M", "score": 86.5, "estimated_tps": 42.5,
     "memory_required_gb": 5.8, "memory_available_gb": 15.1,
     "disk_size_gb": 5.1, "effective_context_length": 8192,
     "estimate_confidence": "estimated", "installed": True,
     "ollama_name": "qwen2.5-coder:7b-instruct"},
    {"name": "unsloth/Qwen3.8-27B-GGUF", "provider": "Unsloth",
     "params_b": 27.0, "use_case": "General purpose",
     "category": "General", "fit_level": "Marginal",
     "fit_label": "Marginal", "run_mode": "CPU+GPU", "runtime": "llama.cpp",
     "best_quant": "UD-Q2_K_XL", "score": 71.0, "estimated_tps": 11.0,
     "memory_required_gb": 13.9, "memory_available_gb": 15.1,
     "disk_size_gb": 12.4, "effective_context_length": 4096,
     "estimate_confidence": "calibrated", "installed": False},
    {"name": "meta-llama/Llama-4-405B-Instruct", "provider": "Meta",
     "params_b": 405.0, "use_case": "General purpose",
     "category": "General", "fit_level": "Too Tight",
     "fit_label": "Too Tight", "run_mode": "CPU", "runtime": "llama.cpp",
     "best_quant": "IQ1_S", "score": 40.0, "estimated_tps": 0.4,
     "memory_required_gb": 180.0, "memory_available_gb": 62.2,
     "disk_size_gb": 96.0, "effective_context_length": 2048,
     "estimate_confidence": "estimated"},
]


@pytest.fixture()
def fake_llmfit(tmp_path: Path, request) -> str:
    """An executable that answers *any* llmfit argv with a canned JSON report.

    It also records its argv to ``<dir>/argv.json`` so a test can assert the
    flag *order* llmfit was called with — the part of the integration that is
    easy to break and impossible to see from the rendered table.
    """
    payload = getattr(request, "param", None) or {"system": SYSTEM,
                                                  "models": MODELS,
                                                  "total_models": len(MODELS)}
    record = tmp_path / "argv.json"
    script = tmp_path / "llmfit-fake"
    script.write_text(textwrap.dedent(f"""\
        #!/usr/bin/env python3
        import json, os, sys
        with open({str(record)!r}, "w") as fh:
            json.dump(sys.argv[1:], fh)
        if "--boom" in sys.argv or os.environ.get("FAKE_LLMFIT_BOOM"):
            sys.stderr.write("error: hardware detection failed\\n")
            sys.exit(3)
        print(json.dumps(json.loads({json.dumps(json.dumps(payload))})))
    """), encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP)
    return str(script)


@pytest.fixture()
def argv_of(fake_llmfit: str) -> Path:
    return Path(fake_llmfit).parent / "argv.json"


def _argv(record: Path) -> list[str]:
    """The argv the fake llmfit was called with (it records it as JSON)."""
    return json.loads(record.read_text(encoding="utf-8"))


# --------------------------------------------------------------- construccion
def test_system_profile_parses_and_renders():
    sys_ = SystemProfile.from_payload(SYSTEM)
    assert sys_.has_gpu and sys_.gpu_count == 1
    assert sys_.total_ram_gb == pytest.approx(62.2)
    text = sys_.render()
    assert "RTX 4060 Ti" in text and "62.2G RAM" in text and "14 nucleos" in text


def test_system_profile_tolerates_garbage():
    """A payload sin `system` (o con un `system` raro) no rompe el render."""
    empty = SystemProfile.from_payload(None)
    assert empty.has_gpu is False
    assert "(desconocido)" in empty.render()


def test_fit_row_maps_and_flags_runnable():
    row = FitRow.from_payload(MODELS[0])
    assert row.runnable and row.params_text() == "7B"
    assert row.quant_text() == "Q5_K_M" and row.mem_text() == "5.8G"
    assert row.tps_text() == "42.5 tok/s"
    tight = FitRow.from_payload(MODELS[2])
    assert not tight.runnable
    assert tight.tps_text() == "0.4 tok/s"


@pytest.mark.parametrize("raw,expected", [
    ("Perfect", "perfect"), ("Too Tight", "too_tight"), ("too_tight", "too_tight"),
    ("Marginal", "marginal"), ("Good", "good"), ("TOO TIGHT", "too_tight"),
    (None, ""), ("algo-nuevo", "algo-nuevo"),
])
def test_fit_level_is_normalized_to_a_machine_code(raw, expected):
    """El JSON de la CLI de llmfit dice "Too Tight"; su API REST, "too_tight".

    Sin reconciliar los dos vocabularios, `--min-fit` y el exit code de
    `--check` fallarian en silencio contra el binario real.
    """
    assert FitRow.from_payload({"name": "m", "fit_level": raw}).fit_level == expected


@pytest.mark.parametrize("raw,expected", [
    ("llama.cpp", "llamacpp"), ("LlamaCpp", "llamacpp"), ("vLLM", "vllm"),
    ("bitnet.cpp", "bitnetcpp"), ("MLX", "mlx"), ("llamacpp", "llamacpp"),
    (None, ""),
])
def test_runtime_is_normalized_to_a_machine_code(raw, expected):
    assert FitRow.from_payload({"name": "m", "runtime": raw}).runtime == expected


@pytest.mark.parametrize("raw,expected", [
    ("GPU", "gpu"), ("CPU", "cpu"), ("CPU+GPU", "cpu+gpu"), ("MoE", "moe"),
    ("cpu_offload", "cpu+gpu"), ("cpu_only", "cpu"),
])
def test_run_mode_is_normalized(raw, expected):
    assert FitRow.from_payload({"name": "m", "run_mode": raw}).run_mode == expected



def test_fit_row_missing_fields_render_as_question_mark():
    row = FitRow.from_payload({"name": "m"})
    assert row.params_text() == "?" and row.tps_text() == "?"
    assert row.quant_text() == "-"
    assert row.render().startswith("m")


def test_fit_report_render_is_deterministic_and_faithful():
    """`render()` pinta lo que se le da: quien estrecha es `filtered()`.

    Un render que ocultara filas por su cuenta haría imposible depurar por qué
    un modelo no aparece; el estrechamiento es explícito (y el CLI lo hace).
    """
    report = FitReport.from_payload({"system": SYSTEM, "models": MODELS,
                                     "total_models": 3})
    out = report.render()
    assert out == report.render()                     # sin aleatoriedad
    assert "Qwen2.5-Coder-7B-Instruct" in out
    assert "Too Tight" in out                         # fiel a lo recibido
    assert "fit OK" in out
    # ... y el estrechamiento por defecto es lo que quita lo que no cabe.
    assert "Too Tight" not in report.filtered().render()
    assert report.filtered(include_too_tight=True).render().count("\n") > \
        report.filtered().render().count("\n")


def test_render_reports_an_empty_catalog_instead_of_a_bare_table():
    out = FitReport(system=SystemProfile.from_payload(SYSTEM)).render()
    assert "sin filas" in out


def test_render_singularizes_and_never_claims_missing_rows():
    """Con filtros de lado SMCP, el total es el del catálogo: hay que decirlo."""
    report = FitReport.from_payload({"models": MODELS, "total_models": 9872})
    one = report.top(1).render()
    assert "1 fila (catálogo: 9872 modelos)" in one
    assert "top 1 de 9872" not in one          # sería una lectura falsa
    assert "2 filas" in report.top(2).render()




# -------------------------------------------------------------------- filtros
def test_filtered_drops_too_tight_unless_asked():
    report = FitReport.from_payload({"models": MODELS})
    assert [r.fit_level for r in report.filtered()] == ["perfect", "marginal"]
    assert len(report.filtered(include_too_tight=True)) == 3


def test_filtered_honours_min_fit_runtime_search():
    report = FitReport.from_payload({"models": MODELS})
    assert len(report.filtered(min_fit="perfect")) == 1
    assert len(report.filtered(runtime="vllm")) == 0
    assert len(report.filtered(runtime="llamacpp", include_too_tight=True)) == 3
    assert len(report.filtered(search="qwen")) == 2
    # Por proveedor, y buscando solo entre lo que cabe: el 405B es de Meta pero
    # no entra ni con --all.
    assert len(report.filtered(search="meta", include_too_tight=True)) == 1
    assert len(report.filtered(search="meta")) == 0


def test_filtered_matches_the_use_case_against_category_and_description():
    """`category` es el enum de llmfit; `use_case`, texto libre. Se buscan los dos."""
    report = FitReport.from_payload({"models": MODELS})
    assert [r.name for r in report.filtered(use_case="coding")] == \
        [MODELS[0]["name"]]
    assert len(report.filtered(use_case="General")) == 1          # el marginal
    assert len(report.filtered(use_case="General", include_too_tight=True)) == 2

    # Solo aparece en la descripción libre, no en la categoría.
    assert len(report.filtered(use_case="code generation")) == 1
    assert len(report.filtered(use_case="razonamiento-inexistente")) == 0




def test_filtered_sorts():
    report = FitReport.from_payload({"models": MODELS})
    by_tps = report.filtered(sort_by="tps", include_too_tight=True)
    assert [r.estimated_tps for r in by_tps] == [42.5, 11.0, 0.4]
    by_name = report.filtered(sort_by="name", include_too_tight=True)
    assert by_name.models[0].name.startswith("meta-llama")


def test_top_slices_and_by_name_matches_normalized():
    report = FitReport.from_payload({"models": MODELS})
    assert len(report.top(2)) == 2
    # Id de runtime served: prefijo de org y sufijo de quant no estan en el
    # nombre del catalogo, pero apuntan al mismo modelo.
    assert report.by_name("Qwen/Qwen2.5-Coder-7B-Instruct-GGUF:Q5_K_M").name == \
        MODELS[0]["name"]


# -------------------------------------------------------------------- verdicts
def test_verdict_says_fits_for_a_runnable_model():
    report = FitReport.from_payload({"models": MODELS})
    v = verdict_for("Qwen/Qwen2.5-Coder-7B-Instruct", report)
    assert isinstance(v, ModelFitVerdict)
    assert v.matched and v.runnable and v.exit_code() == 0
    # El label humano, no el código de máquina.
    assert v.verdict_text().endswith(": Perfect")
    assert v.best_quant == "Q5_K_M" and v.estimated_tps == 42.5
    assert v.suggestions == ()          # cabe: no hay nada que sugerir


def test_verdict_falls_back_to_the_machine_code_when_there_is_no_label():
    """`llmfit fit --json` pone el código bajo la misma clave: es normal."""
    row = dict(MODELS[0])
    row.pop("fit_label")
    v = verdict_for(row["name"], FitReport.from_payload({"models": [row]}))
    assert v.verdict_text().endswith(": perfect")



def test_verdict_flags_a_model_that_does_not_fit_and_suggests():
    report = FitReport.from_payload({"models": MODELS})
    v = verdict_for("meta-llama/Llama-4-405B-Instruct", report)
    assert v.matched and not v.runnable
    assert v.exit_code() == 2
    assert "NO cabe" in v.verdict_text()
    assert v.suggestions[0] == MODELS[0]["name"]


def test_verdict_resolves_a_served_local_id_to_its_catalog_row():
    """El id que sirve un runtime local no es el nombre del catalogo.

    `unsloth/Qwen3.8-27B-GGUF:UD-Q2_K_XL` (lo que un llama.cpp/MeshLLM expone)
    se normaliza al `unsloth/Qwen3.8-27B-GGUF` del catalogo: sin eso, el
    `--check` de una config local real no encontraria nunca su modelo.
    """
    report = FitReport.from_payload({"models": MODELS})
    v = verdict_for("unsloth/Qwen3.8-27B-GGUF:UD-Q2_K_XL", report)
    assert v.matched and v.row_name == "unsloth/Qwen3.8-27B-GGUF"
    assert v.fit_level == "marginal" and v.runnable


def test_verdict_unknown_model_is_not_a_failure():
    """Un id que no esta en el catalogo se informa, no falla.

    La config manda y llmfit asesora: un modelo que no este en su catalogo no es
    motivo para bloquear un pipeline.
    """
    report = FitReport.from_payload({"models": MODELS})
    v = verdict_for("mi-org/mi-modelo-privado-v3", report)
    assert not v.matched
    assert v.exit_code() == 0
    assert "no esta en el catalogo" in v.verdict_text()



def test_verdict_of_empty_model_is_unknown():
    assert verdict_for("", FitReport()).matched is False


# --------------------------------------------------------------------- runner
def test_command_prefix_prefers_explicit_binary(fake_llmfit):
    assert LlmfitRunner(fake_llmfit).command_prefix() == [fake_llmfit]


def test_command_prefix_honors_the_env_var(fake_llmfit, monkeypatch):
    monkeypatch.setenv("DELM_LLMFIT_BIN", fake_llmfit)
    assert LlmfitRunner().command_prefix() == [fake_llmfit]


def test_broken_env_var_is_a_config_error_not_a_fallback(fake_llmfit,
                                                          monkeypatch):
    """Un binario explicito que no existe NO debe caer al PATH en silencio."""
    monkeypatch.setenv("DELM_LLMFIT_BIN", "/no/existe/llmfit")
    with pytest.raises(LlmfitNotFound) as exc:
        LlmfitRunner().command_prefix()
    assert "DELM_LLMFIT_BIN" in str(exc.value)


def test_missing_llmfit_raises_with_an_install_hint(monkeypatch, tmp_path):
    monkeypatch.delenv("DELM_LLMFIT_BIN", raising=False)
    monkeypatch.setattr("shutil.which", lambda _n: None)
    monkeypatch.setattr("importlib.util.find_spec", lambda _n: None)
    with pytest.raises(LlmfitNotFound) as exc:
        LlmfitRunner().command_prefix()
    assert "llmfit" in str(exc.value) and "install" in str(exc.value).lower()


def test_run_json_parses_and_appends_json_flag(fake_llmfit, argv_of):
    payload = LlmfitRunner(fake_llmfit).run_json(["fit", "-n", "3"])
    assert payload["total_models"] == 3
    assert _argv(argv_of) == ["fit", "-n", "3", "--json"]


def test_run_json_reports_a_failing_llmfit(fake_llmfit):
    with pytest.raises(LlmfitFailed) as exc:
        LlmfitRunner(fake_llmfit).run_json(["--boom"])
    assert exc.value.returncode == 3
    assert "hardware detection failed" in str(exc.value)


def test_run_json_rejects_non_json_output(tmp_path):
    script = tmp_path / "llmfit-chatty"
    script.write_text("#!/bin/sh\necho 'not json at all'\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(LlmfitFailed) as exc:
        LlmfitRunner(str(script)).run_json(["fit"])
    assert "no emitio JSON" in str(exc.value)


def test_run_json_rejects_a_json_array(tmp_path):
    script = tmp_path / "llmfit-array"
    script.write_text("#!/bin/sh\necho '[1,2,3]'\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(LlmfitFailed) as exc:
        LlmfitRunner(str(script)).run_json(["fit"])
    assert "se esperaba un objeto" in str(exc.value)


def test_run_json_times_out(tmp_path):
    script = tmp_path / "llmfit-hang"
    script.write_text("#!/bin/sh\nsleep 5\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(LlmfitFailed) as exc:
        LlmfitRunner(str(script), timeout_s=0.3).run_json(["fit"])
    assert "tardo mas de" in str(exc.value)


def test_catalog_orders_global_flags_before_the_subcommand(fake_llmfit, argv_of):
    LlmfitRunner(fake_llmfit).catalog(limit=5, profile="ryzen-ai-max-plus-395",
                                      memory="24G", ram="64G", cpu_cores=8,
                                      max_context=8192)
    assert _argv(argv_of) == [
        "--profile", "ryzen-ai-max-plus-395",   # bloque global, ANTES del sub
        "--memory", "24G",
        "--ram", "64G",
        "--cpu-cores", "8",
        "--max-context", "8192",
        "fit",                                   # subcomando
        "-n", "5",                               # flags del subcomando
        "--json",
    ]


def test_catalog_passes_no_filter_flag_to_the_binary(fake_llmfit, argv_of):
    """El binario solo recibe hardware global + `-n`; los filtros son nuestros.

    En llmfit 1.1.16 `llmfit fit --use-case|--min-fit|--runtime|--search`
    salen con 2 (*unexpected argument*): viven en `recommend`, que a su vez no
    devuelve filas `too_tight`. Por eso el reparto es fetch / narrow.
    """
    LlmfitRunner(fake_llmfit).catalog()
    assert _argv(argv_of) == ["fit", "--json"]


def test_report_only_pushes_the_limit_down_for_a_pure_top_n(fake_llmfit,
                                                             argv_of):
    """Pedir N filas a llmfit y filtrar después devuelve menos de N: no se hace."""
    LlmfitRunner(fake_llmfit).report(limit=5, include_too_tight=True)
    assert _argv(argv_of) == ["fit", "-n", "5", "--json"]

    LlmfitRunner(fake_llmfit).report(limit=5, use_case="coding")
    assert _argv(argv_of) == ["fit", "--json"]       # sin -n: filtramos nosotros


def test_report_narrows_client_side(fake_llmfit):
    """`report()` es la vista: por defecto fuera lo que no cabe."""
    runner = LlmfitRunner(fake_llmfit)
    assert [r.fit_level for r in runner.report(limit=9)] == ["perfect",
                                                              "marginal"]
    assert len(runner.report(limit=9, include_too_tight=True)) == 3
    assert len(runner.report(limit=9, perfect=True)) == 1
    assert len(runner.report(limit=9, use_case="coding")) == 1
    assert len(runner.report(limit=9, min_fit="good")) == 1
    assert runner.report(limit=1).models[0].name == MODELS[0]["name"]




def test_system_command(fake_llmfit, argv_of):
    profile = LlmfitRunner(fake_llmfit).system(ram="128G", cpu_cores=16)
    assert _argv(argv_of) == ["--ram", "128G", "--cpu-cores", "16",
                                   "system", "--json"]
    assert profile.gpu_name == "NVIDIA GeForce RTX 4060 Ti"


def test_plan_command(fake_llmfit, argv_of):
    LlmfitRunner(fake_llmfit).plan("Qwen/Qwen3-4B-MLX-4bit", context=8192,
                                   quant="mlx-4bit", target_tps=25)
    assert _argv(argv_of) == ["plan", "Qwen/Qwen3-4B-MLX-4bit",
                              "--context", "8192", "--quant", "mlx-4bit",
                              "--target-tps", "25", "--json"]



# -------------------------------------------------------------------- la CLI
def test_cli_fit_renders_the_table(fake_llmfit, capsys):
    assert main(["fit", "--llmfit-bin", fake_llmfit, "-n", "2"]) == 0
    out = capsys.readouterr().out
    assert "=== delm fit ===" in out
    assert "RTX 4060 Ti" in out
    assert "Qwen2.5-Coder-7B-Instruct" in out
    assert out.count("tok/s") == 2           # exactamente las 2 filas pedidas
    assert "Too Tight" not in out


def test_cli_fit_all_includes_unrunnable_rows(fake_llmfit, capsys):
    assert main(["fit", "--llmfit-bin", fake_llmfit, "--all", "-n", "9"]) == 0
    assert "Too Tight" in capsys.readouterr().out


def test_cli_fit_json_is_parseable(fake_llmfit, capsys):
    assert main(["fit", "--llmfit-bin", fake_llmfit, "--json", "-n", "1"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["system"]["gpu_name"] == "NVIDIA GeForce RTX 4060 Ti"
    assert len(payload["models"]) == 1
    assert "api_key" not in json.dumps(payload)   # el payload es fit, no config


def test_cli_fit_search_and_sort(fake_llmfit, capsys):
    assert main(["fit", "--llmfit-bin", fake_llmfit, "--search", "qwen",
                 "--sort", "params", "-n", "5"]) == 0
    out = capsys.readouterr().out
    assert "Qwen2.5-Coder-7B-Instruct" in out
    assert "Qwen3.8-27B-GGUF" in out
    assert "Llama-4-405B" not in out


def test_cli_fit_check_passes_for_a_fitting_model(fake_llmfit, capsys,
                                                   monkeypatch):
    monkeypatch.setenv("DELM_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
    monkeypatch.setenv("DELM_BASE_URL", "http://127.0.0.1:8080/v1")
    assert main(["fit", "--llmfit-bin", fake_llmfit, "--check"]) == 0
    out = capsys.readouterr().out
    assert "check del modelo configurado" in out
    assert "Perfect" in out


def test_cli_fit_check_exits_2_when_the_model_does_not_fit(fake_llmfit, capsys,
                                                            monkeypatch):
    """El contrato de `config-check`: un shell bifurca sin parsear la salida."""
    monkeypatch.setenv("DELM_MODEL", "meta-llama/Llama-4-405B-Instruct")
    monkeypatch.setenv("DELM_BASE_URL", "http://127.0.0.1:8080/v1")
    assert main(["fit", "--llmfit-bin", fake_llmfit, "--check"]) == 2
    out = capsys.readouterr().out
    assert "NO cabe" in out
    assert "sugerencia: Qwen/Qwen2.5-Coder-7B-Instruct" in out


def test_cli_fit_check_sees_rows_the_table_hides(fake_llmfit, capsys,
                                                 monkeypatch):
    """`--check` no se queda ciego: el modelo que no cabe esta en la tabla
    filtrada, asi que el veredicto tiene que mirar el catalogo entero."""
    monkeypatch.setenv("DELM_MODEL", "meta-llama/Llama-4-405B-Instruct")
    assert main(["fit", "--llmfit-bin", fake_llmfit, "--check", "--json"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["check"]["matched"] is True
    assert payload["check"]["fit_level"] == "too_tight"
    assert payload["check"]["suggestions"] == [MODELS[0]["name"],
                                               MODELS[1]["name"]]



def test_cli_fit_check_unknown_model_is_not_a_failure(fake_llmfit, capsys,
                                                       monkeypatch):
    monkeypatch.setenv("DELM_MODEL", "mi/modelo-servido-local-v3")
    assert main(["fit", "--llmfit-bin", fake_llmfit, "--check"]) == 0
    assert "no esta en el catalogo" in capsys.readouterr().out


def test_cli_fit_check_with_unset_model_is_unknown(fake_llmfit, capsys,
                                                   monkeypatch):
    monkeypatch.delenv("DELM_MODEL", raising=False)
    assert main(["fit", "--llmfit-bin", fake_llmfit, "--check",
                 "--config", "/no/existe.yaml"]) == 0
    assert "no esta en el catalogo" in capsys.readouterr().out


def test_cli_fit_check_never_prints_the_api_key(fake_llmfit, capsys,
                                                monkeypatch):
    monkeypatch.setenv("DELM_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
    monkeypatch.setenv("DELM_API_KEY", "sk-secret-value-1234567890")
    main(["fit", "--llmfit-bin", fake_llmfit, "--check"])
    assert "sk-secret-value-1234567890" not in capsys.readouterr().out


def test_cli_fit_write_config(fake_llmfit, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "cfg" / "model_config.yaml"
    assert main(["fit", "--llmfit-bin", fake_llmfit, "--write-config",
                 str(target), "--base-url", "http://127.0.0.1:9337/v1"]) == 0
    text = target.read_text(encoding="utf-8")
    assert 'model: "Qwen/Qwen2.5-Coder-7B-Instruct"' in text
    assert 'base_url: "http://127.0.0.1:9337/v1"' in text
    # Y el resultado es una config que el propio repo sabe resolver.
    from delm.config import load_config
    cfg = load_config(target)
    assert cfg.model == "Qwen/Qwen2.5-Coder-7B-Instruct"
    assert cfg.base_url == "http://127.0.0.1:9337/v1"
    assert cfg.api_key == "dummy"          # placeholder local, no un secreto
    assert "Q5_K_M" in text                # el quant que eligió llmfit
    assert "escrito" in capsys.readouterr().out


def test_cli_fit_write_config_never_clobbers_without_force(fake_llmfit,
                                                           tmp_path, capsys):
    target = tmp_path / "model_config.yaml"
    target.write_text("model: no-tocar\n", encoding="utf-8")
    rc = main(["fit", "--llmfit-bin", fake_llmfit, "--write-config",
               str(target)])
    assert rc == 2
    assert target.read_text(encoding="utf-8") == "model: no-tocar\n"
    assert "--force" in capsys.readouterr().err
    # Con --force sí escribe.
    assert main(["fit", "--llmfit-bin", fake_llmfit, "--write-config",
                 str(target), "--force"]) == 0
    assert "Qwen2.5-Coder" in target.read_text(encoding="utf-8")


def test_cli_fit_write_config_refuses_when_nothing_fits(fake_llmfit, tmp_path,
                                                        capsys, monkeypatch):
    target = tmp_path / "model_config.yaml"
    monkeypatch.setenv("DELM_LLMFIT_BIN", fake_llmfit)
    rc = main(["fit", "--min-fit", "perfect", "--search", "llama-405-especifica",
               "--write-config", str(target)])
    assert rc == EXIT_LLMFIT
    assert not target.exists()
    assert "no se escribe" in capsys.readouterr().err


def test_cli_fit_missing_llmfit_is_actionable_not_a_traceback(monkeypatch,
                                                              capsys):
    monkeypatch.delenv("DELM_LLMFIT_BIN", raising=False)
    monkeypatch.setattr("shutil.which", lambda _n: None)
    monkeypatch.setattr("importlib.util.find_spec", lambda _n: None)
    assert main(["fit"]) == EXIT_LLMFIT
    err = capsys.readouterr().err
    assert "llmfit no esta instalado" in err
    assert "install" in err.lower()          # el hint trae la instalacion
    assert "Traceback" not in err


def test_cli_fit_reports_a_failing_llmfit(fake_llmfit, capsys, monkeypatch):
    """Un llmfit que sale con error se reporta como tal (exit 3), sin traceback."""
    monkeypatch.setenv("FAKE_LLMFIT_BOOM", "1")
    assert main(["fit", "--llmfit-bin", fake_llmfit]) == EXIT_LLMFIT
    err = capsys.readouterr().err
    assert "llmfit salio con 3" in err
    assert "hardware detection failed" in err



def test_cli_fit_is_in_the_help_and_the_examples():
    from delm.cli import build_parser
    help_txt = build_parser().format_help()
    assert "fit" in help_txt
    assert "delm fit --check" in help_txt


def test_cli_fit_uses_the_env_var_without_a_flag(fake_llmfit, capsys,
                                                 monkeypatch):
    monkeypatch.setenv("DELM_LLMFIT_BIN", fake_llmfit)
    assert main(["fit", "-n", "1"]) == 0
    assert "Qwen2.5-Coder-7B-Instruct" in capsys.readouterr().out


# ------------------------------------------------------------------ el YAML
def test_local_config_yaml_shape():
    row = FitRow.from_payload(MODELS[0])
    text = local_config_yaml(row, base_url="http://127.0.0.1:8080/v1")
    assert text.startswith("# Generated by")
    assert text.endswith("\n")
    assert "ollama pull qwen2.5-coder:7b-instruct" in text
    # Sin secretos: la key local es un placeholder, no un token real.
    assert 'api_key: "dummy"' in text
    # Timeout propio del cliente (300 s), no el que espera a llmfit.
    assert "timeout_s: 300.0" in text
    # Y el comentario del quant distingue disco de memoria residente: son
    # cifras distintas y confundirlas haría creer que falta VRAM.
    assert "Q5_K_M" in text and "5.1G en disco" in text
    assert "5.8G resident con 8192 tokens" in text
    assert "42.5 tok/s" in text


def test_local_config_yaml_timeout_is_overridable():
    text = local_config_yaml(FitRow(name="x"), base_url="http://h/v1",
                             timeout_s=90.0)
    assert "timeout_s: 90.0" in text


def test_local_config_yaml_survives_a_bare_row():
    text = local_config_yaml(FitRow(name="x"), base_url="http://h/v1")
    assert 'model: "x"' in text
    assert "# quant" not in text               # sin quant, no se inventa



# ------------------------------------------------------------------ opt-in
@pytest.mark.slow
def test_real_llmfit_if_installed():
    """Contra el llmfit de verdad, solo si esta instalado (opt-in, `slow`).

    No se puede exigir en CI: el binario es una dependencia opcional del host,
    igual que la malla en `test_meshllm_wiring.py`. Lo que se verifica aqui es
    solo el contrato: emite JSON con `models[]` y SMCP lo parsea.
    """
    runner = LlmfitRunner(timeout_s=180)
    try:
        report = runner.report(limit=3)
    except LlmfitNotFound:
        pytest.skip("llmfit no instalado (opcional)")
    assert report.total_models >= 0
    for row in report.models:
        assert row.name and row.fit_level in ("perfect", "good", "marginal",
                                              "too_tight")
