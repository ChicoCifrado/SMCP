"""Tests de `delm mesh` — el intercambio a través de la CLI.

Por qué estos tests son distintos de los de `test_contrib.py`: aquí se prueba
la **superficie**, que es donde se cuelan los errores que el core no tiene —
estado compartido entre invocaciones, una identidad persistente por nodo, y
códigos de salida que un script pueda bifurcar sin parsear.

Concretamente se fija:

* ``contribute`` crea la identidad la primera vez y la **reutiliza** después (si
  regenerara la clave, ninguna contribución sería atribuible a nadie);
* el estado sobrevive entre invocaciones en un ``--state`` explícito, así que
  dos "nodos" distintos contra el mismo fichero se ven entre sí — que es
  exactamente lo que hace una malla real;
* ``plan`` dimensiona con llmfit cuando no se le da memoria, y **no** llama a
  llmfit cuando se le da (``--memory-gb``), que es la ruta que permite probar
  todo sin el binario externo;
* ``check`` detecta una cadena manipulada y sale con ``2``;
* ningún camino imprime la clave ni el fichero de identidad.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from delm.cli import DEFAULT_MESH_ID, main
from delm.core.contrib import ContributionLedger

MESH = "malla-test"


@pytest.fixture()
def state(tmp_path) -> Path:
    return tmp_path / "exchange.json"


def contribute(state: Path, ident: Path, peer: str, vram: float, *,
               seconds: float | None = None) -> int:
    rc = main(["mesh", "contribute", "--state", str(state), "--identity",
               str(ident), "--mesh-id", MESH, "--peer-id", peer,
               "--vram-gb", str(vram), "--ram-gb", "64", "--cpu-cores", "12"])
    if seconds:
        rc = rc or main(["mesh", "observe", "--state", str(state),
                         "--mesh-id", MESH, "--peer-id", peer,
                         "--seconds", str(seconds)])
    return rc


# --------------------------------------------------------------- el parser
def test_mesh_is_a_subcommand_with_its_actions(capsys):
    from delm.cli import build_parser

    help_txt = build_parser().format_help()
    assert "mesh" in help_txt
    assert "delm mesh contribute" in help_txt


def test_status_with_no_state_is_empty_not_an_error(state, capsys):
    assert main(["mesh", "status", "--state", str(state)]) == 0
    out = capsys.readouterr().out
    assert "ningún nodo" in out
    assert "aún no existe" in out


# ------------------------------------------------------------ contribute
def test_contribute_admits_and_persists(state, tmp_path, capsys):
    ident = tmp_path / "id.json"
    assert contribute(state, ident, "nodo-a", 16.0) == 0
    out = capsys.readouterr().out
    assert "contribución admitida" in out
    assert "ed25519" in out
    assert state.exists()

    # El estado se puede releer y contiene la capacidad admitida.
    led = ContributionLedger.load(str(state))
    assert led.mesh_id == MESH
    assert led.peers["nodo-a"].vram_gb == 16.0
    assert led.verify_chain() is True


def test_identity_is_created_once_and_reused(state, tmp_path, capsys):
    ident = tmp_path / "id.json"
    contribute(state, ident, "nodo-a", 16.0)
    capsys.readouterr()
    first = json.loads(ident.read_text(encoding="utf-8"))
    assert not ident.exists() or first["kind"] == "ed25519"

    # Segunda contribución: la misma clave, así que el nodo sigue siendo el mismo.
    assert contribute(state, ident, "nodo-a", 24.0) == 0
    capsys.readouterr()
    second = json.loads(ident.read_text(encoding="utf-8"))
    assert second["public_key"] == first["public_key"]
    led = ContributionLedger.load(str(state))
    assert led.peers["nodo-a"].vram_gb == 24.0
    assert led.peers["nodo-a"].reports == 2


def test_two_nodes_contribute_to_the_same_mesh_state(state, tmp_path, capsys):
    """Dos 'nodos' distintos, un solo estado: así se ve una malla de verdad."""
    contribute(state, tmp_path / "a.json", "nodo-a", 16.0, seconds=3600)
    contribute(state, tmp_path / "b.json", "nodo-b", 24.0, seconds=3600)
    capsys.readouterr()
    assert main(["mesh", "status", "--state", str(state), "--mesh-id", MESH]) == 0
    out = capsys.readouterr().out
    assert "nodo-a" in out and "nodo-b" in out
    assert "40.0G verificados" in out          # 16 + 24
    assert "íntegra" in out


def test_contribute_rejects_a_tampered_identity(tmp_path, state, capsys):
    """Una identidad editada a mano firma con otra clave: la malla lo rechaza."""
    ident = tmp_path / "id.json"
    contribute(state, ident, "nodo-a", 16.0)
    capsys.readouterr()
    blob = json.loads(ident.read_text(encoding="utf-8"))
    blob["private_key"] = "00" * 32
    ident.write_text(json.dumps(blob), encoding="utf-8")

    rc = contribute(state, ident, "nodo-a", 16.0)
    assert rc == 2
    err = capsys.readouterr().err
    assert "peer_key_changed" in err
    # Y la capacidad admitida no se mueve: un nombre no puede re-apuntarse a
    # otra clave para quedarse con el crédito del anterior.
    led = ContributionLedger.load(str(state))
    assert led.peers["nodo-a"].vram_gb == 16.0


def test_contribute_never_prints_the_private_key(state, tmp_path, capsys):
    ident = tmp_path / "id.json"
    contribute(state, ident, "nodo-a", 16.0)
    captured = capsys.readouterr()
    priv = json.loads(ident.read_text(encoding="utf-8"))["private_key"]
    assert priv not in captured.out
    assert priv[:32] not in captured.out
    assert "private_key" not in captured.out


# --------------------------------------------------------------- observe
def test_observe_requires_an_admitted_peer(state, tmp_path, capsys):
    rc = main(["mesh", "observe", "--state", str(state), "--mesh-id", MESH,
               "--peer-id", "fantasma", "--seconds", "60"])
    assert rc == 2
    assert "no está admitido" in capsys.readouterr().err


def test_observe_records_uptime_and_credits_nothing(state, tmp_path, capsys):
    """`delm mesh observe` anota cuanto tiempo se ve al nodo, y nada mas.

    Antes acreditaba VRAM x horas, de modo que una caja enchufada generaba
    valor sin servir. El comando lo dice en su propia salida para que nadie lo
    lea como un descuido.
    """
    ident = tmp_path / "id.json"
    contribute(state, ident, "nodo-a", 8.0)
    assert main(["mesh", "observe", "--state", str(state), "--mesh-id", MESH,
                 "--peer-id", "nodo-a", "--seconds", "3600"]) == 0
    out = capsys.readouterr().out
    assert "+3600s" in out
    assert "NO acredita nada" in out
    led = ContributionLedger.load(str(state))
    assert led.peers["nodo-a"].seconds_observed == 3600.0
    assert led.peers["nodo-a"].inferences_served == 0


def test_infer_counts_one_anchored_inference(state, tmp_path, capsys):
    """El camino del ingreso, y el replay que lo hace inutilizable."""
    ident = tmp_path / "id.json"
    contribute(state, ident, "nodo-a", 8.0)
    capsys.readouterr()
    args = ["mesh", "infer", "--state", str(state), "--mesh-id", MESH,
            "--peer-id", "nodo-a"]
    assert main(args + ["--txid", "ab" * 32, "--satoshis", "100"]) == 0
    assert "contada" in capsys.readouterr().out
    # El mismo txid otra vez: no cuenta, y el comando sale con 2.
    assert main(args + ["--txid", "ab" * 32]) == 2
    assert "no_anchor" in capsys.readouterr().err
    led = ContributionLedger.load(str(state))
    assert led.peers["nodo-a"].inferences_served == 1
    assert led.peers["nodo-a"].satoshis_earned == 100


def test_reputation_ranks_by_inferences_served(state, tmp_path, capsys):
    contribute(state, tmp_path / "a.json", "nodo-a", 8.0, seconds=60)
    contribute(state, tmp_path / "b.json", "nodo-b", 24.0, seconds=60)
    capsys.readouterr()
    for i in range(3):
        main(["mesh", "infer", "--state", str(state), "--mesh-id", MESH,
              "--peer-id", "nodo-a", "--txid", f"{i:02x}" * 32,
              "--satoshis", "100"])
    main(["mesh", "infer", "--state", str(state), "--mesh-id", MESH,
          "--peer-id", "nodo-b", "--txid", "ff" * 32, "--satoshis", "100"])
    capsys.readouterr()
    assert main(["mesh", "reputation", "--state", str(state), "--mesh-id", MESH,
                 "--peer-id", "nodo-b"]) == 0
    out = capsys.readouterr().out
    # Tres inferencias de una caja de 8 GiC baten a una de una de 24 GiB.
    assert out.index("nodo-a") < out.index("nodo-b")
    assert "es #2 de 2" in out
    assert "no se gasta" in out


# ------------------------------------------------------------------ plan
def test_plan_reports_the_mesh_cannot_fit_it(state, tmp_path, capsys):
    contribute(state, tmp_path / "id.json", "nodo-a", 16.0, seconds=3600)
    capsys.readouterr()
    rc = main(["mesh", "plan", "Qwen/Qwen3-32B", "--state", str(state),
               "--mesh-id", MESH, "--memory-gb", "40"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "rechazado" in out
    assert "faltan 24.0G" in out


def test_plan_splits_across_nodes(state, tmp_path, capsys):
    contribute(state, tmp_path / "a.json", "nodo-a", 16.0, seconds=3600)
    contribute(state, tmp_path / "b.json", "nodo-b", 24.0, seconds=3600)
    capsys.readouterr()
    rc = main(["mesh", "plan", "Qwen/Qwen3-32B", "--state", str(state),
               "--mesh-id", MESH, "--memory-gb", "36", "--layers", "64"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "2 nodo(s)" in out
    assert "0-63" not in out          # los rangos vienen en dos trozos
    assert "0-" in out
    assert "endpoint" in out


def test_plan_json_is_parseable_and_carries_the_stages(state, tmp_path, capsys):
    contribute(state, tmp_path / "a.json", "nodo-a", 16.0, seconds=3600)
    contribute(state, tmp_path / "b.json", "nodo-b", 24.0, seconds=3600)
    capsys.readouterr()
    assert main(["mesh", "plan", "m", "--state", str(state), "--mesh-id", MESH,
                 "--memory-gb", "36", "--json"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["ok"] is True
    assert plan["node_count"] == 2
    assert sum(s["memory_gb"] for s in plan["stages"]) == pytest.approx(36.0)
    assert plan["endpoint"].startswith("http")


def test_plan_without_llmfit_never_invocates_it(state, tmp_path, capsys,
                                                monkeypatch):
    """`--memory-gb` es la ruta que permite probar (y operar) sin llmfit."""
    import delm.core.llmfit as llmfit_mod

    def boom(*a, **k):  # pragma: no cover - debe fallar el test si se llama
        raise AssertionError("llmfit no debía invocarse con --memory-gb")

    monkeypatch.setattr(llmfit_mod.LlmfitRunner, "catalog", boom)
    monkeypatch.setattr(llmfit_mod.LlmfitRunner, "report", boom)
    contribute(state, tmp_path / "id.json", "nodo-a", 16.0, seconds=3600)
    capsys.readouterr()
    assert main(["mesh", "plan", "m", "--state", str(state), "--mesh-id", MESH,
                 "--memory-gb", "8"]) == 0
    assert "plan OK" in capsys.readouterr().out


def test_plan_uses_llmfit_to_size_when_no_memory_is_given(state, tmp_path,
                                                          capsys, monkeypatch):
    import delm.core.llmfit as llmfit_mod
    from delm.core.llmfit import FitReport

    payload = {"models": [{
        "name": "Qwen/Qwen3-30B-A3B", "params_b": 30.0,
        "memory_required_gb": 15.6, "best_quant": "Q3_K_M",
        "fit_level": "marginal", "estimated_tps": 34.9, "runtime": "llama.cpp",
    }], "total_models": 1}
    monkeypatch.setattr(llmfit_mod.LlmfitRunner, "catalog",
                        lambda self, **kw: FitReport.from_payload(payload))
    contribute(state, tmp_path / "id.json", "nodo-a", 24.0, seconds=3600)
    capsys.readouterr()
    assert main(["mesh", "plan", "Qwen/Qwen3-30B-A3B", "--state", str(state),
                 "--mesh-id", MESH]) == 0
    out = capsys.readouterr().out
    assert "15.6G requeridos" in out
    assert "Q3_K_M" not in out      # el quant no se imprime en el plan


def test_plan_of_an_unknown_model_explains_the_escape_hatch(state, tmp_path,
                                                            capsys, monkeypatch):
    import delm.core.llmfit as llmfit_mod
    from delm.core.llmfit import FitReport

    monkeypatch.setattr(llmfit_mod.LlmfitRunner, "catalog",
                        lambda self, **kw: FitReport.from_payload({"models": []}))
    rc = main(["mesh", "plan", "no-existe", "--state", str(state),
               "--mesh-id", MESH])
    assert rc == 2
    err = capsys.readouterr().err
    assert "no está en el catálogo" in err
    assert "--memory-gb" in err


def test_plan_forwards_hardware_overrides_to_llmfit(state, tmp_path, capsys,
                                                    monkeypatch):
    import delm.core.llmfit as llmfit_mod
    from delm.core.llmfit import FitReport

    seen: dict = {}

    def catalog(self, **kw):
        seen.update(kw)
        return FitReport.from_payload({"models": []})

    monkeypatch.setattr(llmfit_mod.LlmfitRunner, "catalog", catalog)
    main(["mesh", "plan", "x", "--state", str(state), "--mesh-id", MESH,
          "--memory", "24G", "--ram", "64G", "--cpu-cores", "8"])
    capsys.readouterr()
    assert seen["memory"] == "24G" and seen["ram"] == "64G"
    assert seen["cpu_cores"] == 8


def test_an_unobserved_node_is_not_plannable_even_diagnostically(state,
                                                                 tmp_path,
                                                                 capsys):
    """`--no-provider` salta la política, no la observación.

    Un nodo al que la malla no está viendo no puede servir inferencia, así que
    no recibe un stage ni en modo diagnóstico. La válvula de escape existe
    para la **política de proveedores**, no para la liveness.
    """
    contribute(state, tmp_path / "id.json", "nodo-a", 16.0)   # sin observe
    capsys.readouterr()
    for extra in ([], ["--no-provider"]):
        rc = main(["mesh", "plan", "m", "--state", str(state), "--mesh-id", MESH,
                   "--memory-gb", "8"] + extra)
        assert rc == 2
        assert "peer_not_observed" in capsys.readouterr().out


# ----------------------------------------------------------------- check
def test_check_without_state_fails_cleanly(tmp_path, capsys):
    rc = main(["mesh", "check", "--state", str(tmp_path / "nope.json")])
    assert rc == 2
    assert "no hay estado" in capsys.readouterr().err


def test_check_passes_on_a_honest_ledger(state, tmp_path, capsys):
    contribute(state, tmp_path / "id.json", "nodo-a", 8.0, seconds=600)
    capsys.readouterr()
    assert main(["mesh", "check", "--state", str(state), "--mesh-id", MESH]) == 0
    out = capsys.readouterr().out
    assert "íntegra" in out
    # El informe ya no habla de saldos:_historial y la cadena de hashes.
    assert "historial" in out
    assert "saldos" not in out
    # Y dice lo que no prueba: es la mitad del contrato de este comando.
    assert "NO prueba" in out
    assert "atestación de hardware" in out


def test_check_detects_a_tampered_chain(state, tmp_path, capsys):
    contribute(state, tmp_path / "a.json", "nodo-a", 8.0, seconds=600)
    contribute(state, tmp_path / "b.json", "nodo-b", 8.0, seconds=600)
    capsys.readouterr()
    blob = json.loads(state.read_text(encoding="utf-8"))
    blob["records"][0]["digest"] = "0" * 64
    state.write_text(json.dumps(blob), encoding="utf-8")

    rc = main(["mesh", "check", "--state", str(state), "--mesh-id", MESH])
    assert rc == 2
    assert "ALTERADA" in capsys.readouterr().out


def test_check_lists_rejections(state, tmp_path, capsys):
    contribute(state, tmp_path / "id.json", "nodo-a", 8.0, seconds=600)
    capsys.readouterr()
    # Una aportación sin firmar: la malla la rechaza y lo deja escrito.
    from delm.core.contrib import CapacityReport
    led = ContributionLedger.load(str(state))
    led.admit(CapacityReport(mesh_id=MESH, peer_id="nodo-a", vram_gb=999.0,
                     vram_advertised_gb=999.0,
                             nonce="nunca", issued_at=0.0, expires_at=9e9),
              now=1.0)
    led.save(str(state))
    assert main(["mesh", "check", "--state", str(state), "--mesh-id", MESH]) == 0
    out = capsys.readouterr().out
    assert "rechazos  : 1" in out
    assert "signature_invalid" in out


# ------------------------------------------------------------ otras mallas
def test_state_from_another_mesh_is_not_mixed_in(state, tmp_path, capsys):
    """Los nonces y la cadena son por malla: mezclarlos sería contabilidad falsa."""
    contribute(state, tmp_path / "id.json", "nodo-a", 16.0, seconds=60)
    capsys.readouterr()
    assert main(["mesh", "status", "--state", str(state),
                 "--mesh-id", "otra-malla"]) == 0
    out = capsys.readouterr().out
    assert "otra-malla" in out
    assert "ningún nodo" in out       # no hereda los saldos de la otra


def test_corrupt_state_does_not_crash_the_cli(state, tmp_path, capsys):
    state.write_text("{no es json", encoding="utf-8")
    assert main(["mesh", "status", "--state", str(state), "--mesh-id", MESH]) == 0
    cap = capsys.readouterr()
    assert "ilegible o corrupto" in cap.err
    assert "ningún nodo" in cap.out


def test_default_mesh_id_is_used_when_not_given(tmp_path, capsys):
    assert main(["mesh", "status", "--state", str(tmp_path / "s.json")]) == 0
    assert DEFAULT_MESH_ID in capsys.readouterr().out


# ------------------------------------------------------- el entry point real
def test_python_m_delm_mesh_runs_as_a_subprocess(tmp_path):
    """`python -m delm mesh` es el mismo parser (contrato público de la CLI)."""
    p = subprocess.run(
        [sys.executable, "-m", "delm", "mesh", "status", "--state",
         str(tmp_path / "s.json")],
        capture_output=True, text=True, timeout=120,
    )
    assert p.returncode == 0, p.stderr
    assert "smcp mesh" in p.stdout
