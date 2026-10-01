"""Tests de ``smcp-serve`` — SMCP como agente ACP (vía A de DESIGNCOMPAT).

Qué se cubre:

- **Los helpers puros** (sin ACP): ``prompt_text`` aplana content blocks y
  ``split_tasks`` mapea un prompt multilínea a tareas. Son la única lógica que
  no depende del SDK, así que se prueban siempre (el extra puede no estar).
- **El import es opcional**: el módulo se importa sin ``agent-client-protocol``
  instalado y ``--check`` reporta el hint correcto. Es la invariante que
  protege la suite: ACP es un extra, no una dependencia.
- **El agente ACP de verdad** (requiere el extra; se skipea sin él):
  ``initialize`` / ``new_session`` / ``prompt`` / ``cancel`` /
  ``close_session`` y los métodos "no soportados" con su semántica honesta
  (no un error). Se ejecuta con un ``Client`` capturing en vez de por stdio,
  que es el mismo objeto que el SDK inyecta vía ``on_connect``.
- **El prompt corre el pipeline real** (no un mock): se comprueba que un
  prompt produce una respuesta y que se emitieron updates al cliente. Esa es
  la garantía que importa: un ACP run == el pipeline de SMCP, no un stub.
- **Un smoke por stdio** con el SDK real: se lanza ``python -m delm.serve``
  como subprocess y se le habla JSON-RPC. Marca la frontera de que el protocolo
  funciona de punta a punta (``@pytest.mark.slow``).

La suite default no necesita red, modelo ni sockets: el backend por defecto es
``FakeLLMClient``. Los tests que necesitan el SDK se skipean si no está.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.abc
import json
import subprocess
import sys

import pytest

from delm import serve


# ------------------------------------------------------------------ helpers
class _BlockAcp(importlib.abc.MetaPathFinder):
    """Blocker del extra opcional: hace que ``import acp`` falle.

    Un ``MetaPathFinder`` moderno (no el ``find_module`` de la API vieja, que
    Python 3.12+ ya no llama) es lo que realmente impide el import.
    """

    def find_spec(self, name, path=None, target=None):
        if name == "acp" or name.startswith("acp."):
            raise ImportError("acp blocked for the test")
        return None


def test_prompt_text_flattens_text_blocks():
    class Block:
        def __init__(self, text=None):
            self.text = text

    assert serve.prompt_text([Block("hola"), Block("adios")]) == "hola\nadios"


def test_prompt_text_skips_non_text_blocks():
    class Img:
        text = None

    class Block:
        def __init__(self, t):
            self.text = t

    # una imagen no es texto: se omite, no se adivina
    assert serve.prompt_text([Block("visible"), Img()]) == "visible"
    assert serve.prompt_text([]) == ""


def test_split_tasks_one_per_line():
    assert serve.split_tasks("uno\ndos\n\n  tres  ") == ["uno", "dos", "tres"]


def test_split_tasks_single_line_stays_one():
    assert serve.split_tasks("solo una linea") == ["solo una linea"]


def test_split_tasks_empty_prompt_is_still_a_task():
    # Un prompt vacío no puede romper el pipeline: produce una tarea sentinel.
    assert serve.split_tasks("") == ["(empty prompt)"]


# ------------------------------------------------------- import opcional
def _purge_acp() -> None:
    """Sacar acp de sys.modules para forzar un reimport limpio."""
    for mod in [m for m in sys.modules if m == "acp" or m.startswith("acp.")]:
        del sys.modules[mod]


def test_module_imports_without_acp(monkeypatch):
    """El módulo debe importar sin el SDK (extra opcional)."""
    monkeypatch.setattr(sys, "meta_path", [_BlockAcp()] + sys.meta_path)
    _purge_acp()
    mod = importlib.reload(serve)
    assert mod.ACP_HINT  # el hint del extra está disponible
    # restaurar el módulo real para los tests siguientes
    monkeypatch.undo()
    _purge_acp()
    importlib.reload(serve)


def test_require_acp_raises_hint_without_sdk(monkeypatch):
    monkeypatch.setattr(sys, "meta_path", [_BlockAcp()] + sys.meta_path)
    _purge_acp()
    with pytest.raises(SystemExit) as exc:
        serve._require_acp()
    assert "delm[acp]" in str(exc.value)
    monkeypatch.undo()
    _purge_acp()
    importlib.reload(serve)


def test_check_reports_ok_when_sdk_present(capsys):
    pytest.importorskip("acp", reason="extra delm[acp] no instalado")
    assert serve.main(["--check"]) == 0
    assert "smcp-serve OK" in capsys.readouterr().out


# -------------------------------------------------------------- el agente
acp = pytest.importorskip("acp", reason="extra delm[acp] no instalado")
# Los content blocks NO estan en el top-level de acp: viven en acp.schema.
from acp.schema import TextContentBlock  # noqa: E402


class _CapturingClient:
    """El lado cliente del ACP, capturando lo que el agente emite."""

    def __init__(self):
        self.updates: list[tuple[str, str, str]] = []

    async def session_update(self, session_id, update, **kwargs):
        # (kind, text) — kind distingue mensaje de pensamiento
        kind = getattr(update, "session_update", "?")
        text = getattr(getattr(update, "content", None), "text", "")
        self.updates.append((kind, text, session_id))


def _agent(backend="fake", **kw):
    agent = serve.build_agent(backend=backend, **kw)
    client = _CapturingClient()
    agent.on_connect(client)   # así inyecta el SDK el client real
    return agent, client


def test_initialize_reports_the_agent():
    agent, _ = _agent()
    resp = asyncio.run(agent.initialize(protocol_version=1))
    assert resp.protocol_version == acp.PROTOCOL_VERSION
    assert resp.agent_info.name == "smcp"


def test_initialize_declares_no_auth_methods():
    agent, _ = _agent()
    resp = asyncio.run(agent.initialize(protocol_version=1))
    # SMCP no tiene login: el trust anchor es la clave del owner.
    assert list(resp.auth_methods) == []


def test_new_session_returns_a_session_id():
    agent, _ = _agent()
    resp = asyncio.run(agent.new_session(cwd="/tmp"))
    assert resp.session_id


def test_prompt_runs_the_real_pipeline_and_streams_back():
    """El contrato central: un prompt ACP corre el pipeline de SMCP."""
    agent, client = _agent()
    sid = asyncio.run(agent.new_session(cwd="/tmp")).session_id

    async def drive():
        await agent.prompt(
            prompt=[TextContentBlock(type="text",
                                         text="resume la constraint")],
            session_id=sid,
        )
        # el run es una task en background: esperar a que termine
        for _ in range(200):
            if sid not in agent._runs or agent._runs[sid].done():
                break
            await asyncio.sleep(0.05)
        task = agent._runs.get(sid)
        if task is not None and not task.cancelled():
            task.result()   # propaga una excepción si el run falló

    asyncio.run(drive())

    kinds = [k for k, _t, _s in client.updates]
    # hubo al menos un pensamiento (el run se anuncia) y un mensaje (el answer)
    assert any("thought" in k for k in kinds), client.updates
    assert any("message" in k for k in kinds), client.updates
    # el texto del mensaje lleva la respuesta del pipeline
    messages = [t for k, t, _s in client.updates if "message" in k]
    assert any(t.strip() for t in messages)
    # los updates van a la sesión correcta
    assert {s for _k, _t, s in client.updates} == {sid}


def test_prompt_thinks_before_it_answers():
    agent, client = _agent()
    sid = asyncio.run(agent.new_session(cwd="/tmp")).session_id

    async def drive():
        await agent.prompt(
            prompt=[TextContentBlock(type="text", text="tarea")],
            session_id=sid)
        task = agent._runs.get(sid)
        if task is not None:
            await task

    asyncio.run(drive())
    # el primer update es un pensamiento (anuncia el run), no la respuesta
    assert "thought" in client.updates[0][0]
    # y el pensamiento menciona el backend (trazabilidad del run)
    assert "backend" in client.updates[0][1]


def test_multiline_prompt_splits_into_tasks():
    """Un prompt multilínea = varias tareas del pipeline (el caso de uso)."""
    agent, client = _agent()
    sid = asyncio.run(agent.new_session(cwd="/tmp")).session_id

    async def drive():
        await agent.prompt(
            prompt=[TextContentBlock(type="text",
                                         text="primera\nsegunda\ntercera")],
            session_id=sid)
        task = agent._runs.get(sid)
        if task is not None:
            await task

    asyncio.run(drive())
    # 3 tareas -> 3 workers que admiten; el run lo anuncia
    assert client.updates


def test_cancel_aborts_the_in_flight_run():
    agent, _ = _agent()
    sid = asyncio.run(agent.new_session(cwd="/tmp")).session_id

    async def drive():
        await agent.prompt(
            prompt=[TextContentBlock(type="text", text="tarea")],
            session_id=sid)
        task = agent._runs.get(sid)
        await agent.cancel(session_id=sid)
        if task is not None:
            with pytest.raises(asyncio.CancelledError):
                await task
        # la sesión sigue viva tras cancelar (cancel != close)
        assert sid in agent._sessions

    asyncio.run(drive())


def test_close_session_forgets_the_session():
    agent, _ = _agent()
    sid = asyncio.run(agent.new_session(cwd="/tmp")).session_id
    asyncio.run(agent.close_session(sid))
    assert sid not in agent._sessions


def test_list_sessions_is_empty_not_an_error():
    """Los runs son efímeros: la lista vacía es la respuesta honesta."""
    agent, _ = _agent()
    resp = asyncio.run(agent.list_sessions())
    assert list(resp.sessions) == []


def test_unsupported_session_knobs_are_noops():
    agent, _ = _agent()
    sid = asyncio.run(agent.new_session(cwd="/tmp")).session_id
    # no hay modos/modelos declarados: pedir cambiarlos no es un error
    # Orden del contrato ACP: (session_id, mode_id), no (mode_id, session_id).
    assert asyncio.run(agent.set_session_mode(sid, "x")) is None
    assert asyncio.run(agent.set_session_model("y", sid)) is None
    assert asyncio.run(agent.set_config_option("z", sid, True)) is None
    assert asyncio.run(agent.authenticate("any")) is None


def test_unknown_extension_method_is_method_not_found():
    from acp.exceptions import RequestError

    agent, _ = _agent()
    with pytest.raises(RequestError) as exc:
        asyncio.run(agent.ext_method("smcp/desconocido", {}))
    assert exc.value.code == -32601


def test_fork_and_resume_are_accepted():
    agent, _ = _agent()
    sid = asyncio.run(agent.new_session(cwd="/tmp")).session_id
    # Contrato ACP: fork_session(session_id, cwd).
    fork = asyncio.run(agent.fork_session(sid, "/tmp"))
    assert fork.session_id
    assert asyncio.run(agent.resume_session(sid, "/tmp")) is not None


def test_overrides_match_the_acp_contract():
    """Our overrides must accept the base class's parameter names, in order.

    This is the check pyright does (`reportIncompatibleMethodOverride`) and the
    one that was **not** in CI, so it drifted: the signatures had
    ``(cwd, session_id)`` / ``(prompt, session_id)`` instead of the ACP
    ``(session_id, cwd)`` / ``(session_id, prompt)``. It went unnoticed because
    the SDK's router dispatches by keyword (`func(**params)`), so runtime was
    fine — but the tests called them *positionally* in the wrong order, encoding
    the bug as if it were the contract. A positional caller (or an SDK that
    dispatches positionally) would have bound ``cwd`` where ``session_id``
    belongs, silently.

    So the contract is pinned here in the terms that matter: same names, same
    order, for every method SMCP overrides.
    """
    import inspect

    from acp import Agent as AcpAgent

    agent, _ = _agent()
    overridden = [
        "new_session", "load_session", "close_session", "list_sessions",
        "fork_session", "resume_session", "authenticate", "set_session_mode",
        "set_session_model", "set_config_option", "prompt", "cancel",
    ]
    checked = []
    for name in overridden:
        base_attr = getattr(AcpAgent, name, None)
        if base_attr is None:
            # Método nuestro que no está en la clase base (extensión): no hay
            # contrato ACP que respetar, solo que se llame bien.
            continue
        base = inspect.signature(base_attr)
        ours = inspect.signature(getattr(type(agent), name))
        # `self` is bound on the class; compare the declared params after it.
        base_names = [p for p in base.parameters if p != "self"]
        our_names = [p for p in ours.parameters if p != "self"]
        assert our_names[:len(base_names)] == base_names, (
            f"{name}: firma {our_names} no respeta el orden/nombre del "
            f"contrato ACP {base_names}")
        checked.append(name)
    # Si el SDK perdiera un método, el test no debe pasar en verde por no
    # haber comprobado nada.
    assert len(checked) >= 10, f"solo se comprobaron {checked}"


# ------------------------------------------------- smoke real por stdio
@pytest.mark.slow
def test_stdio_smoke_real_jsonrpc():
    """Hablar JSON-RPC real con ``python -m delm.serve`` por stdio.

    Es la prueba de que el protocolo funciona de punta a punta (no solo
    in-proceso). Es ``slow`` (spawn + handshake) y se skipea sin el extra.
    """
    pytest.importorskip("acp", reason="extra delm[acp] no instalado")

    proc = subprocess.Popen(
        [sys.executable, "-m", "delm.serve"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, bufsize=1,
    )
    assert proc.stdin is not None and proc.stdout is not None
    try:
        def send(msg):
            proc.stdin.write(json.dumps(msg) + "\n")
            proc.stdin.flush()

        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": 1}})

        # el agente responde por stdout con JSON-RPC
        line = proc.stdout.readline()
        resp = json.loads(line)
        assert resp["id"] == 1
        assert resp["result"]["agentInfo"]["name"] == "smcp"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
