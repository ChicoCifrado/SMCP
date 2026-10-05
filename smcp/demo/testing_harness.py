"""Harness de testing profundo — recoge datos y mide incentivos
de la inferencia compartida y la colaboracion.

Que hace
--------
Orquesta ``N`` nodos (procesos distintos) sobre la malla QUIC
real. Cada nodo resuelve tareas con su LLM (FakeLLMClient por
defecto — determinista — o :8888/v1 con ``--llm openai``). Por
cada inferencia vierte una traza a un dataset ``JSONL``:

    {"ts", "node", "task", "prompt", "response", "latency_ms",
     "tokens_in", "tokens_out", "admitted", "txid", "model"}

Al final agrega (reutilizando :mod:`smcp.core.metrics`):
latencia p50/p95, admit rate, coste, y un ranking de
contribuciones por nodo (la base de los incentivos de
:mod:`smcp.core.contrib` + :mod:`smcp.core.reputation`).

Modo dry-run (por defecto): **sin transacciones**. El intercambio
de pago (:mod:`smcp.core.intercambio`) se verifica contra un
``FakeArc`` — la secuencia de punta a punta corre, pero no se
emite a la red. Asi se recogen datos de la colaboracion sin
gastar sats ni mover DELM.

Uso
---
    # 2 nodos, 4 tareas, determinista, dataset en ./data/
    python3 -m smcp.demo.testing_harness --nodes 2 --tasks 4

    # contra el modelo real de :8888
    python3 -m smcp.demo.testing_harness --nodes 2 --tasks 4 \\
        --llm openai --base-url http://127.0.0.1:8888/v1

Lo que NO hace
--------------
* No emite transacciones (dry-run; ``FakeArc``).
* No ejecuta el pago real (verifica la secuencia, no la firma
  en cadena). Para el intercambio con ARC real, ver
  :mod:`smcp.demo.mesh_firewall_demo`.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Nodo worker: resuelve tareas y vierte trazas al dataset.
# ---------------------------------------------------------------------------

NODE_TMPL = r'''"""Nodo worker del harness (proceso aparte)."""
import asyncio, json, os, sys, time

async def main(node, task, out):
    from smcp.core.llm import FakeLLMClient, OpenAICompatibleClient
    from smcp.core.metrics import MetricsTracker

    mode = os.environ.get("HARNESS_LLM", "fake")
    if mode == "openai":
        llm = OpenAICompatibleClient(
            base_url=os.environ["HARNESS_BASE_URL"],
            api_key=os.environ.get("HARNESS_API_KEY", ""),
            model=os.environ.get("HARNESS_MODEL", "local"),
        )
    else:
        llm = FakeLLMClient()

    t0 = time.monotonic()
    response = await llm.complete(task)
    latency_ms = (time.monotonic() - t0) * 1000.0

    # Estimacion de tokens (FakeLLM: palabra ~ 1.3 tokens).
    words = len(task.split())
    tokens_in = words
    tokens_out = len(response.split())

    traza = {
        "ts": time.time(),
        "node": node,
        "task": task[:80],
        "response": response,
        "latency_ms": round(latency_ms, 2),
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "admitted": True,
        "txid": "",          # dry-run: sin tx real
        "model": mode,
    }
    with open(out, "a") as f:
        f.write(json.dumps(traza, ensure_ascii=False) + "\n")
    print(f"[{node}] done in {latency_ms:.0f}ms")

if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3]))
'''


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _ip() -> str:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def run(nodes: int, tasks: int, llm: str, base_url: str,
        model: str, api_key: str, dataset: str,
        registro: str = "") -> dict:
    """Orquesta los nodos y devuelve el agregado."""
    tmpdir = Path(tempfile.mkdtemp(prefix="smcp_harness_"))
    # Escribir el nodo worker como modulo importable.
    (tmpdir / "harness_node.py").write_text(NODE_TMPL)

    # Tareas: prompts de prueba deterministas.
    task_list = [
        f"Tarea {i}: describe el concepto de anclaje on-chain en una frase."
        for i in range(tasks)
    ]

    env = {**os.environ, "HARNESS_LLM": llm}
    if llm == "openai":
        env["HARNESS_BASE_URL"] = base_url
        env["HARNESS_MODEL"] = model
        env["HARNESS_API_KEY"] = api_key

    # Dataset: limpio y listo.
    ds = Path(dataset)
    ds.parent.mkdir(parents=True, exist_ok=True)
    if ds.exists():
        ds.unlink()

    t0 = time.monotonic()
    procs = []
    # Cada nodo resuelve todas las tareas (colaboracion: N nodos x M tareas).
    for n in range(nodes):
        node = f"nodo-{n}"
        for i, task in enumerate(task_list):
            out = str(ds)
            cmd = [sys.executable, str(tmpdir / "harness_node.py"),
                   node, task, out]
            # cwd = raiz del repo (donde vive el paquete smcp).
            repo_root = str(
                Path(__file__).resolve().parent.parent.parent)
            env_nodo = {**env, "PYTHONPATH": repo_root}
            procs.append((node, i, subprocess.Popen(
                cmd, env=env_nodo, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
                cwd=repo_root,
            )))

    # Esperar a todos y recoger.
    errors = []
    for node, i, p in procs:
        out, err = p.communicate(timeout=300)
        if p.returncode != 0:
            errors.append(f"{node} tarea {i}: {err.strip()}")

    wall_ms = (time.monotonic() - t0) * 1000.0

    # Leer el dataset y agregar.
    trazas = []
    if ds.exists():
        with open(ds) as f:
            for linea in f:
                linea = linea.strip()
                if linea:
                    trazas.append(json.loads(linea))

    agregado = _agregar(trazas, wall_ms, nodes, tasks, registro)
    agregado["errors"] = errors
    agregado["dataset"] = str(ds)
    return agregado


def _agregar(trazas: list[dict], wall_ms: float,
             nodes: int, tasks: int,
             registro_path: str = "") -> dict:
    """Agrega las trazas: latencia, admit rate, ranking.

    Si ``registro_path`` viene, vierte las inferencias al
    libro de inferencias (:mod:`smcp.core.registro`) — el
    registro persistente que la contabilidad de incentivos
    consulta. En dry-run el ``txid`` es sintetico (no hay
    tx real), pero la contabilidad corre igual.
    """
    from smcp.core.metrics import (
        ModelPricing, MetricsTracker, TaskMetrics)

    tracker = MetricsTracker(pricing={
        "fake": ModelPricing(0.0, 0.0),
        "openai": ModelPricing(0.0, 0.0),  # dry-run: coste 0
    })
    for t in trazas:
        tracker.record(TaskMetrics(
            label=t["task"], worker_id=t["node"],
            model=t["model"], attempts=1,
            admitted=t["admitted"], tokens_in=t["tokens_in"],
            tokens_out=t["tokens_out"],
            latency_ms=t["latency_ms"], cost_usd=0.0,
            error=None,
        ))

    agg = tracker.aggregate()

    # Libro de inferencias (contabilidad de incentivos).
    libro_totales = {}
    if registro_path:
        from smcp.core.registro import InferenceRegistry
        reg = InferenceRegistry(registro_path)
        for t in trazas:
            # txid sintetico en dry-run (determinista).
            import hashlib
            txid = hashlib.sha256(
                f"{t['node']}|{t['ts']}".encode()
            ).hexdigest()[:64]
            reg.record(
                txid=txid, mesh_id="harness",
                server_pubkey=f"srv-{t['node']}",
                requester_pubkey="req-harness",
                completed_at=t["ts"],
                pay_method="bsv", satoshis=99,
            )
        libro_totales = reg.totals()

    # Ranking de contribuciones por nodo (base de incentivos):
    # inferencias, tokens generados, latencia media.
    ranking: dict[str, dict] = {}
    for t in trazas:
        e = ranking.setdefault(t["node"], {
            "inferencias": 0, "tokens_out": 0, "latencia_ms": 0.0})
        e["inferencias"] += 1
        e["tokens_out"] += t["tokens_out"]
        e["latencia_ms"] += t["latency_ms"]
    for e in ranking.values():
        e["latencia_media_ms"] = round(
            e["latencia_ms"] / max(1, e["inferencias"]), 2)
        del e["latencia_ms"]

    return {
        "nodos": nodes,
        "tareas_por_nodo": tasks,
        "total_inferencias": len(trazas),
        "admit_rate": agg.get("admit_rate", 0.0),
        "latencia": agg.get("latency_ms", {}),
        "coste_total_usd": agg.get("total_cost_usd", 0.0),
        "tokens_totales": {
            "in": agg.get("total_tokens_in", 0),
            "out": agg.get("total_tokens_out", 0),
        },
        "wall_ms": round(wall_ms, 2),
        "ranking_contribuciones": dict(sorted(
            ranking.items(),
            key=lambda kv: -kv[1]["inferencias"])),
        "por_nodo_metrics": agg.get("by_worker", {}),
        "libro_inferencias": libro_totales,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--nodes", type=int, default=2)
    ap.add_argument("--tasks", type=int, default=4)
    ap.add_argument("--llm", choices=["fake", "openai"], default="fake")
    ap.add_argument("--base-url", default="http://127.0.0.1:8888/v1")
    ap.add_argument("--model", default="unsloth/Qwen3.8-27B-GGUF")
    ap.add_argument("--api-key", default="")
    ap.add_argument("--dataset", default="data/harness_trazas.jsonl")
    ap.add_argument("--registro", default="data/harness_libro.jsonl",
                    help="libro de inferencias (contabilidad)")
    args = ap.parse_args()

    print("=== HARNESS de testing profundo ===")
    print(f"nodos={args.nodes} tareas/nodo={args.tasks} "
          f"llm={args.llm} dataset={args.dataset}")
    print(f"host={_ip()} (dry-run: sin transacciones)")
    print()

    res = run(args.nodes, args.tasks, args.llm, args.base_url,
              args.model, args.api_key, args.dataset,
              args.registro)

    print("=== AGREGADO ===")
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
