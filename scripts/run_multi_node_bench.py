"""Benchmark multi-nodo: tok/s por nodo.

Uso:
    python scripts/run_multi_node_bench.py [--nodes 1,2,4,8] [--tasks 2]
    python scripts/run_multi_node_bench.py --real --base-urls http://host1:8080/v1,...

Con --real, usa OpenAICompatibleClient contra los endpoints dados.
Por defecto usa FakeLLMClient (smoke, sin modelo).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from smcp.core.llm import FakeLLMClient, OpenAICompatibleClient
from smcp.core.multi_node_bench import MultiNodePoint, run_multi_node, summarize_multi


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", default="1,2,4", help="lista de N separados por coma")
    ap.add_argument("--tasks", type=int, default=2, help="tasks por nodo")
    ap.add_argument("--real", action="store_true", help="usar endpoints reales")
    ap.add_argument("--base-urls", default="", help="URLs separadas por coma (con --real)")
    ap.add_argument("--model", default="local", help="nombre del modelo (con --real)")
    ap.add_argument("--out", default="bench_results.json", help="fichero de salida")
    args = ap.parse_args()

    ns = [int(x) for x in args.nodes.split(",") if x.strip()]
    results = []
    for n in ns:
        if args.real:
            urls = [u.strip() for u in args.base_urls.split(",") if u.strip()]
            if len(urls) < n:
                print(f"error: se necesitan {n} urls, hay {len(urls)}", file=sys.stderr)
                sys.exit(2)
            pool = [OpenAICompatibleClient(base_url=urls[i], model=args.model)
                    for i in range(n)]
        else:
            pool = [FakeLLMClient() for _ in range(n)]
        pt = await run_multi_node(pool, tasks_per_node=args.tasks)
        results.append(pt.to_dict())
        print(f"n={n}: throughput={pt.throughput_tps:.4f} tps, "
              f"p50={pt.latency_p50_ms:.1f}ms, admitted={pt.admitted}")

    pts = []
    for r in results:
        pts.append(MultiNodePoint(**{k: r[k] for k in
                                    ("nodes", "tasks", "admitted", "wall_s",
                                     "throughput_tps", "latency_p50_ms",
                                     "latency_p95_ms", "speedup")}))
    summary = summarize_multi(pts) if len(pts) > 1 else {"points": [p.to_dict() for p in pts]}
    out = {"points": results, "summary": summary}
    Path(args.out).write_text(__import__("json").dumps(out, indent=2))
    print(f"\nGuardado en {args.out}")


if __name__ == "__main__":
    asyncio.run(main())
