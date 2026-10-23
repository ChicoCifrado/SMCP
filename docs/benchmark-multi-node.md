# Benchmark multi-nodo (tok/s por nodo)

Este documento registra el benchmark multi-nodo de SMCP: cada nodo aporta
su propio modelo (N procesos beellama / N endpoints OpenAI-compatible) y se
mide el throughput y la latencia.

## Como correrlo

```bash
# Smoke (FakeLLMClient, sin modelo):
python scripts/run_multi_node_bench.py --nodes 1,2,4 --tasks 2

# Con modelos reales (N endpoints):
python scripts/run_multi_node_bench.py --real \
  --base-urls http://host1:8080/v1,http://host2:8080/v1 \
  --model Qwen3.8-27B --tasks 2
```

Los resultados se guardan en JSON (`--out`).

## Resultados (smoke, FakeLLMClient)

| Nodos | Tareas | Admitidos | Throughput (tps) | p50 (ms) | p95 (ms) |
|-------|--------|-----------|------------------|----------|----------|
| 1     | 2      | 2         | 665.82           | 1.4      | —        |
| 2     | 4      | 4         | 1508.35          | 0.6      | —        |
| 4     | 8      | 8         | 1562.23          | 0.6      | —        |

El FakeLLMClient es instantaneo, asi que estos numeros son un techo, no
una medida real. Con modelos reales (Qwen3.8-27B a ~28 tok/s) se espera
que el throughput escale sublinealmente por el overhead de admission y
verificacion.

## Que se mide

- `throughput_tps`: gists admitidos / segundo de wall-clock.
- `latency_p50_ms`: mediana de latencia por tarea.
- `latency_p95_ms`: percentil 95.
- `speedup`: throughput(N) / throughput(1).

## Hipotesis a verificar (pendiente con modelo real)

Con N modelos distintos (N procesos beellama), el throughput escala
~linealmente con N y la latencia p50 se mantiene. Ver `multi_node_bench.py`.

## Notas

- El benchmark usa `SecureSharedContext` con `TrustPolicy.REQUIRE_SIGNED`.
- Cada worker firma con su propia KeyPair (worker-i).
- La admission es compartida (un solo verifier + compression LLM).
- Los resultados con modelo real requieren infraestructura (GPU + Unsloth).
