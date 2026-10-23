# Inferencia local por nodo en la malla SMCP

## Principio

Cada nodo de la malla ejecuta su propio servidor de inferencia local
(OpenAI-compatible). SMCP no depende de un servicio centralizado de
modelos: el contexto compartido (C) se propaga por gossip y cada nodo
usa su modelo local para comprimir, verificar y admitir gists.

## Endpoint local

El endpoint de inferencia de cada nodo se configura via:

- Variable de entorno: `DELM_BASE_URL` (ej. `http://127.0.0.1:11434/v1`)
- Archivo de config: `config/model_config.yaml` -> `base_url`
- CLI: `smcp config-check` muestra el endpoint resuelto

El modelo se configura via `DELM_MODEL` o `config/model_config.yaml` -> `model`.

## Servidores soportados

Cualquier servidor OpenAI-compatible:

| Servidor | Puerto típico | Notas |
|----------|---------------|-------|
| Ollama | 11434 | `ollama serve`, modelos via `ollama pull` |
| llama.cpp server | 8080 | `llama-server -m model.gguf` |
| beellama | 38263 | Qwen3.8-27B (lento, WSL) |
| Unsloth Studio | 8888 | Qwen3.8-27B (rápido, GPU) |
| OpenAI / Anthropic | remoto | Requiere API key |

## Anuncio en la malla

Cada nodo anuncia su endpoint en el peer record. El campo `endpoint`
se incluye en el estado de la malla (`/api/mesh`, `/api/superadmin/nodes`)
para que otros nodos sepan dónde enrutar inferencias.

## Flujo

1. Nodo A recibe una tarea y la resuelve con su modelo local.
2. El gist resultante se verifica (n-grams) y se admite al contexto C.
3. El gist se propaga por gossip a los demás nodos.
4. Nodo B recibe el gist y lo usa como contexto para sus propias tareas.
5. Cada nodo usa su modelo local para comprimir/verificar/admitir.

## Tests

- `tests/test_real_model_ollama.py`: tests contra modelo real (Ollama).
- `tests/test_real_model_wiring.py`: wiring contra mock HTTP.
- `tests/test_demo_multihost.py`: convergencia de 2 nodos en procesos distintos.

## Próximos pasos

- Test multi-nodo con endpoints locales distintos (Unsloth + Ollama).
- Añadir campo `endpoint` al peer en el ledger (schema v4).
- Documentar en `docs/` cómo arrancar un nodo con su endpoint local.
