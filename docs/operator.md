# Operación de un nodo SMCP

## Arranque rápido (Docker)

```bash
docker build -t smcp-node .
docker run -d --name smcp-node \
  -p 8000:8000 \
  -e DELM_MODEL="nemotron-3.5-bolt:e4b-q4_K_M" \
  -e DELM_BASE_URL="http://host.docker.internal:11434/v1" \
  -e SMCP_SUPERADMIN_PUBKEY="<hex pubkey>" \
  smcp-node
```

## Arranque (pip)

```bash
pip install smcp[web]
export DELM_MODEL="nemotron-3.5-bolt:e4b-q4_K_M"
export DELM_BASE_URL="http://127.0.0.1:11434/v1"
export SMCP_SUPERADMIN_PUBKEY="<hex pubkey>"
smcp-serve-web --host 0.0.0.0 --port 8000
```

## Variables de entorno

| Variable | Descripción | Default |
|----------|-------------|---------|
| `DELM_MODEL` | Modelo de inferencia | (unset) |
| `DELM_BASE_URL` | Endpoint OpenAI-compatible | (unset) |
| `DELM_API_KEY` | API key (si el endpoint la requiere) | (unset) |
| `SMCP_SUPERADMIN_PUBKEY` | Clave pública ed25519 del owner (hex) | (unset) |

## Superadmin

1. Obtener token de sesión:
   ```bash
   smcp superadmin token --url http://localhost:8000 --identity config/mesh_identity.json
   ```
2. Abrir `http://localhost:8000/superadmin.html` y pegar el token.

## Health check

```bash
curl http://localhost:8000/api/health  # si existe
```

## Malla

Cada nodo ejecuta su propio servidor de inferencia local. Ver `docs/mesh-local-inference.md`.
