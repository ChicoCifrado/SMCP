# syntax=docker/dockerfile:1
FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copiar el paquete
COPY pyproject.toml README.md ./
COPY smcp/ ./smcp/

# Instalar SMCP
RUN pip install --no-cache-dir .

# Puerto por defecto
EXPOSE 8000

# Comando por defecto: servidor web
CMD ["smcp-serve-web", "--host", "0.0.0.0", "--port", "8000"]
