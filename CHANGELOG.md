# Changelog

## [0.4.0] — Malla viva

Titulo: **La malla en vivo — consola 3D, inferencia real admitida,
anclaje BSV por inferencia.**

Lo que logra esta release: la malla deja de ser una biblioteca de
pruebas y se convierte en una superficie operativa de punta a punta.
Un operador abre la consola, ve la malla en 3D con nodos reales,
lanza un run contra un modelo local, y cada inferencia admitida
queda anclada a la cadena de bloques BSV con su timestamp.

### Motor DeLM en vivo (consola)
- Modo Motor: POST /api/runs crea el run, GET /api/runs/<id>/events
  es el stream SSE (replay + follow), POST /api/runs/<id>/cancel
  cancela en vivo. Ya no hay una peticion que bloquea 240 s.
- Modo Proyecto: los 5 nodos-funcion, intactos, clic 3D para
  ejecutar.
- window.__delm.nodes como getter (el array funcNodes se reasigna
  al cambiar de modo).

### Malla 3D con peers reales
- Cada peer verificado es un nodo en orbita, leido de /api/mesh.
- Tamano = raiz de la VRAM compartida (no lineal).
- Color = estado: verde vivo, gris muerto; halo ambar cuando tiene
  VRAM reservada (tier 2).
- Posicion = hash del peer_id (estable: un nodo no salta de sitio).
- Sondeo cada 5 s; ficha por nodo con VRAM compartida, libre,
  reservada, inferencias servidas, satoshis, rechazos y segundos
  observado.

### Persistencia de runs
- Al recargar la consola, si hay un run activo se reanuda en vivo:
  SMCPRuns.reconnect() lee /api/runs, toma el activo y sigue el
  SSE, que hace replay de los eventos ya ocurridos.

### Pipeline de punta a punta con modelo real
- admission: el gist es ahora un span literal contiguo del
  trajectory. Un modelo libre reformula al comprimir y el
  verifier (n-grams >= 4) lo rechazaba 3 veces; el span fiel
  pasa en 1 intento. Verificado contra Qwen3.8-27B-GGUF local:
  run done en 46.6 s, admitted_gists=1, attempts=1, gist firmado
  ed25519, contexto size 1.

### Anclaje BSV (una tx por inferencia)
- anchor.py: una transaccion por inferencia, sin hashear el
  contenido. Lleva identidad del nodo, del solicitante y
  occurred_at; content_sha256 existe pero no se rellena (fallo
  por diseno). Firma secp256k1, inclusion Merkle, verificacion
  contra cabecera. Mutacion 18/18; 36 tests verdes.

### Tres tiers de intercambio
- tiers.py: tres precios que se cruzan en exactamente 1.000
  inferencias. x402 aplica al tier 1 (metered). BSV no tiene
  umbral de polvo (BSV_DUST_LIMIT_SATOSHIS = 0); satoshis se
  expone como satoshis_anchored, un conteo, no un pago.

### Verificacion de las cinco capas contra el modelo local
- A) Contexto compartido: el finalizer no inventa claims que no
  esten en C (responde desde el contexto verificado).
- B) Cola de tareas: dependencias reales, apertura en paralelo,
  deteccion de ciclos.
- C) Red malla: contribucion firmada ed25519 con cadena de
  evidencia valida; reparto de VRAM (reservar baja free_gb,
  liberar la devuelve); observe marca vivo.
- D) Paralelizacion: 4 workers x 4 tareas, cola agotada.
- E) Anclaje: 1 ancla verificada contra cabecera.

### Gates
- 1160 tests; readme cuadrado; mutation 18/18 en anchor.

## [0.3.0] — anterior
- Incentivos, reserva atomica de VRAM, inscripcion v3 (DPP + ARC
  + historial), join v3 off-chain en el roster por avales.
