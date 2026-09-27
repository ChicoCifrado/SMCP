# Threat model — SMCP

Qué **garantiza** la capa de seguridad de SMCP, frente a quién, bajo qué
supuestos — y, tan importante como eso, **qué NO garantiza**. Para un
clean-room que vende soberanía, la lista de no-garantías es parte del producto:
un threat model que solo dice "esto es seguro" es peor que ninguno.

- **Doc relacionada**: [`architecture.md`](architecture.md) — qué piezas hay en
  cada capa. Este documento asume que las leíste.
- **Alcance**: el paquete `delm/`, sus capas de red (3 y 4) y la capa 5. La web
  (`web/`, `api_server.py`) es una *vista* sobre el estado local y **no** es una
  superficie de exposición propia: corre en `127.0.0.1` y su API refleja el
  estado en memoria/proceso. Lo mismo para `smcp-serve` (`serve.py`, ACP por
  stdio): su confianza es la del **límite de proceso** (ver §2, superficie ACP).

## 0. Resumen ejecutivo

- **El activo** que protegemos es el **contexto compartido `C`** (la memoria de
  todos los agentes) y, en segundo plano, la **integridad de la malla** (qué
  nodos son de fiar y qué viaja por el cable).
- **El adversario principal** no es un atacante externo clásico: es **otro
  agente** —uno comprometido, desviado o simplemente malicioso— que escribe en
  `C`, y **una fuente de contenido envenenada** (un documento que un agente lee
  y que trae instrucciones incrustadas). El paper de DeLM no cubre ninguno de
  los dos; el contexto compartido es, sin esta capa, un canal de confianza
  ciego entre agentes.
- **La postura es "verificar la entrada, no confiar en eltransportista"**: lo
  que no se puede verificar (firma, digest, attested release, identidad del
  par) **se descarta o se bloquea**, nunca se adopta.
- **Tres limites explícitos**: (1) la detección de prompt-injection es
  heurística, (2) el modo estricto de firma es asimétrico pero su fallback HMAC
  no lo es, y (3) la atestación de release es *provenance de build*, no de
  runtime. Detallados abajo.

## 1. Adversarios y activos

| # | Adversario | Modelo | Qué busca | Capas que lo frenan |
| --- | --- | --- | --- | --- |
| A1 | **Agente de un nodo vecino comprometido** (MITM en la malla) | Conoce el protocolo; controla otro nodo | Suplantar a un par, firmar como otro, inyectar gists falsos | 1+2 (firma), 3 (identity-cert `CN=peer_id`), 4 (bootstrap firmado) |
| A2 | **Agente malicioso en la cola** (participa de buena fe al principio) | Está en la cola y escribe | Escribir en `C` sin autorización, sobrescribir un label | 1+2 (`TrustGate`, inmutabilidad) |
| A3 | **Fuente envenenada** (documento malicioso que un agente lee) | Solo controla el texto que entra | Que un agente siga sus instrucciones (prompt-injection) | 5 (detector + taint + cuarentena) |
| A4 | **Fuente envenenada con linaje limpio** (A3, pero el gist derivado lo "lava") | Escribe un gist que parece legítimo pero viene del texto envenenado | Propagar la inyección bajo otras etiquetas | 5 (cierre transitivo del taint) |
| A5 | **Relay/transport jamming** (saturación, spam) | Controla o afloja la ruta de announce/gossip | Inundar el canal, agotar recursos | 4 (guardia de relay: rate-limit/dedup/tamaño) |

Activos: (i) el **contexto compartido** `C`; (ii) la **cadena de
proveniencia** (digest + firma) de cada gist; (iii) la **identidad** de los
pares (`peer_id` ↔ cert); (iv) la **disponibilidad** del canal de gossip.

## 2. Por capa: adversario, supuestos, garantías, no-garantías

### Capa 0 — Núcleo DeLM

- **Qué es**: la mecánica (contexto, cola, admisión, verificación). No es una
  capa de seguridad; es la que la seguridad endurece.
- **Supuesto**: la verificación determinista (`RuleVerifier`) rechaza un gist
  mal anclado, pero **no** entiende de intenciones adversariales — solo de
  *grounding* y *fidelidad* al texto.
- **Garantía**: un resultado crudo no entra directo a `C`; pasa por
  comprimir → verificar → admitir. El `claim` es el único punto de
  serialización (una tarea en curso no se re-reclama).

### Capa 1+2 — Proveniencia e integridad (on by default)

- **Adversario**: A2 (escritor no autorizado / sobrescritor), A1 (suplantación).
- **Supuestos**: la clave privada de un autor es suya y no se filtra; el
  `digest` canónico no tiene colisiones (SHA-256).
- **Garantías**:
  - **Autoría verificable**: solo un autor cuya firma verifique sobre el digest
    puede escribir, y el `TrustGate` puede exigir además *allowlist*.
  - **Integridad en tránsito**: el digest almacenado debe igualar el digest
    recomputado (regla "tamaño + SHA-256"); un gist alterado no se admite.
  - **Inmutabilidad**: re-admitir un label solo vale si el digest es idéntico
    (re-verificación idempotente); cambiar el digest es un *reject*, no un
    reemplazo silencioso.
  - **Auditabilidad**: cada admit/overwrite/reject entra en un
    `AdmissionLedger` append-only encadenado por hashes → rastro reproducible.
- **NO-garantías (explícitas)**:
  - **El fallback HMAC no es asimétrico.** Si `cryptography` no está
    disponible y se degrada a HMAC (pre-shared key), *cualquier* que posea la
    clave puede **forjar** la firma de cualquier autor — la verificación ya no
    prueba *quién* firmó, sino que se comparte un secreto. El modo estricto
    (default) lanza en vez de degradar en silencio; con
    `allow_hmac_fallback` degrada **con warning visible**. En un despliegue real
    con HMAC, la Capa 1+2 no da *no-repudio* frente a un insider con la clave.
  - **La firma no dice nada sobre el binario ni el proceso**: prueba que *esta*
    clave firmó *este* digest, no que el proceso firmante no esté troyanizado
    (ver Capa 3, atestación).
  - **`TrustPolicy.DENYLIST` es denegación, no autenticación**: quien no esté en
    la lista puede escribir (si firma); la lista solo *expulsa* conocidos.

### Capa 3 — Malla / propagación

- **Adversario**: A1 (par activo en la malla), A5 (saturación del gossip).
- **Supuestos**: los requisitos de malla son inmutables; los pares firmantes de
  release son de confianza.
- **Garantías**:
  - **Rechazo en el ingest**: un par por debajo del `version_floor` no se ingiere ni se
    re-difunde; un par que no pasa los requisitos se rechaza (no entra en la
    tabla).
  - **Inmutabilidad de la política**: cambiar requisitos **deriva una malla
    nueva** (`mesh_id`), nunca muta la política viva bajo los pies de los
    pares.
  - **Regla path-rich**: un anuncio transitorio no sobreescribe una dirección
    directa rica por una más débil (limita la degradación de enrutado por
    gossip).
  - **Enlace identidad-cert (QUIC entre hosts)**: cada nodo presenta un cert con
    **`CN = peer_id`**, y el cliente verifica post-handshake que el `CN` coincida
    con el `peer_id` que espera → un MITM con su *propio* cert (`CN != peer_id`)
    es rechazado. La identidad que firma (BIP340/ed25519) queda ligada al
    transporte TLS.
- **NO-garantías (explícitas)**:
  - **La atestación de release es *build provenance*, no attestation de
    runtime.** Que un binario venga firmado por un firmante de confianza prueba
    que **fue publicado** por ese firmante; no prueba que el proceso remoto en
    ejecución no haya sido modificado, ni que no esté honey-potted, ni que no
    esté en un entorno de alguien más. Es una de las fronteras explícitas del
    diseño.
  - **QUIC entre hosts no verifica el par por defecto en cuanto a criptografía
    de servidor**: el cert es auto-firmado y el handshake usa
    `verify_mode=0` (no hay CA). La defensa es el *enlace* `CN = peer_id`
    (identidad de capa 3) + la firma del gist, no una PKI. El modo
    `insecure=True` desactiva explícitamente el enlace identidad-cert (solo
    para pruebas; un despliegue real no debe usarlo).
  - **Gossip no es consenso.** Los nodos convergen por difusión *best-effort*
    con TTL y re-difusión; no hay acuerdo global tipo Paxos/Raft. Dos sub-mallas
    particionadas pueden quedar con vistas distintas *temporalmente*. La
    convergencia es de los tests (a igualdad de red), no una garantía de
    liveness bajo partición permanente.
  - **El heartbeat detecta caída, no compromiso**: un par vivo y malicioso
    sigue dando beats; el heartbeat no es un detector de intrusión.

### Capa 4 — Despliegue multi-proceso

- **Adversario**: A1 (suplantar al owner en el bootstrap/control-plane), A5
  (jamming del announce).
- **Supuestos**: la clave pública del `Owner` es la raíz de confianza y se
  distribuye fuera de banda.
- **Garantías**:
  - **Bootstrap firmado**: el owner firma cada anuncio; un nodo solo acepta un
    anuncio/orden cuya firma verifique contra la clave del owner → un anuncio
    no verificable **se descarta** (anti-MITM en el discovery).
  - **Control-plane autenticado**: las órdenes (up/down, rotación) van firmadas
    y el nodo las verifica antes de ejecutar.
  - **Transporte swappable con default in-memory** (inmune en tests; en runtime
    depende del backend elegido).
  - **Guardia de relay Nostr** (cuando el announce va por relay):
    rate-limit por `pubkey`, dedup de ids vistos, límite de tamaño de evento y
    snapshot/restore opcional → limita el *flood* (A5).
- **NO-garantías (explícitas)**:
  - **El relay Nostr verifica la firma de cada evento, pero no es una raíz de
    confianza por sí solo**: no comprueba *quién* es el firmante más allá de
    "la firma es válida para ese `pubkey`"; la política de *quién puede
    anunciar* la impone el receptor (el bootstrap firmado del owner). Un relay
    malicioso no puede *forjar* firmas, pero sí **reordenar, retrasar o
    censurar** (y con un relay abierto, espiar metadatos: quién habla con quién).
  - **La persistencia del relay es opcional y el default es efímero**: un
    reinicio pierde el estado de dedup/rate-limit (aceptado como
    compromiso privacy/soberanía).
  - **mDNS depende del entorno**: multicast que algunos routers/firewalls
    filtran; discovery puede fallar (fail-closed: el nodo simplemente no
    descubre, no acepta a cualquiera).
  - **Rotación de clave del owner no es weathering-resistant**: una clave
    revocada deja de ser válida para *futuros* anuncios, pero no "despublica"
    los gists ya admitidos (inmutabilidad: el pasado es inmutable por diseño).

### Capa 5 — Anti prompt-injection (on by default)

- **Adversario**: A3 (fuente con instrucciones inyectadas), A4 (lavado de
  linaje: gist derivado que parece legítimo).
- **Supuestos**: los agentes *respetan* el encuadre de la cuarentena
  (SUSPICIOUS se marca como "dato, no instrucciones"); ningún LLM es perfecto.
- **Garantías**:
  - **Detección en admisión**: se escanea el texto de la fuente (y el `raw`) en
    el momento de admitir, no cuando ya está razonando el agente.
  - **Cierre transitivo**: un gist derivado hereda el taint de su fuente, así
    que un único texto envenenado no puede propagarse como contenido "limpio"
    bajo otras etiquetas (derrumba A4).
  - **Cuarentena en la superficie visible**: los `CONFIRMED` se **omiten** del
    render y del unfolding; los `SUSPICIOUS` se enmarcan explícitamente como
    *dato no confiable* para que el modelo los trate como datos, no como
    instrucciones.
- **NO-garantías (explícitas)**:
  - **El detector es heurístico, no un clasificador.** Atrapa las formas
    comunes y de alta señal ("ignore all previous instructions", extracción de
    system prompt, exfiltración, role-hijack). Un **false positive** solo
    cuarentena (recuperable, coste = visibilidad). Un **false negative** —una
    inyección phrased de forma que el patrón no casa— **no se detecta como
    CONFIRMED**; la contención pasa a depender del taint (la fuente queda
    marcada como no confiable) y del seguimiento del modelo. No se añadió un
    clasificador LLM a propósito: costaría por gist y reintroduciría
    no-determinismo.
  - **Quarantine no es sanitización**: el contenido `CONFIRMED` se *omite del
    render*, no se limpia ni se neutraliza; si un flujo específico lee el
    `raw` por otra vía, la cuarentena de render no lo protege.
  - **El encuadre es una petición, no un sandbox**: que un modelo *trate* un
    bloque como "dato no confiable" depende de que el modelo obedezca el
    encuadre. SMCP acota el *blast radius* (cierre transitivo + omisión de
    CONFIRMED); no convierte al LLM en un intérprete de símbolos.

### Superficie ACP (`smcp-serve`, `serve.py`) — fuera de capa

No es una capa de seguridad; es una **puerta** (el agente habla ACP por stdio).
Se documenta aquí porque añade una superficie de proceso con su propio modelo
de confianza, distinto del de las capas.

- **Adversario**: quien arranca o se engancha al proceso `smcp-serve` (un par no
  de fiar que obtiene control del proceso; A1/A2 en potencia).
- **Supuesto**: la confianza es la del **límite de proceso** — quien puede
  arrancar/engancharse al proceso lo controla. No hay autenticación in-band:
  `authenticate` es un **no-op** (la raíz de confianza es la clave pública del
  owner, no un login).
- **Garantías**:
  - **Config y key en el servidor**: se resuelven en el proceso SMCP y **nunca**
    viajan al cliente ACP; el par no puede exfiltrar ni alterar el modelo/clave
    desde el otro lado del stdio.
  - **Sesiones efímeras**: `list_sessions` → vacío; no hay estado de sesión
    persistente que filtrar a posteriori (persiste el *contexto compartido*,
    no la historia de runs).
  - **Mismo pipeline, no otra vía**: un prompt corre el mismo `DelmPipeline`
    que `/api/run`; las garantías de las Capas 1+2 y 5 se aplican igual (los
    gists admitidos se verifican del mismo modo). La puerta ACP no reintroduce
    una vía aparte.
  - **Integridad del canal**: `stdout` está reservado para JSON-RPC; todo el
    logging va a stderr, así un print erróneo no corrompe el protocolo.
- **NO-garantías (explícitas)**:
  - **No hay autenticación in-band**: la seguridad contra un par no de fiar
    depende del límite de proceso. Un atacante que ya controla el proceso puede
    enviar prompts; las Capas 1+2/5 acotan qué se *admite* en `C`, no quién
    *arrancó* el proceso.
  - **El default es `FakeLLMClient`**: sin configurar, la puerta ACP no llama a
    un modelo real (el smoke no necesita red); por diseño del test, no una
    garantía de runtime.

## 3. No-garantías transversales (el resumen honesto)

Estas aplican a *todas* las capas y conviene tenerlas presentes:

1. **No hay resistencia a un agente que ya es parte de la malla** con una clave
   válida: si un par firmado intenta envenenar `C` con un gist *bien anclado*
   pero semánticamente malicioso, la verificación determinista (grounding +
   fidelidad) **no lo detecta** — la Capa 5 marca la *fuente*, no la
   *intención* de un par de confianza.
2. **Disponibilidad ≠ confidencialidad**: el ledger registra *qué* gists se
   admitieron; en un despliegue compartido, el ledger es un registro que hay que
   proteger por fuera (quien lo lee ve el historial de admisión).
3. **Confianza en el reloj y en el entorno**: TTL de discovery/heartbeat
   dependen del reloj del proceso (los tests inyectan `now`; en runtime es el
   reloj real, sujeto a NTP/jumps).
4. **La red es de confianza-por-firma, no de confianza-por-transporte**: un
   nodo puede ver el tráfico en claro (no hay cifrado de payload en gossip /
   Nostr, solo firmas); para confidencialidad punto a punto hace falta una
   capa de cifrado que **no** está en el alcance actual.
5. **La atestación es de build, no de runtime** (ver Capa 3) y **la
   cuarentena es de render, no de intérprete** (ver Capa 5). El modelo de
   amenazas no promete "infalible"; promete **"verificable, trazable y
   acotado en su radio de explosión"**.

## 4. De dónde a dónde (mapa de responsabilidades)

| Superficie | Confianza | Qué la protege | Dónde NO está |
| --- | --- | --- | --- |
| `C` (contexto compartido) | Solo autores verificados (1+2) | gate, firma, integridad, inmutabilidad, ledger | detección de intención (ver §3.1) |
| firma (digest) | Clave del autor | ed25519 estricto; HMAC solo con warning | no asimétrica en fallback HMAC |
| identidad de par (QUIC) | `CN = peer_id` | enlace identidad-cert, `insecure` explícito | sin CA; solo enlace de identidad |
| announce/gossip (Nostr) | Firma por evento + bootstrap del owner | rate-limit, dedup, tamaño; firma de eventos | relay puede reordenar/censurar |
| contenido de agente (Capa 5) | Taint por fuente | detector + cierre transitivo + cuarentena | heurístico; encuadre ≠ sandbox |
| `smcp-serve` (ACP, stdio) | Límite de proceso (no in-band) | config/key en el servidor; sesiones efímeras; mismo pipeline 1+2/5 | `authenticate` no-op; la confianza es del proceso que lo arranca |

## 5. Cómo se prueba lo anterior (evidencia, no promesa)

Cada garantía de este documento tiene un test que la exercise, y la suite corre
en CI sin red ni modelo:

- firma/integridad/inmutabilidad/ledger → `test_security.py`,
  `test_provenance_strict.py` (no degradación silenciosa), `test_ledger_persistence.py`;
- rotación de clave del owner (cadena de confianza) → `test_owner_rotation.py`;
- identity-cert QUIC (legítimo, MITM, `insecure`, `CN=peer_id`) →
  `test_quic_identity.py`, `test_quic_host.py`;
- requirements/gossip/heartbeat (floor, path-rich, TTL, rechazo de ingest) →
  `test_requirements.py`, `test_gossip.py`, `test_heartbeat.py`;
- guardia de relay (rate-limit/dedup/tamaño/snapshot) → `test_nostr_relay_guard.py`;
- BIP340 contra los vectores oficiales + relay de red → `test_nostr.py`;
- Capa 5 (detector, niveles, cierre transitivo, cuarentena en render/unfold, y
  que el pipeline la trae por defecto) → `test_taint.py`;
- convergencia de la malla (in-memory, QUIC y Nostr) → `test_mesh.py`,
  `test_demo_multihost.py`;
- puerta ACP (`smcp-serve`: helpers, ciclo de vida, que un prompt corre el
  pipeline, los no-ops honestos y el smoke stdio slow) → `test_serve.py`.

## 6. Resumen de no-garantías (la lista corta)

Para tenerla a mano — el threat model en una línea por punto:

- El **detector de inyección es heurístico**: un false negative no se marca
  `CONFIRMED`; la contención cae al taint + al seguimiento del modelo.
- El **fallback HMAC no es asimétrico**: con HMAC, no hay no-repudio frente a
  quien tenga la clave.
- El **relay Nostr verifica firma, no identidad de política**: puede reordenar,
  retrasar, censurar o espiar metadatos; el default del relay es efímero.
- **QUIC entre hosts** usa cert auto-firmado (`verify_mode=0`): no hay CA; la
  defensa es el enlace `CN = peer_id` + la firma del gist, y `insecure=True`
  lo desactiva.
- La **atestación de release es build provenance**, no de runtime.
- El **gossip converge best-effort**, no es consenso: partición permanente =
  vistas divergentes transitorias.
- El **heartbeat detecta caída**, no compromiso.
- La **cuarentena es de render**, no del intérprete: depende de que el modelo
  obedezca el encuadre "dato no confiable".
- El **payload no va cifrado** en gossip/Nostr (solo firmado): la
  confidencialidad punto a punto no está en el alcance.
- Un **par firmado con intención maliciosa** no lo detiene la verificación
  determinista: marca la fuente, no la intención.
- La **puerta ACP** (`smcp-serve`) no autentica in-band: su confianza es el
  límite de proceso (quien lo arranca); la config/key nunca viajan al cliente y
  las sesiones son efímeras.
