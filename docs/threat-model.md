# Threat model — SMCP

Qué **garantiza** la capa de seguridad de SMCP, frente a quién, bajo qué
supuestos — y, tan importante como eso, **qué NO garantiza**. Para un
clean-room que vende soberanía, la lista de no-garantías es parte del producto:
un threat model que solo dice "esto es seguro" es peor que ninguno.

- **Doc relacionada**: [`architecture.md`](architecture.md) — qué piezas hay en
  cada capa. Este documento asume que las leíste.
- **Alcance**: el paquete `delm/`, sus capas de red (3 y 4) y la capa 5. La web
  (`delm/web/`, `app.py` + `api.py`) es una *vista* sobre el estado local y
  **no** es una superficie de exposición propia: corre en `127.0.0.1` y su API
  refleja el estado en memoria/proceso. Lo mismo para `smcp-serve` (`serve.py`,
  ACP por stdio): su confianza es la del **límite de proceso** (ver §2,
  superficie ACP).
- **No-garantía de la capa web**: que la UI servida desde el wheel tenga todo
  lo que la UI del checkout enseña. `delm-serve-web` sin checkout arranca y
  sirve la UI, pero los contadores que leen el árbol de fuentes
  (`test_fns`, `test_files`, `core_modules`) no existen y se declaran como no
  disponibles — la degradación es explícita, pero la *capacidad* de la UI sí
  depende de qué se instaló.

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
| A6 | **Nodo que miente sobre su capacidad** (el adversario con incentivo económico) | Es un par legítimo y posee su clave | Declarar más VRAM de la que tiene: que se le coloque modelo ajeno y aparentar más historial del que tiene | Parcial. La firma solo prueba **quién** afirmó, no **cuánto** (§2, intercambio). La cifra se parte en tres, y dos no dependen de que el nodo diga la verdad: `vram_gb` es el máximo físico, `vram_advertised_gb` lo que el dueño **ofrece** (su decisión, firmada) y `vram_shared_gb` es la telemetría de uso. El plan se calcula sobre `min(ofrecida, física) − usada`, nunca sobre la cifra de cabecera, así que **inflar deja de comprar enrutamiento**. Y el historial ya **no** escala con nada que el nodo declare: cuenta inferencias, y cada una necesita una transacción incluida. Ofrecer más de lo declarado es `capacity_overstated`, fail-closed y encadenado. `capacity_claim_status` cruza la afirmación firmada con la detección local y señala `claim_exceeds_detected` **sin corregir**: detección y afirmación vienen del mismo host por el mismo canal sin autenticar, así que ninguna es evidencia y una corrección por detección expulsaría a un nodo real ante un fallo de `nvidia-smi`. **Lo que sigue sin resolver**: la capacidad sigue siendo una afirmación firmada. Quien quiera inflar de forma consistente solo tiene que mentir igualmente en su detección local, y eso exige un testigo externo ( attestation de hardware o un tercero). **Sin slashing**: detectar la contradicción es trivial; sancionarla no está implementado |
| A7 | **Replay de una afirmación antigua** | Capturó un informe de capacidad válido de otro momento | Reclamar capacidad/inferencia con un informe viejo | intercambio: nonce de un solo uso (se quema al admitir), reto e informe caducan, `peer_id` no se re-apunta a otra clave |
| A8 | **Quien lee la clave de identidad del nodo** | Acceso de lectura a `config/mesh_identity.json` (o al fichero equivalente en el exchange de BSV) | Firmar como ese nodo: reclamar su capacidad y su lugar en el ranking | nada criptográfico lo frena (es la clave); sí lo marca el diseño: `chmod 600`, se **rechaza persistir una clave HMAC**, y el binding de identidad hace que suplantarla sea visible en la cadena |
| A10 | **Nodo que se infla el historial con inferencia local** | Es un par legítimo, publica capacidad y ejecuta inferencias | Contar inferencias que **nadie pidió**: el ranking es su única recompensa y subir de puesto no cuesta si nadie te lo comprueba | el ancla exige `requester_pubkey` distinto del nodo y **no se construye** en autoacreditación (§2, intercambio); el mismo txid no cuenta dos veces. **Lo que sigue abierto**: el solicitante tampoco está atado a una transacción —el grafo demuestra que *alguien* pidió, no que pagara—, así que un par coludido podría inflar el ranking de otro sin gastar. El **importe** del ancla sí está firmado (`test_a_tampered_amount_invalidates_the_signature`), lo que fija la atribución pero no prueba el pago |
| A9 | **Reemplazo en mempool** (Fase 1 del anclaje) | Ha visto la transacción del nodo antes de que se mine | Sustituirla por otra con el mismo input y un alias distinto, y reescribir la historia | `timechain.rebroadcast()` (mientras no esté confirmada) + la cadena, que es el tercero de confianza |

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

### El intercambio de la malla (`contrib.py`, `placement.py`) — fuera de capa

Esta es la superficie que convierte la malla en un **intercambio**: los nodos
aportan VRAM y reciben crédito de inferencia. Es la única parte del proyecto con
un *adversario económico* (mentir sale rentable), así que su no-garantía central
—que la capacidad declarada sea cierta— es la primera línea del documento.

- **Adversario**: A6 (**nodo que miente sobre su capacidad**), A10
  (**nodo que se infla el historial con inferencia local**), A1 (par que quiere
  servicio sin aportar), A7 (replay de una afirmación antigua).
- **Supuestos**: el reloj del observador es aproximadamente honesto; la clave
  ed25519 de un nodo no se la roban (si se la roban, roban su identidad); el
  estado de la malla (`config/mesh_exchange.json`) es local y por tanto está en
  manos del operador, no de la red.
- **Garantías**:
  - **La afirmación viene firmada por una identidad concreta**: la firma cubre
    el digest canónico de *todos* los campos (VRAM, RAM, núcleos, backend, reto,
    caducidades), así que nadie puede subirse la VRAM después de firmar
    (`test_contrib.py::test_signature_stands_behind_the_numbers`).
  - **No es replayable**: la malla emite un reto de un solo uso
    (`Challenge.nonce`) y admitir un informe **quema** el nonce; además reto e
    informe caducan. Reenviar el "tengo 64G" de ayer no vale.
  - **`peer_id` es su clave, no una etiqueta**: la primera clave vista para un
    `peer_id` queda ligada a él para siempre; otro informe del mismo nombre
    firmado por otra clave se rechaza (`peer_key_changed`) y no se roba el
    crédito ya acumulado. Sin esta regla, editar el fichero de identidad local
    sería robar el saldo de otro.
  - **La contabilidad es auditable y los rechazos también**: cada admisión —
    incluida cada **rechazo**, con su motivo— entra en una cadena de hashes
    (`verify_chain`) que sobrevive a un save/load; alterar una entrada previa
    rompe la cadena. Un rechazo que no se registrara sería indistinguible de un
    intento que nunca ocurrió.
  - **El historial solo crece con prueba de cadena**: el único camino es
    `record_inference`, que exige un txid, no admite dos veces la misma
    transacción, y rechaza a quien no ofrece VRAM. **No hay saldo** que gastar,
    transferir ni prometer: `ContributionLedger` no tiene método de cobro, y
    `tests/test_contrib.py::test_history_is_not_a_balance` lo fija por ausencia
    de API para que reintroducirlo no pase desapercibido.
  - **Una inferencia local no se ancla**: el `AnchorRecord` lleva el
    solicitante (`requester_pubkey`, formato v2) y **se niega a construirse** si
    es el propio nodo. Ejecutar inferencia contra uno mismo —lo más barato y lo
    más fácil de multiplicar— no deja registro, así que el ranking no se puede
    inflar sin salir a la red. Y como el solicitante está en el payload firmado,
    reescribirlo después invalida la firma.
  - **Estar vivo no cuenta para nada**: `observe` anota uptime (procedencia) y
    no acredita. Antes sí lo hacía (VRAM × horas), que era un incentivo a no
    hacer nada.
  - **El reparto solo usa capacidad admitida**: `plan_placement` lee los números
    ya admitidos, nunca un announce, y rechaza con un motivo accionable
    (`insufficient_mesh_vram` dice *cuánta* VRAM falta). El plan es
    determinista y tiene round-trip, así que se puede loguear y comparar entre
    observadores.
- **NO-garantías (explícitas)**:
  - **La capacidad declarada NO es una atestación de hardware.** Un nodo puede
    firmar "tengo 4096 GB" y la malla lo admite: lo que se verifica es *quién lo
    afirmó*, no que exista. No hay TPM, ni SGX, ni measured boot, ni challenge
    de hardware sobre la GPU. Esto es la misma frontera que la atestación de
    build de la Capa 3, pero aquí **con Incentivo económico para mentir**.
    Lo que se consigue es honestidad *acotada*: la mentira queda **atribuida y
    auditable**, no puede disfrazarse de otro `peer_id`, no se replaya, y lo forfeita
    en cuanto el nodo deja de estar observado.
  - **No hay stake, ni slashing, ni sanción.** El detection de un mentiro es
    trivial (basta comparar la afirmación con lo observado), pero **castigarlo es
    una decisión de política económica que este proyecto no toma**: no hay
    depósito que confiscar ni reputación que perder. Es la pieza
    siguiente, no una forgetting.
  - **La observación es del entorno, no delClaim**: `observe` acredita lo que el
    *observador* vio. Un clockskew, un reloj que salta o un heartbeat
    falsificado (por un par que ya controla la máquina) inflan o vacían el
    saldo. El heartbeat de la Capa 3 sigue siendo detección de caída, no de
    compromiso.
  - **El intercambio no se propaga por la red todavía**: la cadena de
    contribuciones es local al estado de cada vista. Dos vistas de la misma red
    pueden llevar contabilidad distinta hasta que exista el datagrama que la
    replica y su reconciliación.
  - **El plan no promete que se ejecute**: un plan admisible no garantiza que
    los pesos se bajen, que el mapeo capa→stage sea eficiente, ni que la red
    aguante el tráfico. El executor es MeshLLM y SMCP no lo verifica.
  - **La clave de identidad es un secreto en disco**: `KeyPair.save` la escribe
    con `chmod 600` y **rechaza persistir una clave HMAC** (su mitad privada es
    el secreto compartido, o sea, el trust anchor del verificador). Si alguien
    lee ese fichero, puede firmar como ese nodo — la misma confianza que en
    cualquier esquema de identidad por clave.

### La pertenencia anclada (`membership.py`) — lo que el grafo decide y lo que no

La pertenencia de un nodo se prueba con un output que cumple un lock, su
prueba de inclusion, y la firma de la clave que **controla** ese output. Tres
piezas, y las tres hacen falta: sin la firma, cualquiera que viera el outpoint
en la cadena podria reclamarlo.

**Lo que da la estructura, sin codigo:**

| Propiedad | De donde sale |
|---|---|
| Dos rotaciones simultaneas -> una gana | doble gasto de UTXO |
| La ascendencia ES la sucesion de claves | el grafo, no un registro |
| No se puede renovar sin pagar un fee | hay que gastar un output |

Eso es Sybil en la capa de identidad, y no esta en el codigo porque la
estructura de la cadena ya lo impone. Un nodo no puede renovarse a si mismo
infinidamente sin fees — y la trampa "rotar a la misma clave" (que si
renovaria gratis) esta rechazada en las dos capas: al construir y al verificar,
porque un `RotationProof` puede llegar de la red, no solo de este constructor.

**Lo que NO cubre, y esta escrito para que no se lea al reves:**

* **SPV no valida la cadena (BRC-96).** Verifica que la transaccion esta en
  *esa* cabecera. Que esa cabecera sea la mas larga no lo comprueba nadie, y
  por eso la confianza esta en la **cadena de cabeceras** que el verificador
  elige, no en la prueba. Un gate de pertenencia alimentado con cabeceras de
  un hostil acepta todo lo que el hostil firmo.
* **La lock de confianza es del operador.** Si el lock es un lock de pubkey,
  cualquiera despliega su propio SC y su propia malla, y las dos son
  indistinguibles para un verificador. La lista de locks aceptados vive en el
  cliente, no en la cadena.
* **No parsea Bitcoin Script.** `MembershipLock.from_spent_output` lanza
  `ProtocolError` en vez de devolver un lock. Verificar contra la cadena real
  exige extraer el script del output gastado y hashear; el modulo no finge
  hacerlo.
* **El coste del join lo pone el minado, no el modulo.** Un join de 1 satoshi
  sigue siendo una membresia valida. La presion economica la decide el
  lock elegido, y sin ella el Sybil es barato. Hay test que lo fija.
* **`MembershipSet` es una vista local.** `is_member` responde "lo que este
  nodo ha visto". Un nodo desconectado puede tener una respuesta desactualizada,
  y con ella la garantia de que la misma clave no siga siendo miembro en otro
  sitio.

**Lo que la mutacion encontro (20 trampas, 17 detectadas).** Cuatro de las
que sobrevivieron en la primera ronda eran la garantia central — no
rechazar un outpoint gastado, dejar la clave vieja como miembro, permitir
rotar a si misma, y no verificar la inclusion — y las cuatro estaban
escritas en el codigo sin estar sujetas. La de la inclusion era la mas
interesante: mi mutacion sustituyo solo la ultima linea del metodo, y la
guarda de cabecera la interceptaba antes, asi que la trampa era ciega por
construccion y no por debilidad del test.

Las tres que sobreviven en la ronda final tienen una **segunda guarda** en
`bsv_keys.verify_public` (longitud de firma y de pubkey) o en el `int()` de
la conversion de outpoint. Duplicar la guarda es defensa en profundidad entre
capas; la consecuencia aceptada es que la mutacion no puede distinguir esa
duplicacion de la redundancia. Documentado en el test, no escondido.

### El cerrojo entre procesos (`reservation_ipc.py`) — lo que hace vendible el tier 2

`ReservationBook` protege con un `threading.Lock`. Dentro de un proceso es
correcto, y entre dos es falso: dos procesos del Web API con su libro venderian
la misma VRAM a dos clientes. Ese era el limite escrito que impedia vender el
tier de pago unico en multi-proceso.

**La eleccion: `flock` sobre un fichero de cerrojo, no de estado.** El estado
se queda en memoria de cada proceso; lo que se comparte es la exclusion. Cuando
un proceso entra: espera, recarga si el estado cambio, opera, vuelca, suelta.

Se descarto persistir el libro entero por dos razones concretas: el estado
recargado mantiene VRAM que nadie usa o libera VRAM que alguien prometyo (las
dos cosas que el modulo original evita a proposito), y `reserve` es el camino
caliente del planificador — pagarlo con una escritura por llamada no tiene
sentido cuando lo que hace falta es exclusion, no estado compartido.

**Lo que sigue sin arreglar:**

* **No es transaccional con el trabajo real.** Si el proceso muere entre tomar
  la reserva y despachar, la reserva vive hasta que expire el TTL. Es el mismo
  limite que la version de un proceso.
* **No coordina entre maquinas.** `flock` es local al sistema de ficheros. Dos
  contenedores con ficheros distintos no se ven. La coordinacion entre
  maquinas es OTRO problema, y no se disimule.
* **Un NFS o un bind-mount sin bloqueo fiable no lo da.** Por eso
  `interprocess_available()` dice explicitamente si el cerrojo es de fiar, en
  vez de asumirlo. Un cerrojo que no cierra es peor que no tener cerrojo: da la
  sensacion de seguridad sin darsela.
* **El cerrojo hace correcto, no rapido.** Dos procesos se serializan, que es
  justo lo que hace la garantia atomica; ahora atraviesa la frontera.

**El fallo que un cerrojo bien puesto NO evita**, y que casi se introduce sin
querer: recargar. Si el segundo proceso cierra el cerrojo pero opera sobre su
vista vieja, vende lo mismo. Por eso la operacion es *cerrar -> recargar ->
operar -> volcar*, y hay una trampa de mutacion que quita la recarga a proposito.

**Lo que la mutacion encontro.** La primera trampa — sustituir el `flock` por un
no-op — la detecta el test de dos procesos reales, que existe justamente porque
la version de un solo proceso no puede tener este fallo: el GIL haria cada
operacion simple atomica, y un test con threads daria verde con el cerrojo
eliminado.

**Y un error mio que el detector de capacidad calló en silencio:**
`os.flock` no existe en Linux; la funcion vive en `fcntl.flock`, y las banderas
tambien. La primera version de `interprocess_available()` decia "esta plataforma
no expone os.flock" en un Linux que si soporta el cerrojo. Un detector que
miente es peor que uno que no existe, porque desactiva la proteccion creyendo
que la plataforma es incapaz. Ahora resuelve por `fcntl` y hay test que falla si
vuelve a mirar en `os`.

### Las reservas dedicadas (`reservation.py`) — fuera de capa

`plan_placement` **planifica**. Esto **retiene**. Un plan es JSON, y dos planes
pueden nombrar el mismo nodo y los mismos GiB y ser ambos individualmente
válidos: nada en un plan impide que el segundo despierte. Esa es la razón de que
el módulo exista.

- **Adversario**: el propio llamador legítimo, dos peticiones simultáneas. No
  hace falta un atacante — dos clientes honestos bastan.
- **Garantía**: la comprobación de hueco y la cuenta ocurren en la misma sección
  crítica, así que no hay ventana entre «hay sitio» y «lo he cogido». Un test
  lanza dieciséis hilos pidiendo 1 GiB contra 8 GiB y exige exactamente ocho.
- **La generación va en cada reserva.** Un snapshot es lo que un nodo *reporta*,
  no lo que esta malla repartió. Las reservas **sobreviven** al snapshot y se
  re-marcan; limpiarlas en cada uno liberaba reclamaciones en vivo y entregaba
  la misma VRAM dos veces. Solo se descarta una reserva que ya no cabe en la
  línea base fresca, o cuyo nodo salió de la malla.
- **`release` no es idempotente por diseño, es idempotente por resultado**:
  liberar dos veces la misma reserva devuelve `not_held` y no devuelve la
  memoria dos veces. Un id fabricado por el llamador no libera la memoria de
  otro: se busca dentro del libro del nodo.
- **`move` es el failover**: la carga pasa del origen al destino, y si el
  destino no tiene sitio la reserva **vuelve al origen**. Perderla en silencio
  dejaría al origen verse libre sin estarlo — la sobreventa exacta que el módulo
  evita.
- **Lo que NO arregla**: `ReservationBook` **no se persiste**, así que un
  reinicio pierde las reservas. Es deliberado — una promesa sobre los próximos
  minutos de scheduling local no sobrevive a un proceso nuevo — pero significa
  que un reinicio *durante* una Inferencia dedicada libera la VRAM prometida sin
  avisar. No hay recuperación de reservas. Tampoco hay un TTL
  obligatorio: con `ttl_s=0` la reserva se mantiene hasta que se libere, así que
  un cliente que muere y nunca libera la tiene para siempre dentro de ese
  proceso. Y un `ReservationBook` es **por proceso**: dos procesos del Web API
  no comparten libro y podrían vender la misma VRAM. Eso exige el POSIX
  coordinator de múltiples procesos que la capa 4 ya tiene como zona abierta.

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

### Mejoras opt-in: HCI y métricas (`hci.py`, `metrics.py`, `rsi.py`) — fuera de capa

No son capas de seguridad: son **instrumentación que se afirma a sí misma**. Se
documentan aquí porque el riesgo no es que fallen, sino que alguien lea un
número y lo tome por una medición verificada.

- **Adversario**: nadie externo todavía. El riesgo es el **propio operador**, o
  un tercero que consume la cifra: que confiera a un número autoinformado la
  autoridad de una medición.
- **Supuestos**: el `Scorer` es honesto; los `frontier` de `SMCP_FAMILY` son los
  publicados; el reloj mide latencia de verdad.
- **NO-garantías (explícitas)**:
  - **El HCI no está anclado a nada externo.** `hci.py` normaliza
    linealmente contra un `frontier` y un `perfect` que son **constantes
    escritas a mano** (`0.30` / `0.55` en `SMCP_FAMILY`, orientativas por
    comentario propio). El HCI es aritmética, no evidencia: con las mismas
    entradas da el mismo número aunque el `Scorer` mienta, siempre que la
    fórmula sea la misma. La escala es estable *por construcción*, no por
    medición.
  - **El `Scorer` no está verificado ni atado al ledger.** Es un
    `Callable` que devuelve `benchmark.id -> score`. Nada le impide inventarse
    los scores, y `HCIMeter.improve()` los mete en el `RSIImprovement` tal
    cual, firmándose a sí mismo la conclusión ("cerró 12 puntos de
    headroom"). La mejora RSI queda **auditada** (digest + firma + cadena del
    ledger) pero su *efecto* — el HCI — es **una afirmación sin ancla**.
  - **El HCI no está conectado al loop RSI.** `RSILoop` (`rsi.py`) no importa
    `hci`; solo la demo (`delm/demo/run_rsi_demo.py`) y sus tests lo usan. La
    afirmación de `architecture.md` de que el loop "usa el HCI para medir" y la
    de `hci.py` de "uso en el loop RSI" describen la **intención**, no el
    estado del código: hoy la retención de una regla y su medida van por
    caminos separados y nadie compara ambas.
  - **La precisión de la latencia es la del reloj del proceso** y los
    percentiles (p50/p95) son sobre la mezcla **admitidas + fallidas**
    (`metrics.py::aggregate` lo dice, pero el número agregado por defecto las
    mezcla). Para latencia de rutas felices hay que filtrar `records()`
    antes. Sin NTP/jumps, el reloj es el reloj (§3.3).
  - **El coste es orientativo.** `DEFAULT_PRICING` son precios 2026 de
    referencia; un modelo desconocido **se presupuesta a 0.0 en silencio**
    (`price()` nunca lanza). Un `total_cost_usd` de 0 puede significar "gratis"
    o "no sé el precio": hay que pasar tu propia tabla
    (`MetricsTracker(pricing=...)`) para contabilidad real.
  - **`metrics` es in-process y no persistente**: `MetricsTracker` es un
    `@dataclass` en memoria; `aggregate()` es una vista, y perder el proceso
    pierde las métricas. No es un log de auditoría (para eso está el ledger).
  - **El endpoint al que se cobra es responsabilidad de quien lo opera.**
    `MeteredLLMClient` debita el crédito **antes** del `await` — es lo que
    impide que un par sin crédito gaste GPU ajena — así que una inferencia
    que falla (timeout, 404, modelo no cargado) **también se cobra**. El
    sistema no reembolsa: `served` cuenta lo que se recibió, `failed` lo que
    se cobró sin recibir, y `served + failed` es lo que se facturó. La
    discrepancia es responsabilidad del nodo que opera el endpoint, y solo él
    puede resolverla (reintentar, o dejar la petición sin cobrar).
  - **La interacción RSI ↔ HCI no está verificada.** Aunque mañana se conecten
    (una regla retenida → una medida), el gate de retención sigue siendo
    *consistencia de la evidencia* (`RuleVerifier`), no "la mejora funcionó":
    una regla puede pasar el gate y ser inútil. El HCI, si se conecta, será un
    *observador* del avance, no una *puerta* de admisión.

**Consecuencia práctica para el threat model**: un HCI que sube, o un
`total_cost_usd` que cuadre, **no** son afirmaciones verificables por este
sistema. Para convertirlas en evidencia harían falta (a) un `Scorer` externo y
fijado (suite real con versionado del benchmark), (b) el HCI derivado de esa
suite y no de una constante del repo, y (c) una política que use la medida
como señal, no como verdad.

### El anclaje a BSV (`bsv_keys.py`, `timechain.py`) — fuera de capa, en construcción

Existe la **identidad** y el **reloj del nodo**; el anclaje a la cadena todavía
no. Lo que hay y lo que no, exactamente:

**Lo que hay.** `Secp256k1KeyPair` (ECDSA-secp256k1, firma `r||s` de 64 bytes)
es la identidad que una cadena BSV puede verificar — Bitcoin no tiene Ed25519
nativo, y anclar Ed25519 sería un protocolo propietario. `Timechain` es el
registro del nodo de lo que publicó, con persistencia y `rebroadcast()` de todo
lo no confirmado. Un nodo que no recuerda qué publicó no puede defender que lo
publicó a esa hora, y una transacción no confirmada sigue siendo reemplazable
por cualquiera que la tenga en mempool: reenviarla hasta que la cadena la
confirme es lo que cierra esa ventana.

**Lo que NO hay — y es lo importante:**

- **No se publica nada.** No hay construcción de transacciones, ni
  `OP_RETURN`, ni mAPI, ni chain tracker. `Timechain.status()` lo dice:
  `spv_verified: false`.
- **No se verifica ninguna inclusion.** `mark_mined()` registra lo que la
  cadena *informó*; no comprueba una prueba de Merkle contra una cabecera. Por
  eso `AnchorRecord.proven` existe y vale `False` por defecto, y por eso
  `load()` restaura las entradas como no probadas: un nodo que reinicia no ha
  verificado nada en esta ejecución. "La cadena dijo que está" y "alguien
  comprobó la prueba" no son la misma afirmación.
- **La cadena es un tercero de confianza, y se asume como tal.** El orden, los
  sellos de tiempo y el trabajo de los bloques son lo que da valor de reloj. El
  ledger local (`ledger.py`) no es un sustituto: es rápido y encadenado, pero su
  orden lo fija quien escribe, no la red. `reorg` y Censorship son Threats
  reales de este diseño y no están mitigados por lo que hay hoy.
- **El ledger local no se ancla a este módulo.** Coexisten: las admisiones
  siguen firmando con Ed25519 vía `provenance.py`, y `provenance.verify_public`
  despacha `ecdsa-secp256k1` al módulo nuevo. Migrar las admisiones exige
  cambiar el valor por defecto de `sig_kind`, que viaja por la serialización
  de `contrib.py` y por tanto rompe entradas ya emitidas. Es un paso aparte y
  deliberadamente reversible.
- **Fuga de metadatos.** Solo sale el digest a la cadena, nunca el contenido.
  Pero el `entry_hash` va encadenado y la cadena es pública: un observador ve
  **cuántas** entradas sella cada nodo, **cuándo** y **a qué ritmo**. No ve qué
  admitieron; sí el patrón de actividad. Eso se acepta explícitamente y no se
  considera un detalle de implementación.

### Las reglas de firma de la malla (`mesh_node.py`, `secure_context.py`) — fuera de capa

**La regla que estas cuatro reglas cierran.** Antes, `handle_gist()` hacia
`register_key(author_id, pub_key)` **antes** de verificar nada, con la clave
que venía en el propio mensaje. La firma del gist verificaba — contra la clave
que el atacante acababa de instalar. Autenticación circular: demostraba que
quien firmó poseía la clave, no que la clave fuera de ese autor. `author_id`
era una etiqueta.

**Las cuatro reglas, según las fijó el dueño:**

1. **Una clave escuchando por nodo, a la vez, con idempotencia.**
   `register_key` con la misma clave es no-op (el gossip reentrega anuncios
   constantemente, y un rebind que cambiara estado en cada repetición haría que
   el keyring mintiera sobre lo que ha visto). Una clave *distinta* lanza
   `KeyRotationDenied`. La rotación es un acto explícito (`rotate_key`) que
   queda en el ledger con huellas, nunca las claves. Sin ese rastro, una
   rotación es indistinguible de un nodo comprometido.

2. **La clave firma, no cifra.** C sigue siendo legible; si no, no habría nada
   que renderizarle a un agente. La firma aporta autenticidad e integridad, no
   confidencialidad — y no se promete.

3. **El contexto viaja firmado siempre.** El digest canónico se recalcula del
   contenido recibido y tiene que coincidir con el firmado, así que una
   manipulación en tránsito se detecta aunque la firma sea válida sobre otra
   cosa. La clave viaja en el **anuncio** (handshake), nunca en el gist: una
   clave junto al contenido que firma solo prueba que ambos concuerdan entre sí.

4. **La red solo confía en nodos con contexto firmado.** `signed_only()` es la
   vista que la malla da por buena; `untrusted_labels()` dice qué hay en C que
   el nodo no puede respaldar. Contenido sin firma no es evidencia débil, es
   **ninguna** evidencia, y se rechaza aunque la política se abra.

**Threshold signatures después, sin cambiar esto.** Una atestación umbral
sustituye la prueba de clave única por una combinada; la forma de las reglas no
cambia. Lo que hoy es `is_attributed()` pasa a ser "k de n" y el resto igual.

**Lo que esto NO arregla.** La clave se liga al `peer_id` que el par declara en
su anuncio. Un par que se presenta con un `peer_id` distinto al de ayer es un
par nuevo, no una rotación: el keyring los distingue, pero nada impide que un
nodo se anuncie como quien quiera. Atar identidad a un nombre estable es
identidad fuera de la malla, y es lo que `spv.py` podría aportar después.

### La identidad del nodo (`spv.py`) — fuera de capa, en construcción

La atribución no la da la cadena, la da la clave, y **antes de este módulo no
existía criptográficamente**: `TrustGate.permit()` recibía
`(author_id: str, has_signature: bool)`, así que `author_id` era una etiqueta de
texto sin ninguna firma que la respaldara. Un nodo podía anunciarse
`nodo-0` y firmar con una clave sin relación con ese nombre. El objetivo de
atribución no se cumplía con la cadena ni sin ella.

**Lo que hay.** `SpvWallet` implementa BRC-75 (mnemonic BIP39 → `sha256(seed)`
como maestro), BRC-42 (derivación por secreto ECDH compartido, no BIP32) y
BRC-43 (`keyId` = `<nivel>-<protocolo>-<id>`). `address()` es
`pubkey → hash160 → base58check`: determinista y verificable por un tercero
que extraiga la pubkey de un input.

**Por qué BKDS y no BIP32.** BIP32 deriva las hijas con un chain code, así que
quien tenga la pubkey maestra y un índice ve *todas* las hijas: la pseudonymía
se pierde. BKDS usa el secreto ECDH de las dos partes, y el mismo índice da una
clave distinta para cada contraparte. Aquí se usa autoderivación, así que cada
propósito (`anchor`, `admission`, y el de pagos cuando exista) es una clave
distinta del mismo maestro: comprometer una no compromete la identidad, y un
observador no puede enlazarlas.

**No-garantías de esta capa:**

- **La pseudonymía no es anonimato, y no pretende serlo.** Cada clave es
  pública y las derivadas son deterministas: un observador ve cuántas anclas
  firma un nodo y con qué claves. Lo que la derivación aporta es que no puede
  *enlazar* unas con otras ni con el maestro.
- **El mnemonic es el punto de fallo único.** Está en el fichero 0600, no en
  el `repr`, y `create()` rechaza una frase con el checksum mal en vez de
  aceptarla en silencio. Pero un mnemonic en un disco es un secreto con doce
  palabras de longitud: no hay umbral, no hay hardware. El respaldo en papel
  sigue siendo la única protección real y **no está implementado**.
- **La passphrase no está probada.** `SpvWallet.save()` no la guarda, así que
  una wallet creada con passphrase no se puede restaurar desde su fichero
  (solo desde el mnemonic). Es un hueco conocido, no una decisión.
- **El ledger local sigue sin anclarse y las admisiones siguen con ed25519.**
  `spv.py` da la identidad; no está conectado a `provenance.py` ni a
  `contrib.py`. Esa conexión es un paso aparte.
- **El anclaje sigue sin existir, pero el digest que se anclaría ya es
  portable** (ver la seccion siguiente, `ledger_canon.py`). Lo que falta es la transacción
  `OP_FALSE OP_RETURN` de BRC-220, el certificado y la prueba SPV. Publicar
  hoy es imposible no porque falte el formato, sino porque nadie construye
  la transacción: la diferencia importa, porque el formato es la parte que
  cuesta más cara de arreglar más adelante.

### Los bytes canónicos del ledger (`ledger_canon.py`) — fuera de capa, groundwork

**Qué es.** `entry_hash` es lo que un ancla BSV comprometería. Antes se
calculaba como `sha256(json.dumps(to_dict, sort_keys=True) + "|" + prev)`:
correcto, pero reproducible solo por una implementación concreta de Python.
`ledger_canon.py` define dos formatos y hace que cada entrada declare el suyo.

- **v1**, intacto byte a byte. Los ledgers ya escritos llevan esos digests;
  "limpiarlos" invalidaría cada rastro de auditoría existente. Se conserva
  también su `ensure_ascii=True`, que parece un detalle y no lo es: con texto
  no-ASCII, las dos grafías dan digests distintos, así que un refactor
  aparentemente inocuo re-digere los ficheros en disco.
- **v2**, bytes canónicos con prefijo de longitud `lp(x) = u32be(len) || x`,
  UTF-8 sin escapes, `prev_hash` delimitado y presente una sola vez, y `ts` como
  IEEE-754 de 64 bits en vez del texto `"1.0"`. Un verificador en cualquier
  lenguaje reproduce el digest sin decidir una política de escapado.

**Lo que v2 rechaza, y por qué importa.** Un formato canónico que acepta
campos desconocidos no es canónico: si `kind` se ignorara en silencio, una
admisión y una observación del HCI pre-hashearían igual y un lote podría
relabearse sin invalidar su digest. Por eso sobran campos, hex no minúsculo,
longitudes fuera de rango y `accepted` que no sea `bool` lanzan `ValueError`.

**Corrección a una afirmación previa.** Se afirmo que el separador `"|"` de v1
era ambiguo porque `reason` es texto libre y puede contener una barra. **No es
cierto**: `prev_hash` ya está dentro del JSON con su nombre de campo, así que
la concatenación es redundante, no ambigua. El fallo real de v1 es la
reproducibilidad (y `float`/`ensure_ascii`), no una colisión.

**Lo que no da.** Los bytes canónicos no dan inmediatez ni inmutabilidad. Solo
hacen que, *cuando* exista el ancla, el digest sea comprobable por un tercero
sin este repositorio. Sigue faltando el `kind` por lote como campo de primera
clase (hoy un `kind` añadido es un error, por diseño), la transacción BRC-220,
la prueba de inclusión contra cabeceras y la cadena de confianza completa.


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
6. **La capacidad de un nodo es una afirmación firmada, no una medición**: el
   intercambio garantiza *quién*-la-emitió y *cuándo*, no que la VRAM exista
   (ver §2, "El intercambio de la malla"). El día que la atestación sea real,
   esta línea se reescribe; hasta entonces, el radio de la mentira es
   "acotado y auditable", no "cero".
7. **Las cifras propias no son evidencia**: HCI y `metrics` son
   **instrumentación autoinformada** — un `frontier` de referencia escrito a
   mano y un `Scorer` que nadie verifica. Un HCI que sube o un coste que cuadra
   son afirmaciones del propio sistema, auditables pero **no verificables**
   (ver §2, "Mejoras opt-in"). El HCI ni siquiera está conectado al loop RSI.

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
  pipeline, los no-ops honestos, **el contrato de firmas de los overrides contra
  `acp.Agent`**, y el smoke stdio slow) → `test_serve.py`;
- intercambio (reto de un solo uso y caducidad, firma que ata los números,
  `peer_id` ligado a su clave, cadena con rechazos persistentes, crédito por
  uptime observado, gasto que se niega, metered client) →
  `test_contrib.py`, y la cadena completa de la tesis
  (contribuir → crédito → plan → cobro) → `test_exchange_thesis.py`;
- reparto (rechazo accionable, capacidad no admitida o sin crédito excluida,
  exclusividad del greedy, suma exacta de stages, capas que teselan
  `[0, n-1]`, determinismo, replay) → `test_placement.py`;
- que la CLI y la web sean la misma malla, y que el plan no crece sobre
  capacidad manipulada → `test_api_mesh.py`, `test_mesh_cli.py`;
- dimensionado por hardware y su veredicto → `test_llmfit.py`, `test_api_fit.py`;
- bytes canónicos del ledger (v1/v2, y por qué v1 no era reproducible) →
  `test_ledger_canon.py`; identidad secp256k1, reloj del nodo y rebroadcast →
  `test_bsv_anchor.py`; wallet SPV (BRC-75/42/43) → `test_spv_wallet.py`;
- discovery, mDNS, control-plane, modo estricto y adaptador Harness →
  `test_deployment.py`, `test_mdns.py`, `test_provenance_strict.py`,
  `test_harness_adapter.py`; métricas y expansión → `test_mejoras.py`.

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
- El **HCI y las métricas son autoinformados**: el `frontier` es una constante
  escrita a mano y el `Scorer` no está verificado; además el HCI **no está
  conectado al loop RSI** (solo lo usa la demo). Una cifra que sube no es una
  medición verificada.
- El **coste de `metrics` puede ser 0 por desconocido**, no por gratis: los
  precios por defecto son de referencia y un modelo no listado presupuesta a 0.
- La **puerta ACP** (`smcp-serve`) no autentica in-band: su confianza es el
  límite de proceso (quien lo arranca); la config/key nunca viajan al cliente y
  las sesiones son efímeras.
- La **capacidad de un nodo es una afirmación firmada, no una medición**: no hay
  atestación de hardware, así que un nodo puede mentir sobre su VRAM. Lo que se
  garantiza es que la mentira queda atribuida, encadenada y sin poder
  disfrazarse de otro `peer_id`. **No hay slashing**: detectarla es fácil,
  sancionarla no está implementado.
- El **ranking es historial, no un saldo**, y no se puede gastar ni transferir:
  eso lo hace immune a la mayoría de los sueños de economía interna (emitir,
  prestarse, prometer), pero no lo hace verificable por sí solo — depende de
  que las anclas verifican contra una cabecera.
- El **solicitante de una inferencia no está atado a un pago**: la cadena
  demuestra que alguien pidió, no que pagara. Un par coludido podría inflar el
  ranking de otro sin gastar; para cerrarlo haría falta que el solicitante
  también publicara algo (un output, una firma) en su propia transacción.
- La **observación del uptime es del entorno**: un reloj desincronizado o un
  heartbeat falsificado mueven el saldo de crédito.


### El ancla de inferencias (`anchor.py`) — una transaccion por inferencia, sin contenido

La decision tiene dos mitades, y solo una es mecanismo.

**Una transaccion por inferencia.** La propia transaccion es la verificacion: su
existencia prueba que ocurrio, y el txid compromete a quien la firmo. No hay un
registro paralelo que pueda desincronizarse del grafo. La atribucion sale de que
el output se paga a la clave de membresia del nodo — el grafo ya lo dice, ningun
indice tiene que decirlo.

**No se hashea el contenido.** Ni el prompt, ni la respuesta, ni nada derivado.
La entrada lleva los datos del nodo y nada mas.

Lo que eso compra y lo que cuesta:

- Con hash del contenido: se verifica que ocurrio **y** que decia eso; un
  observador puede confirmar una conversacion; una disputa se resuelve.
- Sin hash (decidido): se verifica que ocurrio; **no** que decia eso; ningun
  observador confirma nada; una disputa de contenido **no** se resuelve.

La fila que no se va: **una disputa sobre el contenido de una inferencia no la
resuelve la cadena.** Nadie, ni el nodo, puede demostrar despues que inferencia
fue; solo que hubo una. Es coherente con lo decidido — resolverlo exigiria el
hash del contenido — y es irreversible para ese caso. Por eso el campo
`content_sha256` existe y **no se puede rellenar**: falla al construir, con el
motivo escrito, para que rellenarlo sea una decision y no un `dict.update`.

**No hay retroactividad.** Una inferencia tiene que estar en un bloque posterior
al de la membresia que la autoriza, y sin altura no se acepta.
El reloj declarado (`occurred_at`) no ordena nada: un reloj hostil pone lo que
quiera. Ordena la altura, que es del verificador.

**Inclusion antes que firma.** Si la transaccion no esta en un bloque, no hay
nada que firmar; al reves se gasta ECDSA de un atacante antes de comprobar lo
barato.

**Y la inclusion tiene que ser de la membresia declarada.** Dos cosas reales que
no van juntas siguen siendo dos cosas reales: sin esa comprobacion, un nodo
presenta una membresia verdadera y la inclusion de una transaccion cualquiera.

#### Lo que sigue sin resolver

* **BRC-96.** `chain_validated` es `False` siempre. La inclusion se comprueba
  contra la cabecera que entrega el verificador, y el CLI exige `--header` como
  entrada separada para que el proof no se avale a si mismo. Dos cabeceras de un
  atacante se validan mutuamente.
* **El importe del output no es un precio.** `satoshis` es el valor que lleva el
  output, elegido por el nodo, y no se verifica contra nada. El resumen lo expone
  como `satoshis_anchored`, que es un **conteo**; no hay ningun campo que lo
  llame pagado, y hay test de que no se pueda usar como si lo fuera.
* **No hay emision de la transaccion.** El modulo construye y verifica el ancla;
  la|`inscription**|

* **No hay emision de la transaccion.** El modulo construye y verifica el ancla;
  la que la publica es otra capa.
