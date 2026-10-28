# Roadmap: SMCP "La BSV Mesh" con BSV Bitcoin Computer

## Resumen ejecutivo

SMCP evoluciona de malla multi-agente a "La BSV Mesh": una red privada y soberana donde la creacion y la entrada se pagan via x402, la computacion se ejecuta con Qwenputer en bf16 con paridad bit a bit, y cada resultado se ancla en BSV. El roadmap cubre desde el scaffold actual hasta un sistema completo y verificable.

---

## Objetivos

1. Crear y unir meshes privadas con pago x402/BRC-121.
2. Ejecutar inferencia y calculo con Qwenputer en bf16.
3. Compartir activaciones entre nodos sin perdida.
4. Anclar resultados y estado en BSV.
5. Sincronizar el filesystem in-model con la cadena.
6. Mantener soberania: claves locales, sin cloud, sin sandboxes externos.

---

## Fase 0: Fundamentos (completada)

### Entregables

- Scaffold `pago2mesh` y `join2mesh`.
- Validacion de headers x402.
- Tests minimos verdes.
- Issues y milestone creados.

### Criterio de salida

- PR abierto y gate README verde.

---

## Fase 1: Validacion x402 real

### Entregables

- Parseo y validacion de BEEF (BRC-95).
- Verificacion de timestamp (ventana 30 s).
- Internalizacion de pago via wallet.
- Anti-replay con `isMerge`.
- Tests unitarios y de integracion.

### Dependencias

- Wallet BSV funcional.
- BRC-121.

### Criterio de salida

- Un request pagado se acepta; un replay se rechaza.

---

## Fase 2: pago2mesh create completo

### Entregables

- Endpoint de creacion con x402.
- Firma canonica de la mesh.
- Inicializacion de `MeshNetwork` con `MeshRequirements`.
- Ancla de creacion en BSV.
- Manejo de errores y codigos HTTP.

### Dependencias

- Fase 1.

### Criterio de salida

- Mesh creada, firmada y anclada; `mesh_id` devuelto.

---

## Fase 3: join2mesh completo

### Entregables

- Endpoint de join con x402.
- Handshake firmado y vinculacion de clave.
- Evaluacion de requirements.
- Anuncio a la mesh y convergencia.
- Ancla de join en BSV.

### Dependencias

- Fase 2.

### Criterio de salida

- Nodo admitido, sincronizado y anclado.

---

## Fase 4: Qwenputer como motor estandar

### Entregables

- Integracion de Qwenputer bf16 en nodos.
- Configuracion de endpoint OpenAI-compatible.
- Driver RvChat empaquetado como servicio.
- Verificacion de paridad bit a bit entre nodos.
- Documentacion de requisitos (GPU 24 GB, checkpoint).

### Dependencias

- Fase 3.

### Criterio de salida

- Nodo ejecuta inferencia y calculo con Qwenputer.

---

## Fase 5: Endpoint 402 de inferencia y calculo

### Entregables

- Endpoint HTTP con x402.
- Ejecucion de inferencia de texto.
- Ejecucion de calculo exacto (CPU RISC-V).
- Metered inference (served/failed/refused).
- Ancla de resultado al finalizar.

### Dependencias

- Fase 4.

### Criterio de salida

- Request pagado produce resultado anclado.

---

## Fase 6: Comparticion de activaciones bf16

### Entregables

- Activacion transport entre nodos Qwenputer.
- Validacion de paridad bit a bit.
- Rechazo de mezcla de cuantizaciones o motores.
- Medicion de latencia.

### Dependencias

- Fase 5.

### Criterio de salida

- Activaciones compartidas sin perdida verificada.

---

## Fase 7: Anclaje BSV del resultado

### Entregables

- Payload canonico de ancla.
- Emision de transaccion al finalizar.
- Rebroadcast de no confirmadas.
- Ancla de fallo.
- Integracion con ledger local.

### Dependencias

- Fase 5.

### Criterio de salida

- Resultado anclado y verificable on-chain.

---

## Fase 8: Sincronizacion de filesystem in-model

### Entregables

- Exportacion de estado a BSV.
- Recuperacion desde cadena.
- Resolucion de conflictos.
- Verificacion de recuperacion determinista.

### Dependencias

- Fase 7.

### Criterio de salida

- Estado recuperado coincide con el anclado.

---

## Arquitectura de referencia

| Capa | Componente | Funcion |
|---|---|---|
| Economia | x402/BRC-121 | Pago por request |
| Identidad | KeyPair ed25519 | Firma y handshake |
| Politica | MeshRequirements | Requisitos inmutables |
| Malla | MeshNetwork | Contenedor de nodos |
| Transporte | Gossip/QUIC/Nostr | Propagacion |
| Computo | Qwenputer bf16 | Inferencia y calculo |
| Memoria | GDN como RAM | Estado exacto |
| Activaciones | Activation transport | Comparticion sin perdida |
| Verdad | BSV | Anclaje y persistencia |
| Contabilidad | Metered inference | served/failed/refused |

---

## Riesgos y mitigaciones

| Riesgo | Mitigacion |
|---|---|
| Qwenputer experimental | Pilotos controlados, auditoria |
| Paridad rota por cuantizacion | Regla bf16 completo, no cuantizar |
| Latencia alta | Firmware especializado, cache |
| Costo de anclaje | Batch de resultados, epochs |
| Grano de bloque | Pre-compromiso, rebroadcast |
| Seguridad heuristica | Documentar no-garantias |

---

## Criterios de aceptacion global

1. Mesh privada creada y anclada.
2. Nodo unido y sincronizado.
3. Request pagado produce resultado anclado.
4. Paridad bit a bit verificada.
5. Recuperacion determinista desde BSV.
6. Tests verdes y gate README actualizado.

---

## Referencias

- `smcp/core/pago2mesh.py`
- `smcp/core/join2mesh.py`
- `references/bsv-ledger-anchoring.md`
- `docs/threat-model.md`
- Qwenputer (Hugging Face)
- BRC-120, BRC-121, BRC-105, BRC-118