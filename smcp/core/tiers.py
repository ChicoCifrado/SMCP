"""Tiers — los tres precios, y donde se cruzan.

Los tres niveles y lo que compra cada uno
------------------------------------------
=========  ==================  ==========================  ==================
Nivel      Coste                Que compra                  Que puede dar
=========  ==================  ==========================  ==================
``free``   gratis (roster)  entrar en la malla          compartir GPU
``ded``    100 000 sats         VRAM dedicada por un rato    capacidad aislada
``metered``250 sats/inferencia  inferencia de pago por uso  **nada**: puede
                                  ser 0 GB de VRAM publicados
=========  ==================  ==========================  ==================

Los nombres siguen lo que compra, no una numeracion. La numeracion que se uso
en la conversacion va al reves entre niveles (el "tier 1" es el de pago por
uso), y un numero que no corresponde a su orden es peor que no tener numero:
se acaba llamando "tier 2" a dos cosas distintas.

El punto de cruce, escrito porque la aritmetica no lo dice solo
-----------------------------------------------------------------
``ded`` cuesta 100 000 sats, y ``metered`` cuesta 250 sats por inferencia. El
corte cae exactamente en **400 inferencias**:

* menos de 400 -> sale mas barato pagar por uso (250 sats x 399 = 99 750)
* mas de 400 -> sale mas barato el pago unico (250 x 401 = 100 250)

Es un numero redondo, y probablemente sea intencionado: el cliente elige sin
tener que hacer cuentas, y el nodo tiene una respuesta estable a "cuanto me
cuesta esto". :func:`tier_for_inferences` lo deja explicito en vez de
dejarlo emerger de la multiplicacion, porque el dia que cambie un precio este
es el sitio donde el corte se mueve — y si el corte se vuelve asimetrico (o se
elimina), que sea una decision y no un accidente de division.

Lo que un nivel NO compra
-------------------------
* ``free`` **no** es gratis de verdad: entrar es gratis, pero servir
  no lo es — cada inferencia servida exige una tx con fee, y la fee
  la paga el servidor. El freno contra Sybil es el trabajo, no la
  entrada. Ver abajo.
* ``metered`` no compra pertenencia ni capacidad. Un nodo con 0 GB publicados
  que paga por inferencia es un consumidor, no un proveedor — y por eso
  :mod:`smcp.core.wiring` no lo trata como miembro.

El limite que no se va: la entrada gratis no es un obstaculo
-------------------------------------------------------------
Entrar cuesta 0: un roster off-chain, un intercambio de claves, un
aval mutuo (:mod:`smcp.core.join`). Y tampoco lo era con 1 satoshi:
con el precio de un pago unico uno compraba cien mil inscripciones.
**El coste de entrada no escala con la malla, punto — el freno no
puede estar en la puerta.**

El freno esta en el trabajo, y es lineal: servir una inferencia
exige una tx con fee que paga el servidor
(:mod:`smcp.core.intercambio`), asi que fabricar *N* inferencias
cuesta *N* fees. El coste escala con lo que el nodo *hace*, no con
lo que *dice ser*. Y un nodo sin VRAM publicada no sirve nada: el
historial no cuenta una inferencia de quien no es proveedor, y el
ranking ordena por inferencias servidas, no por identidades.

Eso no quita el hueco, que se deja explicito. Se arregla de dos
formas, y las dos estan pendientes de tu decision:

1. **La inscripcion paga por capacidad, no por entrada.** Un nodo que
   publica 16 GB podria pagar distinto que uno que publica 0. Entonces
   el coste escala con lo que el nodo realmente aporta desde antes de
   la primera inferencia, y un Sybil de entradas vacias no compra
   nada.
2. **El trabajo es el freno, y la capacidad se mide aparte.** Que es
   lo que hace este modulo: sabe cuanto cuesta servir, y no puede
   aplicarlo a la entrada porque la entrada es gratis — deja el hueco
   explicito: hoy el modulo *sabe* cuanto cuesta el trabajo y no
   puede aplicarlo a la capacidad.

Donde x402 encaja, y donde no — que es la pregunta que se hizo
----------------------------------------------------------------
La respuesta corta: **x402 es el mecanismo de ``metered``, y solo de ahi**, y
la razon esta en el propio modulo de x402, escrita antes de que existiera esta
decision:

    "It says nothing about whether a node is trustworthy, and it creates no
     persistent relationship — the spec is explicit that servers MUST NOT rely
     on nonce tracking, so a paid request does not make you a 'member'."

Eso es exactamente la forma de ``metered``: una relacion por peticion, sin
estado entre una y otra, y sin convertirse en pertenencia. El pago por uso **es**
un producto sin membresia, asi que un protocolo sin membresia le encaja de forma
natural.

Para los otros dos, x402 **no aporta y estorba**:

* ``ded`` — el pago es **unico y anterior**. Se paga una vez y se recibe
  capacidad reservada durante un rato. No hay nada que verificar peticion a
  peticion: lo que hay que garantizar es que la reserva llegue al nodo y no se
  venda dos veces, y eso lo hace :mod:`smcp.core.reservation`. Meter x402 aqui
  seria pedir un proof por inferencia para algo que ya se pago entero, y
  devolveria la eleccion al cliente cuando ya esta cerrada.
* ``free`` — no hay nada que cobrar. Un verifier de pagos aplicado a un nivel
  gratuito solo puede impedirlo.

Y hay un argumento tecnico mas, independiente de la intencion: la
``amount_sats`` de un proof de x402 esta atada a un challenge concreto, con su
nonce del servidor. Para ``metered`` eso encaja (250 sats, peticion a peticion).
Para la entrada (gratis, en el roster) **o** para una reserva de 100 000, el
importe esta en el **contrato**, no en el proof — asi que el proof de x402 no
lleva informacion que_verify_, y el gasto de un proof por operacion no compra nada.

Lo que si tiene sentido para los tres: **x402 como opcion de transporte** (que
un cliente pueda pagar por una inference de un nodo que no conoce la malla), no
como mecanismo de pertenencia. Eso es distinto y no esta decidido.

Lo que este modulo NO verifica
-------------------------------
No toca la cadena. La membresia es del roster
(:mod:`smcp.core.roster`, :mod:`smcp.core.join`) o, en v2, de la
prueba de inclusion (:mod:`smcp.core.membership`); este modulo solo
**nombra** los precios y dice cual de los tres corresponde a
un caso. Cobrar es de otra capa.

Y sobre el polvo, que es donde la primera version se equivoco
---------------------------------------------------------------
**BSV no tiene umbral de polvo.** El 546 sats es de Bitcoin Core (y de ABC, de
donde BSV forked), y se elimino. Una salida de 1 satoshi se minable y se gasta
sin friccion — que es exactamente lo que hace posible el protocolo de 1sat
ordinals: en BTC el dust limit obligaba a usar un rango de satoshis, y en BSV
basta con uno.

La version anterior de este modulo afirmaba lo contrario, y de ahi el nombre
`DUST_LIMIT_SATOSHIS = 546` que lingeron en :data:`BSV_DUST_LIMIT_SATOSHIS`
siendo cero. Se deja el nombre porque el error era el nombre tanto como el
numero, y un valor con nombre documenta el numero mientras que la ausencia de
nombre solo deja el numero suelto.

Y por que importa mas alla de la inscripcion: **la ausencia de polvo no
desampara al nivel gratuito, porque el freno nunca estuvo en la entrada**. El
polvo importaba mientras la entrada era el freno (cien mil salidas de 1
satoshi); hoy la entrada es off-chain y el freno de Sybil es la fee de
servir, que es lineal con el trabajo — no con las identidades.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

TierName = Literal["free", "ded", "metered"]

# ---------------------------------------------------------------------------
# Los precios. Named, y referenciados por los tests — no numeros sueltos.
# ---------------------------------------------------------------------------

#: Entrada: **gratis**. Desde v3 el join es off-chain (roster,
#: avales mutuos — :mod:`smcp.core.join`), no una inscripcion.
#: :data:`ORDINAL_SATOSHIS` sigue siendo 1 sat, pero es el
#: ordinal *dentro* de la tx de inferencia, no una entrada.
JOIN_SATOSHIS = 0

#: Pago unico por VRAM dedicada, en satoshis (0.001 BSV). **Incluye la
#: entrada**: es un pago unico, no una entrada mas una reserva. Sumar ambos
#: cobraria dos veces por lo mismo y doblaria el precio que se decidio.
DEDICATED_SATOSHIS = 100_000

#: Pago por uso, por inferencia, en satoshis.
#:
#: 250, no 100: el presupuesto de fee de la tx de
#: inscripcion es el precio menos el ordinal (249 sats), y
#: la tx serializa ~453 bytes — 249 sats cierran el relay
#: hasta ~0.55 sat/vB, que cubre el rango de 0.1 a 0.5
#: sat/vB con margen (a 0.5 la fee son ~227 sats). El knob
#: es este: si la tarifa objetivo sube, el precio sube con
#: ella (:func:`smcp.core.inscripcion.relay_budget` es la
#: medicion).
PER_INFERENCE_SATOSHIS = 250

#: Umbral de polvo de BSV: **cero**. No es "un umbral bajo" — es que BSV no
#: tiene ninguno. El dust limit de 546 sats era de Bitcoin Core (y ABC, del que
#: BSV forked); BSV lo elimino, y por eso una salida de 1 satoshi se minable
#: y se gasta sin friccion.
#:
#: Por que esta constante existe siendo cero, en vez de no existir: porque el
#: error es facil de cometer y ya se cometio. Importar el 546 de Bitcoin Core y
#: llamarlo "umbral de BSV" hace que un ordinal de 1 sat parezca no minable,
#: que es justo lo contrario de lo cierto. Un valor con nombre documenta el
#: numero; no tener el nombre solo deja el numero sin contexto, y el contexto
#: es lo que se pierde.
BSV_DUST_LIMIT_SATOSHIS = 0

#: 1 satoshi no necesita un rango de satoshis para ser gastable, al contrario
#: que en el Ordinals original de BTC, donde el dust limit obligaba a usar
#: varios. Ese es el motivo del nombre del protocolo.
BSV_SINGLE_SAT_OUTPUTS = True


def tier_for_inferences(n: int) -> TierName:
    """Que nivel conviene para *n* inferencias previstas.

    El corte son 400, y sale de la division exacta de los dos precios:
    :data:`DEDICATED_SATOSHIS` / :data:`PER_INFERENCE_SATOSHIS`.

    Se elige ``ded`` a partir de 400 **inclusive**: exactamente en el corte
    cuestan lo mismo, y el pago unico da capacidad reservada, que el metered no
    da. Ante un empate, el nivel con mas garantia.
    """
    if n < 0:
        raise ValueError(f"inferencias negativas: {n}")
    # Estricto a proposito: en el empate exacto (400) van **iguales**, y
    # gana `ded` porque da capacidad reservada. Con `<=` el empate caeria en
    # `metered`, que es la via que da menos garantia por el mismo precio.
    if n * PER_INFERENCE_SATOSHIS < DEDICATED_SATOSHIS:
        return "metered"
    return "ded"


def metered_cost_sats(n: int) -> int:
    """Satoshis por *n* inferencias al precio unitario."""
    if n < 0:
        raise ValueError(f"inferencias negativas: {n}")
    return n * PER_INFERENCE_SATOSHIS


def dedicated_is_cheaper(n: int) -> bool:
    """Verdad si el pago unico sale **mas barato** (no igual) que pagar por uso.

    El empate no cuenta como "mas barato": son el mismo precio, y la eleccion se
    resuelve por garantia, no por economia.
    """
    return metered_cost_sats(n) > DEDICATED_SATOSHIS


# ---------------------------------------------------------------------------
# Los tres niveles
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Tier:
    """Un nivel: que cuesta, que da, y que no da.

    ``provides_vram`` separado de ``allows_inference`` porque es la distincion
    que mas se confunde: un nodo de pago por uso puede consumir inferencia y no
    publicar nada. Es un cliente de la malla, y el resto del sistema tiene que
    poder distinguirlo de un proveedor sin tratarlo como un nodo que no hace su
    trabajo.

    Donde se nota esa distincion, en otras palabras:

    * ``placement`` solo coloca carga donde ``provides_vram`` —o sea, donde hay
      ``vram_advertised_gb > 0``;
    * ``contrib.record_inference`` no cuenta historial a un nodo que no ofrece
      VRAM (``NOT_A_PROVIDER``), asi que un consumidor no aparece en
      :mod:`smcp.core.reputation`;
    * el ranking ordena por inferencias servidas, no por VRAM: tener hardware no
      es haber servido.
    """

    name: TierName
    #: Satoshis de entrada. En `ded` van **incluidos** en el pago unico: ver
    #: :data:`DEDICATED_SATOSHIS`. Por eso no se suman dos veces.
    join_satoshis: int
    #: Satoshis por inferencia. 0 = sin cargo por uso.
    per_inference_sats: int
    #: Satoshis por la reserva dedicada (0 = este nivel no reserva).
    dedicated_satoshis: int
    provides_vram: bool
    allows_inference: bool
    #: Si la entrada va incluida en el pago unico (true en `ded`).
    #: Si este nivel concede pertenencia en la malla.
    grants_membership: bool
    description: str
    entry_included: bool = False
    #: Si x402 es el mecanismo adecuado de este nivel, y por que no. Es un
    #: campo y no un comentario porque la pregunta "donde encaja x402" es de
    #: diseno y no debe depender de que alguien lea el docstring.
    x402_suitable: bool = False
    x402_note: str = ""

    def quote(self, *, inferences: int = 0,
              dedicated: bool = False) -> int:
        """Satoshis que cuesta un uso de este nivel.

        **El pago unico ya incluye la entrada.** En `ded`, la entrada y la
        reserva son el mismo pago de 0.001 BSV: sumarlas daria 200 000 y seria
        cobrar dos veces por lo mismo. Por eso :attr:`dedicated_satoshis` es el
        total del nivel y no un extra — y :attr:`entry_included` lo deja escrito
        para que nadie lo lea como un descuido.
        """
        if inferences < 0:
            raise ValueError(f"inferencias negativas: {inferences}")
        if dedicated:
            if not self.dedicated_satoshis:
                raise ValueError(
                    f"el nivel {self.name!r} no tiene pago unico: no se puede "
                    f"reservar VRAM dedicada en el")
            # El pago unico es el TOTAL, no un extra sobre la entrada.
            return self.dedicated_satoshis
        return self.join_satoshis + inferences * self.per_inference_sats

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "join_satoshis": self.join_satoshis,
            "per_inference_sats": self.per_inference_sats,
            "dedicated_satoshis": self.dedicated_satoshis,
            "provides_vram": self.provides_vram,
            "allows_inference": self.allows_inference,
            "entry_included": self.entry_included,
            "grants_membership": self.grants_membership,
            "x402_suitable": self.x402_suitable,
            "x402_note": self.x402_note,
            "description": self.description,
        }


#: Entrada gratis (roster, off-chain). Comparte GPU y recibe acceso a
#: la malla; el freno Sybil es el trabajo servido, no la entrada.
TIER_FREE = Tier(
    name="free",
    join_satoshis=JOIN_SATOSHIS,
    per_inference_sats=0,
    dedicated_satoshis=0,
    provides_vram=True,
    allows_inference=True,
    grants_membership=True,
    x402_suitable=False,
    x402_note="No hay nada que cobrar. Un verificador de pagos sobre un nivel "
              "gratuito solo puede impedirlo.",
    description="Entrada gratis por el roster (off-chain). Comparte su "
                "GPU; el freno Sybil es el trabajo servido, no "
                "la entrada.",
)

#: Pago unico por VRAM dedicada.
TIER_DEDICATED = Tier(
    name="ded",
    join_satoshis=DEDICATED_SATOSHIS,
    per_inference_sats=0,
    dedicated_satoshis=DEDICATED_SATOSHIS,
    provides_vram=True,
    allows_inference=True,
    entry_included=True,
    grants_membership=True,
    x402_suitable=False,
    x402_note="El pago es unico y ANTERIOR: lo que hay que garantizar es que la "
              "reserva llegue y no se venda dos veces, y eso lo hace "
              "reservation. Un proof por inferencia para algo ya pagado "
              "devolveria la eleccion al cliente cuando ya se decidio.",
    description="Pago unico de 0.001 BSV por VRAM dedicada durante el tiempo "
                "acordado. A partir de 400 inferencias sale mas barato que "
                "el pago por uso.",
)

#: Pago por uso. Puede publicar 0 GB: es un consumidor, no un proveedor.
TIER_METERED = Tier(
    name="metered",
    join_satoshis=0,
    per_inference_sats=PER_INFERENCE_SATOSHIS,
    dedicated_satoshis=0,
    provides_vram=False,
    allows_inference=True,
    grants_membership=False,
    x402_suitable=True,
    x402_note="Encaja de forma natural: x402 es una relacion por peticion sin "
              "estado entre una y otra, y el pago por uso es justamente un "
              "producto sin membresia. La amount_sats del proof es el precio "
              "de esta inferencia.",
    description="250 sats por inferencia, con 0 GB de VRAM publicados. No "
                "concede pertenencia: es un cliente de la malla.",
)

TIERS: dict[TierName, Tier] = {t.name: t for t in
                              (TIER_FREE, TIER_DEDICATED, TIER_METERED)}


def tier(name: str) -> Tier:
    """El nivel por nombre. Lanza si no existe, en vez de devolver ``None``."""
    try:
        return TIERS[name]  # type: ignore[index]
    except KeyError:
        raise ValueError(
            f"nivel {name!r} desconocido; hay {sorted(TIERS)}") from None


# ---------------------------------------------------------------------------
# La decision
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PlanQuote:
    """Lo que cuesta un plan, y por que nivel.

    ``savings_vs_metered_sats`` es lo que el cliente ahorra eligiendo bien, o
    lo que paga de mas eligiendo mal. Negative = el metered era mas barato.
    Es el numero que hace la eleccion visible en vez de una recomendacion que
    hay que creer.
    """

    tier_name: TierName
    total_satoshis: int
    inferences: int
    metered_equivalent_sats: int
    savings_vs_metered_sats: int
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier_name,
            "total_satoshis": self.total_satoshis,
            "inferences": self.inferences,
            "metered_equivalent_sats": self.metered_equivalent_sats,
            "savings_vs_metered_sats": self.savings_vs_metered_sats,
            "reasons": list(self.reasons),
        }


def quote(*, inferences: int, wants_dedicated: bool = False,
          offers_vram: bool = False) -> PlanQuote:
    """Presupuesta un plan y explica la eleccion.

    La eleccion tiene una sola pregunta: **¿va a compartir VRAM?**

    * si ofrece VRAM -> entra en ``free`` (gratis, roster) y consume su
      propia capacidad;
    * si no ofrece nada y solo quiere inferencia -> ``metered``;
    * si quiere capacidad aislada por un rato -> ``ded``, y solo tiene sentido
      si el plan justifica los 100 000 sats.

    Un nodo que ofrece VRAM **no** necesita pagar ``metered`` por consumir su
    propia capacidad: cobrarle por su propia GPU seria cobrar dos veces. Por eso
    :meth:`quote` no suma ``per_inference`` cuando ``offers_vram`` es cierto, y
    por eso el motivo va en :attr:`PlanQuote.reasons` — que se pueda ver por que
    no se cobra.
    """
    if inferences < 0:
        raise ValueError(f"inferencias negativas: {inferences}")

    reasons: list[str] = []
    metered_equiv = metered_cost_sats(inferences)

    if wants_dedicated:
        exacto = metered_equiv == DEDICATED_SATOSHIS
        if tier_for_inferences(inferences) == "ded":
            chosen = TIER_DEDICATED
            # El empate se dice "empate". Decir "mas que" cuando los numeros
            # son iguales es una mentira pequena que hace que el cliente dude
            # de los numeros, que es justo lo que estos motivos existen para
            # evitar.
            if exacto:
                reasons.append(
                    f"{inferences} inferencias cuestan {metered_equiv} sats, "
                    f"exactamente los {DEDICATED_SATOSHIS} del pago unico: "
                    f"empate, y gana el pago unico porque da capacidad "
                    f"reservada por el mismo precio")
            else:
                reasons.append(
                    f"{inferences} inferencias cuestan {metered_equiv} sats al "
                    f"pago por uso, mas que los {DEDICATED_SATOSHIS} del pago "
                    f"unico")
        else:
            chosen = TIER_METERED
            reasons.append(
                f"{inferences} inferencias cuestan {metered_equiv} sats, menos "
                f"que los {DEDICATED_SATOSHIS} del pago unico: el pago unico "
                f"salen mas barato")
            reasons.append(
                f"pero pediste VRAM dedicada, asi que el metered lo cubrira "
                f"con capacidad compartida, no reservada")
    elif offers_vram:
        chosen = TIER_FREE
        reasons.append(
            "ofrece VRAM: entra gratis por el roster y consume su propia "
            "capacidad, así que no se le cobra por uso")
    else:
        chosen = TIER_METERED
        reasons.append(
            "no ofrece VRAM ni pide dedicada: es un consumidor de la malla, y "
            "se le cobra por inferencia")

    total = chosen.quote(inferences=inferences,
                         dedicated=(chosen is TIER_DEDICATED
                                    and wants_dedicated))
    return PlanQuote(
        tier_name=chosen.name,
        total_satoshis=total,
        inferences=inferences,
        metered_equivalent_sats=metered_equiv,
        savings_vs_metered_sats=metered_equiv - total,
        reasons=tuple(reasons),
    )


def levels() -> dict[str, dict[str, Any]]:
    """Los tres niveles, para el CLI y para un endpoint de precios."""
    return {n: t.to_dict() for n, t in TIERS.items()}


__all__ = [
    "Tier", "TierName", "TIERS", "TIER_FREE", "TIER_DEDICATED", "TIER_METERED",
    "PlanQuote", "tier", "quote", "levels",
    "tier_for_inferences", "metered_cost_sats", "dedicated_is_cheaper",
    "JOIN_SATOSHIS", "DEDICATED_SATOSHIS", "PER_INFERENCE_SATOSHIS",
    "BSV_DUST_LIMIT_SATOSHIS", "BSV_SINGLE_SAT_OUTPUTS",
]