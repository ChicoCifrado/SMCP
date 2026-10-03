"""Tiers — los tres precios, y el punto donde se cruzan.

Lo que estos tests sujetan:

* **El cruce es 1 000 inferencias**, y sale de la division de los dos precios. Si
  un precio cambia, el corte se mueve — asi que hay test de los dos lados del
  corte, no solo del valor bonito.
* **Un empate se resuelve hacia la garantia.** En exactamente 1 000 cuestan lo
  mismo, y el pago unico da capacidad reservada. La eleccion tiene que ser
  determinista, o dos clientes identicos priced differently.
* **Un nodo que ofrece VRAM no paga por su propia capacidad.** Cobrarle dos
  veces (por entrar y por consumir) seria cobrar por la misma cosa.
* **Los tres niveles se nombran por lo que compran**, y el numero de la
  conversacion no corresponde al orden. Un numero que no ordena invite a llamar
  "tier 2" a dos cosas distintas.

Y lo que queda abierto, escrito para que no se lea como resuelto:

* **La entrada gratis no frena a nadie — y el satoshi tampoco
  la frenaba.** El freno contra Sybil es el trabajo: cada
  inferencia servida cuesta una fee que paga el servidor. Hay
  tests que miden exactamente eso.
* **El pago por uso no concede pertenencia.** Es un consumidor, y el gate de
  admision no debe tratarlo como un nodo que no hace su trabajo.
"""
from __future__ import annotations

import pytest

from delm.core.inscripcion import ORDINAL_SATOSHIS
from delm.core.tiers import (
    DEDICATED_SATOSHIS,
    BSV_DUST_LIMIT_SATOSHIS,
    BSV_SINGLE_SAT_OUTPUTS,
    JOIN_SATOSHIS,
    PER_INFERENCE_SATOSHIS,
    TIER_DEDICATED,
    TIER_FREE,
    TIER_METERED,
    dedicated_is_cheaper,
    levels,
    metered_cost_sats,
    quote,
    tier,
    tier_for_inferences,
)


# --------------------------------------------------------------------------
# Los precios, tal cual los fijaste
# --------------------------------------------------------------------------
def test_the_prices_are_the_ones_that_were_decided():
    """Entrada gratis, 100 000 por la dedicada, 100 por inferencia.

    Escritos como constantes nombradas porque un numero suelto incrustado en
    un script es un numero que nadie vuelve a encontrar. Y en satoshis, porque
    el precio tiene que ser exacto: un float seria un error de redondeo con
    dinero.
    """
    assert JOIN_SATOSHIS == 0
    assert DEDICATED_SATOSHIS == 100_000          # 0.001 BSV
    assert PER_INFERENCE_SATOSHIS == 100


# --------------------------------------------------------------------------
# El cruce
# --------------------------------------------------------------------------
def test_the_crossover_is_exactly_one_thousand_inferences():
    """El corte sale de la division, no de una decision.

    100 000 / 100 = 1 000. Por debajo gana el pago por uso, por encima el pago
    unico. Ese numero redondo es lo que hace que el cliente elija sin hacer
    cuentas.
    """
    assert DEDICATED_SATOSHIS // PER_INFERENCE_SATOSHIS == 1_000
    assert tier_for_inferences(999) == "metered"
    assert tier_for_inferences(1_000) == "ded"
    assert tier_for_inferences(1_001) == "ded"


def test_at_the_crossover_they_cost_exactly_the_same():
    """1 000 inferencias cuestan 100 000 sats por las dos vias.

    Y el pago unico gana el empate porque da capacidad **reservada**: mismo
    precio, mas garantia. Ante un empate, el lado con mas promesa.
    """
    assert metered_cost_sats(1_000) == DEDICATED_SATOSHIS
    assert tier_for_inferences(1_000) == "ded", "el empate va a la garantia"


def test_one_below_the_crossover_metered_is_strictly_cheaper():
    assert metered_cost_sats(999) == 99_900
    assert not dedicated_is_cheaper(999)
    assert metered_cost_sats(999) < DEDICATED_SATOSHIS


def test_one_above_the_crossover_dedicated_is_strictly_cheaper():
    assert metered_cost_sats(1_001) == 100_100
    assert dedicated_is_cheaper(1_001)


def test_negative_inferences_are_rejected_not_counted():
    """Menos cero tiene que fallar, no devolver un presupuesto negativo.

    Un total negativo en un sistema de pagos es un regalo silencioso, y un
    "negative zero" de inferencias es la forma mas barata de conseguir
    inferencia gratis — y de subir en el ranking sin haber servido nada.
    """
    for f in (metered_cost_sats, tier_for_inferences):
        with pytest.raises(ValueError):
            f(-1)


# --------------------------------------------------------------------------
# Los tres niveles
# --------------------------------------------------------------------------
def test_the_three_levels_exist_and_are_named_for_what_they_buy():
    """`free`, `ded`, `metered` — por lo que compran, no por su orden.

    La numeracion de la conversacion va al reves entre niveles (el "tier 1" es
    el de pago por uso). Un numero que no corresponde a su orden es peor que
    ninguno: se acaba llamando "tier 2" a dos cosas distintas.
    """
    assert set(levels()) == {"free", "ded", "metered"}
    assert tier("free") is TIER_FREE
    assert tier("ded") is TIER_DEDICATED
    assert tier("metered") is TIER_METERED


def test_an_unknown_level_raises_instead_of_returning_none():
    """Nombre equivocado -> error. ``None`` seria un fallo mas tarde."""
    with pytest.raises(ValueError) as ei:
        tier("tier2")
    assert "tier2" in str(ei.value)


def test_metered_grants_no_membership_and_provides_no_vram():
    """La distincion que mas se confunde: consumir no es pertenecer.

    El pago por uso compra inferencia y puede publicar 0 GB. Es un cliente de
    la malla, no un nodo que aporta. Si ``grants_membership`` fuera cierto,
    el gate de admision lo trataria como miembro y un nodo sin GPU entraria en
    el reparto como si tuviera capacidad.
    """
    assert TIER_METERED.provides_vram is False
    assert TIER_METERED.grants_membership is False
    assert TIER_METERED.allows_inference is True


def test_free_and_dedicated_both_grant_membership():
    assert TIER_FREE.grants_membership is True
    assert TIER_DEDICATED.grants_membership is True


def test_dedicated_is_the_only_level_that_can_reserve():
    """Pedir capacidad reservada en un nivel que no la tiene es un error."""
    with pytest.raises(ValueError) as ei:
        TIER_FREE.quote(inferences=10, dedicated=True)
    assert "reservar" in str(ei.value)


def test_the_one_off_payment_includes_the_entry_and_is_not_charged_twice():
    """0.001 BSV son 100 000 sat, UNA vez. Entrada incluida.

    Sumar entrada y reserva daria 200 000 y seria cobrar dos veces por lo
    mismo — el doble del precio que se decidio. Por eso
    :attr:`Tier.entry_included` existe: para que "la entrada va dentro" sea un
    dato, no algo que alguien lea y piense que es un descuido.
    """
    q = TIER_DEDICATED.quote(inferences=50, dedicated=True)
    assert q == DEDICATED_SATOSHIS, "un pago unico, no entrada mas reserva"
    assert TIER_DEDICATED.entry_included is True
    assert TIER_FREE.entry_included is False
    assert TIER_METERED.entry_included is False
    assert levels()["ded"]["entry_included"] is True
    # y el desglose sigue siendo visible sin cobrar de mas
    assert TIER_DEDICATED.join_satoshis == DEDICATED_SATOSHIS
    assert TIER_METERED.quote(inferences=50) == 50 * PER_INFERENCE_SATOSHIS


def test_a_quote_rejects_negative_inferences():
    with pytest.raises(ValueError):
        TIER_METERED.quote(inferences=-1)


# --------------------------------------------------------------------------
# La eleccion
# --------------------------------------------------------------------------
def test_a_node_that_offers_vram_enters_free_and_is_not_charged_for_its_own():
    """Cobrarle por su propia capacidad seria cobrar dos veces.

    Publica GPU, entra gratis por el roster, y consume de lo suyo sin cargo
    por uso. El motivo va en ``reasons`` para que "no se cobra" sea una
    decision visible y no un total que hay que interpretar.
    """
    q = quote(inferences=5_000, offers_vram=True)
    assert q.tier_name == "free"
    assert q.total_satoshis == JOIN_SATOSHIS == 0
    assert any("gratis" in r for r in q.reasons)


def test_a_consumer_with_no_vram_is_metered():
    """0 GB publicados y quiere inferencia -> pago por uso. Ni entrada ni reserva."""
    q = quote(inferences=10)
    assert q.tier_name == "metered"
    assert q.total_satoshis == 10 * PER_INFERENCE_SATOSHIS
    assert q.reasons


def test_a_large_plan_asking_for_dedicated_gets_dedicated():
    """5 000 inferencias cuestan 100 000, y ahorrar 400 000 frente a metered."""
    q = quote(inferences=5_000, wants_dedicated=True)
    assert q.tier_name == "ded"
    assert q.total_satoshis == DEDICATED_SATOSHIS
    assert q.savings_vs_metered_sats == 500_000 - DEDICATED_SATOSHIS


def test_the_exact_crossover_says_empate_not_mas_que():
    """En 1 000 los numeros son iguales, y el motivo tiene que decirlo.

    Decir "cuestan mas que" cuando cuestan lo mismo es una mentira pequena que
    hace que el cliente dude de los numeros — que es justo para lo que existen
    estos motivos.
    """
    q = quote(inferences=1_000, wants_dedicated=True)
    assert q.total_satoshis == DEDICATED_SATOSHIS
    assert q.savings_vs_metered_sats == 0, "empate exacto"
    assert any("exactamente" in r for r in q.reasons)
    assert not any("mas que" in r for r in q.reasons), \
        "los numeros son iguales: el motivo no puede decir que cuestan mas"


def test_a_small_plan_asking_for_dedicated_is_told_it_is_cheaper():
    """Pide dedicada para 10 inferencias: la eleccion le dice que sale a cuenta.

    Y el motivo explica que el pago por uso lo cubrira con capacidad
    *compartida* — que no es lo mismo, y es la diferencia que el cliente tiene
    que ver antes de aceptar.
    """
    q = quote(inferences=10, wants_dedicated=True)
    assert q.tier_name == "metered"
    assert q.total_satoshis == 1_000
    assert any("mas barato" in r or "más barato" in r for r in q.reasons)
    assert any("compartida" in r for r in q.reasons), (
        "el motivo tiene que decir que la capacidad no sera reservada")


def test_a_quote_shows_the_saving_against_paying_per_use():
    """El numero que hace la eleccion visible en vez de una recomendacion opaca.

    Negativo = el pago por uso era mas barato. Con 5 000 inferencias y
    dedicacion, se ahorran 400 000 sats.
    """
    q = quote(inferences=5_000, wants_dedicated=True)
    assert q.metered_equivalent_sats == 500_000
    assert q.savings_vs_metered_sats == 400_000
    assert q.savings_vs_metered_sats > 0


# --------------------------------------------------------------------------
# El limite que los precios no resuelven
# --------------------------------------------------------------------------
def test_the_join_is_free_and_the_brake_is_the_work():
    """El hueco que midio v2, y como v3 lo mueve de la puerta al trabajo.

    En v2, 100 000 sats / 1 sat = 100 000 entradas: el freno de
    Sybil del nivel gratuito era *el mismo* que el de un pago unico,
    y no escalaba con la malla. En v3 la entrada es off-chain y
    gratis, y el freno es el trabajo: fabricar 100 000 inferencias
    cuesta 100 000 fees que paga el servidor, no 100 000
    inscripciones. El coste escala con lo que el nodo *hace*.
    """
    # La entrada ya no compra nada por si sola.
    assert JOIN_SATOSHIS == 0
    assert TIER_FREE.join_satoshis == JOIN_SATOSHIS
    # El freno es por inferencia servida, y es lineal.
    assert PER_INFERENCE_SATOSHIS == 100


def test_bsv_has_no_dust_limit_and_that_is_what_makes_one_sat_ordinals_work():
    """El polvo de BSV es CERO. No "un umbral bajo": ninguno.

    El 546 sats es de Bitcoin Core y de ABC, de donde BSV forked. BSV lo elimino
    — por eso una salida de 1 satoshi se minable y se gasta sin friccion, y por
    eso el protocolo de 1sat ordinals puede usar un unico satoshi en vez del
    rango que BTC obligaba a usar por el polvo.

    El error que se corrigio aqui: importar el 546 de Core y llamarlo "umbral de
    BSV". Hacia que un ordinal de 1 sat pareciera no minable, que es lo
    contrario de lo cierto. La constante se queda, siendo cero, porque el error
    es el nombre y no el numero.
    """
    assert BSV_DUST_LIMIT_SATOSHIS == 0
    assert BSV_SINGLE_SAT_OUTPUTS is True
    assert ORDINAL_SATOSHIS == 1, "un satoshi es una salida valida en BSV"


def test_no_dust_limit_and_the_sybil_brake_is_not_the_entry():
    """La ausencia de polvo no es un escudo: es la ausencia de un escudo.

    En una cadena con umbral de polvo, cien mil salidas minusculas cuestan
    porque el agregado satoshi-hora de la UTXO se dispara. En BSV no hay ese
    freno — que es lo que hace posible el ordinal de 1 sat *dentro* de la tx
    de inferencia. Que el fee sea barato no es por tanto una ventaja del
    nivel gratuito: el freno de Sybil no es la entrada (gratis, off-chain,
    :func:`test_the_join_is_free_and_the_brake_is_the_work`) sino la fee de
    servir, lineal con el trabajo.
    """
    # sin polvo, el ordinal de 1 sat de la inscripcion es posible
    assert BSV_DUST_LIMIT_SATOSHIS == 0
    assert ORDINAL_SATOSHIS == 1
    # la entrada es gratis: el freno no puede estar en la puerta
    assert TIER_FREE.join_satoshis == JOIN_SATOSHIS == 0
    assert TIER_FREE.join_satoshis < TIER_DEDICATED.join_satoshis

# --------------------------------------------------------------------------
# Donde x402 encaja — y es una decision de diseno, no un comentario
# --------------------------------------------------------------------------
def test_only_metered_is_x402_suitable_and_the_reason_is_recorded():
    """La pregunta "donde encaja x402" tiene que estar en los datos.

    x402 es una relacion por peticion sin estado, y el propio modulo de x402
    dice que un pago **no** convierte a nadie en miembro. Eso encaja con
    `metered`, que es justamente un producto sin membresia. En `free` no hay
    nada que cobrar, y en `ded` el pago ya esta cerrado antes de la inferencia.

    El motivo viaja con el nivel, no en un comentario: una pregunta de diseno no
    debe depender de que alguien lea el docstring.
    """
    assert TIER_METERED.x402_suitable is True
    assert TIER_DEDICATED.x402_suitable is False
    assert TIER_FREE.x402_suitable is False
    for t in (TIER_FREE, TIER_DEDICATED, TIER_METERED):
        assert t.x402_note, f"{t.name} tiene que decir por que"


def test_dedicated_explains_that_a_proof_per_inference_would_buy_nothing():
    """El argumento tecnico, en el sitio donde se lee.

    En `ded` el importe esta en el contrato, no en el proof, asi que el proof
    de x402 no lleva nada que verificar. Pedir uno por inferencia seria gasto
    sin garantia.
    """
    assert "reservation" in TIER_DEDICATED.x402_note
    assert "ya pagado" in TIER_DEDICATED.x402_note


def test_x402_suitability_travels_in_the_serialised_levels():
    """Un cliente tiene que poder preguntar por que sin leer Python."""
    out = levels()
    assert out["metered"]["x402_suitable"] is True
    assert out["ded"]["x402_suitable"] is False
    assert out["free"]["x402_suitable"] is False
    assert out["metered"]["x402_note"]
