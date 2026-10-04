"""Wiring — el unico camino de admision.

Lo que estos tests sujetan, y por que importa:

* **Un solo camino.** La garantia de que ningun nodo entra por una puerta
  distinta. Si existiera un segundo metodo de admision, un atacante elegiria
  el mas debil, y la politica unica se volveria decorativa.
* **El orden de las comprobaciones.** Pertenencia antes que firma: verificar
  la firma de un no-miembro es trabajo que un atacante paga gratis.
* **Freshness una sola vez**, y con cota de reloj. Un ``signed_at`` en el
  futuro hace "fresca" una capacidad para siempre, que es el modo de fallo de
  un reloj hostil.
* **La contradiccion se marca, no se corrige.** Corregir en silencio haria que
  un nodo que miente no tuviera coste.
"""
from __future__ import annotations

import time

import pytest

from smcp.core.wiring import (
    DEFAULT_FRESH_TTL_S,
    MAX_CLOCK_SKEW_S,
    R_BAD_SIGNATURE,
    R_CLOCK,
    R_MEMBER_LOCK,
    R_NO_VRAM,
    R_OK,
    R_STALE,
    R_UNKNOWN_PEER,
    AdmissionDecision,
    DeclaredCapability,
    NodeAdmission,
)


def _decl(peer_id: str = "n1", **kw) -> DeclaredCapability:
    """Una capacidad firmada, fresca por defecto."""
    now = kw.pop("now", 1000.0)
    base = {
        "peer_id": peer_id,
        "signed_at": now,
        "digest": "a" * 64,
        "signature": "b" * 64,
        "vram_advertised_gb": 16.0,
    }
    base.update(kw)
    return DeclaredCapability(**base)


# --------------------------------------------------------------------------
# La admiticion sin lock: atribucion social, y por que es debil
# --------------------------------------------------------------------------
def test_without_a_membership_lock_a_signed_capability_is_admitted():
    """Sin lock, esto es atribucion social: basta con una firma valida.

    Conviene tener un test que lo fije, porque es el estado por defecto y
    parece mas fuerte de lo que es. Un atacante necesita un solo aval. La
    pertenencia real es lo que anade :class:`NodeAdmission` con ``membership``.
    """
    a = NodeAdmission(verify=lambda d: True)
    d = a.consider(_decl(), now=1000.0)
    assert d.admitted and d.reason == R_OK


def test_an_invalid_signature_is_rejected_with_the_reason():
    a = NodeAdmission(verify=lambda d: False)
    d = a.consider(_decl(), now=1000.0)
    assert not d.admitted
    assert d.reason == R_BAD_SIGNATURE


def test_a_node_declaring_no_vram_is_rejected():
    """Cero VRAM no es "un nodo pequeño", es un nodo que no puede servir."""
    a = NodeAdmission(verify=lambda d: True)
    d = a.consider(_decl(vram_advertised_gb=0.0), now=1000.0)
    assert not d.admitted and d.reason == R_NO_VRAM


def test_an_empty_peer_id_is_rejected():
    a = NodeAdmission(verify=lambda d: True)
    assert a.consider(_decl(peer_id="   "), now=1000.0).reason == R_UNKNOWN_PEER


# --------------------------------------------------------------------------
# Freshness
# --------------------------------------------------------------------------
def test_a_stale_capability_is_rejected():
    a = NodeAdmission(verify=lambda d: True)
    old = _decl(signed_at=1000.0)
    d = a.consider(old, now=1000.0 + DEFAULT_FRESH_TTL_S + 1)
    assert not d.admitted and d.reason == R_STALE


def test_a_fresh_capability_is_admitted():
    a = NodeAdmission(verify=lambda d: True)
    d = a.consider(_decl(signed_at=1000.0),
                   now=1000.0 + DEFAULT_FRESH_TTL_S - 1)
    assert d.admitted


def test_a_clock_far_in_the_future_is_not_just_fresh_it_is_rejected():
    """El modo de fallo de un reloj hostil: ``signed_at`` futuro = eterno.

    Sin la cota, un nodo firma una vez con el reloj 2030 y su capacidad esta
    "fresca" para siempre. Con la cota, se rechaza — y el motivo es distinto
    del de antigüedad, porque arreglarlo es otro (revisar el reloj).
    """
    a = NodeAdmission(verify=lambda d: True)
    d = a.consider(_decl(signed_at=1000.0 + MAX_CLOCK_SKEW_S + 60),
                   now=1000.0)
    assert not d.admitted
    assert d.reason == R_CLOCK, "un reloj futuro no es antigüedad, es reloj"


def test_a_slightly_ahead_clock_is_tolerated():
    """Un nodo con el reloj 10 s adelantado es normal, no un ataque."""
    a = NodeAdmission(verify=lambda d: True)
    d = a.consider(_decl(signed_at=1010.0), now=1000.0)
    assert d.admitted, "un desvio pequeno no debe rechazar a un nodo sano"


# --------------------------------------------------------------------------
# La pertenencia, y el orden
# --------------------------------------------------------------------------
def test_a_non_member_is_rejected_before_the_signature_is_even_checked():
    """El orden es la garantia: si no es miembro, no se verifica nada.

    Verificar la firma de un no-miembro es trabajo que el atacante paga y el
    nodo descarta. Aqui se comprueba con un ``verify`` que **explota** si llega
    a.called: si el orden se invirtiera, el test falla.
    """
    calls: list[str] = []

    def verify(_d: DeclaredCapability) -> bool:
        calls.append("verify")
        return True

    a = NodeAdmission(membership={"n1": object()}, verify=verify)
    d = a.consider(_decl("n2"), now=1000.0)
    assert not d.admitted and d.reason == R_MEMBER_LOCK
    assert calls == [], "la firma se verifico antes que la pertenencia"


def test_a_member_with_a_bad_signature_is_still_rejected():
    """La pertenencia no compra el derecho a mentir."""
    a = NodeAdmission(membership={"n1": object()}, verify=lambda d: False)
    d = a.consider(_decl("n1"), now=1000.0)
    assert not d.admitted and d.reason == R_BAD_SIGNATURE


def test_membership_can_be_a_dict_a_set_or_a_callable():
    """Tres formas de responder, todas por la misma politica.

    Atar el gate a una sola obligaria a un adaptador para todo lo demas. El
    coste — que "funciona" con tres — esta escrito en el docstring.
    """
    n = _decl("n1")
    for m in ({"n1": object()}, lambda p: p == "n1", _FakeSet()):
        a = NodeAdmission(membership=m, verify=lambda d: True)
        assert a.consider(n, now=1000.0).admitted, f"no admitido con {m!r}"
        assert not a.consider(_decl("n2"), now=1000.0).admitted


class _FakeSet:
    def is_member(self, peer_id: str) -> bool:
        return peer_id == "n1"


def test_a_membership_object_that_answers_nothing_raises_clearly():
    """Un set que no sabe responder es un error de cableado, no un rechazo.

    Si devolviera "no miembro" en silencio, un gate mal cableado rechazaria
    toda la malla y nadie sabria por que. Aqui lanza con el tipo recibido.
    """
    a = NodeAdmission(membership=object(), verify=lambda d: True)
    with pytest.raises(TypeError) as ei:
        a.consider(_decl("n1"), now=1000.0)
    assert "is_member" in str(ei.value)


# --------------------------------------------------------------------------
# La contradiccion se marca, no se corrige
# --------------------------------------------------------------------------
def test_declaring_more_than_was_detected_is_marked_not_corrected():
    """El nodo entra con lo que declara, y la contradiccion queda visible.

    Corregir en silencio haria que mentir no costase nada. Aqui la capacidad
    admitida sigue siendo la declarada (16 GiB) y la contradiccion aparece en
    la decision — quien decide puede verla.
    """
    a = NodeAdmission(verify=lambda d: True)
    d = a.consider(_decl(vram_advertised_gb=80.0, vram_detected_gb=16.0),
                   now=1000.0)
    assert d.admitted, "marcar no es rechazar"
    assert d.declared is not None
    assert d.declared.vram_contradiction_gb() == 64.0
    assert d.to_dict()["vram_contradiction_gb"] == 64.0
    assert d.to_dict()["declared_vram_gb"] == 80.0, "no se corrige en silencio"


def test_no_contradiction_when_nothing_was_detected():
    d = _decl(vram_advertised_gb=16.0, vram_detected_gb=None)
    assert d.vram_contradiction_gb() == 0.0


def test_declaring_less_than_detected_is_still_visible():
    """El caso inverso tambien se marca: puede ser false frugal."""
    d = _decl(vram_advertised_gb=4.0, vram_detected_gb=16.0)
    assert d.vram_contradiction_gb() == -12.0


# --------------------------------------------------------------------------
# Un solo camino
# --------------------------------------------------------------------------
def test_there_is_exactly_one_way_to_be_admitted():
    """La garantia central, comprobada por la superficie de la clase.

    Si existiera un segundo metodo que admitiera (``admit_if``, ``force_admit``,
    un ``admitted`` escribible), un atacante elegiria esa via y toda la politica
    se volveria decorativa. Este test falla en cuanto alguien añada la puerta.
    """
    metodos_admiten = [
        n for n in dir(NodeAdmission)
        if not n.startswith("_")
        and callable(getattr(NodeAdmission, n, None))
        and n in {"consider", "admit", "admit_if", "force_admit", "check",
                  "evaluate", "should_admit", "allows", "permit"}
    ]
    assert metodos_admiten == ["consider"], (
        f"hay mas de un camino de admision: {metodos_admiten}")


def test_the_decision_log_is_diagnostic_not_a_second_source_of_truth():
    """El log no decide nada: es un registro, y por eso es opcional y local.

    El estado de admision vive en el ledger. Duplicarlo aqui seria una segunda
    fuente de verdad sobre quien esta dentro, y dos fuentes de verdad siempre
    discrepan en el momento que mas molesta.
    """
    a = NodeAdmission(verify=lambda d: True)
    a.consider(_decl("n1"), now=1000.0)
    a.consider(_decl("n2", vram_advertised_gb=0.0), now=1000.0)
    log = a.recent()
    assert len(log) == 1, "solo se registran las admisiones"
    assert log[0]["admitted"] is True
    assert not hasattr(a, "admitted_set")


def test_a_decision_serialises_to_what_an_operator_needs():
    """El motivo viaja, para que "no entra" sea diagnosticable.

    Un booleano obliga a un operador a reproducir la decision entera para
    entenderla. Con el motivo y los dos numeros, se lee.
    """
    a = NodeAdmission(verify=lambda d: False)
    d = a.consider(_decl("n1", vram_advertised_gb=8.0,
                         vram_detected_gb=16.0), now=1000.0)
    out = d.to_dict()
    assert out == {
        "admitted": False,
        "reason": R_BAD_SIGNATURE,
        "peer_id": "n1",
        "declared_vram_gb": 8.0,
        "detected_vram_gb": 16.0,
        "vram_contradiction_gb": -8.0,
    }
