"""Wiring — cómo lo que ya existe se encuentra en el camino real.

El problema que este modulo resuelve
------------------------------------
Hay cinco modulos maduros y probados — :mod:`~smcp.core.capability`,
:mod:`~smcp.core.roster`, :mod:`~smcp.core.backend`,
:mod:`~smcp.core.reservation` y :mod:`~smcp.core.membership` — y **ninguno
habla con el heartbeat**. Son islas: cada una demuestra una propiedad en
aislamiento, y el bucle de la malla no llama a ninguna. Un sistema donde la
firma funciona pero nada verifica firmas no es un sistema parcial: es un
sistema que no hace su trabajo.

Este modulo no reimplementa nada. Conecta, y sobre todo hace **una** cosa que
nadie mas hace: **un solo camino de entrada**, y ninguna via alterna para
esquivarlo.

La regla: un nodo no se admite por el camino que le conviene
---------------------------------------------------------
El fallo tipico al cablear esto es tener varias puertas — la del heartbeat
comprueba la firma, la del planificador comprueba el roster, la del endpoint
comprueba la capacidad — y que cada una acepte lo que la otra rechaza. Tres
nodos con tres verificaciones distintas, y un atacante elige la mas debil.

:class:`NodeAdmission` es el unico sitio donde se decide. Quien quiera admitir
a alguien pasa por aqui:

* el heartbeat publica lo que el nodo **declaro**, firmado y sin verificar;
* :meth:`NodeAdmission.consider` aplica **una sola** politica: pertenencia
  (si hay lock), firma de capacidad, freshness, y capacidad reservable;
* lo que sale es un :class:`AdmissionDecision` con un motivo, no un booleano.

Y lo mas importante: **no hay un segundo metodo de admision**. Si mañana el
planificador necesita lo mismo, llama aqui. Un gate con dos implementaciones
es un gate con la interseccion vacia.

La freshness, una sola vez
-------------------------
Freshness es la unica comprobacion que depende del reloj, y por eso es la
unica que se hace en la frontera (una vez, con la hora del receptor) y no se
re-predicate en cada consumidor. Si el heartbeat ya decidio que una capacidad
tiene 90 s, volver a preguntarlo dentro de planificacion daria una respuesta
distinta segun quien preguntase, y dos planificadores podrian planear distinto
sobre el mismo estado.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

_LOG = logging.getLogger(__name__)

#: Freshness por defecto de una capacidad firmada, en segundos. Coincide con
#: el TTL de heartbeat (30 s) con margen: por debajo, un nodo sano seria
#: rechazado por el mismo reloj que lo declara vivo.
DEFAULT_FRESH_TTL_S = 90.0

#: Ventana de reloj admitida al recibir un anuncio. Un reloj desviado hacia
#: el futuro "fresquiza" un anuncio viejo para siempre, asi que hay que acotar.
MAX_CLOCK_SKEW_S = 120.0


# ---------------------------------------------------------------------------
# Lo que el nodo declara
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DeclaredCapability:
    """Lo que un nodo **dice** de si mismo, con su firma.

    Importa la distincion: esto es una afirmacion firmada, no una medicion. La
    firma garantiza *quien* lo dijo y que no lo cambie despues, no que sea
    cierto. Un nodo que declara 80 GB en una 4060 Ti entra con 80 GB — la
    distincion vive en :attr:`detected_vram_gb` cuando el witness externo lo
    sepa, y mientras no lo sepa, es una afirmacion.
    """

    peer_id: str
    signed_at: float
    digest: str
    signature: str
    vram_advertised_gb: float = 0.0
    vram_detected_gb: float | None = None
    models: tuple[str, ...] = ()
    surface: tuple[str, ...] = ()
    sig_kind: str = "ed25519"

    def age_s(self, now: float) -> float:
        return max(0.0, now - self.signed_at)

    def is_fresh(self, now: float, ttl_s: float = DEFAULT_FRESH_TTL_S) -> bool:
        """Fresco si no es demasiado viejo — y si el reloj no miente.

        El ``signed_at`` en el futuro se trata como fresco (el nodo puede tener
        el reloj un poco adelantado), pero no mas de :data:`MAX_CLOCK_SKEW_S`.
        Un ``signed_at`` muy futuro convierte la freshness en permanente, que
        es exactamente el modo de fallo de un reloj hostil.
        """
        age = self.age_s(now)
        if age > ttl_s:
            return False
        if self.signed_at - now > MAX_CLOCK_SKEW_S:
            return False
        return True

    def vram_contradiction_gb(self) -> float:
        """Cuanto contradice lo declarado a lo detectado, en GiB.

        Positivo = declara mas de lo que se detecto. **No se corrige**: se
        marca. Corregir en silencio seria tragarse una contradiccion y un
        nodo que miente no tendria ningun coste; marcarla hace que la
        contradiccion sea visible para quien decide.
        """
        if self.vram_detected_gb is None:
            return 0.0
        return self.vram_advertised_gb - self.vram_detected_gb


# ---------------------------------------------------------------------------
# La decision
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AdmissionDecision:
    """El veredicto, con el motivo. Un booleano no basta en un camino real.

    ``reason`` es lo que permite que un operador entienda por que un nodo no
    entra, y que un test pueda afirmar el motivo exacto en vez de "no entra".
    """

    admitted: bool
    reason: str
    peer_id: str = ""
    #: Lo que el nodo declara, si fallo por contradiccion o por VRAM cero.
    declared: DeclaredCapability | None = None
    #: Freshness de la vista, evaluada una vez en la frontera.
    observed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        d = {"admitted": self.admitted, "reason": self.reason}
        if self.peer_id:
            d["peer_id"] = self.peer_id
        if self.declared is not None:
            d["declared_vram_gb"] = self.declared.vram_advertised_gb
            if self.declared.vram_detected_gb is not None:
                d["detected_vram_gb"] = self.declared.vram_detected_gb
            d["vram_contradiction_gb"] = self.declared.vram_contradiction_gb()
        return d


#: Motivos de rechazo, como constantes — un test que verifique el motivo
#: deberia citar la constante, no reescribir el texto.
R_MEMBER_LOCK = "membership_required"
R_NO_LOCK = "no_membership_lock_configured"
R_BAD_SIGNATURE = "capacity_signature_invalid"
R_STALE = "capacity_stale"
R_CLOCK = "capacity_from_the_future"
R_NO_VRAM = "no_vram_advertised"
R_UNKNOWN_PEER = "unknown_peer"
R_OK = "ok"


# ---------------------------------------------------------------------------
# El unico camino de admision
# ---------------------------------------------------------------------------
@dataclass
class NodeAdmission:
    """La unica puerta de entrada. Todo lo demas pregunta aqui.

    Con tres piezas opcionales y todas por el mismo camino:

    * ``membership`` — si se pasa, el nodo tiene que probar pertenencia. Sin
      esto el gate es atribucion social y un atacante necesita un solo aval.
    * ``verify`` — como validar la firma de capacidad. Se pasa como funcion
      para no atar este modulo a :mod:`~smcp.core.provenance` ni a un
      algoritmo concreto: la misma politica sirve para ed25519 y secp256k1.
    * ``fresh_ttl_s`` — ventana de frescura, evaluada una vez aqui.
    """

    membership: Any = None
    verify: Callable[[DeclaredCapability], bool] | None = None
    fresh_ttl_s: float = DEFAULT_FRESH_TTL_S
    #: Historial de decisiones, para diagnostico. No es el estado de admision:
    #: el estado vive en el ledger, y duplicarlo aqui seria una segunda
    #: fuente de verdad sobre quien esta dentro.
    _log: list[AdmissionDecision] = field(default_factory=list, repr=False)

    # ------------------------------------------------------------------ decide
    def consider(self, declared: DeclaredCapability, now: float | None = None,
                 header: Any = None) -> AdmissionDecision:
        """Decide sobre un nodo. El unico metodo que admite o rechaza.

        ``header`` solo se necesita si hay lock de pertenencia: es la cabecera
        de bloque que el verificador **elige**, no la que trae la prueba. Sin
        esto la prueba se avalaria a si misma.
        """
        now = time.time() if now is None else now
        if not (declared.peer_id or "").strip():
            return AdmissionDecision(False, R_UNKNOWN_PEER, declared.peer_id)

        # (1) pertenencia. Antes que nada: si no es miembro, no hay nada que
        # verificar. Y el orden importa — verificar una firma de un no-miembro
        # es trabajo que un atacante paga gratis.
        if self.membership is not None:
            if not self._is_member(declared.peer_id, header):
                return AdmissionDecision(False, R_MEMBER_LOCK,
                                         declared.peer_id, declared, now)

        # (2) firma de capacidad
        if self.verify is not None and not self.verify(declared):
            return AdmissionDecision(False, R_BAD_SIGNATURE,
                                     declared.peer_id, declared, now)

        # (3) freshness, evaluada UNA vez
        if not declared.is_fresh(now, self.fresh_ttl_s):
            if declared.signed_at - now > MAX_CLOCK_SKEW_S:
                return AdmissionDecision(False, R_CLOCK,
                                         declared.peer_id, declared, now)
            return AdmissionDecision(False, R_STALE, declared.peer_id,
                                     declared, now)

        # (4) capacidad declarada
        if declared.vram_advertised_gb <= 0.0:
            return AdmissionDecision(False, R_NO_VRAM, declared.peer_id,
                                     declared, now)

        self._log.append(AdmissionDecision(True, R_OK, declared.peer_id,
                                           declared, now))
        return AdmissionDecision(True, R_OK, declared.peer_id, declared, now)

    # ------------------------------------------------------------------ interno
    def _is_member(self, peer_id: str, header: Any) -> bool:
        """¿Es este nodo miembro segun el set de membresias?

        Acepta tres formas de responder, en este orden, porque los tres son
        razonables y atar el gate a una sola haria que cambiar de set
        obligara a reescribir la politica:

        1. ``set.is_member(peer_id)``;
        2. un dict ``{peer_id: proof}``;
        3. un callable ``(peer_id) -> bool``.

        Que haya tres formas de responder es un coste real y esta escrito: un
        gate que solo acepta una obliga a un adaptador para todo lo demas, y
        un gate que solo funciona con un adaptador no se puede usar en un test
        sin el adaptador.
        """
        m = self.membership
        probe = getattr(m, "is_member", None)
        if probe is not None and callable(probe):
            return bool(probe(peer_id))
        if isinstance(m, dict):
            return peer_id in m
        if callable(m):
            return bool(m(peer_id))
        raise TypeError(
            "membership debe responder is_member(peer_id), ser un dict de "
            f"peer_id -> proof, o ser un callable; recibio {type(m).__name__}")

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        """Las ultimas decisiones, para diagnostico."""
        return [d.to_dict() for d in self._log[-limit:]]


__all__ = [
    "DeclaredCapability", "AdmissionDecision", "NodeAdmission",
    "DEFAULT_FRESH_TTL_S", "MAX_CLOCK_SKEW_S",
    "R_MEMBER_LOCK", "R_NO_LOCK", "R_BAD_SIGNATURE", "R_STALE", "R_CLOCK",
    "R_NO_VRAM", "R_UNKNOWN_PEER", "R_OK",
]
