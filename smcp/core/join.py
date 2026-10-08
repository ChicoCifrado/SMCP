"""Join — entrar en la malla sin tocar la cadena (v3).

Qué resuelve este módulo
------------------------
Hasta v3, entrar en la malla costaba una tx: el ancla de
membresía de 1 satoshi de :mod:`smcp.core.membership` (v2).
Eso tenía dos problemas: el coste no escalaba con lo que el
nodo aporta (el freno Sybil era debilísimo — con el precio
de un pago único uno compraba cien mil entradas), y la
membresía en cadena no decía quién es quién.

El join v3 es **gratis y off-chain**: dos nodos se
emparejan (intercambio de claves públicas, una decisión
humana) y se avalan en el roster (:mod:`smcp.core.roster`).
No hay tx, no hay fee, no hay nada en la cadena: la
confianza es el grafo de avales firmados, transitivo, y
cada nodo lo verifica contra su propio keyring.

La secuencia (:func:`pair`) es la que la spec de v3 fija:

    cada nodo funda (o tiene) su roster  ->  se
    intercambian claves públicas  ->  cada uno avala al
    otro (la decisión de emparejar es mutua)  ->
    intercambian rosters y cada uno reconcilia el del
    otro, confiando solo en lo que ya confía  ->  y cada
    uno ve al otro como **verificado**

El freno Sybil no es el coste de entrar (entrar es gratis)
sino el trabajo: cada inferencia servida exige una tx con
fee que paga el servidor (:mod:`smcp.core.intercambio`),
así que fabricar *N* inferencias cuesta *N* fees.

La identidad
------------
El intercambio de claves **afirma** la clave del par sin
probar que la controla: un MITM activo puede sustituirla
en el cable. Cuando la capa de identidad
(:mod:`smcp.core.identidad`, handshake BRC-103) entrega
una :class:`~smcp.core.identidad.Session`, el join la
verifica **antes** de intercambiar nada: cada clave debe
probar su control vivo, ligado a esta sesión por los
nonces. Una prueba que no cuadra es un MITM o un bug, y
el join **falla cerrado** — no se degrada al intercambio
simple. Sin sesión, el join sigue siendo el intercambio
simple de hoy (``authenticated`` es ``None`` en el
resultado, para que quien llama vea la diferencia).

Lo que este módulo NO hace
--------------------------
* No es transporte: el intercambio de rosters es de la
  capa de transporte (gossip, QUIC); aquí los mensajes
  son llamadas, como en :mod:`smcp.core.intercambio`.
* No es una membresía de cadena: v2
  (:mod:`smcp.core.membership`) sigue existiendo intacta;
  v3 es un camino nuevo, no un reemplazo hasta que una
  decisión lo haga.
* No frena Sybil por coste — deliberadamente. Ver arriba:
  el freno se movió de la identidad al trabajo.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from smcp.core.identidad import Session
from smcp.core.provenance import KeyPair
from smcp.core.roster import (
    Roster,
    cert_fingerprint,
)

__all__ = [
    "JoinResult",
    "PeerIdentity",
    "found",
    "pair",
    "pair_local",
]


# ---------------------------------------------------------------------------
# El resultado
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class JoinResult:
    """Lo que un join produce: los rosters actualizados, y la prueba.

    ``keyring_a`` / ``keyring_b`` son los keyrings tras el
    intercambio de claves — cada uno aprendió la clave del
    par, que es lo que permite verificar sus avales.

    ``a_trusts_b`` y ``b_trusts_a`` son la propiedad que el
    join garantiza: cada nodo ve al otro como **verificado**
    (alguien en quien ya confía avaló esa admisión exacta),
    no solo como presente — la distinción que separa un par
    de un desconocido de gossip. Si alguna es ``False``, el
    emparejamiento no cerró (p. ej. clusters distintos) y
    los conteos de reconcile dicen por qué.
    """

    roster_a: Roster
    roster_b: Roster
    keyring_a: dict[str, bytes]
    keyring_b: dict[str, bytes]
    a_trusts_b: bool
    b_trusts_a: bool
    pinned_a: int
    rejected_a: int
    pinned_b: int
    rejected_b: int
    #: ¿La identidad del par quedó probada (BRC-103)?
    #: ``True`` con sesión verificada, ``False`` con sesión
    #: ofrecida que no cuadra (el join no siguió), ``None``
    #: sin sesión — el intercambio simple, donde la clave
    #: del par se afirma sin probar su control.
    authenticated: Optional[bool]

    @property
    def mutual(self) -> bool:
        """¿El emparejamiento cerró por los dos lados?"""
        return self.a_trusts_b and self.b_trusts_a


# ---------------------------------------------------------------------------
# Fundar
# ---------------------------------------------------------------------------
def found(cluster_id: str, node_id: str, key: KeyPair,
          *, now: Optional[float] = None
          ) -> tuple[Roster, dict[str, bytes]]:
    """Funda el roster de un nodo: uno solo, avalado por su propia clave.

    El fundador es su propio primer avalado — no hay un caso
    especial "confía en X" en :mod:`smcp.core.roster`: el
    auto-aval verifica contra la clave del fundador, la misma
    vía que cualquier otro ingreso. Devuelve el roster y el
    keyring inicial (la clave del propio nodo).
    """
    roster, _adm = Roster.create(
        cluster_id, node_id, key, key.public_key, now=now,
    )
    return roster, {node_id: key.public_key}


# ---------------------------------------------------------------------------
# El emparejamiento
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PeerIdentity:
    """La identidad de un par **que llegó por el
    cable**: su clave pública, y nada más.

    :func:`pair_local` solo usa la parte pública de
    la clave del par — la sesión que verifica, el
    keyring que aprende y la huella del certificado
    que avala—, y la clave privada de un par **nunca
    viaja**: un par por el transporte se representa
    con esto, no con su
    :class:`~smcp.core.provenance.KeyPair` completa.
    """

    public_key: bytes


def pair(*, a_roster: Roster, a_key: KeyPair,
         a_keyring: dict[str, bytes],
         b_roster: Roster, b_key: KeyPair,
         b_keyring: dict[str, bytes],
         now: Optional[float] = None,
         session: Session | None = None) -> JoinResult:
    """El join v3: dos nodos se emparejan off-chain, gratis.

    La secuencia, con los dos nodos en los papeles de
    ``a`` y ``b`` (simétricos — ninguno es especial):

    0. **Identidad** (BRC-103, cuando hay ``session``).
       Cada clave que se va a intercambiar debe probar su
       control vivo sobre los nonces de la sesión. Si alguna
       prueba no cuadra el join **falla cerrado**: no se
       intercambia nada, no hay avales, no hay confianza.
    1. **Intercambio de claves.** Cada keyring aprende la
       clave pública del par: el certificado de cada nodo
       es su clave, y es contra el keyring propio contra lo
       que los avales se verifican — nunca contra una clave
       que viaja con el aval.
    2. **Avales mutuos.** Cada uno avala al otro: la
       decisión de emparejar es humana y mutua. El aval de
       A hacia B queda en el roster de A (y el de B hacia
       A en el de B), que es cómo el roster del par llega
       a uno con el aval propio dentro.
    3. **Reconciliación.** Intercambian rosters y cada uno
       reconcilia el del otro, confiando solo en lo que ya
       confía: un aval de un extraño no pinnea nada.
    4. **Verificación.** Cada uno comprueba que ve al otro
       como verificado — y el resultado lo dice, en vez de
       dejar que quien llama recorra el roster pieza por
       pieza.

    Mutar los rosters y los keyrings es parte del contrato
    (la API del roster es de mutación): tras :func:`pair`,
    los rosters son los del par ya emparejado.

    Un roster es un objeto de un cluster: emparejar nodos
    de clusters distintos no cuadra, y no se intenta (ni
    el intercambio de claves ni los avales). El resultado
    lo dice — sin nada pinneado, sin confianza — en vez de
    dejar que quien llama descubra un emparejamiento a
    medio hacer.
    """
    a_id, b_id = a_roster.self_id, b_roster.self_id

    # El roster es de un cluster: el join es dentro de él.
    if a_roster.cluster_id != b_roster.cluster_id:
        return JoinResult(
            roster_a=a_roster, roster_b=b_roster,
            keyring_a=a_keyring, keyring_b=b_keyring,
            a_trusts_b=False, b_trusts_a=False,
            pinned_a=0, rejected_a=len(b_roster.members),
            pinned_b=0, rejected_b=len(a_roster.members),
            authenticated=None,
        )

    # 0. La identidad (BRC-103): con sesión, las claves
    #    que se intercambian deben probar su control vivo.
    #    Una prueba que no cuadra es un MITM o un bug — el
    #    join falla cerrado, no se degrada al intercambio
    #    simple (degradarse sería aceptar la sustitución).
    if session is not None and not session.verified(
            a_key=a_key, b_key=b_key):
        return JoinResult(
            roster_a=a_roster, roster_b=b_roster,
            keyring_a=a_keyring, keyring_b=b_keyring,
            a_trusts_b=False, b_trusts_a=False,
            pinned_a=0, rejected_a=0,
            pinned_b=0, rejected_b=0,
            authenticated=False,
        )

    # 1. El intercambio de claves: cada keyring aprende
    #    la del par.
    a_keyring[b_id] = b_key.public_key
    b_keyring[a_id] = a_key.public_key

    # 2. Los avales mutuos. El *epoch* que se avala es la
    #    admisión corriente del par (la que su roster
    #    declara), no una que este nodo invente.
    a_roster.endorse(
        a_key, b_id, cert_fingerprint(b_key.public_key),
        epoch=b_roster.self_epoch, now=now,
    )
    b_roster.endorse(
        b_key, a_id, cert_fingerprint(a_key.public_key),
        epoch=a_roster.self_epoch, now=now,
    )

    # 3. Intercambio de rosters y reconciliación.
    pinned_a, rejected_a = a_roster.reconcile(b_roster, a_keyring)
    pinned_b, rejected_b = b_roster.reconcile(a_roster, b_keyring)

    # 4. La propiedad: confianza mutua verificada.
    a_trusts_b = a_roster.is_verified_trusted(b_id, a_keyring)
    b_trusts_a = b_roster.is_verified_trusted(a_id, b_keyring)
    return JoinResult(
        roster_a=a_roster, roster_b=b_roster,
        keyring_a=a_keyring, keyring_b=b_keyring,
        a_trusts_b=a_trusts_b, b_trusts_a=b_trusts_a,
        pinned_a=pinned_a, rejected_a=rejected_a,
        pinned_b=pinned_b, rejected_b=rejected_b,
        authenticated=None if session is None else True,
    )


def pair_local(*, roster: Roster, key: KeyPair,
               keyring: dict[str, bytes],
               peer_roster: Roster,
               peer_key: KeyPair | PeerIdentity,
               peer_keyring: dict[str, bytes],
               now: Optional[float] = None,
               session: Session | None = None) -> JoinResult:
    """La mitad de :func:`pair` que corre en **un** nodo.

    :func:`pair` simula los dos lados en un proceso
    (el test offline): firma los dos avales con las
    dos claves privadas. Por el transporte eso no
    existe — la clave privada del par nunca viaja—,
    así que cada nodo corre su mitad con lo que le
    llegó por el cable:

    0. **Identidad** (BRC-103, cuando hay ``session``).
       La misma comprobación, y el mismo fallo cerrado.
       Además, el roster del par debe declarar el
       certificado de la clave que probó: una
       sustitución (un MITM que firma con su propia
       clave) no cuadra aquí, antes de avalar nada.
    1. **Intercambio de claves.** Mi keyring aprende
       la del par (la suya ya aprendió la mía — su
       mitad corre en su nodo).
    2. **Mi aval al par.** El *epoch* que avalo es la
       admisión corriente del par (la que su roster
       declara). El aval del par a mí lo pone **su**
       mitad: corre en su nodo, sobre su roster,
       cuando recibe el mío.
    3. **Reconciliación.** El roster del par entra en
       el mío (y el mío, con mi aval, en el suyo —
       la otra mitad corre en su nodo).
    4. **Verificación.** La confianza desde los dos
       lados: ``a_trusts_b`` es **mi** mitad (cerró
       aquí); ``b_trusts_a`` es la del par, sobre el
       roster que me envió — si su roster aún no
       trae su aval a mí (mi roster acaba de llegar),
       es ``False`` y el intercambio sigue: mi
       roster, con mi aval, vuelve al par.

    Por el transporte, :class:`~smcp.core.mensajeria.JoinWire`
    la llama dos veces por lado (una por cada cruce
    de rosters): el aval es idempotente — el roster
    lo dedup por firmante y *epoch*—, y la
    reconciliación, por admisión ya mergeada.

    Un resultado que no cierra (cluster distinto,
    sesión que no verifica, certificado que no cuadra)
    se dice en el resultado — sin nada pinneado, sin
    confianza — en vez de dejar que quien llama
    descubra un emparejamiento a medio hacer.
    """
    a_id, b_id = roster.self_id, peer_roster.self_id

    # El roster es de un cluster: el join es dentro de él.
    if roster.cluster_id != peer_roster.cluster_id:
        return JoinResult(
            roster_a=roster, roster_b=peer_roster,
            keyring_a=keyring, keyring_b=peer_keyring,
            a_trusts_b=False, b_trusts_a=False,
            pinned_a=0, rejected_a=len(peer_roster.members),
            pinned_b=0, rejected_b=len(roster.members),
            authenticated=None,
        )

    # 0. La identidad (BRC-103): la sesión debe
    #    verificar contra mi clave y la del par —
    #    y el roster del par debe declarar el
    #    certificado de la clave que probó. Una
    #    prueba que no cuadra es un MITM o un bug:
    #    el join falla cerrado, no se degrada al
    #    intercambio simple (degradarse sería aceptar
    #    la sustitución).
    if session is not None and not session.verified(
            a_key=key, b_key=peer_key):
        return JoinResult(
            roster_a=roster, roster_b=peer_roster,
            keyring_a=keyring, keyring_b=peer_keyring,
            a_trusts_b=False, b_trusts_a=False,
            pinned_a=0, rejected_a=0,
            pinned_b=0, rejected_b=0,
            authenticated=False,
        )
    if peer_roster.known_cert(b_id) != cert_fingerprint(
            peer_key.public_key):
        # El par dice ser un nodo cuyo certificado
        # no es el de la clave que probó: sustitución.
        return JoinResult(
            roster_a=roster, roster_b=peer_roster,
            keyring_a=keyring, keyring_b=peer_keyring,
            a_trusts_b=False, b_trusts_a=False,
            pinned_a=0, rejected_a=0,
            pinned_b=0, rejected_b=0,
            authenticated=False,
        )

    # 1. El intercambio de claves: mi keyring
    #    aprende la del par.
    keyring[b_id] = peer_key.public_key
    peer_keyring[a_id] = key.public_key

    # 2. Mi aval al par: el *epoch* que avalo es la
    #    admisión corriente del par (la que su roster
    #    declara). El aval del par a mí ya está en su
    #    roster — lo firmó en su nodo.
    roster.endorse(
        key, b_id, cert_fingerprint(peer_key.public_key),
        epoch=peer_roster.self_epoch, now=now,
    )

    # 3. Reconciliación de los dos lados.
    pinned_a, rejected_a = roster.reconcile(peer_roster, keyring)
    pinned_b, rejected_b = peer_roster.reconcile(roster, peer_keyring)

    # 4. La propiedad: confianza mutua verificada.
    a_trusts_b = roster.is_verified_trusted(b_id, keyring)
    b_trusts_a = peer_roster.is_verified_trusted(a_id, peer_keyring)
    return JoinResult(
        roster_a=roster, roster_b=peer_roster,
        keyring_a=keyring, keyring_b=peer_keyring,
        a_trusts_b=a_trusts_b, b_trusts_a=b_trusts_a,
        pinned_a=pinned_a, rejected_a=rejected_a,
        pinned_b=pinned_b, rejected_b=rejected_b,
        authenticated=None if session is None else True,
    )
