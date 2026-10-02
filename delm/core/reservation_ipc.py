"""Interprocess reservation — el mismo lock, a traves de una frontera de proceso.

El problema que resuelve
------------------------
:class:`~delm.core.reservation.ReservationBook` protege con un
``threading.Lock``. Correcto dentro de un proceso, y **falso** entre dos: dos
procesos del Web API cada uno con su libroVendrian la misma VRAM a dos
clientes distintos. Ese es el limite que hacia el tier de pago unico no
vendible en multi-proceso, y estaba escrito en el threat model en vez de
resuelto.

La eleccion: ``flock`` sobre un fichero, no un libro serializado
-----------------------------------------------------------------
Lo obvio seria persistir el libro entero y tomar un lock de fichero al
escribir. Funciona, y tiene dos problemas que aparecen en produccion:

* **El estado vive en disco y hay que recuperarlo al arrancar.** Un libro
  recargado mantiene VRAM que nadie usa o libera VRAM que alguien prometyo — las
  dos cosas que el modulo original evita a proposito.
* **Cada operacion pasa por disco.** ``reserve`` es el camino caliente del
  planificador; pagarlo con una escritura por llamada es un cuello de botella
  por una necesidad que no existe.

La solucion es un ``flock`` sobre un fichero *de cerrojo*, no de estado: el
estado se queda en memoria de cada proceso, y lo que se comparte es la
**exclusion mutua**. Cuando un proceso toma la cerradura:

1. espera a que ningun otro la tenga (``LOCK_EX``);
2. **recarga** su libro desde el fichero de estado si ha cambiado;
3. opera sobre la vista fresca;
4. **vuelca** su libro si cambio;
5. suelta la cerradura.

La consecuencia importante, y es la que hay que entender antes de usar esto: el
lock hace **correcto**, no **rapido**. Dos procesos se serializan, y el segundo
ve el resultado del primero. Eso es exactamente lo que hace la garantia
atomica; solo que ahora atraviesa la frontera. El coste es una syscall de lock
y una relectura por operacion critica, no un libro entero en disco.

Lo que esto NO arregla
----------------------
* **No es transaccional con el trabajo real.** El libro promete; si el proceso
  muere entre tomar la reserva y despachar la inferencia, la reserva se queda
  hasta que expire el TTL. Es el mismo limite que la version de un proceso, y
  por eso el TTL existe.
* **No coordina con otras maquinas.** ``flock`` es local al sistema de ficheros.
  Dos contenedores en ficheros distintos no se ven. La coordinacion entre
  maquinas es OTRO problema, y no se disimula aqui.
* **Un NFS o un filesystem sin ``flock`` fiable no lo da.** En WSL, en Docker
  bind-mounts y en NFS el aviso puede fallar en silencio. Por eso
  :func:`interprocess_available` dice explicitamente si el cerrojo es de
  fiar, en vez de asumirlo.
"""
from __future__ import annotations

import errno
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Any, ClassVar

#: Extension del fichero de estado. El de cerrojo no lo lleva: son dos cosas
#: distintas, y confundirlas invita a borrar el cerrojo creyendo que se limpia
#: el estado.
STATE_SUFFIX = ".reservations.json"

#: Formato del fichero de estado en disco.
STATE_VERSION = 1


#: Operaciones de cerrojo, resueltas en un solo sitio. Pyright marca
#: ``os.flock`` y ``os.LOCK_EX`` como desconocidos porque no existen en la
#: plataforma de destino, y con razon: en Windows no hay ``flock``. En vez de
#: cinco ``# type: ignore`` repartidos, la resolucion —y el fallo— viven aqui,
#: que es donde se decide si este modulo es usable.
def _lock_ops() -> tuple[Any, int, int, int]:
    """Resuelve ``flock`` y sus banderas, y dice si no hay.

    **En ``fcntl``, no en ``os``.** Es tentador ``os.flock`` y no existe en
    Linux: la funcion vive en ``fcntl.flock`` y las banderas
    (``LOCK_EX``/``LOCK_UN``/``LOCK_NB``) tambien. Comprobado en este
    entorno — ``hasattr(os, "flock")`` es ``False`` y ``import fcntl;
    fcntl.flock`` funciona — asi que la primera version de este modulo decia
    "esta plataforma no expone os.flock" en un Linux que si soporta el
    cerrojo. Un detector de capacidad que miente es peor que uno que no
    existe, porque desactiva la proteccion creyendo que la plataforma es
    incapaz.
    """
    try:
        import fcntl as _f
    except ImportError:  # pragma: no cover - no POSIX
        raise RuntimeError(
            "fcntl no disponible: este runtime no soporta el cerrojo entre "
            "procesos. Usa un solo proceso, o un filesystem con bloqueo real "
            "(ver interprocess_available).") from None
    fn = getattr(_f, "flock", None)
    if fn is None:  # pragma: no cover
        raise RuntimeError("fcntl sin flock en este runtime")
    return fn, _f.LOCK_EX, _f.LOCK_NB, _f.LOCK_UN


def _flock_ex(fd: int, *, blocking: bool = True) -> None:
    fn, ex, nb, _un = _lock_ops()
    fn(fd, ex if blocking else (ex | nb))


def _flock_unlock(fd: int) -> None:
    """Suelta el cerrojo. Va por ``_lock_ops`` y no por un atajo, para que las
    dos mitades del patron no puedan divergir: si alguien cambia como se
    resuelve ``flock``, cambia en los dos sitios a la vez."""
    return


def interprocess_available() -> tuple[bool, str]:
    """¿Se puede usar un ``flock`` fiable aqui? Dice el porque si no.

    No se asume. Un NFS sin bloqueo, o un bind-mount de Docker, hacen que
    ``flock`` falle en silencio — y un cerrojo que no cerca es peor que no
    tener cerrojo, porque da la sensacion de seguridad sin darsela.
    """
    if os.name != "posix":
        return False, f"os.name={os.name!r}; flock es POSIX"
    try:
        import fcntl as _f
    except ImportError:
        return False, "fcntl no importable: sin bloqueo entre procesos"
    if not hasattr(_f, "flock"):
        return False, "fcntl sin flock"
    try:
        fd, path = tempfile.mkstemp(prefix="delm-flock-probe-")
        try:
            _flock_ex(fd, blocking=False)
            _flock_unlock(fd)
            return True, "ok"
        finally:
            os.close(fd)
            os.unlink(path)
    except OSError as exc:  # pragma: no cover - depende del filesystem
        if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EROFS,
                         errno.ENOLCK, errno.EINVAL):
            return False, f"flock no fiable en este filesystem: {exc}"
        return False, f"no se pudo probar flock: {exc}"


@dataclass(frozen=True)
class ReservationSnapshot:
    """Lo que se guarda: generacion, secuencia y las reservas vivas.

    Se guarda **lo vivo**, no el estado completo. No se guardan los snapshots
    de capacidad: son lo que el nodo *reporta*, y ese reporte llega por su
    propio camino (el heartbeat, firmado). Duplicarlo aqui seria una segunda
    fuente de verdad sobre cuanto tiene cada nodo, y las dos discretarian
    justo cuando un nodo cambia de VRAM.
    """

    generation: int
    seq: int
    reservations: list[dict[str, Any]]


class InterprocessGuard:
    """Cerrojo de exclusion mutua entre procesos, con recarga de estado.

    Se usa como context manager::

        with guard.held():
            book.reserve(...)

    **Un guard por fichero de estado, por proceso.** Reentrante consigo mismo
    (contador de profundidad), pero **no** entre dos guards del mismo proceso
    que apuntan al mismo fichero: cada uno abre su propio descriptor, y
    ``flock`` bloquea igual un ``open()`` distinto que el mismo descriptor
    (comprobado: dos fds sobre el mismo inode se auto-bloquean en el mismo
    proceso). Por eso un proceso que quiera reentrar tiene que reusar **la
    misma instancia**, y por eso hay un registro de una instancia por ruta — un
    guard por ruta, no uno por llamada.

    La reentrada con ``flock`` es la trampa clasica de este patron: sin el
    contador de profundidad, anidar la misma instancia se bloquearia contra si
    misma para siempre.
    """

    def __init__(self, state_path: str) -> None:
        self.state_path = state_path
        self._depth = 0
        self._lock_fd: int | None = None
        self._stamp: tuple[int, int, int] | None = None   # (mtime_ns, size, ino)

    # ------------------------------------------------------------------ lock
    def _open(self) -> int:
        if self._lock_fd is None:
            path = self._lock_path()
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            self._lock_fd = fd
        return self._lock_fd

    def _lock_path(self) -> str:
        return self.state_path + ".lock"

    def acquire(self) -> None:
        if self._depth == 0:
            fd = self._open()
            _flock_ex(fd)
        self._depth += 1

    def release(self) -> None:
        self._depth -= 1
        if self._depth == 0 and self._lock_fd is not None:
            _flock_unlock(self._lock_fd)

    def held(self) -> "_HeldGuard":
        return _HeldGuard(self)

    # ------------------------------------------------------------- registro
    #: Una instancia por ruta de estado, por proceso. Dos guards del mismo
    #: proceso sobre la misma ruta se auto-bloquearian (cada uno con su
    #: descriptor), asi que "crear otro" devuelve el mismo en vez de abrir un
    #: fd competidor.
    _registry: ClassVar[dict[str, "InterprocessGuard"]] = {}

    @classmethod
    def get(cls, state_path: str) -> "InterprocessGuard":
        """El guard de esta ruta en este proceso. Singleton por ruta."""
        existing = cls._registry.get(state_path)
        if existing is not None:
            return existing
        made = cls(state_path)
        cls._registry[state_path] = made
        return made

    @classmethod
    def _reset(cls, state_path: str) -> None:
        """Suelta y olvida el guard de una ruta. Para tests y para Cerrar."""
        g = cls._registry.pop(state_path, None)
        if g is not None:
            g.close()

    # ----------------------------------------------------------------- state
    def read_state(self) -> ReservationSnapshot | None:
        """La foto del estado, o ``None`` si no hay estado todavia."""
        try:
            with open(self.state_path, encoding="utf-8") as fh:
                blob = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(blob, dict) or blob.get("v") != STATE_VERSION:
            # Un formato desconocido se ignora en vez deparsearse a medias: un
            # fichero corrupto no puede devolver una lista de reservas que
            # nunca se tomaron.
            return None
        res = blob.get("reservations")
        if not isinstance(res, list):
            return None
        return ReservationSnapshot(
            generation=int(blob.get("generation", 0)),
            seq=int(blob.get("seq", 0)),
            reservations=[r for r in res if isinstance(r, dict)],
        )

    def write_state(self, snap: ReservationSnapshot) -> None:
        """Vuelca el estado de forma atomica (escribir y renombrar)."""
        d = os.path.dirname(self.state_path) or "."
        os.makedirs(d, exist_ok=True)
        blob = {"v": STATE_VERSION, "generation": snap.generation,
                "seq": snap.seq, "reservations": snap.reservations}
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".res-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(blob, fh, sort_keys=True)
                fh.write("\n")
            os.replace(tmp, self.state_path)
            self._stamp = self._current_stamp()
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _current_stamp(self) -> tuple[int, int, int] | None:
        try:
            st = os.stat(self.state_path)
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def changed_since(self) -> bool:
        """¿El estado en disco cambio desde mi ultima escritura?

        Es la comprobacion barata que decide si hace falta recargar. Sin ella,
        cada operacion releeria el fichero entero — que es el cuello de botella
        que este diseño evita.
        """
        return self._current_stamp() != self._stamp

    def close(self) -> None:
        if self._lock_fd is not None:
            try:
                os.close(self._lock_fd)
            except OSError:  # pragma: no cover
                pass
            self._lock_fd = None
        self._depth = 0


class _HeldGuard:
    """Context manager de :meth:`InterprocessGuard.held`."""

    def __init__(self, guard: InterprocessGuard) -> None:
        self._g = guard

    def __enter__(self) -> "_HeldGuard":
        self._g.acquire()
        return self

    def __exit__(self, *exc: object) -> None:
        self._g.release()


__all__ = [
    "InterprocessGuard", "ReservationSnapshot", "interprocess_available",
    "STATE_SUFFIX", "STATE_VERSION",
]
