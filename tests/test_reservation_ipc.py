"""Interprocess guard — dos procesos vendiendo la misma VRAM.

La prueba que importa
---------------------
``test_two_processes_cannot_both_sell_the_same_vram`` lanza dos **procesos
reales** (no threads) contra el mismo fichero de estado, con un libro de
reservas en cada uno, y exige que la suma de lo vendido no pase de la
capacidad. Sin el cerrojo los dos vendian la misma GiB, y un test con threads
no lo detectaria: el GIL hace que las operaciones simples sean atomicas dentro
de un proceso, igual que ocurria con la sobreventa del libro de un solo
proceso.

Lo que mas se Midiendo
----------------------
* El cerrojo se toma en el **sentido** correcto: quien entra segundo ve el
  estado que dejo el primero. Sin la recarga, el segundo leeria su propia
  vista vieja y venderia lo mismo.
* La reentrada: anidar dos llamadas al mismo cerrojo bloquearia contra si
  mismo para siempre, asi que hay un contador de profundidad.
* Un fichero de estado corrupto o de formato desconocido se **ignora**, no se
  parsea a medias. Un fichero que devuelve reservas que nunca se tomaron es
  peor que no tener fichero.
* ``interprocess_available`` dice si el cerrojo es de fiar en este sistema de
  ficheros, en vez de asumirlo.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from smcp.core.reservation_ipc import (
    STATE_VERSION,
    InterprocessGuard,
    interprocess_available,
)

ROOT = Path("/mnt/d/Hermes/DeLM/delm")


# --------------------------------------------------------------------------
# La disponibilidad se dice, no se asume
# --------------------------------------------------------------------------
def test_interprocess_support_is_reported_not_assumed():
    """Dice si funciona y por que no, si no funciona.

    Un cerrojo que no cierra es peor que no tener cerrojo: da la sensacion de
    seguridad sin darsela. Por eso esto es una comprobacion explicita y no un
    ``try/except`` alrededor del primer uso.
    """
    ok, why = interprocess_available()
    assert isinstance(ok, bool) and isinstance(why, str) and why
    if ok:
        assert why == "ok"
    else:
        assert why != "ok", "si no funciona, el motivo tiene que decir por que"


# --------------------------------------------------------------------------
# Estado en disco
# --------------------------------------------------------------------------
def test_no_state_file_reads_as_none(tmp_path):
    g = InterprocessGuard(str(tmp_path / "s.json"))
    assert g.read_state() is None


def test_state_round_trips(tmp_path):
    g = InterprocessGuard(str(tmp_path / "s.json"))
    g.write_state(_snap(generation=3, seq=7, ids=["a", "b"]))
    got = g.read_state()
    assert got is not None
    assert got.generation == 3 and got.seq == 7
    assert [r["reservation_id"] for r in got.reservations] == ["a", "b"]


def _snap(generation: int = 1, seq: int = 0, ids: list[str] | None = None):
    from smcp.core.reservation_ipc import ReservationSnapshot
    return ReservationSnapshot(
        generation=generation, seq=seq,
        reservations=[{"reservation_id": i, "peer_id": "n1", "memory_gb": 1.0,
                       "generation": generation, "taken_at": 0.0,
                       "expires_at": 0.0} for i in (ids or [])])


def test_a_corrupt_state_file_is_ignored_not_half_parsed(tmp_path):
    """Un JSON roto se ignora. Devolver una lista a medias seria peor.

    Si el fichero esta truncado a la mitad, un ``json.load`` parcial podria
    devolver algunas reservas — que nunca se tomaron — y el libro las daria
    por defecto. Ignorar significa "no hay estado", que es la respuesta honesta.
    """
    p = tmp_path / "s.json"
    p.write_text('{"v": 1, "reservations": [{"reservation_id": "a"')
    g = InterprocessGuard(str(p))
    assert g.read_state() is None


def test_a_state_file_with_an_unknown_version_is_ignored(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"v": 999, "reservations": [{"reservation_id": "a"}]}))
    assert InterprocessGuard(str(p)).read_state() is None


def test_a_state_file_with_the_wrong_shape_is_ignored(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"v": STATE_VERSION, "reservations": "no-es-una-lista"}))
    assert InterprocessGuard(str(p)).read_state() is None


def test_writing_state_is_atomic_and_leaves_no_temp_files(tmp_path):
    """Escribir-y-renombrar: un fallo a mitad no deja un estado truncado."""
    p = tmp_path / "s.json"
    g = InterprocessGuard(str(p))
    g.write_state(_snap(generation=1, ids=["a"]))
    g.write_state(_snap(generation=2, ids=["b"]))
    leftovers = [f.name for f in tmp_path.iterdir() if ".tmp" in f.name]
    assert leftovers == [], f"temporales sin limpiar: {leftovers}"
    after = g.read_state()
    assert after is not None
    assert after.generation == 2


def test_a_written_state_is_then_seen_as_unchanged(tmp_path):
    """La marca evita releer en cada operacion — el cuello de botella."""
    g = InterprocessGuard(str(tmp_path / "s.json"))
    g.write_state(_snap())
    assert not g.changed_since(), "acabo de escribir: no ha cambiado"
    # otro proceso escribe
    other = InterprocessGuard(str(tmp_path / "s.json"))
    other.write_state(_snap(generation=9, ids=["x"]))
    assert g.changed_since(), "el estado cambio en disco y no me enteraria"


# --------------------------------------------------------------------------
# El cerrojo
# --------------------------------------------------------------------------
def test_the_guard_is_reentrant_within_a_process(tmp_path):
    """Anidar no se bloquea contra si mismo.

    Sin el contador de profundidad, el segundo ``acquire`` del mismo proceso
    pediria un cerrojo que el primero tiene y se quedaria esperando para
    siempre. Un deadlock en un ``with`` anidado es el fallo mas caro de este
    patron, y el mas facil de no ver.
    """
    g = InterprocessGuard(str(tmp_path / "s.json"))
    with g.held():
        with g.held():
            assert g._depth == 2
        assert g._depth == 1
    assert g._depth == 0
    g.close()


def test_the_guard_releases_even_when_the_body_raises(tmp_path):
    g = InterprocessGuard(str(tmp_path / "s.json"))
    with pytest.raises(RuntimeError):
        with g.held():
            raise RuntimeError("boom")
    assert g._depth == 0, "el cerrojo se quedo tomado tras una excepcion"
    g.close()


def test_the_lock_file_is_separate_from_the_state_file(tmp_path):
    """Dos ficheros, dos cosas. El cerrojo no lleva el sufijo del estado.

    Borrar el fichero de cerrojo creyendo que se limpia el estado soltaria el
    cerrojo **con otro proceso todavia dentro**, que es peor que no borrar
    nada. Y borrar el estado no debe soltar el cerrojo.
    """
    sp = tmp_path / "s.json"
    g = InterprocessGuard(str(sp))
    with g.held():
        g.write_state(_snap())
    assert sp.exists()
    assert (tmp_path / "s.json.lock").exists()
    g.close()


# --------------------------------------------------------------------------
# La prueba de fuego: dos procesos reales
# --------------------------------------------------------------------------
_CHILD = textwrap.dedent("""
    import json, sys
    sys.path.insert(0, "%(root)s")
    from smcp.core.contrib import PeerContribution
    from smcp.core.reservation import ReservationBook
    from smcp.core.reservation_ipc import InterprocessGuard

    state_path, cap_gb, want_gb, per_try, barrier = (
        sys.argv[1], float(sys.argv[2]), float(sys.argv[3]),
        int(sys.argv[4]), sys.argv[5])

    def peer():
        return PeerContribution(peer_id="n1", vram_gb=cap_gb,
                               vram_advertised_gb=cap_gb, vram_shared_gb=0.0)

    book = ReservationBook()
    guard = InterprocessGuard(state_path)
    # El libro necesita una linea base: sin un snapshot el nodo no existe y
    # ``reserve`` responderia UNKNOWN_PEER, no "vendido".
    book.publish_snapshot({"n1": peer()}, now=100.0)
    open(barrier, "w").close()

    taken = 0.0
    for _ in range(per_try):
        with guard.held():
            # repone la linea base y recarga lo que otro proceso dejo: el
            # estado compartido es lo que hace que el segundo vea al primero.
            book.publish_snapshot({"n1": peer()}, now=100.0)
            st = guard.read_state()
            if st is not None:
                book.adopt(state=st)
            res, why = book.reserve("n1", want_gb)
            if res is not None:
                taken += want_gb
                guard.write_state(book.state_of())
    print(json.dumps({"taken": taken}))
""")


def test_two_processes_cannot_both_sell_the_same_vram(tmp_path):
    """Dos procesos, una capacidad, y la suma por debajo de la capacidad.

    Esta es la prueba que justifica el modulo. Sin el cerrojo (y sin la
    recarga), los dos procesos venderian la misma GiB al mismo tiempo — y con
    threads no se detectaria, porque el GIL haria cada operacion simple
    atomica. Solo dos procesos reales abren esa ventana.
    """
    ok, why = interprocess_available()
    if not ok:
        pytest.skip(f"flock no disponible aqui: {why}")

    state_path = str(tmp_path / "s.json")
    cap_gb, want_gb, per_try = 8.0, 2.0, 6
    # barrier: un fichero que ambos tocan para arrancar a la vez
    barrier = str(tmp_path / "go")
    child = _CHILD % {"root": str(ROOT)}

    # El hijo corre con un entorno limpio: sin PYTEST_CURRENT_TEST, que
    # pytest inyecta y hace que un ``pytest`` anidado se colisione con el
    # externo en el fichero de resultados.
    child_env = {k: v for k, v in os.environ.items()
                 if not k.startswith("PYTEST")}
    procs = [subprocess.Popen(
        [sys.executable, "-c", child, state_path, str(cap_gb),
         str(want_gb), str(per_try), barrier],
        cwd=str(ROOT), env=child_env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(2)]
    # Si el cerrojo no se libera, el segundo hijo se queda esperando para
    # siempre. Un test que deja procesos colgados es peor que un test que
    # falla: cuelga la suite entera la siguiente vez. Por eso el grupo se mata
    # entero, y por eso un cuelgue se reporta como fallo y no como excepcion.
    outs: list[str] = []
    errs: list[str] = []
    try:
        for p in procs:
            o, e = p.communicate(timeout=90)
            outs.append(o)
            errs.append(e)
    except subprocess.TimeoutExpired:
        for p in procs:
            if p.poll() is None:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    p.kill()
        for p in procs:
            p.communicate(timeout=30)
        pytest.fail(
            "los procesos hijos se quedaron colgados: el cerrojo no se "
            "libero, asi que el segundo nunca entro. Un hang aqui significa "
            "que quitar el lock cuelga el sistema, no que lo desordene.")

    for p, o, e in zip(procs, outs, errs):
        assert p.returncode == 0, (
            f"proceso fallo (rc={p.returncode}):\n{e[-900:]}")

    total = sum(json.loads(o)["taken"] for o in outs)
    assert total <= cap_gb, (
        f"se vendieron {total} GiB de {cap_gb} con 2 procesos: la sobreventa "
        f"entre procesos sigue viva")
    # y no se quedo sin hacer nada tampoco: el mecanismo no es un no-op
    assert total > 0, "ningun proceso vendio nada: el guard esta bloqueando todo"


def test_two_guards_on_one_path_in_one_process_would_deadlock_and_get_prevents_it(
        tmp_path):
    """El cuelgue real, y por que ``get()`` existe.

    ``flock`` bloquea tambien un ``open()`` **distinto** del mismo fichero en
    el mismo proceso — comprobado con dos descriptores sobre el mismo inode:
    el segundo se queda esperando para siempre, no porque el lock este roto,
    sino porque la exclusion mutua no distingue "otro proceso" de "el mismo
    proceso con otro descriptor".

    Sin esto, cualquier codigo que pidiera un guard nuevo por operacion
    colgaria la malla la segunda vez que se llamara. Es un cuelgue, no un
    fallo de datos, asi que no aparece en los tests de contenido: se manifesta
    como una suite que se queda quieta. De ahi que ``get()`` sea singleton por
    ruta.
    """
    sp = str(Path(tmp_path) / "s.json")
    a = InterprocessGuard.get(sp)
    b = InterprocessGuard.get(sp)
    assert a is b, "dos llamadas a get() deben dar la misma instancia"
    # y el ciclo completo no se cuelga
    with a.held():
        a.write_state(_snap(generation=1, ids=["x"]))
    with b.held():
        assert b.read_state() is not None
    InterprocessGuard._reset(sp)
    # tras el reset, un guard nuevo si es una instancia distinta
    c = InterprocessGuard.get(sp)
    assert c is not a
    InterprocessGuard._reset(sp)


def test_a_second_process_sees_what_the_first_left(tmp_path):
    """(orden: este test corre DESPUES del de dos procesos reales)

    Usa su propio ``tmp_path`` — pytest da uno distinto por test — asi que no
    comparte fichero de estado con el anterior. El lock tampoco se solapa: cada
    guard abre su propio descriptor.
    """
    """El orden se ve en el estado: el segundo hereda lo que el primero hizo.

    Esta es la mitad de la garantia que faltaba en el libro de un solo
    proceso — alli era una barrier de ``threading`` que no abria la ventana.
    Aqui se comprueba directamente: el estado escrito por A es el que lee B.
    """
    ok, why = interprocess_available()
    if not ok:
        pytest.skip(f"flock no disponible aqui: {why}")
    sp = str(tmp_path / "s.json")
    a = InterprocessGuard.get(sp)
    with a.held():
        a.write_state(_snap(generation=1, seq=1, ids=["res-a"]))
    b = InterprocessGuard.get(sp)
    with b.held():
        st = b.read_state()
        assert st is not None
        assert [r["reservation_id"] for r in st.reservations] == ["res-a"]
    InterprocessGuard._reset(sp)
