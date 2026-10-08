"""test_handcash: la identidad de pago del nodo.

El contrato que se fija aquí:

* **El handle es el camino.** ``$Chicocifrado``
  deriva el paymail ``chicocifrado@handcash.io``
  que enruta a la billetera; el ``$`` es
  decorativo y el paymail va en minúsculas.
* **La dirección legacy es el respaldo, no
  recomendado:** se valida (P2PKH de BSV
  mainnet, base58check) y se marca como tal.
* **Al menos uno.** La identidad vacía es el
  estado "sin configurar", no una identidad.
* **La nota cabe.** Las notas de finalización
  caben en el ``note`` de HandCash (<=25
  caracteres) — es la notificación del pago.
* **La identidad es un fichero compartido:**
  CLI y web escriben el mismo JSON.
* **La API dice la verdad:** GET devuelve lo
  que hay, PUT guarda y rechaza lo que no
  verifica.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from smcp.core.handcash import (
    HANDCASH_DOMAIN,
    MAX_NOTE_CHARS,
    HandCashHandle,
    PaymentIdentity,
    PaymentIntent,
    handcash_note,
    load_identity,
    parse_handle,
    save_identity,
    valid_legacy_address,
)
from smcp.core.inscripcion import NOTAS_COMPLETADO
from smcp.core.membership import ProtocolError
from smcp.core.spv import pubkey_to_address
from smcp.web.app import app


def _have_hash160() -> bool:
    """¿Hay ripemd160 (hash160) en este
    intérprete? Sin él, las direcciones no
    se validan."""
    try:
        pubkey_to_address(bytes(33))
    except Exception:  # noqa: BLE001 - sin ripemd160
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _have_hash160(), reason="requiere ripemd160"
)


def _address() -> str:
    """Una P2PKH de BSV mainnet válida (del
    generador del propio módulo)."""
    return pubkey_to_address(bytes(33))


# ------------------------------------------------------------------ handle
def test_el_handle_deriva_el_paymail() -> None:
    assert parse_handle("$Chicocifrado").paymail == (
        "chicocifrado@handcash.io"
    )
    # El $ es decorativo; sin él es el mismo.
    assert parse_handle("Chicocifrado").paymail == (
        parse_handle("$Chicocifrado").paymail
    )
    # La forma paymail también se acepta.
    assert parse_handle(
        "chicocifrado@handcash.io").paymail == (
        "chicocifrado@handcash.io"
    )
    # Un dominio explícito es otro paymail.
    h = parse_handle("alguien@otro.ej")
    assert h.domain == "otro.ej"
    assert h.paymail == "alguien@otro.ej"


def test_el_paymail_va_en_minusculas() -> None:
    h = parse_handle("$ChicoCifrado")
    assert h.display == "$ChicoCifrado"
    assert h.paymail == "chicocifrado@handcash.io"


def test_el_handle_rechaza_aliases_rotos() -> None:
    for malo in ("", "$", "  ", "@handcash.io",
                 "alias@", "-no-empieza-alnum",
                 "con espacio", "a" * 33):
        with pytest.raises(ProtocolError):
            parse_handle(malo)


def test_el_alias_tope_es_32() -> None:
    h = parse_handle("$" + "a" * 32)
    assert len(h.alias) == 32
    with pytest.raises(ProtocolError):
        parse_handle("$" + "a" * 33)


# -------------------------------------------------------- dirección legacy
def test_la_direccion_legacy_se_valida() -> None:
    assert valid_legacy_address(_address()) is True
    # Basura, vacía y de otra red: no.
    assert valid_legacy_address("1x") is False
    assert valid_legacy_address("") is False
    assert valid_legacy_address(
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") is False
    assert valid_legacy_address(
        "14p5cGy5DZmtNMQwTQiytBvxMVuTmFMSyUx") is False


# ------------------------------------------------------------- identidad
def test_la_identidad_requiere_al_menos_uno() -> None:
    vacia = PaymentIdentity()
    assert vacia.configured is False
    assert vacia.recipient == ""
    assert "sin identidad" in vacia.summary
    ident = PaymentIdentity(handle=parse_handle("$X"))
    assert ident.configured is True
    assert ident.recipient == "x@handcash.io"
    assert ident.handle is not None
    assert ident.legacy_address is None


def test_la_direccion_invalida_no_es_identidad() -> None:
    with pytest.raises(ProtocolError):
        PaymentIdentity(legacy_address="1x")


def test_los_dos_pueden_coexistir() -> None:
    ident = PaymentIdentity(
        handle=parse_handle("$Chicocifrado"),
        legacy_address=_address())
    # El handle manda: el destino es el paymail.
    assert ident.recipient == "chicocifrado@handcash.io"
    assert "no recomendado" in ident.summary


def test_el_round_trip_del_fichero(tmp_path) -> None:
    ident = PaymentIdentity(
        handle=parse_handle("$Chicocifrado"),
        legacy_address=_address())
    path = save_identity(ident, tmp_path / "id.json")
    assert path.exists()
    cargada = load_identity(path)
    assert cargada == ident
    # Sin fichero: sin identidad (la v3 pura).
    assert load_identity(
        tmp_path / "no-existe.json") == PaymentIdentity()
    # Un fichero roto no la rompe: sin identidad.
    roto = tmp_path / "roto.json"
    roto.write_text("{no json", encoding="utf-8")
    assert load_identity(roto) == PaymentIdentity()


def test_el_dict_solo_lleva_lo_que_hay() -> None:
    assert PaymentIdentity().to_dict() == {}
    d = PaymentIdentity(
        handle=parse_handle("$X")).to_dict()
    assert d == {"handle_alias": "X",
                 "handle_domain": HANDCASH_DOMAIN}
    assert PaymentIdentity.from_dict(d) == PaymentIdentity(
        handle=HandCashHandle("X"))
    # Claves desconocidas no rompen la carga.
    assert PaymentIdentity.from_dict(
        {"handle_alias": "X", "futuro": 1}).handle == (
        HandCashHandle("X"))


# ------------------------------------------------------------------ nota
def test_las_notas_de_finalizacion_caben() -> None:
    assert all(len(n) <= MAX_NOTE_CHARS
               for n in NOTAS_COMPLETADO)
    assert handcash_note("inferencia completada") == (
        "inferencia completada"
    )
    # El tope es del campo de HandCash, no nuestro.
    with pytest.raises(ProtocolError):
        handcash_note("x" * (MAX_NOTE_CHARS + 1))
    with pytest.raises(ProtocolError):
        handcash_note("   ")


def test_el_intento_de_pago_es_el_contrato() -> None:
    ident = PaymentIdentity(handle=parse_handle("$X"))
    intento = PaymentIntent(sats=250, identity=ident,
                            note=NOTAS_COMPLETADO[0])
    assert intento.recipient == "x@handcash.io"
    # Sin identidad, no hay envío posible.
    with pytest.raises(ProtocolError):
        PaymentIntent(sats=250,
                      identity=PaymentIdentity(),
                      note=NOTAS_COMPLETADO[0])
    # Ni un pago de 0 sats.
    with pytest.raises(ProtocolError):
        PaymentIntent(sats=0, identity=ident,
                      note=NOTAS_COMPLETADO[0])


# ------------------------------------------------------------------- API
@pytest.fixture()
def client(tmp_path, monkeypatch):
    from smcp.web import api
    monkeypatch.setattr(
        api, "_payments_identity_path",
        lambda: tmp_path / "payments_identity.json")
    with TestClient(app) as c:
        yield c


def test_get_devuelve_la_identidad_vacia(client):
    r = client.get("/api/payments/identity")
    assert r.status_code == 200
    j = r.json()
    assert j["configured"] is False
    assert j["handle"] is None
    assert j["paymail"] is None
    assert j["legacy_address"] is None
    assert j["path"].endswith("payments_identity.json")


def test_put_guarda_el_handle(client):
    r = client.put("/api/payments/identity",
                   json={"handle": "$Chicocifrado"})
    assert r.status_code == 200
    j = r.json()
    assert j["configured"] is True
    assert j["handle"] == "$Chicocifrado"
    assert j["paymail"] == "chicocifrado@handcash.io"
    assert j["recipient"] == "chicocifrado@handcash.io"
    # Persistió: otra GET lo ve.
    r2 = client.get("/api/payments/identity")
    assert r2.json()["paymail"] == "chicocifrado@handcash.io"


def test_put_guarda_la_direccion_legacy(client):
    addr = _address()
    r = client.put("/api/payments/identity",
                   json={"legacy_address": addr})
    assert r.status_code == 200
    j = r.json()
    assert j["handle"] is None
    assert j["legacy_address"] == addr
    assert j["recipient"] == addr


def test_put_rechaza_lo_que_no_verifica(client):
    # Alias roto.
    r = client.put("/api/payments/identity",
                   json={"handle": "-mal"})
    assert r.status_code == 400
    assert "detail" in r.json()
    # Dirección que no es P2PKH mainnet.
    r = client.put("/api/payments/identity",
                   json={"legacy_address": "1x"})
    assert r.status_code == 400
    # Vacío: borra la identidad (es la forma de
    # limpiar, no un error).
    client.put("/api/payments/identity",
               json={"handle": "$Chicocifrado"})
    r = client.put("/api/payments/identity", json={})
    assert r.status_code == 200
    assert r.json()["configured"] is False


def test_las_notas_caben_en_el_campo_de_handcash(client):
    r = client.get("/api/payments/note-demo")
    assert r.status_code == 200
    j = r.json()
    assert j["max_note_chars"] == MAX_NOTE_CHARS
    assert j["caben"] is True
    assert NOTAS_COMPLETADO[0] in j["notas"]


# ------------------------------------------------------- fichero compartido
def test_cli_y_web_escriben_el_mismo_fichero(tmp_path):
    """La identidad del CLI y la de la web son un
    fichero — no dos fuentes de verdad."""
    path = tmp_path / "pagos.json"
    ident = PaymentIdentity(
        handle=parse_handle("$Chicocifrado"))
    save_identity(ident, path)
    # Lo que escribe el CLI lo lee la web (y
    # al revés): el JSON es el contrato.
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data == {"handle_alias": "Chicocifrado",
                    "handle_domain": HANDCASH_DOMAIN}
    assert load_identity(path) == ident
