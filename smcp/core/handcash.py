"""HandCash — la identidad de pago del nodo.

Qué resuelve este módulo
------------------------
La pregunta que la v3 dejó abierta: **¿adónde van los
pagos?** La tx de inscripción paga a la pubkey del
servidor — una clave local, sin dueño humano. La
identidad de pago es el puente: el **handle** de
HandCash (``$Chicocifrado``) o, no recomendado, una
**dirección legacy** propia. El paymail que deriva
(``chicocifrado@handcash.io``) enruta los pagos a
las direcciones BSV que el usuario controla en su
billetera HandCash: pagar al paymail es pagar a la
billetera, sin conocer ninguna dirección de antemano.

Handle
------
``$alias`` — el handle de HandCash. El ``$`` es
decorativo (el alias viaja sin él) y el dominio por
defecto es ``handcash.io``: ``$Chicocifrado`` es el
paymail ``chicocifrado@handcash.io``. El alias
admite letras, dígitos, ``.``, ``-`` y ``_`` (hace
32), y es insensible a mayúsculas — se guarda como
se registró y se resuelve sin caso. La forma
paymail (``alias@dominio``) también se acepta.

Dirección legacy
----------------
Una dirección P2PKH de BSV mainnet (empieza por
``1``). Funciona — pero es estática: cada pago a
la misma dirección es rastreable en la cadena y no
hay routing de billetera. Por eso es **no
recomendada**: el handle es el camino, la dirección
es el respaldo.

La nota
-------
El pago viaja con una nota (<=25 caracteres — el
campo ``note`` de HandCash, metadata fuera de la
cadena): es la **notificación** que la billetera
muestra al recibir. Las notas de finalización de
:mod:`smcp.core.inscripcion` caben todas (la más
larga mide 21 caracteres).

Lo que este módulo NO hace
--------------------------
* No envía el pago: la llamada a la API de HandCash
  (la credencial, el envío) es del adaptador que
  consume el :class:`PaymentIntent` — la identidad
  y el intento son el contrato, no el transporte.
* No resuelve el paymail contra la red: derivar el
  paymail del handle es local; la resolución (qué
  dirección concreta sirve hoy) es de HandCash.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from smcp.core.contrib import (
    default_payments_identity_path,
)
from smcp.core.membership import ProtocolError
from smcp.core.spv import address_to_hash160

#: El dominio de los handles de HandCash.
HANDCASH_DOMAIN = "handcash.io"

#: El campo ``note`` de HandCash mide hasta 25
#: caracteres (metadata fuera de la cadena).
MAX_NOTE_CHARS = 25

#: Alias: empieza alfanumérico, luego alfanumérico
#: o ``.``/``-``/``_``, hasta 32 caracteres.
_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")


@dataclass(frozen=True)
class HandCashHandle:
    """Un handle de HandCash: el alias y su dominio.

    ``$Chicocifrado`` y ``chicocifrado`` son el
    mismo handle; ``display`` lo muestra con el
    ``$`` y ``paymail`` es la forma que enruta.
    """

    alias: str
    domain: str = HANDCASH_DOMAIN

    def __post_init__(self) -> None:
        if not _ALIAS_RE.match(self.alias):
            raise ProtocolError(
                f"alias {self.alias!r}: letras, dígitos, "
                "'.', '-' y '_', hasta 32 caracteres"
            )
        if not self.domain:
            raise ProtocolError("dominio vacío")

    @property
    def display(self) -> str:
        """El handle como se escribe: ``$alias``."""
        return f"${self.alias}"

    @property
    def paymail(self) -> str:
        """El paymail que enruta a la billetera."""
        return f"{self.alias.lower()}@{self.domain.lower()}"


def parse_handle(text: str) -> HandCashHandle:
    """Parsea un handle: ``$alias``, ``alias`` o
    ``alias@dominio`` (la forma paymail)."""
    txt = (text or "").strip()
    if not txt:
        raise ProtocolError("handle vacío")
    txt = txt.removeprefix("$")
    if "@" in txt:
        alias, _, domain = txt.partition("@")
        if not alias or not domain:
            raise ProtocolError(
                f"paymail {text!r}: alias@dominio"
            )
        return HandCashHandle(alias, domain)
    return HandCashHandle(txt)


def valid_legacy_address(address: str) -> bool:
    """¿Una dirección P2PKH de BSV mainnet válida?

    Reusa el decodificador base58check de
    :mod:`smcp.core.spv`: longitud, versión 0x00 y
    checksum. Una dirección de otra red (o rota)
    no es válida aquí.
    """
    try:
        address_to_hash160((address or "").strip())
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class PaymentIdentity:
    """Adónde van los pagos del nodo.

    El **handle** es el camino (routing de
    billetera por paymail); la **dirección legacy**
    es el respaldo, no recomendado. Cualquiera de
    los dos puede faltar — los dos faltando es
    ``configured=False``: el nodo paga a la clave
    local, como en la v3 sin identidad.
    """

    handle: HandCashHandle | None = None
    legacy_address: str | None = None

    def __post_init__(self) -> None:
        if self.legacy_address is not None:
            if not valid_legacy_address(self.legacy_address):
                raise ProtocolError(
                    f"dirección {self.legacy_address!r}: "
                    "no es una P2PKH de BSV mainnet válida"
                )

    @property
    def configured(self) -> bool:
        """¿Tiene algo adónde pagar?"""
        return self.handle is not None or bool(
            self.legacy_address
        )

    @property
    def recipient(self) -> str:
        """A quién se envía: el paymail si hay
        handle, si no la dirección."""
        if self.handle is not None:
            return self.handle.paymail
        return self.legacy_address or ""

    @property
    def summary(self) -> str:
        """La identidad en una línea, para mostrar."""
        partes: list[str] = []
        if self.handle is not None:
            partes.append(
                f"handle {self.handle.display} "
                f"→ {self.handle.paymail}"
            )
        if self.legacy_address:
            partes.append(
                f"legacy {self.legacy_address} "
                "(no recomendado)"
            )
        return "; ".join(partes) if partes else "sin identidad"

    def to_dict(self) -> dict[str, Any]:
        """La forma persistente (solo lo que hay)."""
        d: dict[str, Any] = {}
        if self.handle is not None:
            d["handle_alias"] = self.handle.alias
            d["handle_domain"] = self.handle.domain
        if self.legacy_address:
            d["legacy_address"] = self.legacy_address
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PaymentIdentity":
        """Reconstruye la identidad de su forma
        persistente."""
        alias = str(data.get("handle_alias") or "").strip()
        handle = None
        if alias:
            handle = HandCashHandle(
                alias,
                str(data.get("handle_domain")
                    or HANDCASH_DOMAIN),
            )
        legacy = data.get("legacy_address") or None
        return cls(handle=handle,
                   legacy_address=str(legacy) if legacy else None)


def load_identity(
        path: Path | None = None) -> PaymentIdentity:
    """Carga la identidad de pago; sin fichero,
    sin identidad (la v3 pura: clave local)."""
    p = path if path is not None else (
        default_payments_identity_path())
    if not p.exists():
        return PaymentIdentity()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return PaymentIdentity()
    if not isinstance(data, dict):
        return PaymentIdentity()
    return PaymentIdentity.from_dict(data)


def save_identity(identity: PaymentIdentity,
                  path: Path | None = None) -> Path:
    """Guarda la identidad (el CLI y la web escriben
    el mismo fichero — una identidad, no dos)."""
    p = path if path is not None else (
        default_payments_identity_path())
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(identity.to_dict(), indent=2,
                   sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return p


def handcash_note(nota: str) -> str:
    """La nota de finalización, como ``note`` de
    HandCash.

    El campo mide <=25 caracteres y viaja fuera de
    la cadena: es la notificación que la billetera
    del receptor muestra al recibir el pago. Las
    notas fijas de la inscripción caben todas.
    """
    txt = (nota or "").strip()
    if not txt:
        raise ProtocolError("nota vacía")
    if len(txt) > MAX_NOTE_CHARS:
        raise ProtocolError(
            f"nota de {len(txt)} caracteres; el note "
            f"de HandCash llega a {MAX_NOTE_CHARS}"
        )
    return txt


@dataclass(frozen=True)
class PaymentIntent:
    """Lo que el envío a HandCash necesita: cuánto,
    a quién, con qué nota.

    Es el contrato entre la infraestructura de
    pagos (la tx de inscripción, la nota de
    finalización) y el adaptador que habla con la
    API de HandCash: el intento no sabe de HTTP,
    el adaptador no sabe de inscripciones.
    """

    sats: int
    identity: PaymentIdentity
    note: str

    def __post_init__(self) -> None:
        if self.sats < 1:
            raise ProtocolError(
                f"pago de {self.sats} sats: el mínimo es 1"
            )
        if not self.identity.configured:
            raise ProtocolError(
                "identidad de pago sin configurar: "
                "handle o dirección, al menos uno"
            )
        # La nota se valida contra el campo de
        # HandCash aquí, no en el adaptador.
        handcash_note(self.note)

    @property
    def recipient(self) -> str:
        """A quién se envía (el paymail, o la
        dirección si no hay handle)."""
        return self.identity.recipient


__all__ = [
    "HANDCASH_DOMAIN", "MAX_NOTE_CHARS",
    "HandCashHandle", "PaymentIdentity",
    "PaymentIntent", "handcash_note",
    "load_identity", "parse_handle",
    "save_identity", "valid_legacy_address",
]
