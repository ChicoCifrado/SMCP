"""Construccion de transacciones BSV — el serializador que no habia.

Por qué un módulo nuevo y no una dependencia: el repo va a propósito
con cuatro dependencias (openai, pydantic, aiohttp, cryptography), y
una librería de transacciones arrastra el wallet completo. Lo que v3
necesita es poco y concreto: serializar, firmar (SIGHASH_ALL, P2PKH)
y calcular txids. ``membership.py`` ya anticipó el hueco — "Implementarlo
requiere el serializador de transacciones" — y aquí está.

BSV no tiene segwit: el formato legacy es el único, y con él el
algoritmo de sighash clásico (sin marker ni flag, sin witness).

Lo que se validó: vectores de ``sighash.json`` de Bitcoin Core —
con hashTypes positivos y negativos, índices en medio de la lista de
inputs, scripts vacíos y no vacíos. Esa es la prueba de que la
serialización y el preimage del sighash son los de la red, y no los
de una implementación que se valida a sí misma.

Orden de bytes, dicho una vez porque es la trampa clásica:

* En el cable (y en los outpoints) el txid viaja **invertido**
  (orden interno, little-endian).
* El txid y el sighash **de presentación** se muestran volteados
  (big-endian) — es lo que comparan los exploradores y los vectores.
* Lo que **firma** ECDSA es el doble SHA-256 en orden interno, sin
  voltear: la firma cubre los 32 bytes crudos, no su presentación.

Lo que este módulo NO hace:

* No emite a la red. Construir y firmar es una cosa; difundir, otra.
* No evalúa scripts. No es un intérprete de Bitcoin Script.
* No soporta P2SH, multisig ni segwit (BSV no lo tiene).
* No elige fee: la aritmética de lo que entra y lo que sale es del
  que llama.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - solo tipos
    from smcp.core.bsv_keys import Secp256k1KeyPair

#: Tipos de sighash clásicos. El byte que se añade al preimage.
#: SIGHASH_ANYONECANPAY es **0x80** — el bit alto del byte
#: bajo, no el bit alto del entero de 32 bits (que es el
#: bit de signo de la serialización). Confundirlos invierte
#: la semántica: un hashType negativo no lleva ANYONECANPAY
#: por ser negativo, y uno como 0xE9 sí lo lleva.
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

# ---------------------------------------------------------------------------
# Opcodes que usa este módulo (y la inscripción v3)
# ---------------------------------------------------------------------------
OP_FALSE = 0x00
OP_0 = 0x00
OP_1 = 0x51
OP_2 = 0x52
OP_3 = 0x53
OP_4 = 0x54
OP_5 = 0x55
OP_6 = 0x56
OP_IF = 0x63
OP_ENDIF = 0x68
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_CODESEPARATOR = 0xAB
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC


# ---------------------------------------------------------------------------
# Codificaciones
# ---------------------------------------------------------------------------
def varint(n: int) -> bytes:
    """El entero variable del protocolo Bitcoin."""
    if n < 0:
        raise ValueError("varint negativo")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise ValueError("varint fuera del buffer")
    first = data[pos]
    pos += 1
    if first < 0xFD:
        return first, pos
    if first == 0xFD:
        return struct.unpack_from("<H", data, pos)[0], pos + 2
    if first == 0xFE:
        return struct.unpack_from("<I", data, pos)[0], pos + 4
    return struct.unpack_from("<Q", data, pos)[0], pos + 8


def push_data(data: bytes) -> bytes:
    """El prefijo de push para ``data`` (Script, no envelope)."""
    n = len(data)
    if n <= 75:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xFFFF:
        return bytes([OP_PUSHDATA2]) + struct.pack("<H", n) + data
    return bytes([OP_PUSHDATA4]) + struct.pack("<I", n) + data


def p2pkh_lock(pubkey_hash: bytes) -> bytes:
    """``OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG``."""
    if len(pubkey_hash) != 20:
        raise ValueError(
            f"pubkey hash de {len(pubkey_hash)} bytes; se esperan 20"
        )
    return (
        bytes([OP_DUP, OP_HASH160, 0x14])
        + pubkey_hash
        + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
    )


def der_encode(signature: bytes) -> bytes:
    """``r || s`` (64 bytes) -> DER, el formato que lleva un scriptSig.

    Cada entero se codifica sin ceros a la izquierda, con un cero
    adelante si el bit alto queda encendido (enteros con signo).
    """
    if len(signature) != 64:
        raise ValueError(
            f"firma de {len(signature)} bytes; se esperaban 64 (r||s)"
        )

    def _int(raw: int) -> bytes:
        body = raw.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
        if body[0] & 0x80:
            body = b"\x00" + body
        return b"\x02" + bytes([len(body)]) + body

    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    body = _int(r) + _int(s)
    return b"\x30" + bytes([len(body)]) + body


# ---------------------------------------------------------------------------
# La transaccion
# ---------------------------------------------------------------------------
@dataclass
class TxIn:
    """Un input. ``prev_txid`` en hex de presentación (big-endian)."""

    prev_txid: str
    vout: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFF

    @property
    def outpoint(self) -> str:
        return f"{self.prev_txid}:{self.vout}"


@dataclass
class TxOut:
    """Un output: satoshis y su script de bloqueo."""

    satoshis: int
    script: bytes


@dataclass
class Transaction:
    """Una transacción legacy (BSV: sin segwit, un solo formato)."""

    version: int = 1
    inputs: list[TxIn] = field(default_factory=list)
    outputs: list[TxOut] = field(default_factory=list)
    locktime: int = 0

    # ------------------------------------------------------------ serializar
    def serialize(self) -> bytes:
        """El formato del cable: versión, inputs, outputs, locktime."""
        out = bytearray(struct.pack("<i", self.version))
        out += varint(len(self.inputs))
        for txin in self.inputs:
            out += bytes.fromhex(txin.prev_txid)[::-1]
            out += struct.pack("<I", txin.vout)
            out += varint(len(txin.script_sig)) + txin.script_sig
            out += struct.pack("<I", txin.sequence)
        out += varint(len(self.outputs))
        for txout in self.outputs:
            out += struct.pack("<q", txout.satoshis)
            out += varint(len(txout.script)) + txout.script
        out += struct.pack("<I", self.locktime)
        return bytes(out)

    @classmethod
    def parse(cls, raw: bytes) -> "Transaction":
        """La inversa de :meth:`serialize`. Un byte de más es un error."""
        pos = 0
        if len(raw) < 4 + 1 + 1 + 1 + 4:
            raise ValueError("transacción corta")
        version = struct.unpack_from("<i", raw, pos)[0]
        pos += 4
        n_in, pos = _read_varint(raw, pos)
        inputs: list[TxIn] = []
        for _ in range(n_in):
            prev = raw[pos:pos + 32][::-1].hex()
            pos += 32
            vout = struct.unpack_from("<I", raw, pos)[0]
            pos += 4
            script_len, pos = _read_varint(raw, pos)
            script_sig = raw[pos:pos + script_len]
            pos += script_len
            sequence = struct.unpack_from("<I", raw, pos)[0]
            pos += 4
            inputs.append(TxIn(prev, vout, script_sig, sequence))
        n_out, pos = _read_varint(raw, pos)
        outputs: list[TxOut] = []
        for _ in range(n_out):
            satoshis = struct.unpack_from("<q", raw, pos)[0]
            pos += 8
            script_len, pos = _read_varint(raw, pos)
            script = raw[pos:pos + script_len]
            pos += script_len
            outputs.append(TxOut(satoshis, script))
        locktime = struct.unpack_from("<I", raw, pos)[0]
        pos += 4
        if pos != len(raw):
            raise ValueError(
                f"{len(raw) - pos} bytes de más al final de la tx"
            )
        return cls(version, inputs, outputs, locktime)

    def txid(self) -> str:
        """El txid: doble SHA-256 del cable, volteado para presentarlo."""
        digest = hashlib.sha256(hashlib.sha256(self.serialize()).digest())
        return digest.digest()[::-1].hex()

    # -------------------------------------------------------------- sighash
    def sighash(
        self, index: int, script_code: bytes,
        sighash_type: int = SIGHASH_ALL,
    ) -> bytes:
        """Los 32 bytes que firma ECDSA: doble SHA-256 del preimage.

        Implementa el algoritmo legacy completo (el de
        ``SignatureHash`` de Bitcoin Core, contra el que se
        validan los vectores de ``sighash.json``):

        * todo ``OP_CODESEPARATOR`` se borra del ``script_code``
          antes de firmar (``FindAndDelete`` — dos separadores
          concatenados cambiarían la firma);
        * ``SIGHASH_ANYONECANPAY`` (bit 0x80 del tipo): **solo**
          el input firmado va en el preimage, en la posición 0;
        * ``SIGHASH_NONE`` (base 2): no van outputs, y los
          sequences de los demás inputs van a cero;
        * ``SIGHASH_SINGLE`` (base 3): va solo el output del
          índice del input (los anteriores, nullos), y si el
          índice está fuera de los outputs el resultado es el
          hash especial "uno" (un solo bit encendido) — no un
          preimage;
        * cualquier otro tipo (los vectores de Core usan tipos
          aleatorios de 32 bits) se comporta como ALL.

        El preimage es la tx serializada con el scriptSig del
        input ``index`` reemplazado por ``script_code`` (para
        P2PKH: el script de bloqueo del UTXO que se gasta) y los
        scriptSig de los demás inputs vacíos, más el tipo de
        sighash al final.

        Devuelve los bytes **en orden interno** — eso es lo que
        firma :meth:`smcp.core.bsv_keys.Secp256k1KeyPair.sign`.
        Para la forma de presentación (la que comparan los
        vectores de Core), :meth:`sighash_hex`.
        """
        if not 0 <= index < len(self.inputs):
            raise ValueError(f"input {index} fuera de la tx")
        code = script_code.replace(
            bytes([OP_CODESEPARATOR]), b""
        )
        base = sighash_type & 0x1F
        hash_none = base == SIGHASH_NONE
        hash_single = base == SIGHASH_SINGLE
        # SIGHASH_SINGLE fuera de rango: el "uno" de Bitcoin,
        # un hash con un solo bit encendido. No hay preimage.
        if hash_single and index >= len(self.outputs):
            return bytes(31) + b"\x01"
        anyone_can_pay = bool(sighash_type & SIGHASH_ANYONECANPAY)
        out = bytearray(struct.pack("<i", self.version))
        inputs = (
            [self.inputs[index]] if anyone_can_pay
            else list(self.inputs)
        )
        out += varint(len(inputs))
        for pos, txin in enumerate(inputs):
            signed = pos == index if not anyone_can_pay else True
            out += bytes.fromhex(txin.prev_txid)[::-1]
            out += struct.pack("<I", txin.vout)
            if signed:
                out += varint(len(code)) + code
            else:
                out += varint(0)
            # NONE y SINGLE dejan libres los sequences de los
            # inputs que no se firman ("Let the others update").
            sequence = txin.sequence
            if not signed and (hash_none or hash_single):
                sequence = 0
            out += struct.pack("<I", sequence)
        # Outputs: NONE no lleva ninguno; SINGLE lleva solo
        # el del indice del input (los anteriores, nullos);
        # cualquier otro tipo lleva todos.
        if hash_none:
            n_out = 0
        elif hash_single:
            n_out = index + 1
        else:
            n_out = len(self.outputs)
        out += varint(n_out)
        if hash_none:
            pass  # ningun output
        elif hash_single:
            for _ in range(index):
                out += struct.pack("<q", 0) + varint(0)
            txout = self.outputs[index]
            out += struct.pack("<q", txout.satoshis)
            out += varint(len(txout.script)) + txout.script
        else:
            for txout in self.outputs:
                out += struct.pack("<q", txout.satoshis)
                out += varint(len(txout.script)) + txout.script
        out += struct.pack("<I", self.locktime)
        out += struct.pack("<i", sighash_type)
        return hashlib.sha256(
            hashlib.sha256(bytes(out)).digest()
        ).digest()

    def sighash_hex(
        self, index: int, script_code: bytes,
        sighash_type: int = SIGHASH_ALL,
    ) -> str:
        """El sighash en hex de presentación (volteado).

        Es la forma en que lo muestran los vectores de
        ``sighash.json`` de Bitcoin Core y los exploradores; **no**
        es lo que se firma.
        """
        return self.sighash(index, script_code, sighash_type)[::-1].hex()

    # ---------------------------------------------------------------- firmar
    def sign_input(
        self, index: int, key: "Secp256k1KeyPair", script_code: bytes,
    ) -> None:
        """Firma el input ``index`` (SIGHASH_ALL) y lo escribe.

        El scriptSig resultante es ``<sig DER + 0x01> <pubkey>`` —
        lo que gasta un P2PKH. La clave debe ser la que el UTXO
        paga: la firma no gasta nada por sí sola.
        """
        digest = self.sighash(index, script_code).hex()
        compact = key.sign(digest)  # 64 bytes r||s, low-S (BRC-220)
        der = der_encode(compact) + bytes([SIGHASH_ALL])
        self.inputs[index].script_sig = (
            push_data(der) + push_data(key.public_key)
        )


__all__ = [
    "Transaction", "TxIn", "TxOut",
    "SIGHASH_ALL", "SIGHASH_NONE", "SIGHASH_SINGLE",
    "SIGHASH_ANYONECANPAY",
    "OP_FALSE", "OP_0", "OP_1", "OP_2", "OP_3", "OP_4", "OP_5",
    "OP_IF", "OP_ENDIF", "OP_PUSHDATA1", "OP_PUSHDATA2", "OP_PUSHDATA4",
    "OP_CODESEPARATOR", "OP_DUP", "OP_HASH160", "OP_EQUALVERIFY",
    "OP_CHECKSIG",
    "varint", "push_data", "p2pkh_lock", "der_encode",
]
