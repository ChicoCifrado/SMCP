"""Tests del **modo estricto** del provenance (issue #7).

El módulo :mod:`delm.core.provenance` soporta dos backends de firma:

* **ed25519** (asimétrica, real) — cuando ``cryptography`` está instalado.
* **HMAC-SHA256** (pre-shared key) — fallback cuando ``cryptography`` no está.

El **modo estricto** (``STRICT_MODE=True``, el default) hace que el pipeline
real **no degrade silenciosamente** a HMAC si ``cryptography`` falta:
``KeyPair.new()`` (``kind=None``) lanza ``RuntimeError`` en vez de crear una
clave HMAC sin que nadie lo note. El modo no-estricto (``STRICT_MODE=False``)
o ``allow_hmac_fallback=True`` permiten el fallback **con warning visible**
(para el modo de test/zero-deps).

Estos tests verifican:

* El modo estricto (default) lanza si no hay ed25519.
* El modo no-estricto degrada a HMAC **con warning visible**.
* ``allow_hmac_fallback=True`` degrada a HMAC con warning (aún en estricto).
* El modo estricto no rompe cuando ``cryptography`` SÍ está disponible.
"""

from __future__ import annotations

import importlib
import warnings

import pytest

import delm.core.provenance as provenance
from delm.core.provenance import KeyPair


# ---------------------------------------------------------------------------
# Helpers: simular que ``cryptography`` no está disponible
# ---------------------------------------------------------------------------
def _disable_cryptography(monkeypatch):
    """Hace que ``provenance.HAVE_ED25519`` sea ``False`` (simula sin ``cryptography``)."""
    monkeypatch.setattr(provenance, "HAVE_ED25519", False)


def _enable_cryptography(monkeypatch):
    """Hace que ``provenance.HAVE_ED25519`` sea ``True`` (simula con ``cryptography``)."""
    monkeypatch.setattr(provenance, "HAVE_ED25519", True)


# ---------------------------------------------------------------------------
# Modo estricto (default): lanza si no hay ed25519
# ---------------------------------------------------------------------------
def test_strict_mode_raises_without_ed25519(monkeypatch):
    """En modo estricto (default) y sin ``cryptography``, ``KeyPair.new()`` lanza."""
    _disable_cryptography(monkeypatch)
    # STRICT_MODE es True por default (el módulo lo define como True).
    assert provenance.STRICT_MODE is True
    with pytest.raises(RuntimeError, match="ed25519 no disponible.*modo estricto"):
        KeyPair.new("author-1")


def test_strict_mode_explicit_flag_raises_without_ed25519(monkeypatch):
    """Con ``STRICT_MODE=True`` explícito y sin ``cryptography``, ``KeyPair.new()`` lanza."""
    _disable_cryptography(monkeypatch)
    monkeypatch.setattr(provenance, "STRICT_MODE", True)
    with pytest.raises(RuntimeError, match="ed25519 no disponible"):
        KeyPair.new("author-2")


# ---------------------------------------------------------------------------
# Modo no-estricto: degrada a HMAC con warning visible
# ---------------------------------------------------------------------------
def test_non_strict_mode_falls_back_to_hmac_with_warning(monkeypatch):
    """Con ``STRICT_MODE=False`` y sin ``cryptography``, ``KeyPair.new()`` degrada a HMAC **con warning visible**."""
    _disable_cryptography(monkeypatch)
    monkeypatch.setattr(provenance, "STRICT_MODE", False)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        kp = KeyPair.new("author-3")
    # La clave SÍ se crea (fallback a HMAC).
    assert kp.kind == "hmac"
    assert kp.author_id == "author-3"
    # Y hay un warning visible (el fallback ya NO es silencioso).
    assert len(caught) >= 1
    assert any("HMAC" in str(w.message) for w in caught)


def test_allow_hmac_fallback_true_degrades_with_warning_even_in_strict(monkeypatch):
    """Con ``allow_hmac_fallback=True`` (aún en estricto), ``KeyPair.new()`` degrada a HMAC **con warning visible** (no lanza)."""
    _disable_cryptography(monkeypatch)
    monkeypatch.setattr(provenance, "STRICT_MODE", True)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        kp = KeyPair.new("author-4", allow_hmac_fallback=True)
    assert kp.kind == "hmac"
    assert kp.author_id == "author-4"
    assert len(caught) >= 1
    assert any("HMAC" in str(w.message) for w in caught)


# ---------------------------------------------------------------------------
# Modo estricto NO rompe cuando ``cryptography`` SÍ está disponible
# ---------------------------------------------------------------------------
def test_strict_mode_no_raise_when_ed25519_available(monkeypatch):
    """Con ``cryptography`` disponible, el modo estricto NO lanza (crea ed25519)."""
    _enable_cryptography(monkeypatch)
    # STRICT_MODE es True por default, pero ed25519 está disponible → no lanza.
    kp = KeyPair.new("author-5")
    assert kp.kind == "ed25519"
    assert kp.author_id == "author-5"


def test_explicit_ed25519_kind_still_works_in_strict(monkeypatch):
    """Con ``kind='ed25519'`` explícito y ``cryptography`` disponible, funciona en estricto."""
    _enable_cryptography(monkeypatch)
    monkeypatch.setattr(provenance, "STRICT_MODE", True)
    kp = KeyPair.new("author-6", kind="ed25519")
    assert kp.kind == "ed25519"


def test_explicit_hmac_kind_still_works_in_strict(monkeypatch):
    """Con ``kind='hmac'`` explícito, funciona en estricto (no es el fallback automático)."""
    _enable_cryptography(monkeypatch)
    monkeypatch.setattr(provenance, "STRICT_MODE", True)
    kp = KeyPair.new("author-7", kind="hmac")
    assert kp.kind == "hmac"


# ---------------------------------------------------------------------------
# La clave ed25519 y la hmac son funcionales (sign/verify)
# ---------------------------------------------------------------------------
def test_ed25519_key_signs_and_verifies(monkeypatch):
    """La clave ed25519 firma y verifica correctamente."""
    _enable_cryptography(monkeypatch)
    kp = KeyPair.new("author-8")
    assert kp.kind == "ed25519"
    digest = "abc123"
    sig = kp.sign(digest)
    assert kp.verify(digest, sig)
    # Un digest distinto no verifica.
    assert not kp.verify("xyz", sig)


def test_hmac_key_signs_and_verifies(monkeypatch):
    """La clave hmac firma y verifica correctamente."""
    _enable_cryptography(monkeypatch)
    kp = KeyPair.new("author-9", kind="hmac")
    assert kp.kind == "hmac"
    digest = "abc123"
    sig = kp.sign(digest)
    assert kp.verify(digest, sig)
    assert not kp.verify("xyz", sig)
