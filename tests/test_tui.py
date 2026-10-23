"""Tests del TUI (Textual, dependencia opcional)."""
from __future__ import annotations

import pytest

from smcp.tui import available


def test_tui_available():
    """Textual está instalado en el entorno de desarrollo."""
    assert available() is True


def test_dashboard_imports():
    """El dashboard se puede importar sin error."""
    from smcp.tui.dashboard import SmcpDashboard
    assert SmcpDashboard is not None


def test_onboarding_imports():
    """El onboarding se puede importar sin error."""
    from smcp.tui.onboarding import SmcpOnboarding
    assert SmcpOnboarding is not None
