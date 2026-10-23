"""TUI (Text User Interface) para SMCP, basada en Textual.

Es una dependencia opcional (``smcp[tui]``). Si Textual no está instalado,
el módulo se puede importar pero lanzar la app falla con un mensaje claro.
"""
from __future__ import annotations

try:
    import textual  # noqa: F401
    _TEXTUAL_AVAILABLE = True
except ImportError:  # pragma: no cover - depende del entorno
    _TEXTUAL_AVAILABLE = False


def available() -> bool:
    """True si Textual está instalado."""
    return _TEXTUAL_AVAILABLE


def run_dashboard() -> int:
    """Lanza el dashboard TUI. Devuelve 0 si ok, 1 si Textual falta."""
    if not _TEXTUAL_AVAILABLE:
        print("error: Textual no está instalado. Instala con: pip install smcp[tui]",
              file=__import__("sys").stderr)
        return 1
    from smcp.tui.dashboard import SmcpDashboard
    app = SmcpDashboard()
    app.run()
    return 0


def run_onboarding() -> int:
    """Lanza el flujo de onboarding TUI."""
    if not _TEXTUAL_AVAILABLE:
        print("error: Textual no está instalado. Instala con: pip install smcp[tui]",
              file=__import__("sys").stderr)
        return 1
    from smcp.tui.onboarding import SmcpOnboarding
    app = SmcpOnboarding()
    app.run()
    return 0


__all__ = ["available", "run_dashboard", "run_onboarding"]
