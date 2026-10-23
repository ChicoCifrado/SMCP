"""Onboarding TUI para SMCP (Textual).

Flujo interactivo de primer arranque: generar claves, unirse a la malla.
"""
from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, Footer, Header, Input, Static


class SmcpOnboarding(App):
    """Flujo de onboarding interactivo."""

    CSS = """
    Screen { layout: vertical; }
    #welcome { height: 3; content-align: center middle; text-style: bold; }
    #form { padding: 1; border: solid green; }
    """

    BINDINGS = [("q", "quit", "Salir")]  # noqa: RUF012

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("SMCP — Onboarding", id="welcome")
        yield Vertical(
            Static("Bienvenido. Vamos a configurar tu nodo."),
            Input(placeholder="Peer ID (default: local)", id="peer_id"),
            Input(placeholder="VRAM física (GB)", id="vram"),
            Button("Comenzar", id="start"),
            id="form",
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            peer_id = self.query_one("#peer_id", Input).value or "local"
            vram = self.query_one("#vram", Input).value or "0"
            self.exit((peer_id, vram))

    async def action_quit(self):
        self.exit(None)
