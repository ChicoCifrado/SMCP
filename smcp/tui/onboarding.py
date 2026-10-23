"""Onboarding TUI para SMCP (Textual).

Flujo interactivo de primer arranque: generar claves, unirse a la malla.
"""
from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, Footer, Header, Input, Static

from smcp.core.provenance import KeyPair
from smcp.core.contrib import default_identity_path


class SmcpOnboarding(App):
    """Flujo de onboarding interactivo."""

    CSS = """
    Screen { layout: vertical; }
    #welcome { height: 3; content-align: center middle; text-style: bold; }
    #form { padding: 1; border: solid green; }
    #result { padding: 1; border: solid blue; }
    """

    BINDINGS = [("q", "quit", "Salir")]  # noqa: RUF012

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("SMCP — Onboarding", id="welcome")
        yield Vertical(
            Static("Bienvenido. Vamos a configurar tu nodo."),
            Input(placeholder="Peer ID (default: local)", id="peer_id"),
            Input(placeholder="VRAM física (GB, default: 0)", id="vram"),
            Button("Comenzar", id="start"),
            Static("", id="result"),
            id="form",
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            peer_id = self.query_one("#peer_id", Input).value.strip() or "local"
            vram = self.query_one("#vram", Input).value.strip() or "0"
            try:
                vram_gb = float(vram)
            except ValueError:
                vram_gb = 0.0
            # generar identidad
            key = KeyPair.new(peer_id, "ed25519")
            ident_path = default_identity_path()
            ident_path.parent.mkdir(parents=True, exist_ok=True)
            key.save(str(ident_path))
            result = self.query_one("#result", Static)
            result.update(
                f"Identidad creada: {ident_path}\n"
                f"Peer ID: {peer_id}\n"
                f"Clave pública: {key.public_key.hex()[:16]}…\n"
                f"VRAM: {vram_gb}G\n"
                f"Próximo paso: smcp mesh contribute --vram-gb {vram_gb}"
            )

    async def action_quit(self):
        self.exit(None)

