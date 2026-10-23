"""Dashboard TUI de SMCP (Textual).

Muestra el estado del nodo: VRAM contribuida, inferencias servidas,
sats acumulados, reputación y cadena de la malla.
"""
from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Static

from smcp.core.contrib import ContributionLedger, default_state_path


class SmcpDashboard(App):
    """Dashboard interactivo del nodo SMCP."""

    CSS = """
    Screen {
        layout: vertical;
    }
    #title {
        height: 3;
        content-align: center middle;
        text-style: bold;
    }
    #status {
        height: 5;
        border: solid green;
        padding: 1;
    }
    #peers {
        border: solid blue;
    }
    """

    BINDINGS = [  # noqa: RUF012
        ("q", "quit", "Salir"),
        ("r", "refresh", "Refrescar"),
    ]

    def __init__(self, state_path=None, mesh_id="smcp-local"):
        super().__init__()
        self.state_path = state_path
        self.mesh_id = mesh_id
        self.ledger = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("SMCP — Dashboard del nodo", id="title")
        yield Static("Cargando...", id="status")
        yield DataTable(id="peers")
        yield Footer()

    def on_mount(self) -> None:
        self._load_ledger()
        self._refresh_status()
        self._refresh_peers()
        self.set_interval(5.0, self._refresh_all)

    def _load_ledger(self):
        from pathlib import Path
        path = self.state_path or default_state_path()
        if path.exists():
            try:
                self.ledger = ContributionLedger.load(str(path))
            except Exception:
                self.ledger = ContributionLedger(mesh_id=self.mesh_id)
        else:
            self.ledger = ContributionLedger(mesh_id=self.mesh_id)

    def _refresh_status(self):
        w = self.query_one("#status", Static)
        if self.ledger is None:
            w.update("Sin estado de malla.")
            return
        peers = self.ledger.admitted_peers(observed_only=False)
        vram = self.ledger.total_vram_gb(observed_only=False)
        inferences = sum(p.inferences_served for p in peers)
        sats = sum(p.satoshis_earned for p in peers)
        chain_ok = self.ledger.verify_chain()
        lines = [
            f"Malla: {self.mesh_id}  |  Cadena: {len(self.ledger)} entradas · {'íntegra' if chain_ok else 'ALTERADA'}",
            f"VRAM total: {vram:.1f}G  |  Nodos: {len(peers)}",
            f"Inferencias servidas: {inferences}  |  Sats acumulados: {sats}",
        ]
        w.update("\n".join(lines))

    def _refresh_peers(self):
        table = self.query_one("#peers", DataTable)
        table.clear(columns=True)
        table.add_columns("Nodo", "VRAM", "Ofrece", "Vivo", "Inferencias", "Sats")
        if self.ledger is None:
            return
        for p in self.ledger.admitted_peers(observed_only=False):
            table.add_row(
                p.peer_id[:20],
                f"{p.vram_gb:.1f}G",
                f"{p.vram_advertised_gb:.1f}G",
                "sí" if p.alive else "NO",
                str(p.inferences_served),
                str(p.satoshis_earned),
            )

    def _refresh_all(self):
        self._load_ledger()
        self._refresh_status()
        self._refresh_peers()

    def action_refresh(self):
        self._refresh_all()

    async def action_quit(self):
        self.exit()
