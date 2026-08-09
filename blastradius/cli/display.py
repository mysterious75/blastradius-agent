"""RichDisplay — rich terminal output helpers.

Colors: red=CONFIRMED, yellow=NEEDS_HUMAN, green=PATCHED, dim=FP/CANDIDATE.
"""

import sys
from contextlib import contextmanager
from typing import Dict, Iterable, List, Optional

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from blastradius.version import __version__ as VERSION

STATUS_STYLES = {
    "CONFIRMED": "bold red",
    "NEEDS_HUMAN": "bold yellow",
    "PATCHED": "bold green",
    "FP": "dim",
    "CANDIDATE": "dim",
    "PENDING": "dim",
}


def _get(obj, name: str, default=None):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


class RichDisplay:
    """Renders BlastRadius output with Rich."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console(file=sys.stdout)

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------

    def print_banner(self) -> None:
        banner = Panel(
            f"[bold red]🔴 BlastRadius Agent[/] v{VERSION}\nAutonomous Security Engineer",
            box=box.ROUNDED,
            border_style="red",
            padding=(1, 4),
        )
        self.console.print(banner)

    # ------------------------------------------------------------------
    # Findings table
    # ------------------------------------------------------------------

    def print_findings_table(self, findings: Iterable, statuses: Optional[Dict[int, str]] = None) -> None:
        table = Table(title="Findings", box=box.MINIMAL, expand=False)
        for header in ("File", "Line", "Type", "Confidence", "Severity", "Status"):
            table.add_column(header)
        for finding in findings:
            fid = _get(finding, "id", id(finding))
            status = (statuses or {}).get(fid, "CANDIDATE")
            style = STATUS_STYLES.get(status, "dim")
            table.add_row(
                _get(finding, "file", "?"),
                str(_get(finding, "line", "?")),
                _get(finding, "vuln_type", "?"),
                f"{float(_get(finding, 'confidence', 0.0)):.2f}",
                _get(finding, "severity", "?"),
                f"[{style}]{status}[/]",
            )
        self.console.print(table)

    # ------------------------------------------------------------------
    # Scan progress
    # ------------------------------------------------------------------

    @contextmanager
    def scan_progress(self, target: str, total: int = 100):
        progress = Progress(
            SpinnerColumn(),
            TextColumn(f"[bold cyan]Scanning {target}...[/]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("| {task.fields[files]} files"),
            TextColumn("| {task.fields[findings]} findings"),
            console=self.console,
        )
        with progress:
            task = progress.add_task("scan", total=total, files=0, findings=0)

            def update(files: int = 0, findings: int = 0, advance: int = 1) -> None:
                progress.update(task, advance=advance, files=files, findings=findings)

            yield update

    # ------------------------------------------------------------------
    # Patch diff
    # ------------------------------------------------------------------

    def print_patch_result(self, patch_result) -> None:
        diff = patch_result.patch.diff if patch_result and getattr(patch_result, "patch", None) else "(no patch available)"
        self.console.print(Syntax(diff, "diff", theme="monokai"))

    # ------------------------------------------------------------------
    # Stats panel
    # ------------------------------------------------------------------

    def print_stats_panel(self, stats: Dict) -> None:
        total = stats.get("total_scans", 0)
        confirmed = stats.get("confirmed_cves", stats.get("confirmed", 0))
        patches = stats.get("patches_generated", stats.get("patches", 0))
        rate = stats.get("success_rate", 0)
        body = Group(
            Text.from_markup(
                f"[bold red]{total}[/] Total Scans    "
                f"[bold red]{confirmed}[/] Confirmed CVEs\n"
                f"[bold green]{patches}[/] Patches    "
                f"[bold yellow]{rate}%[/] Success Rate"
            )
        )
        self.console.print(Panel(body, title="Stats", border_style="red"))

    # ------------------------------------------------------------------
    # Provider table
    # ------------------------------------------------------------------

    def print_provider_table(self, providers: Iterable) -> None:
        table = Table(title="Providers", box=box.MINIMAL)
        for header in ("Provider", "Models", "Status", "Latency"):
            table.add_column(header)
        for p in providers:
            ok = p.get("ok")
            mark = "✅" if ok else "❌"
            table.add_row(
                f"{mark} {p.get('provider', '?')}",
                p.get("model", "—"),
                p.get("status", "?"),
                p.get("latency", "—"),
            )
        self.console.print(table)

    # ------------------------------------------------------------------
    # Generic table
    # ------------------------------------------------------------------

    def print_table(self, headers: List[str], rows: Iterable, title: Optional[str] = None) -> None:
        table = Table(title=title, box=box.MINIMAL, expand=False)
        for header in headers:
            table.add_column(header)
        for row in rows:
            table.add_row(*[str(cell) for cell in row])
        self.console.print(table)
