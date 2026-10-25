"""Terminal presentation: banner, log handler, summary table.

Uses `rich` when installed for colored output and a proper table; degrades to
clean ANSI otherwise, so the tool looks good with or without the extra dep.
"""
from __future__ import annotations

import logging
from typing import List, Tuple

try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.table import Table
    from rich.panel import Panel
    _RICH = True
    _console = Console()
except Exception:  # pragma: no cover - optional dependency
    _RICH = False
    _console = None

_ANSI = {"cyan": "\033[36m", "red": "\033[31m", "blue": "\033[34m",
         "dim": "\033[2m", "bold": "\033[1m", "reset": "\033[0m"}

_BANNER = r"""
  ____  _               _               ____
 / ___|| |__   __ _  __| | _____      _|  _ \ ___  ___ ___  _ __
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / |_) / _ \/ __/ _ \| '_ \
  ___) | | | | (_| | (_| | (_) \ V  V /|  _ <  __/ (_| (_) | | | |
 |____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_| \_\___|\___\___/|_| |_|
"""


def banner(version: str = "2.0") -> None:
    tag = f"authorized recon & vuln pipeline  -  v{version}"
    if _RICH:
        _console.print(f"[bold red]{_BANNER}[/]")
        _console.print(Panel.fit(tag, border_style="cyan"))
    else:
        c = _ANSI
        print(f"{c['red']}{c['bold']}{_BANNER}{c['reset']}")
        print(f"{c['cyan']}  {tag}{c['reset']}\n")


def log_handler(verbose: bool) -> logging.Handler:
    if _RICH:
        return RichHandler(console=_console, rich_tracebacks=True,
                           show_path=False, markup=False)
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s",
                                     datefmt="%H:%M:%S"))
    return h


def summary_table(rows: List[Tuple[str, int]], title: str = "Run summary") -> None:
    """rows: list of (label, count)."""
    if _RICH:
        t = Table(title=title, header_style="bold cyan", border_style="dim")
        t.add_column("Stage / artifact")
        t.add_column("Count", justify="right")
        for label, count in rows:
            style = "red" if count and ("XSS" in label or "takeover" in label.lower()
                                        or "SQLi" in label) else None
            t.add_row(label, str(count), style=style)
        _console.print(t)
    else:
        c = _ANSI
        print(f"\n{c['bold']}{title}{c['reset']}")
        print(f"{c['dim']}{'-'*44}{c['reset']}")
        for label, count in rows:
            print(f"  {label:<34}{count:>6}")
        print(f"{c['dim']}{'-'*44}{c['reset']}")
