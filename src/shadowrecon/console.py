"""Terminal presentation: banner, log handler, status cards, and summary table.

Uses `rich` when installed for colored output, panels, and tables; degrades to
clean ANSI formatting otherwise, ensuring robust display across all environments.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.panel import Panel
    from rich.table import Table
    _RICH = True
    _console = Console()
except Exception:  # pragma: no cover - optional dependency
    _RICH = False
    _console = None

_ANSI = {
    "cyan": "\033[36m",
    "red": "\033[31m",
    "blue": "\033[34m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}

_BANNER = r"""
  ____  _               _               ____
 / ___|| |__   __ _  __| | _____      _|  _ \ ___  ___ ___  _ __
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / |_) / _ \/ __/ _ \| '_ \
  ___) | | | | (_| | (_| | (_) \ V  V /|  _ <  __/ (_| (_) | | | |
 |____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_| \_\___|\___\___/|_| |_|
"""


def banner(version: str = "3.3") -> None:
    """Print the ShadowRecon ASCII banner with optional Rich formatting."""
    tag = f"authorized recon & vuln pipeline  -  v{version}"
    if _RICH:
        _console.print(f"[bold red]{_BANNER}[/]")
        _console.print(Panel.fit(tag, border_style="cyan"))
    else:
        c = _ANSI
        print(f"{c['red']}{c['bold']}{_BANNER}{c['reset']}")
        print(f"{c['cyan']}  {tag}{c['reset']}\n")


def log_handler(verbose: bool) -> logging.Handler:
    """Return an appropriate logging handler (RichHandler or StreamHandler)."""
    if _RICH:
        return RichHandler(
            console=_console,
            rich_tracebacks=True,
            show_path=False,
            markup=False,
        )
    h = logging.StreamHandler()
    h.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-7s %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    return h


def summary_table(rows: List[Tuple[str, int]], title: str = "Run summary") -> None:
    """Print a summary table of stage results or counts."""
    if _RICH:
        t = Table(title=title, header_style="bold cyan", border_style="dim")
        t.add_column("Stage / artifact")
        t.add_column("Count", justify="right")
        for label, count in rows:
            style = "red" if count and ("XSS" in label or "takeover" in label.lower() or "SQLi" in label) else None
            t.add_row(label, str(count), style=style)
        _console.print(t)
    else:
        c = _ANSI
        print(f"\n{c['bold']}{title}{c['reset']}")
        print(f"{c['dim']}{'-'*44}{c['reset']}")
        for label, count in rows:
            print(f"  {label:<34}{count:>6}")
        print(f"{c['dim']}{'-'*44}{c['reset']}")


def format_status_card(
    target: str,
    domain: str,
    proxy_name: str,
    proxy_url: str,
    cb_stats: Optional[Dict[str, Any]] = None,
    stage_durations: Optional[Dict[str, float]] = None,
    findings_count: int = 0,
) -> str:
    """Generate a formatted terminal status card for real-time observability."""
    lines: List[str] = [
        "==================================================",
        f" ShadowRecon Runtime Status — {domain}",
        "==================================================",
        f" Target URL       : {target}",
        f" Proxy Provider   : {proxy_name} ({proxy_url or 'direct'})",
    ]

    if cb_stats:
        healthy = cb_stats.get("healthy_hosts", 0)
        tripped = cb_stats.get("tripped_hosts", 0)
        probing = cb_stats.get("probing_hosts", 0)
        lines.append(f" Circuit Breaker  : {healthy} Healthy | {tripped} Tripped | {probing} Probing")
        tripped_list = cb_stats.get("tripped_list", [])
        if tripped_list:
            lines.append(f" Tripped Hosts    : {', '.join(tripped_list)}")

    if stage_durations:
        total_time = sum(stage_durations.values())
        completed_stages = len(stage_durations)
        lines.append(f" Stages Executed  : {completed_stages} stages (Total: {total_time:.2f}s)")

    lines.append(f" Findings Recorded: {findings_count}")
    lines.append("==================================================")
    return "\n".join(lines)


def print_status_card(
    target: str,
    domain: str,
    proxy_name: str,
    proxy_url: str,
    cb_stats: Optional[Dict[str, Any]] = None,
    stage_durations: Optional[Dict[str, float]] = None,
    findings_count: int = 0,
) -> None:
    """Print the runtime status card to the terminal."""
    card = format_status_card(
        target=target,
        domain=domain,
        proxy_name=proxy_name,
        proxy_url=proxy_url,
        cb_stats=cb_stats,
        stage_durations=stage_durations,
        findings_count=findings_count,
    )
    if _RICH:
        _console.print(Panel(card, title="Runtime Observability", border_style="blue"))
    else:
        print("\n" + card + "\n")
