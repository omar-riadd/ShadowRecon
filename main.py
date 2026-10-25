#!/usr/bin/env python3
"""
ShadowRecon — Authorized Web-Application Reconnaissance & Vulnerability Pipeline.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional, Sequence

# Ensure local src/ is accessible
src_dir = Path(__file__).resolve().parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from shadowrecon.cli import async_main, main
from shadowrecon.config import BypassContext, Config
from shadowrecon.core.executor import resolve_binary


def resolve_httpx() -> str:
    """Backward-compatible helper resolving httpx binary."""
    return resolve_binary("httpx")


def run_paramspider(cfg: Config, live_file: Path, out_file: Path) -> None:
    """Backward-compatible helper for ParamSpider file handling."""
    from shadowrecon.core.scope import in_scope, read_lines
    results_dir = Path("results")
    if live_file.is_file():
        hosts = read_lines(live_file)
        for host in hosts:
            domain = re.sub(r"^https?://", "", host).lower().strip().rstrip("/")
            pf = results_dir / f"{domain}.txt"
            if pf.exists():
                lines = [
                    line.strip()
                    for line in read_lines(pf)
                    if "=" in line and line.startswith("http") and in_scope(line, cfg.domain)
                ]
                if lines:
                    existing = read_lines(out_file) if out_file.exists() else []
                    out_file.write_text("\n".join(existing + lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
