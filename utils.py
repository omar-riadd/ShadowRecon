"""Pure, dependency-free helpers (stdlib only) so they stay unit-testable
without requests/stem installed."""
from __future__ import annotations

import re
from pathlib import Path
from typing import List
from urllib.parse import urlparse


def parse_target(url: str) -> str:
    """Validate an http(s) URL and return its hostname (apex/subdomain)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"invalid target URL: {url!r} (need http(s)://host/)")
    return parsed.hostname


def in_scope(url: str, domain: str) -> bool:
    """True only for the apex domain or its subdomains. Guardrail used to
    refuse crafted HTTP payloads aimed outside the authorized target."""
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    domain = domain.lower()
    return host == domain or host.endswith("." + domain)


def slugify(value: str, maxlen: int = 80) -> str:
    return re.sub(r"[^a-zA-Z0-9]", "_", value)[:maxlen]


def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def count_lines(path: Path) -> int:
    return len(read_lines(path))
