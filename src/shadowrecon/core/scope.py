"""Scope validation and URL parsing helpers (stdlib only, pure functions)."""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse


def parse_target(url: str) -> str:
    """Validate an http(s) URL and return its hostname (apex/subdomain)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"invalid target URL: {url!r} (need http(s)://host/)")
    return parsed.hostname


def in_scope(url: str, domain: str) -> bool:
    """Verify that a target URL or hostname belongs to the authorized domain or its subdomains.

    Strict guardrail used to prevent requests escaping to third-party endpoints.
    """
    try:
        clean = url.strip()
        if "://" not in clean:
            clean = f"http://{clean}"
        host = (urlparse(clean).hostname or "").lower()
    except ValueError:
        return False
    domain = domain.lower()
    return host == domain or host.endswith("." + domain)


is_in_scope = in_scope


def slugify(value: str, maxlen: int = 80) -> str:
    """Sanitize arbitrary strings (like URLs) into filesystem-safe filenames."""
    return re.sub(r"[^a-zA-Z0-9]", "_", value)[:maxlen]


def read_lines(path: Path) -> list[str]:
    """Read lines from a file, stripping whitespace and discarding empty lines."""
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def count_lines(path: Path) -> int:
    """Return non-empty line count of a file."""
    return len(read_lines(path))
