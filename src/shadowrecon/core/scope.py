"""Scope validation, CIDR matching, exclusions, and URL parsing helpers."""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from pathlib import Path
from typing import Iterable, List, Optional, Union
from urllib.parse import urlparse


def parse_target(url: str) -> str:
    """Validate an http(s) URL and return its hostname (apex/subdomain)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"invalid target URL: {url!r} (need http(s)://host/)")
    return parsed.hostname


def extract_host(url_or_host: str) -> str:
    """Extract canonical lowercased host or IP from a URL or raw string."""
    clean = url_or_host.strip()
    if "://" not in clean:
        clean = f"http://{clean}"
    try:
        return (urlparse(clean).hostname or clean.split("/")[0]).lower()
    except Exception:
        return clean.split("/")[0].lower()


class ScopeManager:
    """Evaluates targets against allowed domains, wildcards, CIDR blocks, and exclusions."""

    def __init__(
        self,
        domain: str = "",
        allowed: Optional[Iterable[str]] = None,
        exclude: Optional[Union[str, Iterable[str]]] = None,
    ) -> None:
        self.primary_domain = domain.strip().lower()
        self.allowed_domains: List[str] = [self.primary_domain] if self.primary_domain else []
        self.allowed_cidrs: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self.wildcard_patterns: List[str] = []

        self.exclude_patterns: List[str] = []
        self.exclude_cidrs: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []

        if allowed:
            for item in allowed:
                self._add_allowed_spec(item)

        if exclude:
            specs = [s.strip() for s in exclude.split(",")] if isinstance(exclude, str) else list(exclude)
            for spec in specs:
                self._add_exclude_spec(spec)

    def _add_allowed_spec(self, spec: str) -> None:
        clean = spec.strip().lower()
        if not clean:
            return
        if "/" in clean:
            try:
                net = ipaddress.ip_network(clean, strict=False)
                self.allowed_cidrs.append(net)
                return
            except ValueError:
                pass
        if "*" in clean or "?" in clean:
            self.wildcard_patterns.append(clean)
        else:
            self.allowed_domains.append(clean)

    def _add_exclude_spec(self, spec: str) -> None:
        clean = spec.strip().lower()
        if not clean:
            return
        if "/" in clean:
            try:
                net = ipaddress.ip_network(clean, strict=False)
                self.exclude_cidrs.append(net)
                return
            except ValueError:
                pass
        self.exclude_patterns.append(clean)
        if not any(ch in clean for ch in ("*", "?")):
            # Also exclude subdomains of excluded domain
            self.exclude_patterns.append(f"*.{clean}")

    def is_in_scope(self, target: str) -> bool:
        """Verify whether a target URL, hostname, or IP address is strictly in-scope."""
        if not target:
            return False

        host = extract_host(target)
        if not host:
            return False

        # Parse host as IP if applicable
        ip_obj: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = None
        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError:
            pass

        # 1. Check Exclusions First
        for pat in self.exclude_patterns:
            if fnmatch.fnmatch(host, pat):
                return False

        if ip_obj and self.exclude_cidrs:
            for net in self.exclude_cidrs:
                if ip_obj in net:
                    return False

        # 2. Check Allowed CIDRs if target is an IP
        if ip_obj and self.allowed_cidrs:
            for net in self.allowed_cidrs:
                if ip_obj in net:
                    return True

        # 3. Check Allowed Wildcard Patterns
        for pat in self.wildcard_patterns:
            if fnmatch.fnmatch(host, pat):
                return True

        # 4. Check Allowed Domains
        for dom in self.allowed_domains:
            if host == dom or host.endswith("." + dom):
                return True

        return False


def in_scope(url: str, domain: str, exclude: str = "") -> bool:
    """Verify that a target URL or hostname belongs to the authorized domain or its subdomains.

    Strict guardrail used to prevent requests escaping to third-party endpoints.
    """
    mgr = ScopeManager(domain=domain, exclude=exclude)
    return mgr.is_in_scope(url)


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
