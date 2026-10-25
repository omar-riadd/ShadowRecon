"""Pluggable proxy providers: Tor circuit rotation, rotating proxy pools, and direct connections."""
from __future__ import annotations

import asyncio
import logging
import random
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable, List, Optional
from urllib.parse import urlparse

from shadowrecon.core.tor import TorManager

log = logging.getLogger("shadowrecon.proxy")


class ProxyProvider(ABC):
    """Abstract base class for proxy routing and IP rotation."""

    @abstractmethod
    def get_proxy_url(self) -> str:
        """Return the active proxy URL (e.g. socks5://127.0.0.1:9050)."""
        pass

    @abstractmethod
    async def rotate(self) -> bool:
        """Rotate the exit IP or advance to the next proxy in the pool."""
        pass

    @abstractmethod
    async def health_check(self, timeout: float = 5.0) -> bool:
        """Probe the proxy for connectivity before launching intensive tasks."""
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifier for logging and reporting."""
        pass


class DirectProxyProvider(ProxyProvider):
    """Null proxy provider used when --no-proxy is set."""

    def get_proxy_url(self) -> str:
        return ""

    async def rotate(self) -> bool:
        return True

    async def health_check(self, timeout: float = 5.0) -> bool:
        return True

    @property
    def provider_name(self) -> str:
        return "direct"


class TorProxyProvider(ProxyProvider):
    """Routes traffic through a Tor SOCKS5 proxy and controls NEWNYM circuit rotations."""

    def __init__(self, tor_manager: TorManager, socks_url: str = "socks5://127.0.0.1:9050") -> None:
        self.tor_manager = tor_manager
        self.socks_url = socks_url

    def get_proxy_url(self) -> str:
        return self.socks_url

    async def rotate(self) -> bool:
        return await self.tor_manager.rotate()

    async def health_check(self, timeout: float = 5.0) -> bool:
        """Check if Tor SOCKS5 port is accepting TCP connections."""
        if self.tor_manager.dry_run:
            return True

        parsed = urlparse(self.socks_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 9050

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception as exc:
            log.warning("Tor SOCKS proxy health check failed at %s:%d: %s", host, port, exc)
            return False

    @property
    def provider_name(self) -> str:
        return "tor"


class ProxyPoolProvider(ProxyProvider):
    """Manages a pool of residential, datacenter, or API Gateway proxies."""

    def __init__(
        self,
        proxies: Iterable[str],
        strategy: str = "round_robin",
    ) -> None:
        self.proxies: List[str] = [p.strip() for p in proxies if p.strip()]
        if not self.proxies:
            raise ValueError("ProxyPoolProvider requires at least one proxy URL")
        self.strategy = strategy
        self._current_index: int = 0
        self._lock = asyncio.Lock()

    @classmethod
    def from_file(cls, path: Path, strategy: str = "round_robin") -> "ProxyPoolProvider":
        """Load proxy list from a file (one URL per line)."""
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        valid = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
        return cls(proxies=valid, strategy=strategy)

    def get_proxy_url(self) -> str:
        return self.proxies[self._current_index]

    async def rotate(self) -> bool:
        """Switch to another proxy in the pool."""
        async with self._lock:
            if len(self.proxies) <= 1:
                log.info("Proxy pool has only 1 proxy; rotation no-op")
                return True

            if self.strategy == "random":
                next_idx = self._current_index
                while next_idx == self._current_index and len(self.proxies) > 1:
                    next_idx = random.randint(0, len(self.proxies) - 1)
                self._current_index = next_idx
            else:  # round_robin
                self._current_index = (self._current_index + 1) % len(self.proxies)

            log.info("Rotated proxy pool to: %s (%d/%d)", self.get_proxy_url(), self._current_index + 1, len(self.proxies))
            return True

    async def health_check(self, timeout: float = 5.0) -> bool:
        """Check TCP connectivity for the current active proxy."""
        active = self.get_proxy_url()
        parsed = urlparse(active)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 8080)

        if not host:
            return False

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception as exc:
            log.warning("Proxy pool node %s health check failed: %s", active, exc)
            return False

    @property
    def provider_name(self) -> str:
        return f"pool({len(self.proxies)})"
