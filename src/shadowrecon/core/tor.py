"""Tor controller and circuit rotation manager."""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

try:
    from stem import Signal
    from stem.control import Controller
    _STEM_AVAILABLE = True
except ImportError:  # pragma: no cover
    _STEM_AVAILABLE = False

log = logging.getLogger("shadowrecon.tor")


class TorManager:
    """Manages Tor control port authentication and circuit rotation."""

    def __init__(
        self,
        control_port: int = 9051,
        control_password: str = "",
        socks_proxy: str = "socks5://127.0.0.1:9050",
        rotate_wait: int = 10,
        dry_run: bool = False,
    ) -> None:
        self.control_port = control_port
        self.control_password = control_password
        self.socks_proxy = socks_proxy
        self.rotate_wait = rotate_wait
        self.dry_run = dry_run

    @property
    def is_available(self) -> bool:
        return _STEM_AVAILABLE and bool(self.control_password)

    def rotate_circuit_sync(self) -> bool:
        """Synchronously request a new Tor identity (Signal.NEWNYM)."""
        if self.dry_run:
            log.info("[dry-run] would request a new Tor circuit (NEWNYM)")
            return True

        if not _STEM_AVAILABLE:
            log.warning("stem library not installed; cannot rotate Tor circuit")
            return False

        if not self.control_password:
            log.warning("no Tor control password configured; circuit rotation disabled")
            return False

        log.info("Requesting new Tor circuit from control port %d ...", self.control_port)
        try:
            with Controller.from_port(port=self.control_port) as controller:
                controller.authenticate(self.control_password)
                controller.signal(Signal.NEWNYM)
            log.info("Tor circuit rotation signal sent. Waiting %ds...", self.rotate_wait)
            return True
        except Exception as err:
            log.error("Tor circuit rotation failed: %s", err)
            return False

    async def rotate_circuit(self) -> bool:
        """Asynchronously request a new Tor identity without blocking event loop."""
        success = await asyncio.to_thread(self.rotate_circuit_sync)
        if success and not self.dry_run and self.rotate_wait > 0:
            await asyncio.sleep(self.rotate_wait)
        return success
