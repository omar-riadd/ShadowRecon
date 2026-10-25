"""Driver registry for discovering and swapping pluggable scanner drivers."""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

from shadowrecon.drivers.base import ScannerDriver

log = logging.getLogger("shadowrecon.drivers.registry")


class DriverRegistry:
    """Manages available scanner drivers for different pipeline stages."""

    def __init__(self) -> None:
        self._drivers: Dict[str, Dict[str, ScannerDriver]] = {}
        self._active_driver: Dict[str, str] = {}

    def register(self, stage: str, driver: ScannerDriver, is_default: bool = False) -> None:
        """Register a scanner driver for a specific pipeline stage."""
        if stage not in self._drivers:
            self._drivers[stage] = {}

        self._drivers[stage][driver.name] = driver

        if is_default or stage not in self._active_driver:
            self._active_driver[stage] = driver.name

    def set_active(self, stage: str, driver_name: str) -> None:
        """Set the active driver for a stage by name."""
        if stage not in self._drivers or driver_name not in self._drivers[stage]:
            raise KeyError(f"Driver '{driver_name}' not registered for stage '{stage}'")
        self._active_driver[stage] = driver_name

    def get_driver(self, stage: str, driver_name: Optional[str] = None) -> ScannerDriver:
        """Retrieve the active driver or a specific driver by name for a stage."""
        if stage not in self._drivers:
            raise KeyError(f"No drivers registered for stage '{stage}'")

        selected = driver_name or self._active_driver.get(stage)
        if not selected or selected not in self._drivers[stage]:
            # Fallback to first available driver in stage
            return next(iter(self._drivers[stage].values()))

        return self._drivers[stage][selected]

    def list_drivers(self, stage: Optional[str] = None) -> Dict[str, List[str]]:
        """List all registered driver names, optionally filtered by stage."""
        if stage:
            return {stage: list(self._drivers.get(stage, {}).keys())}
        return {s: list(drivers.keys()) for s, drivers in self._drivers.items()}


def register_defaults(reg: DriverRegistry) -> None:
    """Register default concrete scanner drivers into the specified registry."""
    from shadowrecon.drivers.tools import (
        AmassDriver,
        AssetfinderDriver,
        DalfoxDriver,
        GauDriver,
        HttpxDriver,
        KatanaDriver,
        NucleiDriver,
        ParamspiderDriver,
        SqlmapDriver,
        SubfinderDriver,
        Sublist3rDriver,
        WaybackDriver,
    )

    # Subdomain discovery stage
    reg.register("subdomains", SubfinderDriver(), is_default=True)
    reg.register("subdomains", AssetfinderDriver())
    reg.register("subdomains", AmassDriver())
    reg.register("subdomains", Sublist3rDriver())

    # Probing & crawling stages
    reg.register("probing", HttpxDriver(), is_default=True)
    reg.register("crawling", KatanaDriver(), is_default=True)

    # URL gathering stage
    reg.register("urls", WaybackDriver(), is_default=True)
    reg.register("urls", GauDriver())
    reg.register("urls", KatanaDriver())
    reg.register("urls", ParamspiderDriver())

    # Vulnerability scanning stages
    reg.register("nuclei", NucleiDriver(), is_default=True)
    reg.register("xss", DalfoxDriver(), is_default=True)
    reg.register("sqli", SqlmapDriver(), is_default=True)


# Global default registry instance populated with default concrete tools
global_registry = DriverRegistry()
register_defaults(global_registry)
