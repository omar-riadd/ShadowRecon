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


# Global default registry instance
global_registry = DriverRegistry()
