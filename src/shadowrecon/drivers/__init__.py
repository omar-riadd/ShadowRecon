"""Pluggable scanner drivers and mock abstractions for ShadowRecon."""
from shadowrecon.drivers.base import ScanResult, ScannerDriver
from shadowrecon.drivers.mock import MockScannerDriver
from shadowrecon.drivers.registry import DriverRegistry, global_registry

__all__ = [
    "DriverRegistry",
    "MockScannerDriver",
    "ScanResult",
    "ScannerDriver",
    "global_registry",
]
