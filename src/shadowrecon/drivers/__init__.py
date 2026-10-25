"""Pluggable scanner drivers and mock abstractions for ShadowRecon."""
from shadowrecon.drivers.base import ScanResult, ScannerDriver
from shadowrecon.drivers.mock import MockScannerDriver
from shadowrecon.drivers.registry import DriverRegistry, global_registry, register_defaults
from shadowrecon.drivers.tools import (
    DalfoxDriver,
    HttpxDriver,
    KatanaDriver,
    NucleiDriver,
    SqlmapDriver,
    SubfinderDriver,
)

__all__ = [
    "DalfoxDriver",
    "DriverRegistry",
    "HttpxDriver",
    "KatanaDriver",
    "MockScannerDriver",
    "NucleiDriver",
    "ScanResult",
    "ScannerDriver",
    "SqlmapDriver",
    "SubfinderDriver",
    "global_registry",
    "register_defaults",
]
