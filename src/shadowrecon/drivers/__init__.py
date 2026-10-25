"""Pluggable scanner drivers and mock abstractions for ShadowRecon."""
from shadowrecon.drivers.base import ScanResult, ScannerDriver
from shadowrecon.drivers.mock import MockScannerDriver
from shadowrecon.drivers.registry import DriverRegistry, global_registry, register_defaults
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

__all__ = [
    "AmassDriver",
    "AssetfinderDriver",
    "DalfoxDriver",
    "DriverRegistry",
    "GauDriver",
    "HttpxDriver",
    "KatanaDriver",
    "MockScannerDriver",
    "NucleiDriver",
    "ParamspiderDriver",
    "ScanResult",
    "ScannerDriver",
    "SqlmapDriver",
    "SubfinderDriver",
    "Sublist3rDriver",
    "WaybackDriver",
    "global_registry",
    "register_defaults",
]
