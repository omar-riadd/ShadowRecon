"""Abstract base class and execution results for pluggable scanner drivers."""
from __future__ import annotations

import logging
import os
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from shadowrecon.core.executor import resolve_binary
from shadowrecon.pipeline.runner import StageContext

log = logging.getLogger("shadowrecon.drivers")


@dataclass
class ScanResult:
    """Standardized result returned by a scanner driver execution."""
    success: bool
    output_files: List[Path] = field(default_factory=list)
    items_count: int = 0
    raw_output: str = ""
    error: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class ScannerDriver(ABC):
    """Abstract base class for all external scanner and reconnaissance tool drivers."""

    def __init__(self, name: str, binary_name: str) -> None:
        self.name = name
        self.binary_name = binary_name

    def is_available(self) -> bool:
        """Check whether the required driver binary is installed and executable."""
        resolved = resolve_binary(self.binary_name)
        if shutil.which(resolved):
            return True
        p = Path(resolved)
        return p.is_file() and os.access(p, os.X_OK)

    @abstractmethod
    async def execute(self, ctx: StageContext, **kwargs: Any) -> ScanResult:
        """Execute the scanner tool against the target in StageContext."""
        pass
