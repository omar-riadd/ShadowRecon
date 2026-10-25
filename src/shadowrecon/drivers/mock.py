"""Synthetic mock scanner drivers for testing and CI environments."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional

from shadowrecon.drivers.base import ScanResult, ScannerDriver
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import FindingRecord, HostRecord


class MockScannerDriver(ScannerDriver):
    """Synthetic scanner driver for headless CI testing without external tool dependencies."""

    def __init__(
        self,
        name: str,
        binary_name: str = "mock",
        synthetic_items: Optional[List[Any]] = None,
        should_succeed: bool = True,
        delay: float = 0.0,
        output_file_name: Optional[str] = None,
    ) -> None:
        super().__init__(name=name, binary_name=binary_name)
        self.synthetic_items = synthetic_items or []
        self.should_succeed = should_succeed
        self.delay = delay
        self.output_file_name = output_file_name
        self.executed_contexts: List[StageContext] = []

    def is_available(self) -> bool:
        """Mock drivers are always available in test environments."""
        return True

    async def execute(self, ctx: StageContext, **kwargs: Any) -> ScanResult:
        """Simulate scanner execution, writing synthetic artifacts into session and outdir."""
        self.executed_contexts.append(ctx)

        if self.delay > 0:
            await asyncio.sleep(self.delay)

        if not self.should_succeed:
            return ScanResult(
                success=False,
                error=f"Mock driver '{self.name}' simulated execution failure",
            )

        output_files: List[Path] = []
        if self.output_file_name:
            out_file = ctx.config.outdir / self.output_file_name
            out_file.parent.mkdir(parents=True, exist_ok=True)
            lines = [str(item) for item in self.synthetic_items]
            out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            output_files.append(out_file)

        # Ingest into store based on item types
        for item in self.synthetic_items:
            if isinstance(item, FindingRecord):
                ctx.store.add_finding(item)
                await ctx.bus.publish("finding", item, source=self.name)
            elif isinstance(item, HostRecord):
                ctx.store.add_hosts([item])
                await ctx.bus.publish("host", item, source=self.name)
            elif isinstance(item, str) and item.startswith("http"):
                ctx.store.add_hosts([item])
            elif isinstance(item, str) and "." in item:
                ctx.store.add_subdomains([item], source=self.name)

        return ScanResult(
            success=True,
            output_files=output_files,
            items_count=len(self.synthetic_items),
            raw_output=f"Simulated execution for {len(self.synthetic_items)} items",
        )
