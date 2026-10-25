"""Pipeline stage runner with isolated error handling, stage filtering, and resume."""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

from shadowrecon.config import BypassContext, Config
from shadowrecon.core.executor import AsyncExecutor
from shadowrecon.core.tor import TorManager
from shadowrecon.pipeline.queue import AsyncEventBus
from shadowrecon.storage.session import SessionStore

log = logging.getLogger("shadowrecon.pipeline")


class PipelineExecutionError(Exception):
    """Raised when a required pipeline stage fails."""
    pass


def should_run_stage(stage_name: str, stages_spec: str = "all", skip_spec: str = "") -> bool:
    """Determine if a stage should run based on include and skip specs.

    Args:
        stage_name: The name of the stage (case-insensitive).
        stages_spec: 'all' or comma-separated list of stages to include.
        skip_spec: Comma-separated list of stages to exclude.
    """
    clean_name = stage_name.strip().lower()

    # Parse skipped stages
    skipped: Set[str] = {
        s.strip().lower() for s in (skip_spec or "").split(",") if s.strip()
    }
    if clean_name in skipped:
        return False

    spec = (stages_spec or "all").strip().lower()
    if spec in ("", "all"):
        return True

    selected: Set[str] = {s.strip().lower() for s in spec.split(",") if s.strip()}
    return clean_name in selected


@dataclass
class StageResult:
    name: str
    status: str  # "completed", "failed", "skipped", "resumed"
    duration_seconds: float = 0.0
    error_message: str = ""

    @property
    def success(self) -> bool:
        return self.status in ("completed", "resumed")


@dataclass
class StageContext:
    config: Config
    store: SessionStore
    executor: AsyncExecutor
    bus: AsyncEventBus
    tor: TorManager
    bypass_context: BypassContext
    rate_limiter: Optional[Any] = None
    proxy_provider: Optional[Any] = None
    circuit_breaker: Optional[Any] = None
    scope: Optional[Any] = None
    drivers: Optional[Any] = None

    def __post_init__(self) -> None:
        if self.drivers is None:
            from shadowrecon.drivers.registry import global_registry
            self.drivers = global_registry

    def is_in_scope(self, target: str) -> bool:
        """Check if target is in-scope according to active ScopeManager or domain."""
        if self.scope:
            return self.scope.is_in_scope(target)
        from shadowrecon.core.scope import in_scope
        return in_scope(target, self.config.domain, getattr(self.config, "exclude", ""))


StageCallable = Callable[[StageContext], Coroutine[Any, Any, Any]]


@dataclass
class Stage:
    name: str
    description: str
    runner: StageCallable
    required: bool = False


class PipelineRunner:
    """Orchestrates sequential or event-streamed pipeline stages with fault isolation."""

    def __init__(
        self,
        on_stage_start: Optional[Callable[[str, str], None]] = None,
        on_stage_end: Optional[Callable[[StageResult], None]] = None,
    ) -> None:
        self._stages: List[Stage] = []
        self.on_stage_start = on_stage_start
        self.on_stage_end = on_stage_end

    def add_stage(
        self,
        name: str,
        description: str,
        runner: StageCallable,
        required: bool = False,
    ) -> None:
        """Register a stage in pipeline execution order."""
        self._stages.append(Stage(name=name, description=description, runner=runner, required=required))

    async def run(self, ctx: StageContext) -> Dict[str, StageResult]:
        """Execute registered stages according to configuration and resume state."""
        results: Dict[str, StageResult] = {}

        for stage in self._stages:
            # 1. Check if skipped by --stages or --skip-stages
            if not should_run_stage(stage.name, ctx.config.stages, ctx.config.skip_stages):
                log.info("Stage '%s' skipped by stage filter", stage.name)
                res = StageResult(name=stage.name, status="skipped")
                results[stage.name] = res
                if self.on_stage_end:
                    self.on_stage_end(res)
                continue

            # 2. Check if already completed (instant resume)
            if not ctx.config.force_rerun and ctx.store.is_stage_completed(stage.name):
                log.info("Stage '%s' already completed in session, skipping (use --force-rerun to override)", stage.name)
                res = StageResult(name=stage.name, status="resumed")
                results[stage.name] = res
                if self.on_stage_end:
                    self.on_stage_end(res)
                continue

            # 3. Notify stage starting
            if self.on_stage_start:
                self.on_stage_start(stage.name, stage.description)

            ctx.store.set_stage(stage.name, status="running")
            start_time = time.perf_counter()

            try:
                log.info("Starting stage '%s': %s", stage.name, stage.description)
                await stage.runner(ctx)
                duration = round(time.perf_counter() - start_time, 2)
                ctx.store.set_stage(stage.name, status="completed", duration=duration)
                res = StageResult(name=stage.name, status="completed", duration_seconds=duration)
                results[stage.name] = res
                log.info("Stage '%s' completed in %.2fs", stage.name, duration)

            except (asyncio.CancelledError, KeyboardInterrupt) as exc:
                duration = round(time.perf_counter() - start_time, 2)
                ctx.store.set_stage(stage.name, status="interrupted", duration=duration, error="Interrupted by user or task cancellation")
                res = StageResult(
                    name=stage.name,
                    status="interrupted",
                    duration_seconds=duration,
                    error_message="Interrupted by user or task cancellation",
                )
                results[stage.name] = res
                if self.on_stage_end:
                    self.on_stage_end(res)
                try:
                    ctx.store.export_flat_artifacts(ctx.config.outdir)
                    log.info("Checkpoint: exported collected artifacts to %s", ctx.config.outdir)
                except Exception as flush_err:
                    log.warning("Failed to flush artifacts on interrupt: %s", flush_err)
                await ctx.bus.close()
                raise

            except Exception as exc:
                duration = round(time.perf_counter() - start_time, 2)
                err_str = str(exc)
                ctx.store.set_stage(stage.name, status="failed", duration=duration, error=err_str)
                res = StageResult(
                    name=stage.name,
                    status="failed",
                    duration_seconds=duration,
                    error_message=err_str,
                )
                results[stage.name] = res
                log.error("Stage '%s' failed after %.2fs: %s", stage.name, duration, exc, exc_info=True)

                if stage.required:
                    if self.on_stage_end:
                        self.on_stage_end(res)
                    await ctx.bus.close()
                    raise PipelineExecutionError(
                        f"Required stage '{stage.name}' failed: {err_str}"
                    ) from exc

            if self.on_stage_end:
                self.on_stage_end(res)

        # Close the event bus once pipeline completes
        await ctx.bus.close()
        return results
