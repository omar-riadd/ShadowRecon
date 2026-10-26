"""Unit tests for Phase 5: Progressive Stage Streaming & Concurrency Controls."""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from shadowrecon.cli import build_parser
from shadowrecon.config import BypassContext, Config, TOML_SCHEMA, validate_toml_config
from shadowrecon.core.executor import AsyncExecutor, ProcessResult
from shadowrecon.core.scope import ScopeManager
from shadowrecon.core.tor import TorManager
from shadowrecon.drivers.base import ScanResult, ScannerDriver
from shadowrecon.drivers.registry import DriverRegistry
from shadowrecon.drivers.tools import HttpxDriver
from shadowrecon.modules.recon import (
    consume_live_hosts_stream,
    run_probing_stage,
    run_progressive_recon,
    run_subdomains_stage,
    run_urls_stage,
)
from shadowrecon.pipeline.queue import AsyncEventBus, Event
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import HostRecord, SessionStore


class TestConfigConcurrency(unittest.TestCase):
    def test_config_concurrency_defaults_and_override(self) -> None:
        cfg = Config(
            target="https://example.com",
            domain="example.com",
            wordlist=Path("/tmp/wl.txt"),
            outdir=Path("/tmp/out"),
            concurrency=5,
        )
        self.assertEqual(cfg.concurrency, 5)

    def test_config_concurrency_safe_mode_clamp(self) -> None:
        cfg = Config(
            target="https://example.com",
            domain="example.com",
            wordlist=Path("/tmp/wl.txt"),
            outdir=Path("/tmp/out"),
            concurrency=5,
            safe_mode=True,
        )
        # Clamped to 1 by safe_mode
        self.assertEqual(cfg.concurrency, 1)

    def test_toml_schema_validation_concurrency(self) -> None:
        self.assertIn("concurrency", TOML_SCHEMA)
        valid = validate_toml_config({"concurrency": 4})
        self.assertEqual(valid["concurrency"], 4)

        with self.assertRaises(Exception):
            validate_toml_config({"concurrency": 0})

    def test_cli_parser_concurrency_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-u", "https://example.com", "-w", "w.txt", "--concurrency", "8"])
        self.assertEqual(args.concurrency, 8)


class TestStreamingAndConcurrency(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.tmp_dir.name) / "out"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.out_dir / "session.db"
        self.store = SessionStore(self.db_path)
        self.bus = AsyncEventBus()
        self.registry = DriverRegistry()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _make_context(self, concurrency: int = 3, safe_mode: bool = False) -> StageContext:
        cfg = Config(
            target="https://example.com",
            domain="example.com",
            wordlist=Path(self.tmp_dir.name) / "wl.txt",
            outdir=self.out_dir,
            dry_run=True,
            concurrency=concurrency,
            safe_mode=safe_mode,
        )
        executor = AsyncExecutor(socks_proxy="", use_proxy=False, dry_run=True)
        tor = TorManager(dry_run=True)
        return StageContext(
            config=cfg,
            store=self.store,
            executor=executor,
            bus=self.bus,
            tor=tor,
            bypass_context=BypassContext(),
            drivers=self.registry,
            scope=ScopeManager(domain="example.com"),
        )

    def test_httpx_publishes_host_live_events(self) -> None:
        async def run_test() -> None:
            ctx = self._make_context()
            self.store.add_subdomains(["sub1.example.com", "sub2.example.com"])
            driver = HttpxDriver()

            received_live: list[str] = []
            q = self.bus.subscribe("host_live")

            async def collector() -> None:
                while True:
                    item = await q.get()
                    if item is None:
                        break
                    received_live.append(item.data)

            collector_task = asyncio.create_task(collector())

            async def fake_run(cmd, **kwargs):
                return ProcessResult(
                    returncode=0,
                    stdout="https://sub1.example.com\nhttps://sub2.example.com\n",
                    stderr="",
                    command=cmd,
                )

            ctx.executor.run = AsyncMock(side_effect=fake_run)
            res = await driver.execute(ctx)
            await self.bus.close_topic("host_live")
            await collector_task

            self.assertTrue(res.success)
            self.assertEqual(len(received_live), 2)
            self.assertIn("https://sub1.example.com", received_live)
            self.assertIn("https://sub2.example.com", received_live)

        asyncio.run(run_test())

    def test_run_probing_stage_streaming(self) -> None:
        async def run_test() -> None:
            ctx = self._make_context()
            mock_probing_driver = MagicMock(spec=ScannerDriver)
            mock_probing_driver.name = "httpx"
            mock_probing_driver.is_available.return_value = True

            async def mock_execute(c, **kwargs):
                c.store.add_hosts([
                    HostRecord(url="https://app.example.com", status_code=200),
                    HostRecord(url="https://api.example.com", status_code=200),
                ])
                return ScanResult(success=True, items_count=2)

            mock_probing_driver.execute = AsyncMock(side_effect=mock_execute)
            self.registry.register("probing", mock_probing_driver, is_default=True)

            streamed_hosts: list[str] = []

            async def on_host(host: str) -> None:
                streamed_hosts.append(host)

            q = ctx.bus.subscribe("host_live")
            consumer_task = asyncio.create_task(consume_live_hosts_stream(ctx, on_host, queue=q))
            hosts = await run_probing_stage(ctx)
            await consumer_task


            self.assertEqual(len(hosts), 2)
            self.assertEqual(len(streamed_hosts), 2)
            self.assertIn("https://app.example.com", streamed_hosts)
            self.assertIn("https://api.example.com", streamed_hosts)

        asyncio.run(run_test())

    def test_run_urls_stage_concurrent_execution(self) -> None:
        async def run_test() -> None:
            ctx = self._make_context(concurrency=3)
            ctx.config.driver_urls = "driver_a,driver_b,driver_c"

            active_concurrent = 0
            max_concurrent = 0

            def make_driver(name: str, discovered: list[str]) -> ScannerDriver:
                d = MagicMock(spec=ScannerDriver)
                d.name = name
                d.is_available.return_value = True

                async def execute(c, **kwargs):
                    nonlocal active_concurrent, max_concurrent
                    active_concurrent += 1
                    max_concurrent = max(max_concurrent, active_concurrent)
                    await asyncio.sleep(0.02)
                    active_concurrent -= 1
                    return ScanResult(success=True, items_count=len(discovered), metadata={"urls": discovered})

                d.execute = AsyncMock(side_effect=execute)
                return d

            d_a = make_driver("driver_a", ["https://example.com/a?id=1"])
            d_b = make_driver("driver_b", ["https://example.com/b?key=secret"])
            d_c = make_driver("driver_c", ["https://example.com/c?val=test"])

            self.registry.register("urls", d_a)
            self.registry.register("urls", d_b)
            self.registry.register("urls", d_c)

            param_events: list[str] = []
            q = self.bus.subscribe("param_url")

            async def drain_param():
                while True:
                    ev = await q.get()
                    if ev is None:
                        break
                    param_events.append(ev.data)

            drain_task = asyncio.create_task(drain_param())
            urls = await run_urls_stage(ctx)
            await drain_task

            self.assertEqual(len(urls), 3)
            self.assertGreater(max_concurrent, 1)  # Verified concurrent execution
            self.assertEqual(len(param_events), 3)

        asyncio.run(run_test())

    def test_run_urls_stage_safe_mode_serial(self) -> None:
        async def run_test() -> None:
            ctx = self._make_context(concurrency=1, safe_mode=True)
            ctx.config.driver_urls = "driver_x,driver_y"

            active_concurrent = 0
            max_concurrent = 0

            def make_driver(name: str, discovered: list[str]) -> ScannerDriver:
                d = MagicMock(spec=ScannerDriver)
                d.name = name
                d.is_available.return_value = True

                async def execute(c, **kwargs):
                    nonlocal active_concurrent, max_concurrent
                    active_concurrent += 1
                    max_concurrent = max(max_concurrent, active_concurrent)
                    await asyncio.sleep(0.01)
                    active_concurrent -= 1
                    return ScanResult(success=True, items_count=len(discovered), metadata={"urls": discovered})

                d.execute = AsyncMock(side_effect=execute)
                return d

            d_x = make_driver("driver_x", ["https://example.com/x?p=1"])
            d_y = make_driver("driver_y", ["https://example.com/y?p=2"])
            self.registry.register("urls", d_x)
            self.registry.register("urls", d_y)

            urls = await run_urls_stage(ctx)
            self.assertEqual(len(urls), 2)
            self.assertEqual(max_concurrent, 1)  # Strictly serialized in safe-mode

        asyncio.run(run_test())

    def test_progressive_recon_streaming_execution(self) -> None:
        async def run_test() -> None:
            ctx = self._make_context(concurrency=2)
            ctx.config.driver_urls = "driver_stream"

            # Mock probing driver that emits 2 hosts
            mock_probing = MagicMock(spec=ScannerDriver)
            mock_probing.name = "httpx"
            mock_probing.is_available.return_value = True

            async def fake_probing(c, **kwargs):
                c.store.add_hosts([
                    HostRecord(url="https://site1.example.com", status_code=200),
                    HostRecord(url="https://site2.example.com", status_code=200),
                ])
                return ScanResult(success=True, items_count=2)

            mock_probing.execute = AsyncMock(side_effect=fake_probing)
            self.registry.register("probing", mock_probing, is_default=True)

            # Mock crawler driver that extracts URL per host
            mock_crawler = MagicMock(spec=ScannerDriver)
            mock_crawler.name = "driver_stream"
            mock_crawler.is_available.return_value = True

            async def fake_crawler(c, live_file=None, **kwargs):
                host_line = live_file.read_text(encoding="utf-8").strip() if live_file and live_file.is_file() else ""
                discovered = [f"{host_line}/profile?id=99"] if host_line else []
                return ScanResult(success=True, items_count=len(discovered), metadata={"urls": discovered})

            mock_crawler.execute = AsyncMock(side_effect=fake_crawler)
            self.registry.register("urls", mock_crawler)

            live_hosts, urls = await run_progressive_recon(ctx)

            self.assertEqual(len(live_hosts), 2)
            self.assertEqual(len(urls), 2)
            self.assertIn("https://site1.example.com/profile?id=99", urls)
            self.assertIn("https://site2.example.com/profile?id=99", urls)

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
