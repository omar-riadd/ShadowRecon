"""Unit tests for Phase 2 comprehensive scanner drivers and multi-driver discovery."""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from shadowrecon.config import BypassContext, Config, validate_toml_config
from shadowrecon.core.executor import AsyncExecutor, ProcessResult
from shadowrecon.core.proxy import DirectProxyProvider
from shadowrecon.core.tor import TorManager
from shadowrecon.drivers import (
    AmassDriver,
    AssetfinderDriver,
    DriverRegistry,
    GauDriver,
    ParamspiderDriver,
    SubfinderDriver,
    Sublist3rDriver,
    WaybackDriver,
    global_registry,
    register_defaults,
)
from shadowrecon.modules.recon import run_subdomains_stage, run_urls_stage
from shadowrecon.pipeline.queue import AsyncEventBus
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import SessionStore


class TestPhase2DriversRegistration(unittest.TestCase):
    def test_registered_subdomain_and_url_drivers(self) -> None:
        drivers = global_registry.list_drivers()
        self.assertIn("subdomains", drivers)
        self.assertIn("subfinder", drivers["subdomains"])
        self.assertIn("assetfinder", drivers["subdomains"])
        self.assertIn("amass", drivers["subdomains"])
        self.assertIn("sublist3r", drivers["subdomains"])

        self.assertIn("urls", drivers)
        self.assertIn("wayback", drivers["urls"])
        self.assertIn("gau", drivers["urls"])
        self.assertIn("katana", drivers["urls"])
        self.assertIn("paramspider", drivers["urls"])


class TestPhase2DriverExecution(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.outdir = Path(self.temp_dir.name)
        self.db_path = self.outdir / "session.db"
        self.store = SessionStore(self.db_path)
        self.bus = AsyncEventBus()

        self.config = Config(
            target="https://example.com/",
            domain="example.com",
            wordlist=self.outdir / "wordlist.txt",
            outdir=self.outdir,
            dry_run=True,
        )

        self.executor = AsyncExecutor(dry_run=True)
        self.tor = TorManager(dry_run=True)
        self.bypass_ctx = BypassContext()
        self.proxy_provider = DirectProxyProvider()

        self.registry = DriverRegistry()
        register_defaults(self.registry)

        self.ctx = StageContext(
            config=self.config,
            store=self.store,
            executor=self.executor,
            bus=self.bus,
            tor=self.tor,
            bypass_context=self.bypass_ctx,
            proxy_provider=self.proxy_provider,
            drivers=self.registry,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_assetfinder_driver(self) -> None:
        async def run_test() -> None:
            driver = AssetfinderDriver()
            captured_cmd = []

            async def fake_run(cmd, **kwargs):
                captured_cmd.extend(cmd)
                return ProcessResult(
                    returncode=0,
                    stdout="api.example.com\ncdn.example.com\nexternal.org\n",
                    stderr="",
                    command=cmd,
                )

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            res = await driver.execute(self.ctx)

            self.assertTrue(res.success)
            self.assertEqual(captured_cmd[0], "assetfinder")
            self.assertIn("-subs-only", captured_cmd)
            stored = self.store.get_subdomains()
            self.assertIn("api.example.com", stored)
            self.assertIn("cdn.example.com", stored)
            self.assertNotIn("external.org", stored)

        asyncio.run(run_test())

    def test_amass_driver(self) -> None:
        async def run_test() -> None:
            driver = AmassDriver()
            captured_cmd = []

            async def fake_run(cmd, **kwargs):
                captured_cmd.extend(cmd)
                return ProcessResult(
                    returncode=0,
                    stdout="admin.example.com\ndb.example.com\n",
                    stderr="",
                    command=cmd,
                )

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            res = await driver.execute(self.ctx)

            self.assertTrue(res.success)
            self.assertEqual(captured_cmd[0], "amass")
            self.assertIn("enum", captured_cmd)
            stored = self.store.get_subdomains()
            self.assertIn("admin.example.com", stored)
            self.assertIn("db.example.com", stored)

        asyncio.run(run_test())

    def test_sublist3r_driver(self) -> None:
        async def run_test() -> None:
            driver = Sublist3rDriver()
            captured_cmd = []

            async def fake_run(cmd, **kwargs):
                captured_cmd.extend(cmd)
                out_file = self.outdir / "sublist3r_out.txt"
                out_file.write_text("beta.example.com\n", encoding="utf-8")
                return ProcessResult(returncode=0, stdout="", stderr="", command=cmd)

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            res = await driver.execute(self.ctx)

            self.assertTrue(res.success)
            self.assertEqual(captured_cmd[0], "sublist3r")
            stored = self.store.get_subdomains()
            self.assertIn("beta.example.com", stored)

        asyncio.run(run_test())

    def test_gau_driver(self) -> None:
        async def run_test() -> None:
            driver = GauDriver()
            captured_cmd = []

            async def fake_run(cmd, **kwargs):
                captured_cmd.extend(cmd)
                out_file = self.outdir / "gau.txt"
                out_file.write_text(
                    "https://example.com/item?id=123\nhttps://example.com/about\nhttps://evil.com/x?a=1\n",
                    encoding="utf-8",
                )
                return ProcessResult(returncode=0, stdout="", stderr="", command=cmd)

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            res = await driver.execute(self.ctx)

            self.assertTrue(res.success)
            self.assertEqual(captured_cmd[0], "gau")
            urls = res.metadata.get("urls", [])
            self.assertIn("https://example.com/item?id=123", urls)
            self.assertIn("https://example.com/about", urls)
            self.assertNotIn("https://evil.com/x?a=1", urls)

        asyncio.run(run_test())

    def test_wayback_driver(self) -> None:
        async def run_test() -> None:
            driver = WaybackDriver()
            captured_cmd = []

            async def fake_run(cmd, **kwargs):
                captured_cmd.extend(cmd)
                return ProcessResult(
                    returncode=0,
                    stdout="https://example.com/archive?page=1\n",
                    stderr="",
                    command=cmd,
                )

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            res = await driver.execute(self.ctx)

            self.assertTrue(res.success)
            self.assertEqual(captured_cmd[0], "waybackpy")
            urls = res.metadata.get("urls", [])
            self.assertIn("https://example.com/archive?page=1", urls)

        asyncio.run(run_test())

    def test_paramspider_driver(self) -> None:
        async def run_test() -> None:
            driver = ParamspiderDriver()
            live_file = self.outdir / "live.txt"
            live_file.write_text("https://example.com\n", encoding="utf-8")

            results_dir = Path("results")
            results_dir.mkdir(parents=True, exist_ok=True)
            res_file = results_dir / "example.com.txt"
            res_file.write_text("https://example.com/api?key=secret\n", encoding="utf-8")

            captured_cmd = []

            async def fake_run(cmd, **kwargs):
                captured_cmd.extend(cmd)
                return ProcessResult(returncode=0, stdout="", stderr="", command=cmd)

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            try:
                res = await driver.execute(self.ctx, live_file=live_file)
                self.assertTrue(res.success)
                self.assertEqual(captured_cmd[0], "paramspider")
                urls = res.metadata.get("urls", [])
                self.assertIn("https://example.com/api?key=secret", urls)
            finally:
                if res_file.exists():
                    res_file.unlink()
                if results_dir.exists() and not any(results_dir.iterdir()):
                    results_dir.rmdir()

        asyncio.run(run_test())


class TestMultiDriverAggregation(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.outdir = Path(self.temp_dir.name)
        self.db_path = self.outdir / "session.db"
        self.store = SessionStore(self.db_path)
        self.bus = AsyncEventBus()

        self.config = Config(
            target="https://example.com/",
            domain="example.com",
            wordlist=self.outdir / "wordlist.txt",
            outdir=self.outdir,
            dry_run=True,
            driver_subdomains="subfinder,assetfinder",
            driver_urls="wayback,gau",
        )

        self.executor = AsyncExecutor(dry_run=True)
        self.tor = TorManager(dry_run=True)
        self.bypass_ctx = BypassContext()

        self.registry = DriverRegistry()
        register_defaults(self.registry)

        self.ctx = StageContext(
            config=self.config,
            store=self.store,
            executor=self.executor,
            bus=self.bus,
            tor=self.tor,
            bypass_context=self.bypass_ctx,
            drivers=self.registry,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_multi_driver_subdomains_aggregation(self) -> None:
        async def run_test() -> None:
            executed_tools = []

            async def fake_run(cmd, **kwargs):
                tool = cmd[0]
                executed_tools.append(tool)
                if tool == "subfinder":
                    return ProcessResult(returncode=0, stdout="sub1.example.com\n", stderr="", command=cmd)
                elif tool == "assetfinder":
                    return ProcessResult(returncode=0, stdout="sub2.example.com\nsub1.example.com\n", stderr="", command=cmd)
                return ProcessResult(returncode=0, stdout="", stderr="", command=cmd)

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            subs = await run_subdomains_stage(self.ctx)

            self.assertIn("subfinder", executed_tools)
            self.assertIn("assetfinder", executed_tools)
            self.assertIn("sub1.example.com", subs)
            self.assertIn("sub2.example.com", subs)
            self.assertEqual(len(subs), 2)  # deduplicated

        asyncio.run(run_test())

    def test_multi_driver_urls_aggregation(self) -> None:
        async def run_test() -> None:
            live_file = self.outdir / "live.txt"
            live_file.write_text("https://example.com\n", encoding="utf-8")

            executed_tools = []

            async def fake_run(cmd, **kwargs):
                tool = cmd[0]
                executed_tools.append(tool)
                if tool == "waybackpy":
                    return ProcessResult(returncode=0, stdout="https://example.com/p1?foo=bar\n", stderr="", command=cmd)
                elif tool == "gau":
                    return ProcessResult(returncode=0, stdout="https://example.com/p2?baz=qux\nhttps://example.com/p1?foo=bar\n", stderr="", command=cmd)
                return ProcessResult(returncode=0, stdout="", stderr="", command=cmd)

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            urls = await run_urls_stage(self.ctx)

            self.assertIn("waybackpy", executed_tools)
            self.assertIn("gau", executed_tools)
            self.assertIn("https://example.com/p1?foo=bar", urls)
            self.assertIn("https://example.com/p2?baz=qux", urls)
            self.assertEqual(len(urls), 2)  # deduplicated signatures

        asyncio.run(run_test())


class TestDriverConfigTOMLPhase2(unittest.TestCase):
    def test_driver_urls_in_toml(self) -> None:
        cfg = {
            "target": "https://example.com/",
            "driver_subdomains": "subfinder,amass",
            "driver_urls": "gau,katana",
        }
        validated = validate_toml_config(cfg)
        self.assertEqual(validated["driver_subdomains"], "subfinder,amass")
        self.assertEqual(validated["driver_urls"], "gau,katana")


if __name__ == "__main__":
    unittest.main()
