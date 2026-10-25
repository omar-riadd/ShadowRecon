"""Unit tests for concrete ScannerDriver implementations and tool decoupling."""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from shadowrecon.config import BypassContext, Config, validate_toml_config
from shadowrecon.core.executor import AsyncExecutor, ProcessResult
from shadowrecon.core.proxy import DirectProxyProvider
from shadowrecon.core.tor import TorManager
from shadowrecon.drivers import (
    DalfoxDriver,
    DriverRegistry,
    HttpxDriver,
    KatanaDriver,
    MockScannerDriver,
    NucleiDriver,
    ScanResult,
    SqlmapDriver,
    SubfinderDriver,
    global_registry,
    register_defaults,
)
from shadowrecon.modules.recon import run_probing_stage, run_subdomains_stage
from shadowrecon.modules.vuln import run_sqli_stage, run_xss_stage
from shadowrecon.pipeline.queue import AsyncEventBus
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import FindingRecord, SessionStore


class TestConcreteDriversRegistration(unittest.TestCase):
    def test_global_registry_defaults(self) -> None:
        drivers = global_registry.list_drivers()
        self.assertIn("subdomains", drivers)
        self.assertIn("probing", drivers)
        self.assertIn("crawling", drivers)
        self.assertIn("nuclei", drivers)
        self.assertIn("xss", drivers)
        self.assertIn("sqli", drivers)

        self.assertIn("subfinder", drivers["subdomains"])
        self.assertIn("httpx", drivers["probing"])
        self.assertIn("katana", drivers["crawling"])
        self.assertIn("nuclei", drivers["nuclei"])
        self.assertIn("dalfox", drivers["xss"])
        self.assertIn("sqlmap", drivers["sqli"])

    def test_register_defaults_on_fresh_registry(self) -> None:
        reg = DriverRegistry()
        self.assertEqual(len(reg.list_drivers()), 0)
        register_defaults(reg)
        self.assertEqual(reg.get_driver("subdomains").name, "subfinder")
        self.assertEqual(reg.get_driver("probing").name, "httpx")
        self.assertEqual(reg.get_driver("crawling").name, "katana")
        self.assertEqual(reg.get_driver("nuclei").name, "nuclei")
        self.assertEqual(reg.get_driver("xss").name, "dalfox")
        self.assertEqual(reg.get_driver("sqli").name, "sqlmap")


class TestConcreteDriverExecution(unittest.TestCase):
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

    def test_subfinder_driver(self) -> None:
        async def run_test() -> None:
            driver = SubfinderDriver()
            captured_cmd = []

            async def fake_run(cmd, **kwargs):
                captured_cmd.extend(cmd)
                return ProcessResult(
                    returncode=0,
                    stdout="api.example.com\napp.example.com\nout-of-scope.org\n",
                    stderr="",
                    command=cmd,
                )

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            res = await driver.execute(self.ctx)

            self.assertTrue(res.success)
            self.assertEqual(captured_cmd[0], "subfinder")
            stored = self.store.get_subdomains()
            self.assertIn("api.example.com", stored)
            self.assertIn("app.example.com", stored)
            self.assertNotIn("out-of-scope.org", stored)

        asyncio.run(run_test())

    def test_httpx_driver(self) -> None:
        async def run_test() -> None:
            self.store.add_subdomains(["app.example.com"], source="test")
            driver = HttpxDriver()
            captured_cmd = []

            async def fake_run(cmd, **kwargs):
                captured_cmd.extend(cmd)
                return ProcessResult(
                    returncode=0,
                    stdout="https://app.example.com\n",
                    stderr="",
                    command=cmd,
                )

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            res = await driver.execute(self.ctx)

            self.assertTrue(res.success)
            self.assertEqual(captured_cmd[0], "httpx")
            hosts = self.store.get_hosts()
            self.assertIn("https://app.example.com", hosts)

        asyncio.run(run_test())

    def test_katana_driver(self) -> None:
        async def run_test() -> None:
            driver = KatanaDriver()
            captured_cmd = []

            async def fake_run(cmd, **kwargs):
                captured_cmd.extend(cmd)
                return ProcessResult(
                    returncode=0,
                    stdout="https://example.com/search?q=test\nhttps://example.com/login\n",
                    stderr="",
                    command=cmd,
                )

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            res = await driver.execute(self.ctx)

            self.assertTrue(res.success)
            self.assertEqual(captured_cmd[0], "katana")
            self.assertIn("https://example.com/search?q=test", res.metadata.get("urls", []))

        asyncio.run(run_test())

    def test_nuclei_driver(self) -> None:
        async def run_test() -> None:
            self.store.add_hosts(["https://example.com"])
            driver = NucleiDriver()
            captured_cmd = []

            dummy_event = {
                "template-id": "cve-2024-test",
                "info": {"name": "Test CVE", "severity": "critical"},
                "matched-at": "https://example.com/vuln",
            }

            async def fake_run(cmd, **kwargs):
                captured_cmd.extend(cmd)
                out_file = self.outdir / "nuclei_findings.jsonl"
                out_file.write_text(json.dumps(dummy_event) + "\n", encoding="utf-8")
                return ProcessResult(returncode=0, stdout="", stderr="", command=cmd)

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            res = await driver.execute(self.ctx)

            self.assertTrue(res.success)
            self.assertEqual(captured_cmd[0], "nuclei")
            findings = self.store.get_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].vuln_type, "Nuclei:cve-2024-test")
            self.assertEqual(findings[0].severity, "critical")

        asyncio.run(run_test())

    def test_httpx_driver_with_bypass_headers(self) -> None:
        async def run_test() -> None:
            self.ctx.bypass_context = BypassContext(headers={"X-Forwarded-For": "127.0.0.1"})
            driver = HttpxDriver()
            captured_cmd = []

            async def fake_run(cmd, **kwargs):
                captured_cmd.extend(cmd)
                return ProcessResult(returncode=0, stdout="", stderr="", command=cmd)

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            await driver.execute(self.ctx)

            self.assertIn("-H", captured_cmd)
            self.assertIn("X-Forwarded-For: 127.0.0.1", captured_cmd)

        asyncio.run(run_test())

    def test_nuclei_driver_with_bypass_headers(self) -> None:
        async def run_test() -> None:
            self.store.add_hosts(["https://example.com"])
            self.ctx.bypass_context = BypassContext(headers={"X-Forwarded-For": "127.0.0.1"})
            driver = NucleiDriver()
            captured_cmd = []

            async def fake_run(cmd, **kwargs):
                captured_cmd.extend(cmd)
                return ProcessResult(returncode=0, stdout="", stderr="", command=cmd)

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            await driver.execute(self.ctx)

            self.assertIn("-H", captured_cmd)
            self.assertIn("X-Forwarded-For: 127.0.0.1", captured_cmd)

        asyncio.run(run_test())

    def test_dalfox_driver(self) -> None:
        async def run_test() -> None:
            self.store.add_urls(["https://example.com/search?q=1"], source="test")
            driver = DalfoxDriver()
            captured_cmd = []

            poc_line = "[POC][G][V] https://example.com/search?q=1 <script>alert(1)</script>"

            async def fake_run(cmd, **kwargs):
                captured_cmd.extend(cmd)
                out_file = self.outdir / "xss_dalfox.txt"
                out_file.write_text(poc_line + "\n", encoding="utf-8")
                return ProcessResult(returncode=0, stdout=poc_line, stderr="", command=cmd)

            self.ctx.executor.run = AsyncMock(side_effect=fake_run)
            res = await driver.execute(self.ctx)

            self.assertTrue(res.success)
            self.assertEqual(captured_cmd[0], "dalfox")
            findings = self.store.get_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].vuln_type, "XSS")
            self.assertIn("alert(1)", findings[0].payload)

        asyncio.run(run_test())

    def test_sqlmap_driver_single_and_batch(self) -> None:
        async def run_test() -> None:
            driver = SqlmapDriver()

            # 1. Single URL
            captured_cmd = []

            async def fake_run_single(cmd, **kwargs):
                captured_cmd.extend(cmd)
                return ProcessResult(
                    returncode=0,
                    stdout="sqlmap identified the following injection points: parameter 'id' is vulnerable",
                    stderr="",
                    command=cmd,
                )

            self.ctx.executor.run = AsyncMock(side_effect=fake_run_single)
            res = await driver.execute(self.ctx, url="https://example.com/item?id=1")

            self.assertTrue(res.success)
            self.assertEqual(captured_cmd[0], "sqlmap")
            self.assertIn("-u", captured_cmd)
            findings = self.store.get_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].vuln_type, "SQLi")

        asyncio.run(run_test())


class TestPluggableDriverSwapping(unittest.TestCase):
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

    def test_swap_subdomains_with_mock_driver(self) -> None:
        async def run_test() -> None:
            # Custom mock driver that injects synthetic subdomains
            mock_driver = MockScannerDriver(
                name="custom_sub_mock",
                synthetic_items=["mock1.example.com", "mock2.example.com"],
            )

            # Register and activate
            self.registry.register("subdomains", mock_driver, is_default=False)
            self.registry.set_active("subdomains", "custom_sub_mock")

            # Run standard stage runner
            subs = await run_subdomains_stage(self.ctx)
            self.assertIn("mock1.example.com", subs)
            self.assertIn("mock2.example.com", subs)

        asyncio.run(run_test())


class TestDriverConfigTOML(unittest.TestCase):
    def test_driver_keys_in_toml_validation(self) -> None:
        cfg = {
            "target": "https://example.com/",
            "driver_subdomains": "amass",
            "driver_probing": "httpx",
            "driver_crawling": "katana",
            "driver_nuclei": "nuclei",
            "driver_xss": "dalfox",
            "driver_sqli": "sqlmap",
        }
        validated = validate_toml_config(cfg)
        self.assertEqual(validated["driver_subdomains"], "amass")


if __name__ == "__main__":
    unittest.main()
