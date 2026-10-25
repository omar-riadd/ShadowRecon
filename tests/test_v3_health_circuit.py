"""Unit tests for Phase 4: Preflight Health Checker (Doctor) and HostCircuitBreaker."""
from __future__ import annotations

import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from shadowrecon.config import BypassContext, Config
from shadowrecon.core.circuit import CircuitState, HostCircuitBreaker
from shadowrecon.core.executor import AsyncExecutor
from shadowrecon.core.health import CheckStatus, DoctorReport, HealthCheckResult, PreflightChecker
from shadowrecon.core.tor import TorManager
from shadowrecon.pipeline.queue import AsyncEventBus
from shadowrecon.pipeline.runner import PipelineRunner, StageContext
from shadowrecon.storage.session import FindingRecord, HostRecord, SessionStore


class TestHealthAndCircuitBreaker(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.tmp_dir.name) / "out"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.out_dir / "session.db"
        self.store = SessionStore(self.db_path)
        self.cfg = Config(
            target="https://example.com",
            domain="example.com",
            wordlist=Path(self.tmp_dir.name) / "words.txt",
            outdir=self.out_dir,
            dry_run=True,
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # -------------------------------------------------------------------------
    # Preflight Health Checker (Doctor Engine) Tests
    # -------------------------------------------------------------------------
    def test_check_binary_resolved(self) -> None:
        checker = PreflightChecker(self.cfg)
        with patch("shadowrecon.core.health.resolve_binary", return_value="/usr/bin/subfinder"):
            res = checker.check_binary("subfinder", "Subdomain discovery", is_core=True)
            self.assertEqual(res.status, CheckStatus.OK)
            self.assertIn("/usr/bin/subfinder", res.message)

    def test_check_binary_missing_core_vs_optional(self) -> None:
        checker = PreflightChecker(self.cfg)
        with patch("shadowrecon.core.health.resolve_binary", return_value=None):
            # Missing core binary -> FAIL
            core_res = checker.check_binary("wafw00f", "WAF detector", is_core=True)
            self.assertEqual(core_res.status, CheckStatus.FAIL)
            self.assertIn("apt install wafw00f", core_res.remediation)

            # Missing optional driver -> WARNING
            opt_res = checker.check_binary("gau", "Archive tool", is_core=False)
            self.assertEqual(opt_res.status, CheckStatus.WARNING)

    def test_check_binary_alternative_name(self) -> None:
        checker = PreflightChecker(self.cfg)

        def mock_resolve(name: str):
            if name == "httpx-toolkit":
                return "/usr/bin/httpx-toolkit"
            return None

        with patch("shadowrecon.core.health.resolve_binary", side_effect=mock_resolve):
            res = checker.check_binary("httpx", "Prober", is_core=True)
            self.assertEqual(res.status, CheckStatus.OK)
            self.assertIn("httpx-toolkit", res.message)

    def test_check_proxy_reachability_success(self) -> None:
        checker = PreflightChecker(self.cfg)
        mock_sock = MagicMock()

        with patch("socket.socket", return_value=mock_sock):
            res = checker.check_proxy_reachability("socks5://127.0.0.1:9050")
            self.assertEqual(res.status, CheckStatus.OK)
            self.assertIn("127.0.0.1:9050", res.message)

    def test_check_proxy_reachability_failure(self) -> None:
        checker = PreflightChecker(self.cfg)
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError("Connection refused")

        with patch("socket.socket", return_value=mock_sock):
            res = checker.check_proxy_reachability("socks5://127.0.0.1:9050")
            self.assertEqual(res.status, CheckStatus.WARNING)
            self.assertIn("Cannot reach proxy", res.message)
            self.assertIn("systemctl start tor", res.remediation)

    def test_check_nuclei_templates(self) -> None:
        checker = PreflightChecker(self.cfg)
        tmpl_dir = Path(self.tmp_dir.name) / "nuclei-templates"
        tmpl_dir.mkdir(parents=True, exist_ok=True)
        (tmpl_dir / "cve.yaml").write_text("id: test-cve\n", encoding="utf-8")

        res = checker.check_nuclei_templates(tmpl_dir)
        self.assertEqual(res.status, CheckStatus.OK)
        self.assertIn("1 templates", res.message)

    def test_check_storage_permissions(self) -> None:
        checker = PreflightChecker(self.cfg)
        res = checker.check_storage_permissions(self.out_dir)
        self.assertEqual(res.status, CheckStatus.OK)
        self.assertIn("Writable output directory", res.message)

    def test_doctor_report_formatting(self) -> None:
        report = DoctorReport(
            checks=[
                HealthCheckResult("subfinder", "Core Binaries", CheckStatus.OK, "Found"),
                HealthCheckResult("gau", "Optional Drivers", CheckStatus.WARNING, "Missing", "Install gau"),
                HealthCheckResult("wafw00f", "Core Binaries", CheckStatus.FAIL, "Not found", "sudo apt install wafw00f"),
            ]
        )
        self.assertFalse(report.all_passed)
        self.assertTrue(report.has_critical_failures)
        summary = report.summary_counts()
        self.assertEqual(summary["OK"], 1)
        self.assertEqual(summary["WARNING"], 1)
        self.assertEqual(summary["FAIL"], 1)

        table = report.format_table()
        self.assertIn("ShadowRecon Doctor", table)
        self.assertIn("✅ PASS", table)
        self.assertIn("⚠️  WARN", table)
        self.assertIn("❌ FAIL", table)
        self.assertIn("Install gau", table)

    # -------------------------------------------------------------------------
    # HostCircuitBreaker Tests
    # -------------------------------------------------------------------------
    def test_circuit_breaker_lifecycle(self) -> None:
        cb = HostCircuitBreaker(failure_threshold=3, recovery_timeout=0.2)
        host = "https://api.flakey-host.com/v1"

        # Initially CLOSED
        self.assertTrue(cb.allow_request(host))

        # Record 2 failures (under threshold)
        cb.record_failure(host, "504 Gateway Timeout")
        cb.record_failure(host, "504 Gateway Timeout")
        self.assertTrue(cb.allow_request(host))

        # 3rd failure trips circuit to OPEN
        cb.record_failure(host, "504 Gateway Timeout")
        self.assertFalse(cb.allow_request(host))
        self.assertIn("api.flakey-host.com", cb.get_open_circuits())

        # Fast-fail while recovery timeout has not elapsed
        self.assertFalse(cb.allow_request(host))

        # Wait for cool-down recovery window
        time.sleep(0.25)

        # First request after recovery_timeout transitions to HALF_OPEN (allows canary)
        self.assertTrue(cb.allow_request(host))

        # Success on canary probe resets circuit to CLOSED
        cb.record_success(host)
        self.assertTrue(cb.allow_request(host))
        self.assertEqual(len(cb.get_open_circuits()), 0)

    def test_circuit_breaker_canary_failure_retrips(self) -> None:
        cb = HostCircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        host = "https://dead.target.com/test"

        cb.record_failure(host, "Connection reset")
        cb.record_failure(host, "Connection reset")
        self.assertFalse(cb.allow_request(host))

        # Wait for cool-down
        time.sleep(0.15)
        # Canary allowed
        self.assertTrue(cb.allow_request(host))

        # Canary fails -> re-trips back to OPEN immediately
        cb.record_failure(host, "Connection timeout")
        self.assertFalse(cb.allow_request(host))

    def test_circuit_breaker_url_filtering(self) -> None:
        cb = HostCircuitBreaker(failure_threshold=2, recovery_timeout=60.0)

        # Trip host B
        cb.record_failure("https://b.com/api", "503 Service Unavailable")
        cb.record_failure("https://b.com/api", "503 Service Unavailable")

        urls = [
            "https://a.com/search?q=1",
            "https://b.com/user?id=2",
            "https://c.com/view?item=3",
        ]
        healthy = cb.filter_healthy_urls(urls)
        self.assertEqual(healthy, ["https://a.com/search?q=1", "https://c.com/view?item=3"])

        hosts = ["a.com", "b.com", "c.com"]
        healthy_hosts = cb.filter_healthy_hosts(hosts)
        self.assertEqual(healthy_hosts, ["a.com", "c.com"])

    def test_circuit_breaker_disabled_mode(self) -> None:
        cb = HostCircuitBreaker(failure_threshold=1, enabled=False)
        host = "https://broken.com"

        cb.record_failure(host, "Dropped connection")
        self.assertTrue(cb.allow_request(host))
        self.assertEqual(cb.filter_healthy_urls(["https://broken.com/path"]), ["https://broken.com/path"])

    # -------------------------------------------------------------------------
    # Stage Interruption and Checkpointing Tests
    # -------------------------------------------------------------------------
    def test_stage_interruption_saves_checkpoint(self) -> None:
        async def _test() -> None:
            runner = PipelineRunner()
            bus = AsyncEventBus()
            tor = TorManager(dry_run=True)
            executor = AsyncExecutor(socks_proxy="", use_proxy=False, dry_run=True)
            ctx = StageContext(
                config=self.cfg,
                store=self.store,
                executor=executor,
                bus=bus,
                tor=tor,
                bypass_context=BypassContext(),
            )

            # Stage 1 succeeds and writes a finding
            async def stage_ok(c: StageContext) -> None:
                c.store.add_subdomains(["sub1.example.com"])
                c.store.add_finding(
                    FindingRecord(
                        target_url="https://sub1.example.com",
                        vuln_type="sqli",
                        severity="high",
                    )
                )

            # Stage 2 gets cancelled midway
            async def stage_abort(c: StageContext) -> None:
                c.store.add_subdomains(["sub2.example.com"])
                raise asyncio.CancelledError("User hit Ctrl+C")

            runner.add_stage("subdomains", "Discovery", stage_ok)
            runner.add_stage("crawling", "Crawling", stage_abort)

            with self.assertRaises(asyncio.CancelledError):
                await runner.run(ctx)

            # Check that stage 1 is marked completed and stage 2 is marked interrupted
            stages = self.store.get_stages()
            self.assertEqual(stages["subdomains"]["status"], "completed")
            self.assertEqual(stages["crawling"]["status"], "interrupted")

            # Check that subdomains and findings discovered before cancellation were preserved
            subs = self.store.get_subdomains()
            self.assertIn("sub1.example.com", subs)
            self.assertIn("sub2.example.com", subs)

            # Check that flat artifacts were exported as checkpoint
            self.assertTrue((self.out_dir / "subdomains.txt").is_file())

        asyncio.run(_test())


if __name__ == "__main__":
    unittest.main()
