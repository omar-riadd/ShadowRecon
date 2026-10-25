"""Unit tests for Phase 5: ScopeManager (CIDR, Wildcards, Exclusions), Port Matrix, and Safe Mode."""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from shadowrecon.config import BypassContext, Config
from shadowrecon.core.executor import AsyncExecutor, ExecutionResult
from shadowrecon.core.scope import ScopeManager, extract_host, in_scope, is_in_scope
from shadowrecon.core.tor import TorManager
from shadowrecon.drivers.tools import HttpxDriver
from shadowrecon.pipeline.queue import AsyncEventBus
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import SessionStore


class TestScopePortsAndSafeMode(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.tmp_dir.name) / "out"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.out_dir / "session.db"
        self.store = SessionStore(self.db_path)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # -------------------------------------------------------------------------
    # ScopeManager Tests (Domain, Wildcard, CIDR, Exclusions)
    # -------------------------------------------------------------------------
    def test_scope_manager_basic_domains(self) -> None:
        mgr = ScopeManager(domain="example.com")
        self.assertTrue(mgr.is_in_scope("example.com"))
        self.assertTrue(mgr.is_in_scope("api.example.com"))
        self.assertTrue(mgr.is_in_scope("https://sub.api.example.com/v1?id=1"))
        self.assertFalse(mgr.is_in_scope("notexample.com"))
        self.assertFalse(mgr.is_in_scope("example.org"))
        self.assertFalse(mgr.is_in_scope("https://evil.com/"))

    def test_scope_manager_cidr_matching(self) -> None:
        mgr = ScopeManager(
            domain="internal.corp",
            allowed=["192.168.1.0/24", "10.0.0.0/16"],
        )
        # In-scope IPs
        self.assertTrue(mgr.is_in_scope("192.168.1.50"))
        self.assertTrue(mgr.is_in_scope("http://192.168.1.1:8080/admin"))
        self.assertTrue(mgr.is_in_scope("https://10.0.5.20/"))

        # Out-of-scope IPs
        self.assertFalse(mgr.is_in_scope("192.168.2.1"))
        self.assertFalse(mgr.is_in_scope("10.1.0.1"))
        self.assertFalse(mgr.is_in_scope("8.8.8.8"))

    def test_scope_manager_wildcard_patterns(self) -> None:
        mgr = ScopeManager(
            domain="target.com",
            allowed=["*.api.target.com", "dev-*.target.com"],
        )
        self.assertTrue(mgr.is_in_scope("v1.api.target.com"))
        self.assertTrue(mgr.is_in_scope("dev-auth.target.com"))
        self.assertTrue(mgr.is_in_scope("target.com"))

    def test_scope_manager_exclusion_filters(self) -> None:
        mgr = ScopeManager(
            domain="target.com",
            allowed=["10.0.0.0/8"],
            exclude="mail.*,vpn.*,checkout.target.com,10.0.99.0/24",
        )
        # In-scope
        self.assertTrue(mgr.is_in_scope("api.target.com"))
        self.assertTrue(mgr.is_in_scope("https://target.com/"))
        self.assertTrue(mgr.is_in_scope("10.0.1.5"))

        # Excluded by pattern
        self.assertFalse(mgr.is_in_scope("mail.target.com"))
        self.assertFalse(mgr.is_in_scope("vpn.target.com"))
        self.assertFalse(mgr.is_in_scope("https://checkout.target.com/pay"))

        # Excluded by CIDR
        self.assertFalse(mgr.is_in_scope("10.0.99.10"))

    def test_backward_compatible_in_scope_helper(self) -> None:
        self.assertTrue(in_scope("api.test.com", "test.com"))
        self.assertFalse(in_scope("evil.com", "test.com"))
        self.assertFalse(in_scope("mail.test.com", "test.com", exclude="mail.*"))

    # -------------------------------------------------------------------------
    # HttpxDriver Port Matrix Tests
    # -------------------------------------------------------------------------
    def test_httpx_driver_port_matrix_default(self) -> None:
        async def _test() -> None:
            cfg = Config(
                target="https://example.com",
                domain="example.com",
                wordlist=Path("/tmp/wl.txt"),
                outdir=self.out_dir,
                probe_ports="default",
                dry_run=True,
            )
            executor = AsyncExecutor(socks_proxy="", use_proxy=False, dry_run=True)
            bus = AsyncEventBus()
            tor = TorManager(dry_run=True)
            ctx = StageContext(
                config=cfg,
                store=self.store,
                executor=executor,
                bus=bus,
                tor=tor,
                bypass_context=BypassContext(),
            )

            driver = HttpxDriver()
            captured_cmds = []

            async def mock_run(cmd, **kwargs):
                captured_cmds.append(cmd)
                return ExecutionResult(returncode=0, stdout="https://example.com\n", stderr="", command=cmd)

            with patch.object(executor, "run", side_effect=mock_run):
                await driver.execute(ctx)

            self.assertEqual(len(captured_cmds), 1)
            cmd = captured_cmds[0]
            self.assertNotIn("-ports", cmd)

        asyncio.run(_test())

    def test_httpx_driver_port_matrix_web(self) -> None:
        async def _test() -> None:
            cfg = Config(
                target="https://example.com",
                domain="example.com",
                wordlist=Path("/tmp/wl.txt"),
                outdir=self.out_dir,
                probe_ports="web",
                dry_run=True,
            )
            executor = AsyncExecutor(socks_proxy="", use_proxy=False, dry_run=True)
            bus = AsyncEventBus()
            tor = TorManager(dry_run=True)
            ctx = StageContext(
                config=cfg,
                store=self.store,
                executor=executor,
                bus=bus,
                tor=tor,
                bypass_context=BypassContext(),
            )

            driver = HttpxDriver()
            captured_cmds = []

            async def mock_run(cmd, **kwargs):
                captured_cmds.append(cmd)
                return ExecutionResult(returncode=0, stdout="https://example.com:8443\n", stderr="", command=cmd)

            with patch.object(executor, "run", side_effect=mock_run):
                await driver.execute(ctx)

            self.assertEqual(len(captured_cmds), 1)
            cmd = captured_cmds[0]
            self.assertIn("-ports", cmd)
            idx = cmd.index("-ports")
            self.assertIn("8080", cmd[idx + 1])
            self.assertIn("8443", cmd[idx + 1])

        asyncio.run(_test())

    def test_httpx_driver_port_matrix_custom_ports(self) -> None:
        async def _test() -> None:
            cfg = Config(
                target="https://example.com",
                domain="example.com",
                wordlist=Path("/tmp/wl.txt"),
                outdir=self.out_dir,
                probe_ports="8000,8888,9000",
                dry_run=True,
            )
            executor = AsyncExecutor(socks_proxy="", use_proxy=False, dry_run=True)
            bus = AsyncEventBus()
            tor = TorManager(dry_run=True)
            ctx = StageContext(
                config=cfg,
                store=self.store,
                executor=executor,
                bus=bus,
                tor=tor,
                bypass_context=BypassContext(),
            )

            driver = HttpxDriver()
            captured_cmds = []

            async def mock_run(cmd, **kwargs):
                captured_cmds.append(cmd)
                return ExecutionResult(returncode=0, stdout="", stderr="", command=cmd)

            with patch.object(executor, "run", side_effect=mock_run):
                await driver.execute(ctx)

            self.assertEqual(len(captured_cmds), 1)
            cmd = captured_cmds[0]
            self.assertIn("-ports", cmd)
            idx = cmd.index("-ports")
            self.assertEqual(cmd[idx + 1], "8000,8888,9000")

        asyncio.run(_test())

    # -------------------------------------------------------------------------
    # StageContext Scope Integration Tests
    # -------------------------------------------------------------------------
    def test_stage_context_scope_integration(self) -> None:
        scope_mgr = ScopeManager(domain="example.com", exclude="secret.*")
        cfg = Config(
            target="https://example.com",
            domain="example.com",
            wordlist=Path("/tmp/wl.txt"),
            outdir=self.out_dir,
            exclude="secret.*",
        )
        ctx = StageContext(
            config=cfg,
            store=self.store,
            executor=MagicMock(),
            bus=AsyncEventBus(),
            tor=MagicMock(),
            bypass_context=BypassContext(),
            scope=scope_mgr,
        )

        self.assertTrue(ctx.is_in_scope("https://api.example.com/test"))
        self.assertFalse(ctx.is_in_scope("https://secret.example.com/admin"))
        self.assertFalse(ctx.is_in_scope("https://external.com"))


if __name__ == "__main__":
    unittest.main()
