"""End-to-end live HTTP integration tests against local mock target server."""
from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Add src and tests to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))
sys.path.insert(0, str(root_dir))

from shadowrecon.cli import async_main
from shadowrecon.config import BypassContext, Config
from shadowrecon.core.executor import AsyncExecutor
from shadowrecon.core.tor import TorManager
from shadowrecon.modules.waf import execute_http_probe, run_waf_stage
from shadowrecon.pipeline.queue import AsyncEventBus
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import SessionStore
from tests.mock_target_server import MockTargetServer


class TestV3LiveMockIntegration(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = MockTargetServer()
        cls.base_url = cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    async def test_live_server_endpoints(self) -> None:
        """Verify the mock target server returns live HTTP responses over loopback."""
        import requests
        no_proxy = {"http": None, "https": None}
        resp = requests.get(self.base_url, timeout=5, proxies=no_proxy)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Mock Application", resp.text)

        # Baseline probe blocked with 403
        probe_resp = requests.get(f"{self.base_url}/?__shadowrecon_probe=1'OR'1'='1", timeout=5, proxies=no_proxy)
        self.assertEqual(probe_resp.status_code, 403)

        # Bypass probe with X-Forwarded-For returns 200
        bypass_resp = requests.get(
            f"{self.base_url}/?__shadowrecon_probe=1'OR'1'='1",
            headers={"X-Forwarded-For": "127.0.0.1"},
            timeout=5,
            proxies=no_proxy,
        )
        self.assertEqual(bypass_resp.status_code, 200)

    async def test_live_waf_stage_detects_and_confirms_bypass(self) -> None:
        """Execute real HTTP probing in run_waf_stage against the live mock server."""
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir) / "waf_live_out"
            outdir.mkdir(parents=True, exist_ok=True)
            db_path = outdir / "session.db"
            store = SessionStore(db_path)

            cfg = Config(
                target=f"{self.base_url}/",
                domain="127.0.0.1",
                wordlist=outdir / "wl.txt",
                outdir=outdir,
                dry_run=False,
                use_proxy=False,
            )
            executor = AsyncExecutor(dry_run=False, use_proxy=False)
            bus = AsyncEventBus()
            tor = TorManager(dry_run=True)
            ctx = StageContext(cfg, store, executor, bus, tor, BypassContext())

            # Mock detect_waf returning Cloudflare so cloudflare payload set is evaluated
            with patch("shadowrecon.modules.waf.detect_waf", return_value="Cloudflare"):
                bypass = await run_waf_stage(ctx)

            # Cloudflare payload set contains X-Forwarded-For: 127.0.0.1, which succeeds against mock server
            self.assertNotEqual(bypass.desc, "none")
            self.assertEqual(bypass.headers.get("X-Forwarded-For"), "127.0.0.1")

            bypasses = store.get_waf_bypasses(confirmed_only=True)
            self.assertTrue(len(bypasses) >= 1)
            self.assertEqual(bypasses[0]["status_code"], 200)

    async def test_live_full_pipeline_cli_execution(self) -> None:
        """Run async_main against the live server without mocking internal Python logic."""
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir) / "e2e_live_run"
            wordlist = Path(tmpdir) / "wordlist.txt"
            wordlist.write_text("admin\nsearch\napi\n", encoding="utf-8")

            argv = [
                "-u", f"{self.base_url}/",
                "-w", str(wordlist),
                "-o", str(outdir),
                "--stages", "waf",
                "--authorized",
                "--no-proxy",
            ]

            # In this test environment, wafw00f is optional/mocked or executed live
            with patch("shadowrecon.modules.waf.detect_waf", return_value="Cloudflare"):
                exit_code = await async_main(argv)

            self.assertEqual(exit_code, 0)
            db_path = outdir / "session.db"
            self.assertTrue(db_path.is_file())

            store = SessionStore(db_path)
            self.assertTrue(store.is_stage_completed("waf"))
            bypasses = store.get_waf_bypasses()
            self.assertTrue(len(bypasses) > 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
