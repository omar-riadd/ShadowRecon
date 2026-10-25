"""Unit tests for ShadowRecon v3 modular stage runners."""
import sys
import tempfile
import unittest
from pathlib import Path

# Add src and root to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))
sys.path.insert(0, str(root_dir))

from shadowrecon.config import BypassContext, Config
from shadowrecon.core.executor import AsyncExecutor
from shadowrecon.core.tor import TorManager
from shadowrecon.modules.recon import (
    run_fuzzing_stage,
    run_probing_stage,
    run_subdomains_stage,
    run_urls_stage,
)
from shadowrecon.modules.takeover import find_takeover_templates, run_takeover_stage
from shadowrecon.modules.vuln import parse_dalfox_line, run_lfi_stage, run_sqli_stage, run_xss_stage
from shadowrecon.modules.waf import parse_waf_name, run_waf_stage
from shadowrecon.pipeline.queue import AsyncEventBus
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import FindingRecord, SessionStore


class TestV3WafModule(unittest.IsolatedAsyncioTestCase):
    def test_parse_waf_name(self):
        output = "The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF."
        self.assertEqual(parse_waf_name(output), "Cloudflare")
        self.assertIsNone(parse_waf_name("No WAF detected by the generic detection."))

    async def test_run_waf_stage_dry_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cfg = Config(
                target="https://example.com/",
                domain="example.com",
                wordlist=tmp / "wl.txt",
                outdir=tmp / "out",
                dry_run=True,
                use_proxy=False,
            )
            store = SessionStore(tmp / "session.db")
            executor = AsyncExecutor(dry_run=True, use_proxy=False)
            bus = AsyncEventBus()
            tor = TorManager(dry_run=True)
            ctx = StageContext(cfg, store, executor, bus, tor, BypassContext())

            bypass = await run_waf_stage(ctx)
            self.assertIsInstance(bypass, BypassContext)
            # In dry-run, baseline probe returns 200 (not blocked), so candidate mutations logged but desc stays none
            self.assertEqual(bypass.desc, "none")
            bypasses = store.get_waf_bypasses()
            self.assertTrue(len(bypasses) > 0)
            self.assertTrue(all(not b.get("confirmed") for b in bypasses))

    async def test_run_waf_stage_confirmed_bypass(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cfg = Config(
                target="https://example.com/",
                domain="example.com",
                wordlist=tmp / "wl.txt",
                outdir=tmp / "out",
                dry_run=False,
                use_proxy=False,
            )
            store = SessionStore(tmp / "session.db")
            executor = AsyncExecutor(dry_run=True, use_proxy=False)
            bus = AsyncEventBus()
            tor = TorManager(dry_run=True)
            ctx = StageContext(cfg, store, executor, bus, tor, BypassContext())

            # Baseline probe returns 403 (blocked), mutations: first returns 403, second returns 200
            responses = [(403, 100), (403, 100), (200, 500)]
            resp_iter = iter(responses)

            async def fake_execute_probe(*args, **kwargs):
                try:
                    return next(resp_iter)
                except StopIteration:
                    return (403, 100)

            with patch("shadowrecon.modules.waf.detect_waf", return_value="Cloudflare"), \
                 patch("shadowrecon.modules.waf.execute_http_probe", side_effect=fake_execute_probe):
                bypass = await run_waf_stage(ctx)
                self.assertNotEqual(bypass.desc, "none")
                bypasses = store.get_waf_bypasses()
                confirmed = [b for b in bypasses if b.get("confirmed")]
                self.assertTrue(len(confirmed) > 0)


class TestV3ReconModule(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.cfg = Config(
            target="https://example.com/",
            domain="example.com",
            wordlist=self.tmp / "wl.txt",
            outdir=self.tmp / "out",
            dry_run=True,
            use_proxy=False,
        )
        self.cfg.wordlist.write_text("admin\napi\n", encoding="utf-8")
        self.store = SessionStore(self.tmp / "session.db")
        self.executor = AsyncExecutor(dry_run=True, use_proxy=False)
        self.bus = AsyncEventBus()
        self.tor = TorManager(dry_run=True)
        self.ctx = StageContext(self.cfg, self.store, self.executor, self.bus, self.tor, BypassContext())

    def tearDown(self):
        self.tmpdir.cleanup()

    async def test_subdomains_and_probing(self):
        # 1. Subdomains
        subs = await run_subdomains_stage(self.ctx)
        self.assertIn("example.com", subs)
        self.assertTrue((self.cfg.outdir / "subdomains.txt").is_file())

        # 2. Probing (in dry run, simulates target)
        hosts = await run_probing_stage(self.ctx)
        self.assertIn("https://example.com", hosts)
        self.assertTrue((self.cfg.outdir / "live.txt").is_file())

    async def test_urls_stage_deduplication(self):
        # Seed the session with URLs
        self.store.add_urls([
            "https://example.com/item?id=1&name=test",
            "https://example.com/item?name=foo&id=2",  # duplicate params
            "https://example.com/search?q=shadow",
        ])
        urls = await run_urls_stage(self.ctx)
        self.assertEqual(len(urls), 2)
        self.assertTrue((self.cfg.outdir / "params.txt").is_file())

    async def test_fuzzing_stage(self):
        self.store.add_hosts(["https://example.com"])
        await run_fuzzing_stage(self.ctx)
        self.assertTrue((self.cfg.outdir / "ffuf_dirs").is_dir())

    async def test_fuzzing_stage_multi_host_concurrency(self):
        from unittest.mock import AsyncMock
        from shadowrecon.core.executor import ProcessResult
        self.cfg.concurrency = 3
        self.store.add_hosts(["https://api.example.com", "https://app.example.com", "https://dev.example.com"])

        executed_cmds = []
        async def fake_run(cmd, **kwargs):
            executed_cmds.append(cmd)
            out_idx = cmd.index("-o")
            out_file = Path(cmd[out_idx + 1])
            out_file.write_text("url,status\n", encoding="utf-8")
            return ProcessResult(returncode=0, stdout="", stderr="", command=cmd)

        self.ctx.executor.run = AsyncMock(side_effect=fake_run)
        await run_fuzzing_stage(self.ctx)

        ffuf_dir = self.cfg.outdir / "ffuf_dirs"
        self.assertTrue(ffuf_dir.is_dir())
        self.assertEqual(len(executed_cmds), 3)
        csvs = list(ffuf_dir.glob("*.csv"))
        self.assertEqual(len(csvs), 3)


class TestV3TakeoverModule(unittest.IsolatedAsyncioTestCase):
    def test_find_takeover_templates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            self.assertIsNone(find_takeover_templates(base))
            (base / "http" / "takeovers").mkdir(parents=True)
            self.assertEqual(find_takeover_templates(base), base / "http" / "takeovers")

    async def test_takeover_stage_graceful_missing_templates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cfg = Config(
                target="https://example.com/",
                domain="example.com",
                wordlist=tmp / "wl.txt",
                outdir=tmp / "out",
                nuclei_templates=tmp / "nonexistent-templates",
                dry_run=True,
                use_proxy=False,
            )
            store = SessionStore(tmp / "session.db")
            executor = AsyncExecutor(dry_run=True, use_proxy=False)
            bus = AsyncEventBus()
            tor = TorManager(dry_run=True)
            ctx = StageContext(cfg, store, executor, bus, tor, BypassContext())

            findings = await run_takeover_stage(ctx)
            # Returns empty list gracefully without throwing an exception
            self.assertEqual(findings, [])


class TestV3VulnModule(unittest.IsolatedAsyncioTestCase):
    def test_parse_dalfox_line(self):
        line = "[POC][V] https://example.com/?q=1 <script>alert(1)</script>"
        f = parse_dalfox_line(line)
        self.assertIsNotNone(f)
        self.assertEqual(f.vuln_type, "XSS")
        self.assertEqual(f.target_url, "https://example.com/?q=1")
        self.assertIn("alert(1)", f.payload)

    async def test_run_xss_and_sqli_empty_urls_skip_safely(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cfg = Config(
                target="https://example.com/",
                domain="example.com",
                wordlist=tmp / "wl.txt",
                outdir=tmp / "out",
                dry_run=True,
                use_proxy=False,
            )
            store = SessionStore(tmp / "session.db")
            executor = AsyncExecutor(dry_run=True, use_proxy=False)
            bus = AsyncEventBus()
            tor = TorManager(dry_run=True)
            ctx = StageContext(cfg, store, executor, bus, tor, BypassContext())

            xss_findings = await run_xss_stage(ctx)
            self.assertEqual(xss_findings, [])

            sqli_findings = await run_sqli_stage(ctx)
            self.assertEqual(sqli_findings, [])

            # LFI skips safely without payloads
            await run_lfi_stage(ctx)


if __name__ == "__main__":
    unittest.main(verbosity=2)
