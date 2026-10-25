"""Unit tests for ShadowRecon v3 CLI entrypoint and HTML reporting."""
import sys
import tempfile
import unittest
from pathlib import Path

# Add src and root to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))
sys.path.insert(0, str(root_dir))

from shadowrecon.cli import async_main, build_parser
from shadowrecon.reporting.html import generate_report_from_store
from shadowrecon.storage.session import FindingRecord, SessionStore


class TestV3Cli(unittest.IsolatedAsyncioTestCase):
    def test_parser_defaults_and_options(self):
        p = build_parser()
        args = p.parse_args(["-u", "https://example.com/", "--stages", "waf,subdomains", "--threads", "3"])
        self.assertEqual(args.target, "https://example.com/")
        self.assertEqual(args.stages, "waf,subdomains")
        self.assertEqual(args.threads, 3)
        self.assertEqual(args.socks, "socks5h://127.0.0.1:9050")

    async def test_dry_run_pipeline_execution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir) / "out"
            argv = [
                "-u", "https://example.com/",
                "-o", str(outdir),
                "--stages", "waf,subdomains,probing",
                "--dry-run",
            ]
            code = await async_main(argv)
            self.assertEqual(code, 0)

            # Session DB and artifacts created
            self.assertTrue((outdir / "session.db").is_file())
            self.assertTrue((outdir / "subdomains.txt").is_file())
            self.assertTrue((outdir / "live.txt").is_file())
            self.assertTrue((outdir / "report.html").is_file())

            # Verify session content
            store = SessionStore(outdir / "session.db")
            stages = store.get_stages()
            self.assertIn("waf", stages)
            self.assertIn("subdomains", stages)
            self.assertIn("probing", stages)
            self.assertEqual(stages["waf"]["status"], "completed")

    async def test_authorization_gate_refuses_without_authorized_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir) / "out"
            argv = [
                "-u", "https://example.com/",
                "-o", str(outdir),
                # No --dry-run and no --authorized
            ]
            code = await async_main(argv)
            self.assertEqual(code, 2)


class TestV3HtmlReport(unittest.TestCase):
    def test_generate_report_from_store(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir)
            db_path = outdir / "session.db"
            store = SessionStore(db_path)

            store.add_subdomains(["api.example.com", "dev.example.com"])
            store.add_hosts(["https://api.example.com"])
            store.add_urls(["https://api.example.com/v1/user?id=1"])
            store.add_finding(
                FindingRecord(
                    vuln_type="XSS",
                    severity="high",
                    target_url="https://api.example.com/v1/user?id=1",
                    payload="<script>alert(1)</script>",
                )
            )

            report_file = generate_report_from_store(
                store=store,
                out_dir=outdir,
                meta={"Target": "https://example.com/", "Domain": "example.com"},
            )

            self.assertTrue(report_file.is_file())
            content = report_file.read_text(encoding="utf-8")
            self.assertIn("ShadowRecon", content)
            self.assertIn("Subdomains", content)
            self.assertIn("api.example.com", content)
            self.assertIn("XSS", content)
            self.assertIn("<svg", content)  # Chart embedded


if __name__ == "__main__":
    unittest.main(verbosity=2)
