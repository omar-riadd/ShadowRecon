"""Unit tests for ShadowRecon v3 SQLite session store."""
import sys
import tempfile
import unittest
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from shadowrecon.storage.session import FindingRecord, HostRecord, SessionStore


class TestV3SessionStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_session.db"
        self.store = SessionStore(self.db_path)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_metadata_operations(self):
        self.store.set_metadata("target", "https://example.com/")
        self.store.set_metadata("tags", ["recon", "prod"])
        self.assertEqual(self.store.get_metadata("target"), "https://example.com/")
        self.assertEqual(self.store.get_metadata("tags"), ["recon", "prod"])
        self.assertIsNone(self.store.get_metadata("nonexistent"))

    def test_stage_tracking_and_resume(self):
        self.assertFalse(self.store.is_stage_completed("subdomains"))
        self.store.set_stage("subdomains", "running")
        self.assertFalse(self.store.is_stage_completed("subdomains"))
        self.store.set_stage("subdomains", "completed", duration=12.4)
        self.assertTrue(self.store.is_stage_completed("subdomains"))

        stages = self.store.get_stages()
        self.assertIn("subdomains", stages)
        self.assertEqual(stages["subdomains"]["status"], "completed")
        self.assertEqual(stages["subdomains"]["duration_seconds"], 12.4)

    def test_subdomains_deduplication(self):
        inserted1 = self.store.add_subdomains(["api.example.com", "dev.example.com"])
        self.assertEqual(inserted1, 2)
        # Duplicate should not increase count
        inserted2 = self.store.add_subdomains(["API.EXAMPLE.COM", "mail.example.com"])
        self.assertEqual(inserted2, 1)

        subs = self.store.get_subdomains()
        self.assertEqual(subs, ["api.example.com", "dev.example.com", "mail.example.com"])

    def test_hosts(self):
        self.store.add_hosts(["https://api.example.com", "https://shop.example.com"])
        self.store.add_hosts([HostRecord(url="https://dev.example.com", status_code=200)])
        hosts = self.store.get_hosts()
        self.assertEqual(len(hosts), 3)

    def test_urls_deduplication(self):
        urls = [
            "https://api.example.com/v1/user?id=1&token=xyz",
            "https://api.example.com/v1/user?token=abc&id=99",  # duplicate params
            "https://api.example.com/v1/user?ref=google",       # different params
            "https://api.example.com/static/file",              # no params - ignored
        ]
        inserted = self.store.add_urls(urls)
        # First two have identical param signatures (id, token), so only 1 inserted + 1 ref
        self.assertEqual(inserted, 2)
        stored = self.store.get_urls()
        self.assertEqual(len(stored), 2)

    def test_findings_and_waf_bypasses(self):
        self.store.add_finding(
            FindingRecord(
                vuln_type="XSS",
                severity="high",
                target_url="https://api.example.com/?q=1",
                payload="<script>alert(1)</script>",
                source_tool="dalfox",
            )
        )
        findings = self.store.get_findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "XSS")

        self.store.add_waf_bypass(
            desc="UA Googlebot",
            method="GET",
            url="https://example.com/",
            headers={"User-Agent": "Googlebot"},
            status_code=200,
            confirmed=True,
        )
        bypasses = self.store.get_waf_bypasses(confirmed_only=True)
        self.assertEqual(len(bypasses), 1)
        self.assertEqual(bypasses[0]["desc"], "UA Googlebot")

    def test_summary_and_export_flat_artifacts(self):
        self.store.add_subdomains(["api.example.com"])
        self.store.add_hosts(["https://api.example.com"])
        self.store.add_urls(["https://api.example.com/v1?user=1"])
        self.store.add_finding(
            FindingRecord(
                vuln_type="XSS",
                severity="high",
                target_url="https://api.example.com/v1?user=1",
                payload="alert(1)",
            )
        )
        self.store.add_finding(
            FindingRecord(
                vuln_type="Takeover",
                severity="high",
                target_url="https://dev.example.com",
                details="github-takeover",
            )
        )

        counts = self.store.get_summary_counts()
        self.assertEqual(counts["Subdomains"], 1)
        self.assertEqual(counts["Live hosts"], 1)
        self.assertEqual(counts["Parameterized URLs"], 1)
        self.assertEqual(counts["Vulnerabilities"], 2)

        export_dir = Path(self.tmpdir.name) / "artifacts"
        self.store.export_flat_artifacts(export_dir)

        self.assertTrue((export_dir / "subdomains.txt").is_file())
        self.assertTrue((export_dir / "live.txt").is_file())
        self.assertTrue((export_dir / "params.txt").is_file())
        self.assertTrue((export_dir / "xss_dalfox.txt").is_file())
        self.assertTrue((export_dir / "nuclei_takeover.txt").is_file())

        subs_text = (export_dir / "subdomains.txt").read_text(encoding="utf-8")
        self.assertIn("api.example.com", subs_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
