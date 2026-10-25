"""Unit and integration tests for ShadowRecon Phase 3: Differential Drift Analysis."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))
sys.path.insert(0, str(root_dir))

from shadowrecon.cli import build_parser, async_main
from shadowrecon.reporting.html import generate_report_from_store
from shadowrecon.storage.diff import SessionDiff, diff_sessions, main as diff_cli_main
from shadowrecon.storage.session import FindingRecord, HostRecord, SessionStore


class TestDifferentialAnalysisEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)

        # Baseline / Prior session
        self.db_prior_path = self.tmp / "prior_session.db"
        self.store_prior = SessionStore(self.db_prior_path)
        self.store_prior.set_metadata("target", "https://example.com")
        self.store_prior.set_metadata("start_time", "2026-10-01T10:00:00")

        # Seed prior session data
        self.store_prior.add_subdomains(["api.example.com", "old.example.com", "www.example.com"])
        self.store_prior.add_hosts([
            HostRecord(url="https://api.example.com", status_code=200),
            HostRecord(url="https://old.example.com", status_code=200),
            HostRecord(url="https://admin.example.com", status_code=403),
        ])
        self.store_prior.add_urls([
            "https://api.example.com/item?id=1",
            "https://old.example.com/info?v=2",
        ])
        self.store_prior.add_finding(FindingRecord(
            vuln_type="XSS",
            severity="medium",
            target_url="https://old.example.com/search?q=1",
            details="Reflected XSS",
        ))

        # Current session
        self.db_cur_path = self.tmp / "cur_session.db"
        self.store_cur = SessionStore(self.db_cur_path)
        self.store_cur.set_metadata("target", "https://example.com")
        self.store_cur.set_metadata("start_time", "2026-10-25T10:00:00")

        # Seed current session data:
        # - "old.example.com" removed
        # - "dev.example.com" added
        # - "https://admin.example.com" changed status from 403 to 200
        # - "https://dev.example.com" new live host
        # - "https://old.example.com" host removed
        # - XSS on old.example.com resolved
        # - SQLi on api.example.com newly found
        self.store_cur.add_subdomains(["api.example.com", "dev.example.com", "www.example.com"])
        self.store_cur.add_hosts([
            HostRecord(url="https://api.example.com", status_code=200),
            HostRecord(url="https://dev.example.com", status_code=200),
            HostRecord(url="https://admin.example.com", status_code=200),  # status shift!
        ])
        self.store_cur.add_urls([
            "https://api.example.com/item?id=1",
            "https://dev.example.com/login?redirect=dash",
        ])
        self.store_cur.add_finding(FindingRecord(
            vuln_type="SQLi",
            severity="critical",
            target_url="https://api.example.com/item?id=1",
            details="Error-based SQL injection",
        ))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_diff_subdomains(self):
        diff = diff_sessions(self.store_cur, self.store_prior)
        self.assertTrue(diff.has_drift())
        self.assertEqual(diff.new_subdomains, ["dev.example.com"])
        self.assertEqual(diff.removed_subdomains, ["old.example.com"])

    def test_diff_hosts_and_status_shifts(self):
        diff = diff_sessions(self.store_cur, self.store_prior)
        self.assertEqual(diff.new_hosts, ["https://dev.example.com"])
        self.assertEqual(diff.removed_hosts, ["https://old.example.com"])

        # Check status transition 403 -> 200
        self.assertEqual(len(diff.status_changes), 1)
        shift = diff.status_changes[0]
        self.assertEqual(shift["url"], "https://admin.example.com")
        self.assertEqual(shift["old_status"], 403)
        self.assertEqual(shift["new_status"], 200)

    def test_diff_urls(self):
        diff = diff_sessions(self.store_cur, self.store_prior)
        self.assertEqual(diff.new_urls, ["https://dev.example.com/login?redirect=dash"])
        self.assertEqual(diff.removed_urls, ["https://old.example.com/info?v=2"])

    def test_diff_findings(self):
        diff = diff_sessions(self.store_cur, self.store_prior)
        # New finding
        self.assertEqual(len(diff.new_findings), 1)
        self.assertEqual(diff.new_findings[0].vuln_type, "SQLi")
        self.assertEqual(diff.new_findings[0].severity, "critical")

        # Remediated / resolved finding
        self.assertEqual(len(diff.resolved_findings), 1)
        self.assertEqual(diff.resolved_findings[0].vuln_type, "XSS")

    def test_diff_identical_sessions_no_drift(self):
        diff = diff_sessions(self.store_prior, self.store_prior)
        self.assertFalse(diff.has_drift())
        self.assertEqual(diff.summary_counts()["new_subdomains"], 0)
        report = diff.format_console_report()
        self.assertIn("No drift detected between sessions", report)

    def test_serialization_to_dict_and_json(self):
        diff = diff_sessions(self.store_cur, self.store_prior)
        data = diff.to_dict()
        self.assertTrue(data["metadata"]["has_drift"])
        self.assertEqual(data["summary"]["new_subdomains"], 1)
        self.assertEqual(data["summary"]["removed_subdomains"], 1)
        self.assertEqual(data["summary"]["status_changes"], 1)
        self.assertEqual(data["summary"]["new_findings"], 1)
        self.assertEqual(data["summary"]["resolved_findings"], 1)

        # Ensure valid JSON encoding
        json_str = json.dumps(data)
        self.assertIn("dev.example.com", json_str)
        self.assertIn("SQLi", json_str)

    def test_format_console_report_contains_markers(self):
        diff = diff_sessions(self.store_cur, self.store_prior)
        report = diff.format_console_report()
        self.assertIn("[+] Discovered Subdomains (+1):", report)
        self.assertIn("dev.example.com", report)
        self.assertIn("[-] Decommissioned / Missing Subdomains (-1):", report)
        self.assertIn("old.example.com", report)
        self.assertIn("[*] HTTP Status Code Transitions (1):", report)
        self.assertIn("HTTP 403 -> HTTP 200", report)
        self.assertIn("[+] NEW Vulnerability Findings (+1):", report)
        self.assertIn("[CRITICAL] SQLi", report)
        self.assertIn("[-] RESOLVED Vulnerabilities (-1):", report)

    def test_diff_sessions_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            diff_sessions(self.store_cur, self.tmp / "nonexistent.db")


class TestDiffCliAndReporting(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)

        # Baseline DB
        self.prior_db = self.tmp / "prior.db"
        prior_store = SessionStore(self.prior_db)
        prior_store.add_subdomains(["target.com", "legacy.target.com"])
        prior_store.add_hosts([HostRecord("https://target.com", 200), HostRecord("https://legacy.target.com", 200)])

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_standalone_cli_tool(self):
        cur_db = self.tmp / "cur.db"
        cur_store = SessionStore(cur_db)
        cur_store.add_subdomains(["target.com", "new.target.com"])
        cur_store.add_hosts([HostRecord("https://target.com", 200), HostRecord("https://new.target.com", 200)])

        out_file = self.tmp / "cli_diff.txt"
        ret = diff_cli_main([str(cur_db), str(self.prior_db), "-o", str(out_file)])
        self.assertEqual(ret, 0)
        self.assertTrue(out_file.is_file())
        content = out_file.read_text(encoding="utf-8")
        self.assertIn("new.target.com", content)

    def test_html_report_with_drift(self):
        cur_db = self.tmp / "cur.db"
        cur_store = SessionStore(cur_db)
        cur_store.add_subdomains(["target.com", "api.target.com"])
        diff = diff_sessions(cur_store, self.prior_db)

        report_file = generate_report_from_store(
            cur_store,
            self.tmp / "out",
            {"Target": "https://target.com", "Domain": "target.com"},
            drift=diff,
        )
        self.assertTrue(report_file.is_file())
        html_content = report_file.read_text(encoding="utf-8")
        self.assertIn("Asset &amp; Vuln Drift", html_content)
        self.assertIn("New Subdomains", html_content)

    async def test_cli_diff_flag_integration(self):
        outdir = self.tmp / "scan_out"
        wl = self.tmp / "wl.txt"
        wl.write_text("test\n", encoding="utf-8")

        # Run dry-run scan with --diff against self.prior_db
        ret = await async_main([
            "-u", "https://target.com/",
            "-w", str(wl),
            "-o", str(outdir),
            "--stages", "waf",
            "--diff", str(self.prior_db),
            "--dry-run",
            "--no-proxy",
        ])
        self.assertEqual(ret, 0)

        # Verify drift artifacts generated
        drift_json = outdir / "drift_summary.json"
        drift_txt = outdir / "drift_summary.txt"
        self.assertTrue(drift_json.is_file())
        self.assertTrue(drift_txt.is_file())

        data = json.loads(drift_json.read_text(encoding="utf-8"))
        self.assertIn("deltas", data)
        self.assertIn("summary", data)


if __name__ == "__main__":
    unittest.main()
