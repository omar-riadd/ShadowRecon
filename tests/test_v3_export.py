"""Unit and integration tests for ShadowRecon Phase 4: Enterprise Exports (SARIF, JSON, CSV)."""
import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))
sys.path.insert(0, str(root_dir))

from shadowrecon.cli import async_main, build_parser
from shadowrecon.reporting.export import build_manifest_dict, export_csv, export_json
from shadowrecon.reporting.sarif import export_sarif, generate_sarif_dict, resolve_cwe_metadata
from shadowrecon.storage.session import FindingRecord, HostRecord, SessionStore


class TestSarifExporter(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.store = SessionStore(self.tmp / "session.db")
        self.store.set_metadata("target", "https://example.com")
        self.store.set_metadata("domain", "example.com")

        # Seed findings with various types & severities
        self.store.add_finding(FindingRecord(
            vuln_type="XSS",
            severity="high",
            target_url="https://example.com/search?q=1",
            payload="<script>alert(1)</script>",
            details="Reflected XSS in search query parameter",
            source_tool="dalfox",
        ))
        self.store.add_finding(FindingRecord(
            vuln_type="SQLi",
            severity="critical",
            target_url="https://example.com/api/users?id=1",
            payload="1' OR '1'='1",
            details="Boolean-based blind SQL injection",
            source_tool="sqlmap",
        ))
        self.store.add_finding(FindingRecord(
            vuln_type="Nuclei:cve-2023-1234",
            severity="medium",
            target_url="https://example.com/api/test",
            payload="admin_token",
            details="Information disclosure via API test endpoint",
            source_tool="nuclei",
        ))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_resolve_cwe_metadata(self):
        cwe_xss, rule_xss, _, _ = resolve_cwe_metadata("XSS")
        self.assertEqual(cwe_xss, "CWE-79")
        self.assertIn("CWE-79", rule_xss)

        cwe_sqli, rule_sqli, _, _ = resolve_cwe_metadata("SQLi")
        self.assertEqual(cwe_sqli, "CWE-89")

        cwe_lfi, _, _, _ = resolve_cwe_metadata("LFI")
        self.assertEqual(cwe_lfi, "CWE-22")

        cwe_ssrf, _, _, _ = resolve_cwe_metadata("SSRF")
        self.assertEqual(cwe_ssrf, "CWE-918")

        cwe_takeover, _, _, _ = resolve_cwe_metadata("Takeover")
        self.assertEqual(cwe_takeover, "CWE-284")

        cwe_cve, rule_cve, _, _ = resolve_cwe_metadata("Nuclei:cve-2023-1234")
        self.assertEqual(cwe_cve, "CWE-937")
        self.assertIn("CVE-2023-1234", rule_cve)

    def test_generate_sarif_dict(self):
        sarif = generate_sarif_dict(self.store, tool_version="3.1.0")
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0.json", sarif["$schema"])

        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "ShadowRecon")
        self.assertEqual(run["tool"]["driver"]["version"], "3.1.0")

        # 3 findings should yield 3 rules and 3 results
        rules = run["tool"]["driver"]["rules"]
        results = run["results"]
        self.assertEqual(len(rules), 3)
        self.assertEqual(len(results), 3)

        # Check results levels
        results_by_rule = {r["ruleId"]: r for r in results}
        self.assertIn("SR-CWE-79-CROSSSITESCRIPTING", results_by_rule)
        self.assertEqual(results_by_rule["SR-CWE-79-CROSSSITESCRIPTING"]["level"], "error")
        self.assertEqual(results_by_rule["SR-CWE-79-CROSSSITESCRIPTING"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "https://example.com/search?q=1")

    def test_export_sarif_file(self):
        out_file = self.tmp / "report.sarif"
        path = export_sarif(self.store, out_file)
        self.assertEqual(path, out_file)
        self.assertTrue(out_file.is_file())

        parsed = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual(parsed["version"], "2.1.0")
        self.assertEqual(len(parsed["runs"][0]["results"]), 3)


class TestJsonExporter(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.store = SessionStore(self.tmp / "session.db")
        self.store.set_metadata("target", "https://example.com")
        self.store.set_metadata("domain", "example.com")
        self.store.set_stage("waf", "completed", 1.25)
        self.store.add_subdomains(["api.example.com", "dev.example.com"])
        self.store.add_hosts([
            HostRecord(url="https://api.example.com", status_code=200, title="API Gateway", webserver="nginx"),
        ])
        self.store.add_urls(["https://api.example.com/v1?user=123"])
        self.store.add_finding(FindingRecord(vuln_type="XSS", severity="high", target_url="https://api.example.com/v1?user=123"))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_build_manifest_and_export_json(self):
        out_file = self.tmp / "manifest.json"
        res_path = export_json(self.store, out_file)
        self.assertTrue(res_path.is_file())

        data = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual(data["generator"]["name"], "ShadowRecon")
        self.assertEqual(data["target"]["domain"], "example.com")
        self.assertEqual(data["stages"]["waf"]["status"], "completed")
        self.assertIn("api.example.com", data["assets"]["subdomains"])
        self.assertEqual(len(data["assets"]["hosts"]), 1)
        self.assertEqual(data["assets"]["hosts"][0]["webserver"], "nginx")
        self.assertEqual(data["findings"][0]["cwe"], "CWE-79")


class TestCsvExporter(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.store = SessionStore(self.tmp / "session.db")
        self.store.add_subdomains(["sub1.example.com", "sub2.example.com"])
        self.store.add_hosts([
            HostRecord(url="https://sub1.example.com", status_code=200, title="Sub 1", webserver="Apache", content_length=1024),
        ])
        self.store.add_urls(["https://sub1.example.com/test?a=1"])
        self.store.add_finding(FindingRecord(
            vuln_type="SQLi",
            severity="high",
            target_url="https://sub1.example.com/test?a=1",
            payload="' OR 1=1--",
            details="SQL Injection test",
            source_tool="sqlmap",
        ))
        self.store.add_waf_bypass("Header bypass", "GET", "https://sub1.example.com", {"X-Custom": "1"}, 200, confirmed=True)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_export_csv_tables(self):
        out_dir = self.tmp / "csv_out"
        generated = export_csv(self.store, out_dir)

        # All 5 CSV files must be present
        self.assertIn("subdomains", generated)
        self.assertIn("hosts", generated)
        self.assertIn("urls", generated)
        self.assertIn("findings", generated)
        self.assertIn("waf_bypasses", generated)

        for name, p in generated.items():
            self.assertTrue(p.is_file())

        # Inspect subdomains.csv
        with generated["subdomains"].open(newline="", encoding="utf-8") as f:
            reader = list(csv.reader(f))
            self.assertEqual(reader[0], ["subdomain"])
            self.assertEqual(len(reader), 3)  # header + 2 subdomains

        # Inspect findings.csv
        with generated["findings"].open(newline="", encoding="utf-8") as f:
            reader = list(csv.reader(f))
            self.assertEqual(reader[0], ["vuln_type", "cwe", "severity", "target_url", "payload", "details", "source_tool", "created_at"])
            self.assertEqual(reader[1][0], "SQLi")
            self.assertEqual(reader[1][1], "CWE-89")
            self.assertEqual(reader[1][2], "high")


class TestCliExportFlags(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_build_parser_export_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "-u", "https://example.com",
            "--export-sarif", "/tmp/out.sarif",
            "--export-json", "/tmp/out.json",
            "--export-csv", "/tmp/csv_dir",
        ])
        self.assertEqual(args.export_sarif, "/tmp/out.sarif")
        self.assertEqual(args.export_json, "/tmp/out.json")
        self.assertEqual(args.export_csv, "/tmp/csv_dir")

    async def test_full_pipeline_with_exports(self):
        outdir = self.tmp / "scan_out"
        wl = self.tmp / "wl.txt"
        wl.write_text("test\n", encoding="utf-8")

        sarif_file = outdir / "custom.sarif"
        json_file = outdir / "custom.json"
        csv_dir = outdir / "csv_tables"

        ret = await async_main([
            "-u", "https://example.com/",
            "-w", str(wl),
            "-o", str(outdir),
            "--stages", "waf",
            "--export-sarif", str(sarif_file),
            "--export-json", str(json_file),
            "--export-csv", str(csv_dir),
            "--dry-run",
            "--no-proxy",
        ])
        self.assertEqual(ret, 0)

        # Verify export files exist
        self.assertTrue(sarif_file.is_file())
        self.assertTrue(json_file.is_file())
        self.assertTrue((csv_dir / "subdomains.csv").is_file())
        self.assertTrue((csv_dir / "hosts.csv").is_file())


if __name__ == "__main__":
    unittest.main()
