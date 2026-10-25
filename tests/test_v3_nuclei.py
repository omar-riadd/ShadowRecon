"""Unit tests for ShadowRecon Phase 2: Nuclei Engine Expansion."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))
sys.path.insert(0, str(root_dir))

from shadowrecon.cli import build_parser
from shadowrecon.config import BypassContext, Config
from shadowrecon.core.executor import AsyncExecutor, ProcessResult
from shadowrecon.core.tor import TorManager
from shadowrecon.modules.nuclei import parse_nuclei_json_line, run_nuclei_stage
from shadowrecon.pipeline.queue import AsyncEventBus
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import SessionStore


class TestNucleiParser(unittest.TestCase):
    def test_parse_valid_jsonl(self):
        line = json.dumps({
            "template-id": "cve-2023-1234",
            "info": {
                "name": "Spring Framework RCE",
                "severity": "CRITICAL",
                "description": "Remote code execution vulnerability via spel expression",
            },
            "matched-at": "https://example.com/api/v1",
            "extracted-results": ["root", "admin_hash"],
        })
        record = parse_nuclei_json_line(line)
        self.assertIsNotNone(record)
        self.assertEqual(record.vuln_type, "Nuclei:cve-2023-1234")
        self.assertEqual(record.severity, "critical")
        self.assertEqual(record.target_url, "https://example.com/api/v1")
        self.assertEqual(record.payload, "root, admin_hash")
        self.assertIn("[cve-2023-1234] Spring Framework RCE", record.details)
        self.assertIn("Remote code execution vulnerability", record.details)
        self.assertEqual(record.source_tool, "nuclei")

    def test_parse_jsonl_with_host_and_string_extracted(self):
        line = json.dumps({
            "template-id": "git-config-disclosure",
            "info": {
                "name": "Git Config Disclosure",
                "severity": "medium",
            },
            "host": "http://192.168.1.100",
            "extracted-results": "repository = https://github.com/...",
        })
        record = parse_nuclei_json_line(line)
        self.assertIsNotNone(record)
        self.assertEqual(record.vuln_type, "Nuclei:git-config-disclosure")
        self.assertEqual(record.target_url, "http://192.168.1.100")
        self.assertEqual(record.payload, "repository = https://github.com/...")

    def test_parse_empty_and_whitespace(self):
        self.assertIsNone(parse_nuclei_json_line(""))
        self.assertIsNone(parse_nuclei_json_line("   \n\t  "))

    def test_parse_cli_log_prefixes_filtered(self):
        self.assertIsNone(parse_nuclei_json_line("[INF] Current nuclei version: v3.1.0"))
        self.assertIsNone(parse_nuclei_json_line("[WRN] Rate limit exceeded"))
        self.assertIsNone(parse_nuclei_json_line("[ERR] Failed to resolve host"))

    def test_parse_plain_text_fallback(self):
        line = "[cve-2021-44228] [http] [critical] https://example.com/login"
        record = parse_nuclei_json_line(line)
        self.assertIsNotNone(record)
        self.assertEqual(record.vuln_type, "Nuclei")
        self.assertEqual(record.severity, "medium")
        self.assertEqual(record.target_url, "https://example.com/login")
        self.assertEqual(record.details, line)


class TestNucleiStageExecution(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.templates_dir = self.tmp / "templates"
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.cfg = Config(
            target="https://example.com/",
            domain="example.com",
            wordlist=self.tmp / "wl.txt",
            outdir=self.tmp / "out",
            nuclei_templates=self.templates_dir,
            nuclei_severity="medium,high,critical",
            nuclei_tags="cve,misconfig",
            dry_run=False,
            use_proxy=False,
        )
        self.cfg.wordlist.write_text("test\n", encoding="utf-8")
        self.store = SessionStore(self.tmp / "session.db")
        self.executor = AsyncExecutor(dry_run=True, use_proxy=False)
        self.bus = AsyncEventBus()
        self.tor = TorManager(dry_run=True)
        self.ctx = StageContext(self.cfg, self.store, self.executor, self.bus, self.tor, BypassContext())

    def tearDown(self):
        self.tmpdir.cleanup()

    async def test_nuclei_missing_templates_graceful_skip(self):
        self.cfg.nuclei_templates = self.tmp / "nonexistent-templates-dir"
        self.cfg.dry_run = False
        findings = await run_nuclei_stage(self.ctx)
        self.assertEqual(findings, [])

    async def test_nuclei_no_hosts_graceful_skip(self):
        # templates exist, but no hosts recorded in store
        findings = await run_nuclei_stage(self.ctx)
        self.assertEqual(findings, [])

    async def test_nuclei_command_construction(self):
        # Add host to store
        self.store.add_hosts(["https://example.com"])

        # Intercept executor.run to check arguments
        captured_cmd = []

        async def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            # Create dummy output file
            out_file = self.cfg.outdir / "nuclei_findings.jsonl"
            dummy_event = {
                "template-id": "test-vuln",
                "info": {"name": "Test Vulnerability", "severity": "high"},
                "matched-at": "https://example.com/test",
            }
            out_file.write_text(json.dumps(dummy_event) + "\n", encoding="utf-8")
            return ProcessResult(returncode=0, stdout="", stderr="", command=cmd)

        self.ctx.executor.run = AsyncMock(side_effect=fake_run)

        # Track bus events
        sub_q = self.bus.subscribe("finding")

        findings = await run_nuclei_stage(self.ctx)

        # Verify command flags
        self.assertEqual(captured_cmd[0], "nuclei")
        self.assertIn("-s", captured_cmd)
        self.assertEqual(captured_cmd[captured_cmd.index("-s") + 1], "medium,high,critical")
        self.assertIn("-tags", captured_cmd)
        self.assertEqual(captured_cmd[captured_cmd.index("-tags") + 1], "cve,misconfig")
        self.assertIn("-jsonl", captured_cmd)

        # Verify findings persisted and published
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "Nuclei:test-vuln")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(len(self.store.get_findings()), 1)
        self.assertFalse(sub_q.empty())
        event = sub_q.get_nowait()
        self.assertIsNotNone(event)
        self.assertEqual(event.data.vuln_type, "Nuclei:test-vuln")

    async def test_nuclei_dry_run_missing_templates_simulates_cleanly(self):
        self.cfg.nuclei_templates = self.tmp / "nonexistent-templates-dir"
        self.cfg.dry_run = True
        self.store.add_hosts(["https://example.com"])
        findings = await run_nuclei_stage(self.ctx)
        self.assertEqual(findings, [])
        self.assertTrue((self.cfg.outdir / "live.txt").is_file())


class TestNucleiCliOptions(unittest.TestCase):
    def test_cli_flags_parsing(self):
        parser = build_parser()
        args = parser.parse_args([
            "-u", "https://example.com",
            "--severity", "critical",
            "--tags", "cve,rce",
            "--nuclei-templates", "/opt/nuclei-templates",
        ])
        self.assertEqual(args.nuclei_severity, "critical")
        self.assertEqual(args.nuclei_tags, "cve,rce")
        self.assertEqual(args.nuclei_templates, "/opt/nuclei-templates")

    def test_cli_alternative_flag_names(self):
        parser = build_parser()
        args = parser.parse_args([
            "-u", "https://example.com",
            "--nuclei-severity", "high",
            "--nuclei-tags", "exposure",
        ])
        self.assertEqual(args.nuclei_severity, "high")
        self.assertEqual(args.nuclei_tags, "exposure")


if __name__ == "__main__":
    unittest.main()
