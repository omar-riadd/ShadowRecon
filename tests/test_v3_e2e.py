"""End-to-end integration test verifying complete v3 pipeline lifecycle, persistence, and reports."""
import sys
import tempfile
import unittest
from pathlib import Path

# Add src and root to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))
sys.path.insert(0, str(root_dir))

from shadowrecon.cli import async_main
from shadowrecon.storage.session import SessionStore


class TestV3PipelineE2E(unittest.IsolatedAsyncioTestCase):
    async def test_full_pipeline_dry_run_artifacts_and_database(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir) / "e2e_run"
            wordlist = Path(tmpdir) / "words.txt"
            wordlist.write_text("admin\napi\nlogin\n", encoding="utf-8")

            argv = [
                "-u", "https://app.example.com/",
                "-w", str(wordlist),
                "-o", str(outdir),
                "--dry-run",
            ]

            exit_code = await async_main(argv)
            self.assertEqual(exit_code, 0, f"Expected 0 exit code, got {exit_code}")

            # 1. Verify SQLite Database State
            db_path = outdir / "session.db"
            self.assertTrue(db_path.is_file(), "session.db was not created")

            store = SessionStore(db_path)
            self.assertEqual(store.get_metadata("target"), "https://app.example.com/")
            self.assertEqual(store.get_metadata("domain"), "app.example.com")
            self.assertEqual(store.get_metadata("version"), "3.0.0")

            stages = store.get_stages()
            # Verify every standard stage is tracked
            for stage_name in ("waf", "subdomains", "probing", "takeover", "urls", "fuzzing", "vuln_xss", "vuln_sqli", "vuln_lfi"):
                self.assertIn(stage_name, stages, f"Stage {stage_name} not found in database stages")
                self.assertEqual(stages[stage_name]["status"], "completed", f"Stage {stage_name} status not completed")

            # 2. Verify Flat File Artifacts Exported
            self.assertTrue((outdir / "subdomains.txt").is_file(), "subdomains.txt missing")
            self.assertTrue((outdir / "live.txt").is_file(), "live.txt missing")
            self.assertTrue((outdir / "params.txt").is_file(), "params.txt missing")
            self.assertTrue((outdir / "200-ok.txt").is_file(), "200-ok.txt missing")

            # 3. Verify HTML Report Generation
            report_path = outdir / "report.html"
            self.assertTrue(report_path.is_file(), "report.html missing")
            report_html = report_path.read_text(encoding="utf-8")
            self.assertIn("ShadowRecon v3.0 Report", report_html)
            self.assertIn("https://app.example.com/", report_html)
            self.assertIn("<svg", report_html)  # Embedded SVG bar chart
            self.assertIn("Pipeline Stages", report_html)

    async def test_stage_resumption_e2e(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir) / "resume_run"
            wordlist = Path(tmpdir) / "words.txt"
            wordlist.write_text("admin\napi\n", encoding="utf-8")

            # Run 1: Only run subdomains & probing
            argv1 = [
                "-u", "https://app.example.com/",
                "-w", str(wordlist),
                "-o", str(outdir),
                "--stages", "subdomains,probing",
                "--dry-run",
            ]
            code1 = await async_main(argv1)
            self.assertEqual(code1, 0)

            store = SessionStore(outdir / "session.db")
            self.assertTrue(store.is_stage_completed("subdomains"))
            self.assertTrue(store.is_stage_completed("probing"))
            self.assertFalse(store.is_stage_completed("fuzzing"))

            # Run 2: Run all stages without --force-rerun
            # subdomains & probing should be resumed (skipped), fuzzing should complete
            argv2 = [
                "-u", "https://app.example.com/",
                "-w", str(wordlist),
                "-o", str(outdir),
                "--dry-run",
            ]
            code2 = await async_main(argv2)
            self.assertEqual(code2, 0)

            stages = store.get_stages()
            self.assertEqual(stages["subdomains"]["status"], "completed")
            self.assertEqual(stages["probing"]["status"], "completed")
            self.assertEqual(stages["fuzzing"]["status"], "completed")

    async def test_toml_config_file_e2e(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            outdir = tmp / "toml_out"
            toml_file = tmp / "shadowrecon.toml"
            wordlist = tmp / "words.txt"
            wordlist.write_text("admin\n", encoding="utf-8")

            toml_content = f"""
[shadowrecon]
target = "https://toml.example.com/"
wordlist = "{wordlist}"
outdir = "{outdir}"
stages = "subdomains,probing"
threads = 3
"""
            toml_file.write_text(toml_content.strip(), encoding="utf-8")

            argv = [
                "--config", str(toml_file),
                "--dry-run",
            ]
            code = await async_main(argv)
            self.assertEqual(code, 0)

            store = SessionStore(outdir / "session.db")
            self.assertEqual(store.get_metadata("target"), "https://toml.example.com/")
            self.assertEqual(store.get_metadata("domain"), "toml.example.com")
            self.assertTrue(store.is_stage_completed("subdomains"))
            self.assertTrue(store.is_stage_completed("probing"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
