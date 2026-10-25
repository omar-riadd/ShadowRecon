"""Unit tests for Phase 3: Markdown and PDF reporting, and multi-platform webhooks."""
from __future__ import annotations

import asyncio
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from shadowrecon.pipeline.queue import AsyncEventBus, Event
from shadowrecon.reporting.markdown import export_markdown, generate_markdown_report
from shadowrecon.reporting.pdf import export_pdf, generate_pdf_html
from shadowrecon.reporting.webhook import (
    attach_finding_notifier,
    build_completion_payload,
    build_finding_payload,
    detect_webhook_type,
    send_webhook,
)
from shadowrecon.storage.diff import SessionDiff
from shadowrecon.storage.session import FindingRecord, HostRecord, SessionStore


class TestReportingAndWebhooks(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_session.db"
        self.store = SessionStore(self.db_path)

        self.store.set_metadata("target", "https://api.target.com")
        self.store.set_metadata("domain", "target.com")
        self.store.set_metadata("start_time", "2026-10-25 12:00:00")

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _seed_sample_data(self) -> None:
        self.store.add_subdomains(["sub1.target.com", "sub2.target.com"], "subfinder")
        self.store.add_hosts([
            HostRecord(
                url="https://sub1.target.com",
                status_code=200,
                title="API Gateway",
                webserver="nginx",
                content_length=1024,
            )
        ])
        self.store.add_urls(["https://sub1.target.com/api?id=1"], "paramspider")
        self.store.add_waf_bypass(
            desc="Cloudflare bypass",
            method="POST",
            url="https://api.target.com",
            headers={"X-Forwarded-For": "127.0.0.1"},
            status_code=200,
            confirmed=True,
        )
        self.store.set_stage("probing", "completed", 1.25)

        # Critical SQLi finding
        self.store.add_finding(
            FindingRecord(
                target_url="https://sub1.target.com/api?id=1",
                vuln_type="sqli",
                severity="critical",
                source_tool="sqlmap",
                payload="id=1' OR '1'='1",
                details="Boolean-based blind SQL Injection detected on parameter 'id'.",
            )
        )
        # High Reflected XSS finding
        self.store.add_finding(
            FindingRecord(
                target_url="https://sub1.target.com/search?q=test",
                vuln_type="xss",
                severity="high",
                source_tool="dalfox",
                payload='<script>alert(1)</script>',
                details="Reflected Cross-Site Scripting verified via dalfox headless browser.",
            )
        )
        # Medium Subdomain Takeover finding
        self.store.add_finding(
            FindingRecord(
                target_url="https://sub2.target.com",
                vuln_type="subdomain_takeover",
                severity="medium",
                source_tool="nuclei",
                payload="cname: target.s3.amazonaws.com",
                details="Dangling S3 CNAME record detected.",
            )
        )

    # -------------------------------------------------------------------------
    # Markdown Report Tests
    # -------------------------------------------------------------------------
    def test_markdown_report_empty_session(self) -> None:
        report = generate_markdown_report(self.store)
        self.assertIn("# ShadowRecon Scan Report — target.com", report)
        self.assertIn("## Executive Summary", report)
        self.assertIn("_No vulnerabilities detected in this scan session._", report)

    def test_markdown_report_populated_session(self) -> None:
        self._seed_sample_data()
        report = generate_markdown_report(self.store)

        self.assertIn("# ShadowRecon Scan Report — target.com", report)
        self.assertIn("🔴 Critical | 1 |", report)
        self.assertIn("🟠 High | 1 |", report)
        self.assertIn("🟡 Medium | 1 |", report)
        self.assertIn("CWE-89", report)
        self.assertIn("CWE-79", report)
        self.assertIn("Boolean-based blind SQL Injection", report)
        self.assertIn("## WAF Bypasses & Candidate Mutations", report)
        self.assertIn("## Execution Pipeline Stages", report)

    def test_markdown_report_with_differential_drift(self) -> None:
        self._seed_sample_data()
        diff = SessionDiff(
            prior_db_path="/tmp/prior_session.db",
            current_db_path=str(self.db_path),
            new_findings=[
                FindingRecord(
                    target_url="https://sub1.target.com/api?id=1",
                    vuln_type="sqli",
                    severity="critical",
                    source_tool="sqlmap",
                )
            ],
            resolved_findings=[],
            new_subdomains=["sub1.target.com"],
            removed_subdomains=[],
            status_changes=[
                {
                    "url": "https://sub1.target.com/admin",
                    "old_status": 403,
                    "new_status": 200,
                }
            ],
        )

        report = generate_markdown_report(self.store, diff=diff)
        self.assertIn("## Differential Drift Analysis", report)
        self.assertIn("Newly Introduced Findings", report)
        self.assertIn("Attack Surface Status Code Transitions", report)
        self.assertIn("HTTP 403 | HTTP 200", report)

    def test_export_markdown_writes_file(self) -> None:
        self._seed_sample_data()
        out_file = Path(self.tmp_dir.name) / "out" / "report.md"
        result_path = export_markdown(self.store, out_file)

        self.assertTrue(result_path.is_file())
        content = result_path.read_text(encoding="utf-8")
        self.assertIn("# ShadowRecon Scan Report", content)
        self.assertIn("sqli", content)

    # -------------------------------------------------------------------------
    # PDF Report Tests
    # -------------------------------------------------------------------------
    def test_generate_pdf_html(self) -> None:
        self._seed_sample_data()
        html = generate_pdf_html(self.store)

        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Security Assessment Report", html)
        self.assertIn("target.com", html)
        self.assertIn("CWE-89", html)
        self.assertIn("High & Critical Vulnerability Analysis", html)

    def test_export_pdf_creates_valid_pdf_binary(self) -> None:
        self._seed_sample_data()
        pdf_out = Path(self.tmp_dir.name) / "report.pdf"
        res_path = export_pdf(self.store, pdf_out)

        self.assertTrue(res_path.is_file())
        with open(res_path, "rb") as f:
            header = f.read(5)
            self.assertEqual(header, b"%PDF-")
        self.assertGreater(res_path.stat().st_size, 1000)

    # -------------------------------------------------------------------------
    # Webhook Target Classification & Payloads Tests
    # -------------------------------------------------------------------------
    def test_detect_webhook_type(self) -> None:
        self.assertEqual(
            detect_webhook_type("https://discord.com/api/webhooks/123/xyz"),
            "discord",
        )
        self.assertEqual(
            detect_webhook_type("https://discordapp.com/api/webhooks/123/xyz"),
            "discord",
        )
        self.assertEqual(
            detect_webhook_type("https://hooks.slack.com/services/T00/B00/X00"),
            "slack",
        )
        self.assertEqual(
            detect_webhook_type("https://webhook.site/abcdef-1234"),
            "generic",
        )

    def test_build_completion_payloads(self) -> None:
        manifest = {
            "target": {"url": "https://example.com", "domain": "example.com"},
            "summary": {
                "subdomains": 12,
                "hosts": 8,
                "urls": 54,
                "findings": 3,
                "by_severity": {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0},
            },
        }

        # Discord
        discord_p = build_completion_payload(manifest, webhook_type="discord", status="completed")
        self.assertIn("embeds", discord_p)
        self.assertIn("ShadowRecon Scan Finished (completed)", discord_p["content"])
        self.assertEqual(discord_p["embeds"][0]["color"], 0xDC2626)  # Critical color

        # Slack
        slack_p = build_completion_payload(manifest, webhook_type="slack", status="completed")
        self.assertIn("blocks", slack_p)
        self.assertIn("ShadowRecon scan completed", slack_p["text"])

        # Generic
        gen_p = build_completion_payload(manifest, webhook_type="generic", status="completed")
        self.assertEqual(gen_p["event"], "scan_completed")
        self.assertEqual(gen_p["scanner"], "ShadowRecon")
        self.assertEqual(gen_p["status"], "completed")
        self.assertEqual(gen_p["summary"]["findings"], 3)

    def test_build_finding_payloads(self) -> None:
        finding = FindingRecord(
            target_url="https://api.example.com/v1/user?id=1",
            vuln_type="sqli",
            severity="critical",
            source_tool="sqlmap",
            payload="1' OR '1'='1",
        )

        # Discord
        d_finding = build_finding_payload(finding, target="api.example.com", webhook_type="discord")
        self.assertIn("CRITICAL", d_finding["content"])
        self.assertEqual(d_finding["embeds"][0]["title"], "sqli")

        # Slack
        s_finding = build_finding_payload(finding, target="api.example.com", webhook_type="slack")
        self.assertIn("CRITICAL", s_finding["text"])

        # Generic
        g_finding = build_finding_payload(finding, target="api.example.com", webhook_type="generic")
        self.assertEqual(g_finding["event"], "finding_alert")
        self.assertEqual(g_finding["finding"]["vuln_type"], "sqli")

    # -------------------------------------------------------------------------
    # Webhook Delivery and Real-Time Notifier Tests
    # -------------------------------------------------------------------------
    def test_send_webhook_success(self) -> None:
        async def _test() -> None:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__.return_value = mock_resp

            with patch("urllib.request.urlopen", return_value=mock_resp):
                ok = await send_webhook("https://webhook.site/test", {"test": True})
                self.assertTrue(ok)

        asyncio.run(_test())

    def test_send_webhook_failure_handles_gracefully(self) -> None:
        async def _test() -> None:
            with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
                ok = await send_webhook("https://invalid-hook.site/fail", {"test": True})
                self.assertFalse(ok)

        asyncio.run(_test())

    def test_attach_finding_notifier_filters_by_severity(self) -> None:
        async def _test() -> None:
            bus = AsyncEventBus()
            delivered_payloads = []

            async def mock_send(url: str, payload: dict, timeout: float = 10.0) -> bool:
                delivered_payloads.append(payload)
                return True

            with patch("shadowrecon.reporting.webhook.send_webhook", side_effect=mock_send):
                task = await attach_finding_notifier(
                    bus=bus,
                    webhook_url="https://webhook.site/alerts",
                    target="example.com",
                    min_severity="high",
                )

                # Info finding - should be filtered out
                await bus.publish(
                    "finding",
                    FindingRecord(
                        target_url="https://example.com/banner",
                        vuln_type="banner_disclosure",
                        severity="info",
                        source_tool="httpx",
                    ),
                )

                # Low finding - should be filtered out
                await bus.publish(
                    "finding",
                    FindingRecord(
                        target_url="https://example.com/cookie",
                        vuln_type="cookie_without_samesite",
                        severity="low",
                        source_tool="nuclei",
                    ),
                )

                # High finding - should trigger notification
                await bus.publish(
                    "finding",
                    FindingRecord(
                        target_url="https://example.com/search",
                        vuln_type="xss",
                        severity="high",
                        source_tool="dalfox",
                    ),
                )

                # Critical finding - should trigger notification
                await bus.publish(
                    "finding",
                    FindingRecord(
                        target_url="https://example.com/login",
                        vuln_type="sqli",
                        severity="critical",
                        source_tool="sqlmap",
                    ),
                )

                # Close topic and wait for worker
                await bus.close_topic("finding")
                await asyncio.wait_for(task, timeout=1.0)

                self.assertEqual(len(delivered_payloads), 2)
                vuln_types = [p["finding"]["vuln_type"] for p in delivered_payloads]
                self.assertIn("xss", vuln_types)
                self.assertIn("sqli", vuln_types)

        asyncio.run(_test())


if __name__ == "__main__":
    unittest.main()
