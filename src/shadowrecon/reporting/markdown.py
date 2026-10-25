"""Markdown report generator for ShadowRecon."""
from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from shadowrecon import __version__
from shadowrecon.reporting.sarif import resolve_cwe_metadata
from shadowrecon.storage.diff import SessionDiff
from shadowrecon.storage.session import SessionStore

log = logging.getLogger("shadowrecon.reporting.markdown")


def generate_markdown_report(
    store: SessionStore,
    meta: Optional[Dict[str, Any]] = None,
    diff: Optional[SessionDiff] = None,
) -> str:
    """Generate a GitHub-Flavored Markdown report summarizing the scan session."""
    target = store.get_metadata("target", meta.get("Target", "unknown") if meta else "unknown")
    domain = store.get_metadata("domain", meta.get("Domain", "unknown") if meta else "unknown")
    start_time = store.get_metadata("start_time", datetime.now().isoformat())
    counts = store.get_summary_counts()
    findings = store.get_findings()
    stages = store.get_stages()
    bypasses = store.get_waf_bypasses()

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: (sev_order.get(f.severity.lower(), 5), f.vuln_type, f.target_url),
    )

    by_sev: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.severity.lower()
        by_sev[s] = by_sev.get(s, 0) + 1

    sub_count = counts.get("Subdomains", len(store.get_subdomains()))
    host_count = counts.get("Live hosts", len(store.get_hosts()))
    url_count = counts.get("Parameterized URLs", len(store.get_urls()))
    bypass_count = counts.get("WAF bypasses", len(bypasses))
    total_findings = counts.get("Vulnerabilities", len(findings))

    lines: List[str] = [
        f"# ShadowRecon Scan Report — {domain}",
        "",
        "> Automated Attack Surface Discovery & Vulnerability Intelligence",
        "",
        "## Executive Summary",
        "",
        f"- **Target URL:** `{target}`",
        f"- **Domain:** `{domain}`",
        f"- **Scan Date:** {start_time}",
        f"- **ShadowRecon Version:** `v{__version__}`",
        f"- **Total Vulnerabilities:** **{total_findings}**",
        "",
        "### Asset & Discovery Metrics",
        "",
        "| Metric | Count |",
        "|---|---:|",
        f"| Discovered Subdomains | {sub_count} |",
        f"| Active HTTP/S Hosts | {host_count} |",
        f"| Parameterized Endpoints | {url_count} |",
        f"| Confirmed WAF Bypasses | {bypass_count} |",
        "",
        "### Vulnerability Severity Breakdown",
        "",
        "| Severity | Count |",
        "|---|---:|",
        f"| 🔴 Critical | {by_sev.get('critical', 0)} |",
        f"| 🟠 High | {by_sev.get('high', 0)} |",
        f"| 🟡 Medium | {by_sev.get('medium', 0)} |",
        f"| 🔵 Low | {by_sev.get('low', 0)} |",
        f"| ⚪ Info | {by_sev.get('info', 0)} |",
        "",
    ]

    # Vulnerability Details Section
    lines.extend([
        "## Identified Vulnerabilities",
        "",
    ])

    if not sorted_findings:
        lines.extend([
            "_No vulnerabilities detected in this scan session._",
            "",
        ])
    else:
        lines.extend([
            "| Severity | Vulnerability | CWE | Target URL | Source Tool |",
            "|---|---|---|---|---|",
        ])
        for f in sorted_findings:
            sev_badge = {
                "critical": "🔴 Critical",
                "high": "🟠 High",
                "medium": "🟡 Medium",
                "low": "🔵 Low",
                "info": "⚪ Info",
            }.get(f.severity.lower(), f.severity.upper())

            cwe_id, cwe_name, _, _ = resolve_cwe_metadata(f.vuln_type)
            cwe_str = f"[{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html)" if cwe_id else "N/A"
            target_str = f"`{f.target_url}`" if f.target_url else "_N/A_"

            lines.append(
                f"| {sev_badge} | **{f.vuln_type}** | {cwe_str} | {target_str} | `{f.source_tool}` |"
            )

        lines.append("")

        # Detailed breakdown of high/critical findings
        high_crit = [f for f in sorted_findings if f.severity.lower() in ("critical", "high")]
        if high_crit:
            lines.extend([
                "### High & Critical Vulnerability Details",
                "",
            ])
            for idx, f in enumerate(high_crit, 1):
                cwe_id, cwe_name, cvss, desc = resolve_cwe_metadata(f.vuln_type)
                lines.extend([
                    f"#### {idx}. [{f.severity.upper()}] {f.vuln_type}",
                    "",
                    f"- **Target:** `{f.target_url}`",
                    f"- **Source Tool:** `{f.source_tool}`",
                    f"- **CWE:** {cwe_id}: {cwe_name}",
                    f"- **CVSS Baseline:** {cvss}",
                ])
                if f.payload:
                    lines.extend([
                        f"- **Payload / Match:** `{f.payload}`",
                    ])
                if f.details:
                    lines.extend([
                        "",
                        "**Details:**",
                        "```text",
                        f.details.strip(),
                        "```",
                    ])
                lines.append("")

    # WAF Bypasses Section
    if bypasses:
        lines.extend([
            "## WAF Bypasses & Candidate Mutations",
            "",
            "| Method | Path Prefix | Headers |",
            "|---|---|---|",
        ])
        for b in bypasses:
            method = b.get("method", "GET")
            prefix = b.get("path_prefix", "") or "/"
            hdrs = b.get("headers", {})
            hdrs_str = ", ".join(f"`{k}: {v}`" for k, v in hdrs.items()) if hdrs else "None"
            lines.append(f"| `{method}` | `{prefix}` | {hdrs_str} |")
        lines.append("")

    # Differential Drift Analysis Section (if diff provided)
    if diff:
        prior_name = Path(diff.prior_db_path).name if diff.prior_db_path else "Prior"
        status_changes = getattr(diff, "status_changes", [])
        lines.extend([
            "## Differential Drift Analysis",
            "",
            f"- **Prior Session Database:** `{prior_name}`",
            f"- **New Findings:** {len(diff.new_findings)}",
            f"- **Resolved Findings:** {len(diff.resolved_findings)}",
            f"- **New Subdomains:** {len(diff.new_subdomains)}",
            f"- **HTTP Status Code Changes:** {len(status_changes)}",
            "",
        ])
        if diff.new_findings:
            lines.extend([
                "### ⚠️ Newly Introduced Findings",
                "",
                "| Severity | Vulnerability | Target URL |",
                "|---|---|---|",
            ])
            for f in diff.new_findings:
                lines.append(f"| {f.severity.upper()} | **{f.vuln_type}** | `{f.target_url}` |")
            lines.append("")

        if status_changes:
            lines.extend([
                "### 🔄 Attack Surface Status Code Transitions",
                "",
                "| URL | Prior Status | Current Status |",
                "|---|---|---|",
            ])
            for sc in status_changes:
                lines.append(f"| `{sc.get('url', '')}` | HTTP {sc.get('old_status', '')} | HTTP {sc.get('new_status', '')} |")
            lines.append("")

    # Pipeline Stages Summary
    if stages:
        stage_list: List[Dict[str, Any]] = []
        if isinstance(stages, dict):
            for st_name, st_info in stages.items():
                item = dict(st_info) if isinstance(st_info, dict) else {}
                item["stage_name"] = st_name
                stage_list.append(item)
        elif isinstance(stages, list):
            stage_list = stages

        if stage_list:
            lines.extend([
                "## Execution Pipeline Stages",
                "",
                "| Stage | Status | Duration (s) | Error / Notes |",
                "|---|---|---:|---|",
            ])
            for s in stage_list:
                status_icon = "✅" if s.get("status") in ("completed", "resumed") else "⚠️"
                err = s.get("error_message", "") or "-"
                lines.append(f"| `{s.get('stage_name', '')}` | {status_icon} {s.get('status', '')} | {s.get('duration_seconds', 0.0):.2f}s | {err} |")
            lines.append("")

    lines.extend([
        "---",
        f"_Generated automatically by ShadowRecon v{__version__} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}._",
        "",
    ])

    return "\n".join(lines)


def export_markdown(
    store: SessionStore,
    output_path: Path,
    meta: Optional[Dict[str, Any]] = None,
    diff: Optional[SessionDiff] = None,
) -> Path:
    """Generate and write a Markdown report to disk."""
    content = generate_markdown_report(store, meta=meta, diff=diff)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    log.info("Markdown report generated -> %s (%d bytes)", output_path, len(content))
    return output_path
