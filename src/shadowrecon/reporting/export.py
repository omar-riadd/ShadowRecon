"""Enterprise machine-readable JSON manifest and tabular CSV exporters for ShadowRecon."""
from __future__ import annotations

import csv
import json
import logging
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from shadowrecon import __version__
from shadowrecon.reporting.sarif import resolve_cwe_metadata
from shadowrecon.storage.session import SessionStore

log = logging.getLogger("shadowrecon.reporting.export")


def build_manifest_dict(
    store: SessionStore,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Construct a full machine-readable manifest dictionary from SessionStore."""
    target = store.get_metadata("target", meta.get("Target", "unknown") if meta else "unknown")
    domain = store.get_metadata("domain", meta.get("Domain", "unknown") if meta else "unknown")
    start_time = store.get_metadata("start_time", "")
    summary_counts = store.get_summary_counts()

    # Enriched findings with CWE identifiers
    findings_raw = store.get_findings()
    findings_data = []
    for f in findings_raw:
        item = asdict(f)
        cwe_id, _, _, _ = resolve_cwe_metadata(f.vuln_type)
        item["cwe"] = cwe_id
        findings_data.append(item)

    # Hosts with full status codes and headers
    hosts_data = [asdict(h) for h in store.get_host_records()]

    manifest: Dict[str, Any] = {
        "generator": {
            "name": "ShadowRecon",
            "version": f"v{__version__}",
            "generated_at": datetime.now().isoformat(),
        },
        "target": {
            "url": target,
            "domain": domain,
            "scan_started_at": start_time,
        },
        "summary": summary_counts,
        "stages": store.get_stages(),
        "assets": {
            "subdomains": store.get_subdomains(),
            "hosts": hosts_data,
            "parameterized_urls": store.get_urls(),
        },
        "findings": findings_data,
        "waf_bypasses": store.get_waf_bypasses(),
    }
    return manifest


def export_json(
    store: SessionStore,
    output_path: Path,
    meta: Optional[Dict[str, Any]] = None,
) -> Path:
    """Export complete session data as a structured JSON manifest."""
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = build_manifest_dict(store, meta=meta)
    output_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    log.info("JSON manifest exported -> %s", output_path)
    return output_path


def export_csv(
    store: SessionStore,
    output_dir: Path,
) -> Dict[str, Path]:
    """Export session data into standardized RFC 4180 CSV tables."""
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    generated: Dict[str, Path] = {}

    # 1. Subdomains CSV
    sub_path = output_dir / "subdomains.csv"
    with sub_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["subdomain"])
        for sub in store.get_subdomains():
            writer.writerow([sub])
    generated["subdomains"] = sub_path

    # 2. Hosts CSV
    host_path = output_dir / "hosts.csv"
    with host_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "status_code", "title", "webserver", "content_length", "created_at"])
        for h in store.get_host_records():
            writer.writerow([h.url, h.status_code, h.title, h.webserver, h.content_length, h.timestamp])
    generated["hosts"] = host_path

    # 3. URLs CSV
    url_path = output_dir / "urls.csv"
    with url_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url"])
        for u in store.get_urls():
            writer.writerow([u])
    generated["urls"] = url_path

    # 4. Findings CSV
    find_path = output_dir / "findings.csv"
    with find_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["vuln_type", "cwe", "severity", "target_url", "payload", "details", "source_tool", "created_at"])
        for finding in store.get_findings():
            cwe_id, _, _, _ = resolve_cwe_metadata(finding.vuln_type)
            writer.writerow([
                finding.vuln_type,
                cwe_id,
                finding.severity,
                finding.target_url,
                finding.payload,
                finding.details,
                finding.source_tool,
                finding.timestamp,
            ])
    generated["findings"] = find_path

    # 5. WAF Bypasses CSV
    waf_path = output_dir / "waf_bypasses.csv"
    with waf_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["desc", "method", "url", "status_code", "confirmed"])
        for b in store.get_waf_bypasses():
            writer.writerow([b["desc"], b["method"], b["url"], b["status_code"], 1 if b["confirmed"] else 0])
    generated["waf_bypasses"] = waf_path

    log.info("CSV tables exported to %s: %s", output_dir, ", ".join(generated.keys()))
    return generated
