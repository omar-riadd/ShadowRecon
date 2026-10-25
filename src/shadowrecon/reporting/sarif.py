"""OASIS SARIF v2.1.0 compliant exporter with CWE metadata mapping for ShadowRecon."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from shadowrecon import __version__
from shadowrecon.storage.session import FindingRecord, SessionStore

log = logging.getLogger("shadowrecon.reporting.sarif")

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/core/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"

# Vulnerability type to (CWE ID, Rule Name, Short Description)
CWE_DEFINITIONS: Dict[str, Tuple[str, str, str]] = {
    "xss": (
        "CWE-79",
        "CrossSiteScripting",
        "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    ),
    "sqli": (
        "CWE-89",
        "SqlInjection",
        "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    ),
    "lfi": (
        "CWE-22",
        "PathTraversal",
        "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    ),
    "ssrf": (
        "CWE-918",
        "ServerSideRequestForgery",
        "Server-Side Request Forgery (SSRF)",
    ),
    "takeover": (
        "CWE-284",
        "SubdomainTakeover",
        "Improper Access Control (Subdomain DNS Takeover)",
    ),
}

SEVERITY_TO_SARIF_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def resolve_cwe_metadata(vuln_type: str) -> Tuple[str, str, str, str]:
    """Resolve (cwe_id, rule_id, rule_name, description) for a vulnerability type."""
    v_lower = vuln_type.lower()

    # 1. Check known core types
    for key, (cwe, name, desc) in CWE_DEFINITIONS.items():
        if key in v_lower:
            rule_id = f"SR-{cwe}-{name.upper()}"
            return cwe, rule_id, name, desc

    # 2. Check for Nuclei CVE template identifiers (e.g. Nuclei:cve-2023-1234)
    if "cve-" in v_lower:
        parts = vuln_type.split(":")
        template_id = parts[-1].strip().upper() if len(parts) > 1 else vuln_type.upper()
        rule_id = f"SR-{template_id}"
        return "CWE-937", rule_id, "UsingVulnerableLibrary", f"Vulnerability detected via template {template_id}"

    # 3. Generic fallback
    clean_name = "".join(c for c in vuln_type.title() if c.isalnum()) or "SecurityWeakness"
    rule_id = f"SR-CWE-699-{clean_name.upper()}"
    return "CWE-699", rule_id, clean_name, f"Security weakness detected: {vuln_type}"


def generate_sarif_dict(
    store: SessionStore,
    tool_version: str = __version__,
) -> Dict[str, Any]:
    """Build a complete SARIF v2.1.0 dictionary from SessionStore records."""
    findings = store.get_findings()

    rules_by_id: Dict[str, Dict[str, Any]] = {}
    rule_id_to_index: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        cwe_id, rule_id, rule_name, desc = resolve_cwe_metadata(f.vuln_type)
        cwe_num = cwe_id.replace("CWE-", "")
        level = SEVERITY_TO_SARIF_LEVEL.get(f.severity.lower(), "warning")

        if rule_id not in rules_by_id:
            rule_index = len(rules_by_id)
            rule_id_to_index[rule_id] = rule_index
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": desc},
                "fullDescription": {"text": f.details or desc},
                "defaultConfiguration": {"level": level},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                "properties": {
                    "tags": ["security", "cwe", f"cwe-{cwe_num}", f.vuln_type.lower()],
                    "problem.severity": level,
                    "cwe": cwe_id,
                },
            }

        rule_idx = rule_id_to_index[rule_id]
        result_item: Dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_idx,
            "level": level,
            "message": {
                "text": f"[{f.severity.upper()}] {f.vuln_type} vulnerability discovered on {f.target_url}"
                + (f" (details: {f.details})" if f.details else "")
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.target_url,
                        }
                    }
                }
            ],
            "properties": {
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "payload": f.payload,
                "source_tool": f.source_tool,
                "discovered_at": f.timestamp,
            },
        }
        results.append(result_item)

    sarif_doc: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ShadowRecon",
                        "version": tool_version,
                        "informationUri": "https://github.com/omar-riadd/ShadowRecon",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return sarif_doc


def export_sarif(
    store: SessionStore,
    output_path: Path,
    tool_version: str = __version__,
) -> Path:
    """Export SessionStore findings to a SARIF v2.1.0 JSON file."""
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = generate_sarif_dict(store, tool_version=tool_version)
    output_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    log.info("SARIF report exported -> %s (%d results)", output_path, len(data["runs"][0]["results"]))
    return output_path
