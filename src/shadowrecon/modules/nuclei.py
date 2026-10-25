"""Nuclei vulnerability scanning engine with CVSS severity and tag filtering."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional

from shadowrecon.core.scope import read_lines
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import FindingRecord

log = logging.getLogger("shadowrecon.modules.nuclei")


def parse_nuclei_json_line(line: str) -> Optional[FindingRecord]:
    """Parse a single JSONL event emitted by Nuclei into a structured FindingRecord."""
    clean = line.strip()
    if not clean:
        return None

    try:
        data = json.loads(clean)
        info = data.get("info", {})
        template_id = data.get("template-id", "unknown")
        name = info.get("name", template_id)
        severity = info.get("severity", "medium").lower()
        matched_at = data.get("matched-at") or data.get("host") or ""
        extracted = data.get("extracted-results", [])
        payload = ", ".join(extracted) if isinstance(extracted, list) else str(extracted)
        description = info.get("description", "")
        details = f"[{template_id}] {name}" + (f" - {description[:200]}" if description else "")

        return FindingRecord(
            vuln_type=f"Nuclei:{template_id}",
            severity=severity,
            target_url=matched_at,
            payload=payload,
            details=details,
            source_tool="nuclei",
        )
    except json.JSONDecodeError:
        # Filter out informational and error logs if emitted to stdout
        if clean.startswith(("[INF]", "[WRN]", "[ERR]", "[*]")):
            return None
        # Fallback to plain text line format
        parts = clean.split()
        if not parts:
            return None
        target = parts[-1] if parts[-1].startswith("http") else parts[0]
        return FindingRecord(
            vuln_type="Nuclei",
            severity="medium",
            target_url=target,
            details=clean,
            source_tool="nuclei",
        )


async def run_nuclei_stage(ctx: StageContext) -> List[FindingRecord]:
    """Execute full Nuclei vulnerability scan with CVSS severity and tag filters."""
    driver = ctx.drivers.get_driver("nuclei")
    result = await driver.execute(ctx)
    findings = result.metadata.get("findings", [])
    log.info(
        "Nuclei vulnerability scan complete: %d findings recorded (severities: %s)",
        len(findings),
        ctx.config.nuclei_severity or "all",
    )
    return findings

