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
    if not ctx.config.nuclei_templates.is_dir():
        if not ctx.config.dry_run:
            log.warning(
                "Nuclei templates directory not found at '%s'. Skipping Nuclei scan stage. "
                "(Run 'nuclei -ut' to download official templates)",
                ctx.config.nuclei_templates,
            )
            return []
        log.debug("Nuclei templates directory '%s' simulated in dry-run mode.", ctx.config.nuclei_templates)

    hosts = ctx.store.get_hosts()
    if not hosts:
        log.info("No live hosts available for Nuclei scanning. Skipping.")
        return []

    live_file = ctx.config.outdir / "live.txt"
    live_file.parent.mkdir(parents=True, exist_ok=True)
    live_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    out_file = ctx.config.outdir / "nuclei_findings.jsonl"
    cmd = [
        "nuclei",
        "-l",
        str(live_file),
        "-t",
        str(ctx.config.nuclei_templates),
        "-jsonl",
        "-o",
        str(out_file),
        "-timeout",
        "50",
        "-silent",
    ]

    # Add CVSS severity filtering
    if ctx.config.nuclei_severity:
        cmd.extend(["-s", ctx.config.nuclei_severity])

    # Add template tag filtering if specified
    if ctx.config.nuclei_tags:
        cmd.extend(["-tags", ctx.config.nuclei_tags])

    res = await ctx.executor.run(cmd, proxy=True, timeout=3600)

    findings: List[FindingRecord] = []
    lines: List[str] = []
    if out_file.is_file():
        lines = read_lines(out_file)
    elif res.stdout.strip():
        lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]

    for line in lines:
        record = parse_nuclei_json_line(line)
        if record:
            findings.append(record)
            ctx.store.add_finding(record)
            await ctx.bus.publish("finding", record, source="nuclei")

    log.info(
        "Nuclei vulnerability scan complete: %d findings recorded (severities: %s)",
        len(findings),
        ctx.config.nuclei_severity or "all",
    )
    return findings
