"""Subdomain takeover detection module using Nuclei."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from shadowrecon.core.scope import read_lines
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import FindingRecord

log = logging.getLogger("shadowrecon.modules.takeover")


def find_takeover_templates(base_dir: Path) -> Path | None:
    """Locate the takeover template directory within nuclei-templates."""
    candidates = [
        base_dir / "http" / "takeovers",
        base_dir / "takeovers",
        base_dir / "http" / "cve" / "takeovers",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return None


async def run_takeover_stage(ctx: StageContext) -> List[FindingRecord]:
    """Execute Nuclei subdomain takeover checks with template existence guards."""
    templates = find_takeover_templates(ctx.config.nuclei_templates)
    if templates is None:
        log.warning(
            "Nuclei takeover templates not found in '%s'. Skipping takeover stage. "
            "(Run 'nuclei -ut' to update templates)",
            ctx.config.nuclei_templates,
        )
        return []

    hosts = ctx.store.get_hosts()
    if not hosts:
        log.info("No live hosts available for takeover scanning. Skipping.")
        return []

    live_file = ctx.config.outdir / "live.txt"
    live_file.parent.mkdir(parents=True, exist_ok=True)
    live_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    out_file = ctx.config.outdir / "nuclei_takeover.txt"
    cmd = [
        "nuclei",
        "-l",
        str(live_file),
        "-t",
        str(templates),
        "-o",
        str(out_file),
        "-timeout",
        "50",
        "-silent",
    ]

    res = await ctx.executor.run(cmd, proxy=True, timeout=3600)

    findings: List[FindingRecord] = []
    lines: List[str] = []
    if out_file.is_file():
        lines = read_lines(out_file)
    elif res.stdout.strip():
        lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]

    for line in lines:
        parts = line.split()
        target_url = parts[-1] if parts else ""
        finding = FindingRecord(
            vuln_type="Takeover",
            severity="high",
            target_url=target_url,
            details=line,
            source_tool="nuclei",
        )
        findings.append(finding)
        ctx.store.add_finding(finding)
        await ctx.bus.publish("finding", finding, source="nuclei")

    log.info("Nuclei takeover scan complete: %d findings -> %s", len(findings), out_file.name)
    return findings
