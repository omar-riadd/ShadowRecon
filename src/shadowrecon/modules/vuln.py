"""Vulnerability scanning stages: XSS (Dalfox), SQLi (SQLMap), and LFI/SSRF (FFUF)."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List

from shadowrecon.core.scope import read_lines, slugify
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import FindingRecord

log = logging.getLogger("shadowrecon.modules.vuln")


def parse_dalfox_line(line: str) -> FindingRecord | None:
    """Parse Dalfox POC output line into a FindingRecord."""
    clean = line.strip()
    if not clean:
        return None

    # Dalfox formats include:
    # [POC][G][V] http://example.com/?q=1 <script>alert(1)</script>
    # or [POC] http://example.com/?q=1 payload=...
    parts = clean.split()
    target_url = ""
    payload = ""
    for idx, token in enumerate(parts):
        if token.startswith("http://") or token.startswith("https://"):
            target_url = token
            if idx + 1 < len(parts):
                payload = " ".join(parts[idx + 1:])
            break

    if not target_url:
        target_url = parts[-1] if parts else clean

    return FindingRecord(
        vuln_type="XSS",
        severity="high",
        target_url=target_url,
        payload=payload,
        details=clean,
        source_tool="dalfox",
    )


async def run_xss_stage(ctx: StageContext) -> List[FindingRecord]:
    """Execute XSS scanner driver (default: Dalfox) across harvested parameterized endpoints."""
    driver = ctx.drivers.get_driver("xss")
    result = await driver.execute(ctx)
    findings = result.metadata.get("findings", [])
    out_file = ctx.config.outdir / "xss_dalfox.txt"
    log.info("XSS scan complete: %d vulnerabilities -> %s", len(findings), out_file.name)
    return findings


async def run_sqli_stage(ctx: StageContext) -> List[FindingRecord]:
    """Execute SQL injection scanner driver (default: SQLMap) against parameterized URLs."""
    driver = ctx.drivers.get_driver("sqli")
    result = await driver.execute(ctx)
    findings = result.metadata.get("findings", [])
    log.info("SQLMap scan complete: %d confirmed SQLi targets", len(findings))
    return findings


async def run_lfi_stage(ctx: StageContext) -> None:
    """Execute FFUF LFI/SSRF parameter fuzzing."""
    if not ctx.config.lfi_payloads or not ctx.config.lfi_payloads.is_file():
        log.info("No LFI payloads provided. Skipping LFI stage.")
        return

    params = ctx.store.get_urls()
    if ctx.circuit_breaker:
        params = ctx.circuit_breaker.filter_healthy_urls(params)

    if not params:
        log.info("No parameterized URLs available on healthy hosts for LFI fuzzing. Skipping.")
        return

    out_dir = ctx.config.outdir / "ffuf_lfi_ssrf"
    out_dir.mkdir(parents=True, exist_ok=True)
    extra_args = ctx.bypass_context.ffuf_args()

    for base in params:
        if "=" not in base:
            continue
        fuzz_url = re.sub(r"=([^&]*)", "=FUZZ", base, count=1)
        out_csv = out_dir / f"{slugify(fuzz_url)}.csv"
        cmd = [
            "ffuf",
            "-w",
            str(ctx.config.lfi_payloads),
            "-u",
            fuzz_url,
            "-mc",
            "200,500",
            "-of",
            "csv",
            "-o",
            str(out_csv),
            *extra_args,
        ]
        await ctx.executor.run(cmd, proxy=True, timeout=1200)

    log.info("FFUF LFI/SSRF fuzzing complete -> %s", out_dir.name)
