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
    """Execute Dalfox reflected XSS scanner across harvested parameterized endpoints."""
    params = ctx.store.get_urls()
    if not params:
        log.info("No parameterized URLs available for XSS scanning. Skipping.")
        return []

    params_file = ctx.config.outdir / "params.txt"
    params_file.parent.mkdir(parents=True, exist_ok=True)
    params_file.write_text("\n".join(params) + "\n", encoding="utf-8")

    out_file = ctx.config.outdir / "xss_dalfox.txt"
    extra_args = ctx.bypass_context.dalfox_args()

    cmd = [
        "dalfox",
        "file",
        str(params_file),
        "--only-poc",
        "--worker",
        "1",
        "-o",
        str(out_file),
        *extra_args,
    ]

    res = await ctx.executor.run(cmd, proxy=True, timeout=600)

    findings: List[FindingRecord] = []
    lines: List[str] = []
    if out_file.is_file():
        lines = read_lines(out_file)
    elif res.stdout.strip():
        lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]

    for line in lines:
        f = parse_dalfox_line(line)
        if f:
            findings.append(f)
            ctx.store.add_finding(f)
            await ctx.bus.publish("finding", f, source="dalfox")

    log.info("Dalfox XSS scan complete: %d vulnerabilities -> %s", len(findings), out_file.name)
    return findings


async def run_sqli_stage(ctx: StageContext) -> List[FindingRecord]:
    """Execute SQLMap vulnerability scanner against parameterized URLs."""
    params = ctx.store.get_urls()
    if not params:
        log.info("No parameterized URLs available for SQLi scanning. Skipping.")
        return []

    params_file = ctx.config.outdir / "params.txt"
    params_file.write_text("\n".join(params) + "\n", encoding="utf-8")

    out_dir = ctx.config.outdir / "sqlmap_out"
    out_dir.mkdir(parents=True, exist_ok=True)
    extra_args = ctx.bypass_context.sqlmap_args()

    cmd = [
        "sqlmap",
        "-m",
        str(params_file),
        "--batch",
        "--random-agent",
        "--level",
        "1",
        "--risk",
        "1",
        f"--output-dir={out_dir}",
        *extra_args,
    ]

    res = await ctx.executor.run(cmd, proxy=True, timeout=3600)

    # Inspect sqlmap output directory for confirmed targets
    findings: List[FindingRecord] = []
    for item in out_dir.iterdir():
        if item.is_dir() and item.name != "csv":
            target_host = item.name
            log_file = item / "log"
            details = log_file.read_text(errors="replace") if log_file.is_file() else ""
            if "sqlmap identified the following injection points" in details.lower():
                f = FindingRecord(
                    vuln_type="SQLi",
                    severity="critical",
                    target_url=f"http://{target_host}/",
                    details=details[:500],
                    source_tool="sqlmap",
                )
                findings.append(f)
                ctx.store.add_finding(f)
                await ctx.bus.publish("finding", f, source="sqlmap")

    log.info("SQLMap scan complete: %d confirmed SQLi targets", len(findings))
    return findings


async def run_lfi_stage(ctx: StageContext) -> None:
    """Execute FFUF LFI/SSRF parameter fuzzing."""
    if not ctx.config.lfi_payloads or not ctx.config.lfi_payloads.is_file():
        log.info("No LFI payloads provided. Skipping LFI stage.")
        return

    params = ctx.store.get_urls()
    if not params:
        log.info("No parameterized URLs available for LFI fuzzing. Skipping.")
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
