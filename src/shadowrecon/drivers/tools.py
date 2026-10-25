"""Concrete ScannerDriver implementations for ShadowRecon tools."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from shadowrecon.core.executor import resolve_binary
from shadowrecon.core.scope import is_in_scope, read_lines
from shadowrecon.drivers.base import ScanResult, ScannerDriver
from shadowrecon.modules.nuclei import parse_nuclei_json_line
from shadowrecon.modules.vuln import parse_dalfox_line
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import FindingRecord, HostRecord

log = logging.getLogger("shadowrecon.drivers.tools")


class SubfinderDriver(ScannerDriver):
    """Concrete driver for ProjectDiscovery subfinder passive subdomain enumeration."""

    def __init__(self, binary_name: str = "subfinder") -> None:
        super().__init__(name="subfinder", binary_name=binary_name)

    async def execute(self, ctx: StageContext, **kwargs: Any) -> ScanResult:
        out_file = ctx.config.outdir / "subdomains.txt"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        cmd = [self.binary_name, "-silent", "-d", ctx.config.domain]

        res = await ctx.executor.run(cmd, proxy=True, timeout=600)

        subs: Set[str] = set()
        for line in res.stdout.splitlines():
            clean = line.strip().lower()
            if clean and ctx.is_in_scope(clean):
                subs.add(clean)

        if not subs:
            if ctx.config.dry_run or not out_file.is_file():
                subs.add(ctx.config.domain.lower())
            elif out_file.is_file():
                for line in read_lines(out_file):
                    clean = line.strip().lower()
                    if clean and ctx.is_in_scope(clean):
                        subs.add(clean)

        clean_subs = sorted(list(subs))
        out_file.write_text("\n".join(clean_subs) + "\n", encoding="utf-8")

        ctx.store.add_subdomains(clean_subs, source=self.name)
        for sub in clean_subs:
            await ctx.bus.publish("subdomain", sub, source=self.name)

        return ScanResult(
            success=res.success,
            output_files=[out_file],
            items_count=len(clean_subs),
            raw_output=res.stdout,
            error=res.stderr if not res.success else "",
            metadata={"subdomains": clean_subs},
        )


class HttpxDriver(ScannerDriver):
    """Concrete driver for ProjectDiscovery httpx HTTP probing tool."""

    def __init__(self, binary_name: str = "httpx") -> None:
        super().__init__(name="httpx", binary_name=binary_name)

    async def execute(self, ctx: StageContext, input_file: Optional[Path] = None, **kwargs: Any) -> ScanResult:
        subs = ctx.store.get_subdomains()
        if not subs:
            subs = [ctx.config.domain]

        sub_file = input_file or (ctx.config.outdir / "subdomains.txt")
        sub_file.parent.mkdir(parents=True, exist_ok=True)
        sub_file.write_text("\n".join(subs) + "\n", encoding="utf-8")

        live_file = ctx.config.outdir / "live.txt"

        ports_spec = getattr(ctx.config, "probe_ports", "default")
        port_args: List[str] = []
        if ports_spec and ports_spec != "default":
            if ports_spec == "web":
                port_args = ["-ports", "80,443,8000,8008,8080,8443,8888,9000,9090,9443"]
            else:
                port_args = ["-ports", ports_spec]

        cmd = [
            self.binary_name,
            "-silent",
            "-l",
            str(sub_file),
            "-mc",
            "200,301,302",
            *port_args,
            "-o",
            str(live_file),
        ]

        res = await ctx.executor.run(cmd, proxy=True, timeout=900)

        hosts: List[str] = []
        if live_file.is_file():
            hosts = read_lines(live_file)
        elif res.stdout.strip():
            hosts = [l.strip() for l in res.stdout.splitlines() if l.strip().startswith("http")]

        if not hosts and ctx.config.dry_run:
            hosts = [ctx.config.target.rstrip("/")]
            live_file.write_text(hosts[0] + "\n", encoding="utf-8")

        host_records = [HostRecord(url=h, status_code=200) for h in hosts]
        ctx.store.add_hosts(host_records)
        for h in hosts:
            await ctx.bus.publish("host", h, source=self.name)

        return ScanResult(
            success=res.success,
            output_files=[live_file] if live_file.is_file() else [],
            items_count=len(hosts),
            raw_output=res.stdout,
            error=res.stderr if not res.success else "",
            metadata={"hosts": hosts},
        )


class KatanaDriver(ScannerDriver):
    """Concrete driver for ProjectDiscovery katana modern web crawler."""

    def __init__(self, binary_name: str = "katana") -> None:
        super().__init__(name="katana", binary_name=binary_name)

    async def execute(self, ctx: StageContext, live_file: Optional[Path] = None, **kwargs: Any) -> ScanResult:
        target_file = live_file or (ctx.config.outdir / "live.txt")
        if not target_file.is_file() and not ctx.config.dry_run:
            return ScanResult(success=True, items_count=0, error="Live hosts file not found for Katana crawler")

        out_file = ctx.config.outdir / "katana.txt"
        cmd = [
            self.binary_name,
            "-list",
            str(target_file),
            "-silent",
            "-jc",
            "-kf",
            "all",
        ]
        res = await ctx.executor.run(cmd, proxy=True, timeout=900, capture_to=out_file)
        urls = [line.strip() for line in res.stdout.splitlines() if line.strip().startswith("http")]

        return ScanResult(
            success=res.success,
            output_files=[out_file] if out_file.is_file() else [],
            items_count=len(urls),
            raw_output=res.stdout,
            error=res.stderr if not res.success else "",
            metadata={"urls": urls},
        )


class NucleiDriver(ScannerDriver):
    """Concrete driver for ProjectDiscovery nuclei vulnerability scanner."""

    def __init__(self, binary_name: str = "nuclei") -> None:
        super().__init__(name="nuclei", binary_name=binary_name)

    async def execute(self, ctx: StageContext, live_file: Optional[Path] = None, **kwargs: Any) -> ScanResult:
        if not ctx.config.nuclei_templates.is_dir():
            if not ctx.config.dry_run:
                log.warning(
                    "Nuclei templates directory not found at '%s'. Skipping Nuclei scan stage.",
                    ctx.config.nuclei_templates,
                )
                return ScanResult(
                    success=True,
                    items_count=0,
                    error=f"Nuclei templates directory not found at '{ctx.config.nuclei_templates}'",
                    metadata={"findings": []},
                )

        hosts = ctx.store.get_hosts()
        if not hosts and not ctx.config.dry_run:
            log.info("No live hosts available for Nuclei scanning. Skipping.")
            return ScanResult(success=True, items_count=0, metadata={"findings": []})

        target_file = live_file or (ctx.config.outdir / "live.txt")
        target_file.parent.mkdir(parents=True, exist_ok=True)
        if hosts:
            target_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

        out_file = ctx.config.outdir / "nuclei_findings.jsonl"

        cmd = [
            self.binary_name,
            "-l",
            str(target_file),
            "-t",
            str(ctx.config.nuclei_templates),
            "-jsonl",
            "-o",
            str(out_file),
            "-timeout",
            "50",
            "-silent",
        ]

        if ctx.config.nuclei_severity:
            cmd.extend(["-s", ctx.config.nuclei_severity])
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
                await ctx.bus.publish("finding", record, source=self.name)

        return ScanResult(
            success=res.success,
            output_files=[out_file] if out_file.is_file() else [],
            items_count=len(findings),
            raw_output=res.stdout,
            error=res.stderr if not res.success else "",
            metadata={"findings": findings},
        )


class DalfoxDriver(ScannerDriver):
    """Concrete driver for hahwul dalfox XSS scanner."""

    def __init__(self, binary_name: str = "dalfox") -> None:
        super().__init__(name="dalfox", binary_name=binary_name)

    async def execute(self, ctx: StageContext, params_file: Optional[Path] = None, **kwargs: Any) -> ScanResult:
        params = ctx.store.get_urls()
        if not params and not ctx.config.dry_run:
            log.info("No parameterized URLs available for XSS scanning. Skipping.")
            return ScanResult(success=True, items_count=0, metadata={"findings": []})

        target_file = params_file or (ctx.config.outdir / "params.txt")
        target_file.parent.mkdir(parents=True, exist_ok=True)
        if params:
            target_file.write_text("\n".join(params) + "\n", encoding="utf-8")

        out_file = ctx.config.outdir / "xss_dalfox.txt"

        extra_args = ctx.bypass_context.dalfox_args() if ctx.bypass_context else []
        cmd = [
            self.binary_name,
            "file",
            str(target_file),
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
                await ctx.bus.publish("finding", f, source=self.name)

        return ScanResult(
            success=res.success,
            output_files=[out_file] if out_file.is_file() else [],
            items_count=len(findings),
            raw_output=res.stdout,
            error=res.stderr if not res.success else "",
            metadata={"findings": findings},
        )


class SqlmapDriver(ScannerDriver):
    """Concrete driver for sqlmap SQL injection scanner."""

    def __init__(self, binary_name: str = "sqlmap") -> None:
        super().__init__(name="sqlmap", binary_name=binary_name)

    async def execute(
        self,
        ctx: StageContext,
        url: Optional[str] = None,
        params_file: Optional[Path] = None,
        **kwargs: Any
    ) -> ScanResult:
        extra_args = ctx.bypass_context.sqlmap_args() if ctx.bypass_context else []
        findings: List[FindingRecord] = []

        if url:
            cmd = [
                self.binary_name,
                "-u",
                url,
                "--batch",
                "--smart",
                "--level",
                "1",
                "--risk",
                "1",
                *extra_args,
            ]
            res = await ctx.executor.run(cmd, proxy=True, timeout=600)
            found = "is vulnerable" in res.stdout.lower() or "sqlmap identified the following injection point" in res.stdout.lower()
            if found:
                f = FindingRecord(
                    vuln_type="SQLi",
                    severity="critical",
                    target_url=url,
                    payload=(ctx.bypass_context.desc if ctx.bypass_context else "") or "SQLMap detected injectable parameter",
                    details=res.stdout[:500],
                    source_tool=self.name,
                )
                findings.append(f)
                ctx.store.add_finding(f)
                await ctx.bus.publish("finding", f, source=self.name)

            return ScanResult(
                success=res.success,
                items_count=len(findings),
                raw_output=res.stdout,
                error=res.stderr if not res.success else "",
                metadata={"findings": findings},
            )

        # Batch mode scanning against parameterized URLs
        params = ctx.store.get_urls()
        if not params and not ctx.config.dry_run:
            log.info("No parameterized URLs available for SQLi scanning. Skipping.")
            return ScanResult(success=True, items_count=0, metadata={"findings": []})

        target_file = params_file or (ctx.config.outdir / "params.txt")
        target_file.parent.mkdir(parents=True, exist_ok=True)
        if params:
            target_file.write_text("\n".join(params) + "\n", encoding="utf-8")

        out_dir = ctx.config.outdir / "sqlmap_out"
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            self.binary_name,
            "-m",
            str(target_file),
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
        if out_dir.is_dir():
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
                            source_tool=self.name,
                        )
                        findings.append(f)
                        ctx.store.add_finding(f)
                        await ctx.bus.publish("finding", f, source=self.name)

        return ScanResult(
            success=res.success,
            items_count=len(findings),
            raw_output=res.stdout,
            error=res.stderr if not res.success else "",
            metadata={"findings": findings},
        )


class AssetfinderDriver(ScannerDriver):
    """Concrete driver for tomnomnom assetfinder passive subdomain enumeration."""

    def __init__(self, binary_name: str = "assetfinder") -> None:
        super().__init__(name="assetfinder", binary_name=binary_name)

    async def execute(self, ctx: StageContext, **kwargs: Any) -> ScanResult:
        cmd = [self.binary_name, "-subs-only", ctx.config.domain]
        res = await ctx.executor.run(cmd, proxy=True, timeout=600)

        subs: Set[str] = set()
        for line in res.stdout.splitlines():
            clean = line.strip().lower()
            if clean and ctx.is_in_scope(clean):
                subs.add(clean)

        clean_subs = sorted(list(subs))
        if clean_subs:
            ctx.store.add_subdomains(clean_subs, source=self.name)
            for sub in clean_subs:
                await ctx.bus.publish("subdomain", sub, source=self.name)

        return ScanResult(
            success=res.success,
            items_count=len(clean_subs),
            raw_output=res.stdout,
            error=res.stderr if not res.success else "",
            metadata={"subdomains": clean_subs},
        )


class AmassDriver(ScannerDriver):
    """Concrete driver for OWASP Amass passive attack surface mapping & subdomain enumeration."""

    def __init__(self, binary_name: str = "amass") -> None:
        super().__init__(name="amass", binary_name=binary_name)

    async def execute(self, ctx: StageContext, **kwargs: Any) -> ScanResult:
        cmd = [self.binary_name, "enum", "-silent", "-d", ctx.config.domain]
        res = await ctx.executor.run(cmd, proxy=True, timeout=1200)

        subs: Set[str] = set()
        for line in res.stdout.splitlines():
            clean = line.strip().lower()
            if clean and ctx.is_in_scope(clean):
                subs.add(clean)

        clean_subs = sorted(list(subs))
        if clean_subs:
            ctx.store.add_subdomains(clean_subs, source=self.name)
            for sub in clean_subs:
                await ctx.bus.publish("subdomain", sub, source=self.name)

        return ScanResult(
            success=res.success,
            items_count=len(clean_subs),
            raw_output=res.stdout,
            error=res.stderr if not res.success else "",
            metadata={"subdomains": clean_subs},
        )


class Sublist3rDriver(ScannerDriver):
    """Concrete driver for sublist3r OSINT search engine subdomain discovery."""

    def __init__(self, binary_name: str = "sublist3r") -> None:
        super().__init__(name="sublist3r", binary_name=binary_name)

    async def execute(self, ctx: StageContext, **kwargs: Any) -> ScanResult:
        out_file = ctx.config.outdir / "sublist3r_out.txt"
        cmd = [self.binary_name, "-d", ctx.config.domain, "-n", "-o", str(out_file)]
        res = await ctx.executor.run(cmd, proxy=True, timeout=900)

        lines: List[str] = []
        if out_file.is_file():
            lines = read_lines(out_file)
        elif res.stdout.strip():
            lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]

        subs: Set[str] = set()
        for line in lines:
            clean = line.strip().lower()
            if clean and ctx.is_in_scope(clean):
                subs.add(clean)

        clean_subs = sorted(list(subs))
        if clean_subs:
            ctx.store.add_subdomains(clean_subs, source=self.name)
            for sub in clean_subs:
                await ctx.bus.publish("subdomain", sub, source=self.name)

        return ScanResult(
            success=res.success,
            output_files=[out_file] if out_file.is_file() else [],
            items_count=len(clean_subs),
            raw_output=res.stdout,
            error=res.stderr if not res.success else "",
            metadata={"subdomains": clean_subs},
        )


class WaybackDriver(ScannerDriver):
    """Concrete driver for waybackpy Wayback Machine archive URL harvest."""

    def __init__(self, binary_name: str = "waybackpy") -> None:
        super().__init__(name="wayback", binary_name=binary_name)

    async def execute(self, ctx: StageContext, **kwargs: Any) -> ScanResult:
        out_file = ctx.config.outdir / "wayback.txt"
        cmd = [self.binary_name, "--url", ctx.config.domain, "-sub", "-ku"]
        res = await ctx.executor.run(cmd, proxy=True, timeout=900, capture_to=out_file)

        lines = [line.strip() for line in res.stdout.splitlines() if line.strip().startswith("http")]
        if not lines and out_file.is_file():
            lines = [l for l in read_lines(out_file) if l.startswith("http")]

        urls = [u for u in lines if ctx.is_in_scope(u)]

        return ScanResult(
            success=res.success,
            output_files=[out_file] if out_file.is_file() else [],
            items_count=len(urls),
            raw_output=res.stdout,
            error=res.stderr if not res.success else "",
            metadata={"urls": urls},
        )


class GauDriver(ScannerDriver):
    """Concrete driver for lc/gau (GetAllUrls) multi-provider URL miner."""

    def __init__(self, binary_name: str = "gau") -> None:
        super().__init__(name="gau", binary_name=binary_name)

    async def execute(self, ctx: StageContext, **kwargs: Any) -> ScanResult:
        out_file = ctx.config.outdir / "gau.txt"
        cmd = [self.binary_name, "--subs", ctx.config.domain, "--o", str(out_file)]
        res = await ctx.executor.run(cmd, proxy=True, timeout=900)

        lines: List[str] = []
        if out_file.is_file():
            lines = read_lines(out_file)
        elif res.stdout.strip():
            lines = [l.strip() for l in res.stdout.splitlines() if l.strip().startswith("http")]

        urls = [u for u in lines if ctx.is_in_scope(u)]

        return ScanResult(
            success=res.success,
            output_files=[out_file] if out_file.is_file() else [],
            items_count=len(urls),
            raw_output=res.stdout,
            error=res.stderr if not res.success else "",
            metadata={"urls": urls},
        )


class ParamspiderDriver(ScannerDriver):
    """Concrete driver for ParamSpider endpoint parameter extractor."""

    def __init__(self, binary_name: str = "paramspider") -> None:
        super().__init__(name="paramspider", binary_name=binary_name)

    async def execute(self, ctx: StageContext, live_file: Optional[Path] = None, **kwargs: Any) -> ScanResult:
        target_file = live_file or (ctx.config.outdir / "live.txt")
        if not target_file.is_file() and not ctx.config.dry_run:
            return ScanResult(success=True, items_count=0, error="Live hosts file not found for ParamSpider")

        cmd = [self.binary_name, "--list", str(target_file), "--proxy", ctx.config.tor_socks]
        res = await ctx.executor.run(cmd, proxy=False, timeout=900)

        results_dir = Path("results")
        urls: List[str] = []

        if target_file.is_file():
            hosts = read_lines(target_file)
            for host in hosts:
                domain = re.sub(r"^https?://", "", host).lower().strip().rstrip("/")
                pf = results_dir / f"{domain}.txt"
                if pf.exists():
                    for line in read_lines(pf):
                        if "=" in line and line.startswith("http") and ctx.is_in_scope(line):
                            urls.append(line.strip())

        return ScanResult(
            success=res.success,
            items_count=len(urls),
            raw_output=res.stdout,
            error=res.stderr if not res.success else "",
            metadata={"urls": urls},
        )

