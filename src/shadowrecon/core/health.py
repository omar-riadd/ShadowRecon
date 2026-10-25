"""Preflight environment diagnostic and health check subsystem (Doctor Engine)."""
from __future__ import annotations

import logging
import os
import shutil
import socket
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from shadowrecon import __version__
from shadowrecon.config import Config, default_nuclei_templates_dir
from shadowrecon.core.executor import resolve_binary
from shadowrecon.drivers.registry import global_registry

log = logging.getLogger("shadowrecon.core.health")


class CheckStatus(str, Enum):
    OK = "OK"
    WARNING = "WARNING"
    FAIL = "FAIL"


@dataclass
class HealthCheckResult:
    name: str
    category: str  # "Core Binaries", "Optional Drivers", "Proxy & Network", "Storage", "Templates"
    status: CheckStatus
    message: str
    remediation: str = ""


@dataclass
class DoctorReport:
    """Carries the outcome of preflight health checks."""
    checks: List[HealthCheckResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        """True if there are no FAIL or WARNING statuses."""
        return all(c.status == CheckStatus.OK for c in self.checks)

    @property
    def has_critical_failures(self) -> bool:
        """True if any required/core check failed."""
        return any(c.status == CheckStatus.FAIL for c in self.checks)

    def summary_counts(self) -> Dict[str, int]:
        counts = {"OK": 0, "WARNING": 0, "FAIL": 0}
        for c in self.checks:
            counts[c.status.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary_counts(),
            "has_critical_failures": self.has_critical_failures,
            "all_passed": self.all_passed,
            "checks": [
                {
                    "name": c.name,
                    "category": c.category,
                    "status": c.status.value,
                    "message": c.message,
                    "remediation": c.remediation,
                }
                for c in self.checks
            ],
        }

    def format_table(self) -> str:
        """Render a formatted ANSI console table of diagnostic checks."""
        lines: List[str] = [
            "=" * 70,
            f" ShadowRecon Doctor — Preflight Diagnostic Suite (v{__version__})",
            "=" * 70,
        ]

        categories: Dict[str, List[HealthCheckResult]] = {}
        for c in self.checks:
            categories.setdefault(c.category, []).append(c)

        status_symbols = {
            CheckStatus.OK: "✅ PASS",
            CheckStatus.WARNING: "⚠️  WARN",
            CheckStatus.FAIL: "❌ FAIL",
        }

        for cat, items in categories.items():
            lines.append(f"\n[{cat}]")
            for item in items:
                sym = status_symbols[item.status]
                lines.append(f"  {sym:<8} {item.name:<18} : {item.message}")
                if item.remediation and item.status != CheckStatus.OK:
                    lines.append(f"           {'':18}   -> Fix: {item.remediation}")

        counts = self.summary_counts()
        lines.append("\n" + "-" * 70)
        lines.append(
            f" Diagnostics Result: {counts['OK']} Passed, "
            f"{counts['WARNING']} Warnings, {counts['FAIL']} Failed"
        )
        if self.has_critical_failures:
            lines.append(" ❌ Core components are missing. Scan execution may fail.")
        elif counts["WARNING"] > 0:
            lines.append(" ⚠️  All core components verified. Some optional drivers are missing.")
        else:
            lines.append(" ✅ System environment is fully healthy and ready for scans.")
        lines.append("=" * 70)

        return "\n".join(lines)


class PreflightChecker:
    """Verifies scanner binaries, network/proxy reachability, templates, and storage."""

    CORE_BINARIES = {
        "subfinder": "Passive subdomain discovery engine (core)",
        "httpx": "High-throughput active probing engine (or httpx-toolkit)",
        "wafw00f": "WAF fingerprinting and firewall detector",
        "ffuf": "Fast web fuzzer for directory brute-forcing",
    }

    OPTIONAL_DRIVERS = {
        "assetfinder": "Alternative subdomain gathering driver",
        "amass": "In-depth OWASP subdomain enumeration",
        "sublist3r": "Python-based subdomain enumeration",
        "katana": "Next-gen crawling and endpoint discovery",
        "wayback": "Wayback Machine archive scraper (waybackpy)",
        "gau": "GetAllUrls archive harvesting utility",
        "paramspider": "Parameter mining tool for endpoint discovery",
        "nuclei": "Fast CVSS vulnerability template scanner",
        "dalfox": "XSS scanning and parameter analysis tool",
        "sqlmap": "Automatic SQL injection exploitation engine",
    }

    def __init__(self, cfg: Optional[Config] = None) -> None:
        self.cfg = cfg

    def check_binary(self, binary_name: str, description: str, is_core: bool = True) -> HealthCheckResult:
        """Verify binary presence in PATH or local Go/Python directories."""
        cat = "Core Binaries" if is_core else "Optional Drivers"
        resolved = resolve_binary(binary_name)
        if resolved:
            return HealthCheckResult(
                name=binary_name,
                category=cat,
                status=CheckStatus.OK,
                message=f"Found at {resolved}",
            )

        # Fallback check for alternative names (e.g. httpx -> httpx-toolkit)
        alt_names = {
            "httpx": ["httpx-toolkit"],
            "wayback": ["waybackpy"],
        }.get(binary_name, [])

        for alt in alt_names:
            alt_res = resolve_binary(alt)
            if alt_res:
                return HealthCheckResult(
                    name=binary_name,
                    category=cat,
                    status=CheckStatus.OK,
                    message=f"Found alternative '{alt}' at {alt_res}",
                )

        status = CheckStatus.FAIL if is_core else CheckStatus.WARNING
        remedy_map = {
            "subfinder": "Install via 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' or 'sudo apt install subfinder'",
            "httpx": "Install via 'sudo apt install httpx-toolkit' or 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest'",
            "wafw00f": "Install via 'sudo apt install wafw00f'",
            "ffuf": "Install via 'sudo apt install ffuf'",
            "katana": "Install via 'go install github.com/projectdiscovery/katana/cmd/katana@latest'",
            "nuclei": "Install via 'sudo apt install nuclei' or 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'",
            "dalfox": "Install via 'go install github.com/hahwul/dalfox/v2@latest'",
            "sqlmap": "Install via 'sudo apt install sqlmap'",
            "assetfinder": "Install via 'go install github.com/tomnomnom/assetfinder@latest'",
            "amass": "Install via 'sudo apt install amass'",
            "sublist3r": "Install via 'sudo apt install sublist3r'",
            "gau": "Install via 'go install github.com/lc/gau/v2/cmd/gau@latest'",
            "wayback": "Install via 'pip install waybackpy'",
            "paramspider": "Install via 'pip install paramspider'",
        }
        remediation = remedy_map.get(binary_name, f"Ensure '{binary_name}' is in your $PATH.")

        return HealthCheckResult(
            name=binary_name,
            category=cat,
            status=status,
            message=f"Binary not found ({description})",
            remediation=remediation,
        )

    def check_python_dependencies(self) -> List[HealthCheckResult]:
        """Verify core and reporting Python library dependencies."""
        results = []
        # WeasyPrint
        try:
            import weasyprint
            v = getattr(weasyprint, "__version__", "unknown")
            results.append(
                HealthCheckResult(
                    name="weasyprint",
                    category="Python Packages",
                    status=CheckStatus.OK,
                    message=f"Installed (v{v}) for executive PDF generation",
                )
            )
        except ImportError:
            results.append(
                HealthCheckResult(
                    name="weasyprint",
                    category="Python Packages",
                    status=CheckStatus.WARNING,
                    message="Not installed. PDF report export will be unavailable.",
                    remediation="Install via 'pip install weasyprint' or 'sudo apt install python3-weasyprint'",
                )
            )

        # SQLite3
        try:
            import sqlite3
            results.append(
                HealthCheckResult(
                    name="sqlite3",
                    category="Python Packages",
                    status=CheckStatus.OK,
                    message=f"SQLite3 runtime supported (v{sqlite3.sqlite_version})",
                )
            )
        except ImportError:
            results.append(
                HealthCheckResult(
                    name="sqlite3",
                    category="Python Packages",
                    status=CheckStatus.FAIL,
                    message="Python sqlite3 module missing.",
                    remediation="Reinstall Python with SQLite3 support.",
                )
            )

        return results

    def check_proxy_reachability(self, proxy_url: str, timeout: float = 3.0) -> HealthCheckResult:
        """Verify TCP socket reachability for configured proxy endpoint."""
        if not proxy_url:
            return HealthCheckResult(
                name="proxy_socket",
                category="Proxy & Network",
                status=CheckStatus.OK,
                message="No proxy configured (direct connection)",
            )

        try:
            parsed = urlparse(proxy_url)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or (9050 if "socks" in (parsed.scheme or "") else 8080)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            return HealthCheckResult(
                name="proxy_socket",
                category="Proxy & Network",
                status=CheckStatus.OK,
                message=f"Connected to proxy at {host}:{port}",
            )
        except Exception as exc:
            return HealthCheckResult(
                name="proxy_socket",
                category="Proxy & Network",
                status=CheckStatus.WARNING,
                message=f"Cannot reach proxy at {proxy_url} ({exc})",
                remediation="Ensure Tor is running ('sudo systemctl start tor') or check proxy endpoint.",
            )

    def check_nuclei_templates(self, templates_dir: Optional[Path] = None) -> HealthCheckResult:
        """Check presence of Nuclei vulnerability templates."""
        t_dir = templates_dir or (self.cfg.nuclei_templates if self.cfg else default_nuclei_templates_dir())
        if t_dir and t_dir.is_dir():
            yaml_count = len(list(t_dir.glob("**/*.yaml"))) + len(list(t_dir.glob("**/*.yml")))
            if yaml_count > 0:
                return HealthCheckResult(
                    name="nuclei_templates",
                    category="Templates & Rules",
                    status=CheckStatus.OK,
                    message=f"Templates found at {t_dir} ({yaml_count} templates)",
                )

        return HealthCheckResult(
            name="nuclei_templates",
            category="Templates & Rules",
            status=CheckStatus.WARNING,
            message=f"Templates not found at {t_dir or 'default directory'}",
            remediation="Run 'nuclei -ut' to download community vulnerability templates.",
        )

    def check_storage_permissions(self, outdir: Optional[Path] = None) -> HealthCheckResult:
        """Check write permissions to output directory."""
        target_dir = outdir or (self.cfg.outdir if self.cfg else Path.cwd() / "out")
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            probe_file = target_dir / ".shadowrecon_probe_write"
            probe_file.write_text("probe", encoding="utf-8")
            probe_file.unlink()
            return HealthCheckResult(
                name="storage_write",
                category="Storage & Output",
                status=CheckStatus.OK,
                message=f"Writable output directory at {target_dir}",
            )
        except Exception as exc:
            return HealthCheckResult(
                name="storage_write",
                category="Storage & Output",
                status=CheckStatus.FAIL,
                message=f"Cannot write to output directory {target_dir}: {exc}",
                remediation=f"Check filesystem permissions for {target_dir}.",
            )

    def run_all_checks(self) -> DoctorReport:
        """Execute the full preflight diagnostic battery."""
        report = DoctorReport()

        # 1. Core Binaries
        for b_name, b_desc in self.CORE_BINARIES.items():
            report.checks.append(self.check_binary(b_name, b_desc, is_core=True))

        # 2. Optional Drivers
        for b_name, b_desc in self.OPTIONAL_DRIVERS.items():
            report.checks.append(self.check_binary(b_name, b_desc, is_core=False))

        # 3. Python Packages
        report.checks.extend(self.check_python_dependencies())

        # 4. Proxy & Network
        if self.cfg and self.cfg.use_proxy:
            report.checks.append(self.check_proxy_reachability(self.cfg.tor_socks))
        else:
            # Check default Tor port if proxy is enabled by default
            report.checks.append(self.check_proxy_reachability("socks5://127.0.0.1:9050"))

        # 5. Templates
        report.checks.append(self.check_nuclei_templates())

        # 6. Storage
        report.checks.append(self.check_storage_permissions())

        return report
