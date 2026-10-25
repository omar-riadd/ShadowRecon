"""Cross-session differential analysis and asset drift detection for ShadowRecon."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from shadowrecon.storage.session import FindingRecord, HostRecord, SessionStore

log = logging.getLogger("shadowrecon.storage.diff")


@dataclass
class SessionDiff:
    """Carries the differential delta between two scan sessions."""
    new_subdomains: List[str] = field(default_factory=list)
    removed_subdomains: List[str] = field(default_factory=list)
    new_hosts: List[str] = field(default_factory=list)
    removed_hosts: List[str] = field(default_factory=list)
    status_changes: List[Dict[str, Any]] = field(default_factory=list)
    new_urls: List[str] = field(default_factory=list)
    removed_urls: List[str] = field(default_factory=list)
    new_findings: List[FindingRecord] = field(default_factory=list)
    resolved_findings: List[FindingRecord] = field(default_factory=list)
    current_db_path: str = ""
    prior_db_path: str = ""
    current_target: str = ""
    prior_target: str = ""
    current_timestamp: str = ""
    prior_timestamp: str = ""

    def has_drift(self) -> bool:
        """Return True if any infrastructure or vulnerability delta was observed."""
        return any([
            self.new_subdomains,
            self.removed_subdomains,
            self.new_hosts,
            self.removed_hosts,
            self.status_changes,
            self.new_urls,
            self.removed_urls,
            self.new_findings,
            self.resolved_findings,
        ])

    def summary_counts(self) -> Dict[str, int]:
        """Return a mapping of delta category counts."""
        return {
            "new_subdomains": len(self.new_subdomains),
            "removed_subdomains": len(self.removed_subdomains),
            "new_hosts": len(self.new_hosts),
            "removed_hosts": len(self.removed_hosts),
            "status_changes": len(self.status_changes),
            "new_urls": len(self.new_urls),
            "removed_urls": len(self.removed_urls),
            "new_findings": len(self.new_findings),
            "resolved_findings": len(self.resolved_findings),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize diff to a JSON-compatible dictionary."""
        return {
            "metadata": {
                "current_db": self.current_db_path,
                "prior_db": self.prior_db_path,
                "current_target": self.current_target,
                "prior_target": self.prior_target,
                "current_timestamp": self.current_timestamp,
                "prior_timestamp": self.prior_timestamp,
                "diff_calculated_at": datetime.now().isoformat(),
                "has_drift": self.has_drift(),
            },
            "summary": self.summary_counts(),
            "deltas": {
                "new_subdomains": self.new_subdomains,
                "removed_subdomains": self.removed_subdomains,
                "new_hosts": self.new_hosts,
                "removed_hosts": self.removed_hosts,
                "status_changes": self.status_changes,
                "new_urls": self.new_urls,
                "removed_urls": self.removed_urls,
                "new_findings": [asdict(f) for f in self.new_findings],
                "resolved_findings": [asdict(f) for f in self.resolved_findings],
            },
        }

    def format_console_report(self) -> str:
        """Produce a clean, color/marker formatted text report of drift."""
        lines: List[str] = [
            "=" * 60,
            " ShadowRecon Differential Analysis (Asset & Vulnerability Drift)",
            "=" * 60,
            f" Current Session : {self.current_db_path or 'current'} ({self.current_target})",
            f" Prior Session   : {self.prior_db_path or 'prior'} ({self.prior_target})",
            "-" * 60,
        ]

        if not self.has_drift():
            lines.append(" [*] No drift detected between sessions. Target assets remain identical.")
            lines.append("=" * 60)
            return "\n".join(lines)

        counts = self.summary_counts()
        lines.append(
            f" Delta Overview: +{counts['new_subdomains']} / -{counts['removed_subdomains']} Subdomains | "
            f"+{counts['new_hosts']} / -{counts['removed_hosts']} Hosts | "
            f"{counts['status_changes']} Status Shifts | "
            f"+{counts['new_findings']} / -{counts['resolved_findings']} Vulns"
        )
        lines.append("-" * 60)

        # 1. Subdomains
        if self.new_subdomains:
            lines.append(f" [+] Discovered Subdomains (+{len(self.new_subdomains)}):")
            for sub in self.new_subdomains[:20]:
                lines.append(f"     + {sub}")
            if len(self.new_subdomains) > 20:
                lines.append(f"     ... and {len(self.new_subdomains) - 20} more")

        if self.removed_subdomains:
            lines.append(f" [-] Decommissioned / Missing Subdomains (-{len(self.removed_subdomains)}):")
            for sub in self.removed_subdomains[:20]:
                lines.append(f"     - {sub}")
            if len(self.removed_subdomains) > 20:
                lines.append(f"     ... and {len(self.removed_subdomains) - 20} more")

        # 2. Live Hosts
        if self.new_hosts:
            lines.append(f" [+] New Live Hosts (+{len(self.new_hosts)}):")
            for host in self.new_hosts[:20]:
                lines.append(f"     + {host}")

        if self.removed_hosts:
            lines.append(f" [-] Unreachable / Removed Hosts (-{len(self.removed_hosts)}):")
            for host in self.removed_hosts[:20]:
                lines.append(f"     - {host}")

        # 3. HTTP Status Transitions
        if self.status_changes:
            lines.append(f" [*] HTTP Status Code Transitions ({len(self.status_changes)}):")
            for sc in self.status_changes[:20]:
                lines.append(f"     * {sc['url']}: HTTP {sc['old_status']} -> HTTP {sc['new_status']}")

        # 4. URLs
        if self.new_urls or self.removed_urls:
            lines.append(f" [*] Parameterized URLs: +{len(self.new_urls)} new, -{len(self.removed_urls)} removed")

        # 5. Vulnerabilities / Findings
        if self.new_findings:
            lines.append(f" [+] NEW Vulnerability Findings (+{len(self.new_findings)}):")
            for f in self.new_findings:
                lines.append(f"     [+] [{f.severity.upper()}] {f.vuln_type} on {f.target_url}")
                if f.payload:
                    lines.append(f"         Payload: {f.payload[:100]}")

        if self.resolved_findings:
            lines.append(f" [-] RESOLVED Vulnerabilities (-{len(self.resolved_findings)}):")
            for f in self.resolved_findings:
                lines.append(f"     [-] [{f.severity.upper()}] {f.vuln_type} on {f.target_url} (remediated)")

        lines.append("=" * 60)
        return "\n".join(lines)


def _to_store(target: Union[SessionStore, Path, str]) -> SessionStore:
    """Normalize input into an active SessionStore instance."""
    if isinstance(target, SessionStore):
        return target
    p = Path(target)
    if not p.is_file():
        raise FileNotFoundError(f"Session database not found: '{p}'")
    return SessionStore(p)


def diff_sessions(
    current: Union[SessionStore, Path, str],
    prior: Union[SessionStore, Path, str],
) -> SessionDiff:
    """Compare two ShadowRecon session databases and return an asset drift analysis."""
    cur_store = _to_store(current)
    old_store = _to_store(prior)

    diff = SessionDiff(
        current_db_path=str(cur_store.db_path),
        prior_db_path=str(old_store.db_path),
        current_target=cur_store.get_metadata("target", "unknown"),
        prior_target=old_store.get_metadata("target", "unknown"),
        current_timestamp=cur_store.get_metadata("start_time", ""),
        prior_timestamp=old_store.get_metadata("start_time", ""),
    )

    # 1. Subdomains
    cur_subs = set(cur_store.get_subdomains())
    old_subs = set(old_store.get_subdomains())
    diff.new_subdomains = sorted(list(cur_subs - old_subs))
    diff.removed_subdomains = sorted(list(old_subs - cur_subs))

    # 2. Hosts and HTTP Status Codes
    cur_host_recs = {r.url: r for r in cur_store.get_host_records()}
    old_host_recs = {r.url: r for r in old_store.get_host_records()}

    cur_host_urls = set(cur_host_recs.keys())
    old_host_urls = set(old_host_recs.keys())

    diff.new_hosts = sorted(list(cur_host_urls - old_host_urls))
    diff.removed_hosts = sorted(list(old_host_urls - cur_host_urls))

    # Detect status code changes for common URLs
    for url in sorted(list(cur_host_urls & old_host_urls)):
        c_status = cur_host_recs[url].status_code
        o_status = old_host_recs[url].status_code
        if c_status != o_status and c_status != 0 and o_status != 0:
            diff.status_changes.append({
                "url": url,
                "old_status": o_status,
                "new_status": c_status,
            })

    # 3. Parameterized URLs
    cur_urls = set(cur_store.get_urls())
    old_urls = set(old_store.get_urls())
    diff.new_urls = sorted(list(cur_urls - old_urls))
    diff.removed_urls = sorted(list(old_urls - cur_urls))

    # 4. Findings (Keyed by vuln_type and target_url)
    def finding_key(f: FindingRecord) -> Tuple[str, str]:
        return (f.vuln_type.lower(), f.target_url.lower())

    cur_findings = cur_store.get_findings()
    old_findings = old_store.get_findings()

    old_finding_keys = {finding_key(f) for f in old_findings}
    cur_finding_keys = {finding_key(f) for f in cur_findings}

    for f in cur_findings:
        if finding_key(f) not in old_finding_keys:
            diff.new_findings.append(f)

    for f in old_findings:
        if finding_key(f) not in cur_finding_keys:
            diff.resolved_findings.append(f)

    return diff


def main(argv: Optional[List[str]] = None) -> int:
    """CLI utility for comparing two ShadowRecon session databases directly."""
    parser = argparse.ArgumentParser(
        prog="shadowrecon-diff",
        description="Compare two ShadowRecon SQLite session databases to calculate asset and vulnerability drift.",
    )
    parser.add_argument("current_db", help="Path to the current / newer session.db")
    parser.add_argument("prior_db", help="Path to the prior / baseline session.db")
    parser.add_argument("--json", action="store_true", help="Output summary in JSON format")
    parser.add_argument("-o", "--output", help="Save output to a file")

    args = parser.parse_args(argv)

    try:
        diff = diff_sessions(args.current_db, args.prior_db)
    except Exception as exc:
        log.error("Failed to calculate diff: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        result_text = json.dumps(diff.to_dict(), indent=2)
    else:
        result_text = diff.format_console_report()

    print(result_text)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(result_text + "\n", encoding="utf-8")
        log.info("Diff written to %s", out_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
