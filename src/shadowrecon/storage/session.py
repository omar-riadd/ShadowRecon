"""SQLite session store for pipeline deduplication, run caching, and artifact export."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional
from urllib.parse import parse_qs, urlparse


@dataclass
class FindingRecord:
    vuln_type: str        # XSS, SQLi, Takeover, LFI, SSRF
    severity: str         # info, low, medium, high, critical
    target_url: str
    payload: str = ""
    details: str = ""
    source_tool: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class HostRecord:
    url: str
    status_code: int = 200
    title: str = ""
    webserver: str = ""
    content_length: int = 0
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class SessionStore:
    """Manages SQLite-backed state for run persistence, instant resume, and deduplication."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );

                CREATE TABLE IF NOT EXISTS stages (
                    name TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    duration_seconds REAL DEFAULT 0.0,
                    error_message TEXT DEFAULT '',
                    updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS subdomains (
                    subdomain TEXT PRIMARY KEY,
                    source TEXT,
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS hosts (
                    url TEXT PRIMARY KEY,
                    status_code INTEGER,
                    title TEXT,
                    webserver TEXT,
                    content_length INTEGER,
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS urls (
                    url TEXT PRIMARY KEY,
                    param_signature TEXT UNIQUE,
                    source TEXT,
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vuln_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    payload TEXT,
                    details TEXT,
                    source_tool TEXT,
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS waf_bypasses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    desc TEXT NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    headers_json TEXT,
                    status_code INTEGER,
                    confirmed INTEGER DEFAULT 0,
                    created_at TEXT
                );
            """)

    # ------------------
    #   METADATA
    # ------------------

    def set_metadata(self, key: str, value: Any) -> None:
        str_val = value if isinstance(value, str) else json.dumps(value)
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                (key, str_val),
            )

    def get_metadata(self, key: str, default: Any = None) -> Any:
        with self._get_connection() as conn:
            row = conn.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
            if row is None:
                return default
            val = row["value"]
            try:
                return json.loads(val)
            except (json.JSONDecodeError, TypeError):
                return val

    # ------------------
    #   STAGE LIFECYCLE
    # ------------------

    def set_stage(self, name: str, status: str, duration: float = 0.0, error: str = "") -> None:
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO stages
                   (name, status, duration_seconds, error_message, updated_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (name, status, duration, error, now),
            )

    def is_stage_completed(self, name: str) -> bool:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT status FROM stages WHERE name = ?", (name,)
            ).fetchone()
            return row is not None and row["status"] == "completed"

    def get_stages(self) -> Dict[str, Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM stages").fetchall()
            return {
                r["name"]: {
                    "status": r["status"],
                    "duration_seconds": r["duration_seconds"],
                    "error_message": r["error_message"],
                    "updated_at": r["updated_at"],
                }
                for r in rows
            }

    # ------------------
    #   RECON ENTITIES
    # ------------------

    def add_subdomains(self, subdomains: Iterable[str], source: str = "subfinder") -> int:
        now = datetime.now().isoformat()
        inserted = 0
        with self._get_connection() as conn:
            for sub in subdomains:
                clean = sub.strip().lower()
                if not clean:
                    continue
                try:
                    conn.execute(
                        "INSERT INTO subdomains (subdomain, source, created_at) VALUES (?, ?, ?)",
                        (clean, source, now),
                    )
                    inserted += 1
                except sqlite3.IntegrityError:
                    pass  # already present
        return inserted

    def get_subdomains(self) -> List[str]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT subdomain FROM subdomains ORDER BY subdomain").fetchall()
            return [r["subdomain"] for r in rows]

    def add_hosts(self, hosts: Iterable[HostRecord | str]) -> int:
        now = datetime.now().isoformat()
        inserted = 0
        with self._get_connection() as conn:
            for item in hosts:
                if isinstance(item, str):
                    rec = HostRecord(url=item.strip())
                else:
                    rec = item
                if not rec.url:
                    continue
                try:
                    conn.execute(
                        """INSERT INTO hosts
                           (url, status_code, title, webserver, content_length, created_at)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (rec.url, rec.status_code, rec.title, rec.webserver, rec.content_length, now),
                    )
                    inserted += 1
                except sqlite3.IntegrityError:
                    pass
        return inserted

    def get_hosts(self) -> List[str]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT url FROM hosts ORDER BY url").fetchall()
            return [r["url"] for r in rows]

    def add_urls(self, urls: Iterable[str], source: str = "archive") -> int:
        """Add URLs with parameter signature deduplication.

        URLs matching (netloc + path + sorted query parameters) are treated as duplicates
        to avoid feeding thousands of redundant endpoints to SQLMap/Dalfox.
        """
        now = datetime.now().isoformat()
        inserted = 0
        with self._get_connection() as conn:
            for u in urls:
                clean_url = u.strip()
                if not clean_url or "=" not in clean_url:
                    continue
                try:
                    parsed = urlparse(clean_url)
                    param_keys = sorted(parse_qs(parsed.query).keys())
                    sig = f"{parsed.netloc}{parsed.path}?{','.join(param_keys)}"
                except Exception:
                    sig = clean_url

                try:
                    conn.execute(
                        "INSERT INTO urls (url, param_signature, source, created_at) VALUES (?, ?, ?, ?)",
                        (clean_url, sig, source, now),
                    )
                    inserted += 1
                except sqlite3.IntegrityError:
                    pass
        return inserted

    def get_urls(self) -> List[str]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT url FROM urls ORDER BY url").fetchall()
            return [r["url"] for r in rows]

    # ------------------
    #   FINDINGS & WAF
    # ------------------

    def add_finding(self, finding: FindingRecord) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """INSERT INTO findings
                   (vuln_type, severity, target_url, payload, details, source_tool, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.vuln_type,
                    finding.severity,
                    finding.target_url,
                    finding.payload,
                    finding.details,
                    finding.source_tool,
                    finding.timestamp,
                ),
            )

    def get_findings(self) -> List[FindingRecord]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
            return [
                FindingRecord(
                    vuln_type=r["vuln_type"],
                    severity=r["severity"],
                    target_url=r["target_url"],
                    payload=r["payload"] or "",
                    details=r["details"] or "",
                    source_tool=r["source_tool"] or "",
                    timestamp=r["created_at"],
                )
                for r in rows
            ]

    def add_waf_bypass(
        self,
        desc: str,
        method: str,
        url: str,
        headers: Dict[str, str],
        status_code: int,
        confirmed: bool = False,
    ) -> None:
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """INSERT INTO waf_bypasses
                   (desc, method, url, headers_json, status_code, confirmed, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (desc, method, url, json.dumps(headers), status_code, 1 if confirmed else 0, now),
            )

    def get_waf_bypasses(self, confirmed_only: bool = False) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            query = "SELECT * FROM waf_bypasses"
            if confirmed_only:
                query += " WHERE confirmed = 1"
            rows = conn.execute(query).fetchall()
            return [
                {
                    "desc": r["desc"],
                    "method": r["method"],
                    "url": r["url"],
                    "headers": json.loads(r["headers_json"] or "{}"),
                    "status_code": r["status_code"],
                    "confirmed": bool(r["confirmed"]),
                }
                for r in rows
            ]

    # ------------------
    #   AGGREGATION & EXPORT
    # ------------------

    def get_summary_counts(self) -> Dict[str, int]:
        with self._get_connection() as conn:
            subs = conn.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0]
            hosts = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
            urls = conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
            findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            waf = conn.execute("SELECT COUNT(*) FROM waf_bypasses WHERE confirmed = 1").fetchone()[0]
            return {
                "Subdomains": subs,
                "Live hosts": hosts,
                "Parameterized URLs": urls,
                "WAF bypasses": waf,
                "Vulnerabilities": findings,
            }

    def export_flat_artifacts(self, outdir: Path) -> None:
        """Export SQLite records into backward-compatible flat text files."""
        outdir = Path(outdir)
        outdir.mkdir(parents=True, exist_ok=True)

        subs = self.get_subdomains()
        (outdir / "subdomains.txt").write_text(
            "\n".join(subs) + ("\n" if subs else ""), encoding="utf-8"
        )

        hosts = self.get_hosts()
        (outdir / "live.txt").write_text(
            "\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8"
        )

        urls = self.get_urls()
        (outdir / "params.txt").write_text(
            "\n".join(urls) + ("\n" if urls else ""), encoding="utf-8"
        )

        bypasses = self.get_waf_bypasses()
        lines_200 = [
            f"[{b['desc']}] -> {b['method']} {b['url']} | {b['status_code']}"
            for b in bypasses
        ]
        (outdir / "200-ok.txt").write_text(
            "\n".join(lines_200) + ("\n" if lines_200 else ""), encoding="utf-8"
        )

        findings = self.get_findings()
        xss_lines = [f"[POC] {f.target_url} payload={f.payload}" for f in findings if f.vuln_type == "XSS"]
        if xss_lines:
            (outdir / "xss_dalfox.txt").write_text("\n".join(xss_lines) + "\n", encoding="utf-8")

        takeover_lines = [f"[{f.details}] {f.target_url}" for f in findings if f.vuln_type == "Takeover"]
        if takeover_lines:
            (outdir / "nuclei_takeover.txt").write_text("\n".join(takeover_lines) + "\n", encoding="utf-8")
