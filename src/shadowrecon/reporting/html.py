"""Self-contained offline dark HTML report generator."""
from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from shadowrecon.core.scope import read_lines
from shadowrecon.storage.diff import SessionDiff
from shadowrecon.storage.session import SessionStore


@dataclass
class Section:
    title: str
    accent: str
    count: int
    items: List[str]
    note: str = ""


MAX_PREVIEW = 500

_CSS = """
:root{--bg:#0b0f17;--panel:#121826;--panel2:#0e1420;--border:#1f2a3d;
--text:#e6edf6;--muted:#8aa0bd;--info:#4ea1ff;--warn:#ffb454;--high:#ff5d6c;--ok:#49d19e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:32px 20px 80px}
header{display:flex;align-items:center;gap:16px;border-bottom:1px solid var(--border);padding-bottom:20px}
.logo{font-weight:800;font-size:26px;letter-spacing:.5px}
.logo .s{color:var(--high)}.logo .r{color:var(--info)}
.sub{color:var(--muted);font-size:13px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:22px 0}
.meta div{background:var(--panel2);border:1px solid var(--border);border-radius:10px;padding:12px 14px}
.meta b{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:8px 0 26px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px 18px;position:relative;overflow:hidden}
.card .n{font-size:30px;font-weight:800}.card .t{color:var(--muted);font-size:13px}
.card::after{content:"";position:absolute;left:0;top:0;bottom:0;width:4px}
.card.info::after{background:var(--info)}.card.warn::after{background:var(--warn)}
.card.high::after{background:var(--high)}.card.muted::after{background:var(--muted)}.card.ok::after{background:var(--ok)}
.chart{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px;margin-bottom:26px}
h2{font-size:14px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin:0 0 14px}
details{background:var(--panel);border:1px solid var(--border);border-radius:12px;margin:10px 0}
summary{cursor:pointer;padding:14px 16px;font-weight:600;display:flex;justify-content:space-between;align-items:center}
summary::-webkit-details-marker{display:none}
.badge{background:var(--panel2);border:1px solid var(--border);border-radius:999px;padding:2px 10px;font-size:12px;color:var(--muted)}
pre{margin:0;padding:0 16px 16px;max-height:420px;overflow:auto;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:#c7d6ea;white-space:pre-wrap;word-break:break-all}
.empty{color:var(--muted);padding:0 16px 16px}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:40px}
a{color:var(--info)}
"""


def _count_ffuf_hits(csv_path: Path) -> int:
    """Count non-header rows in an FFUF CSV."""
    lines = read_lines(csv_path)
    if not lines:
        return 0
    if "fuzz" in lines[0].lower() or "url" in lines[0].lower():
        return max(0, len(lines) - 1)
    return len(lines)


def _svg_bar_chart(sections: List[Section]) -> str:
    data = [(s.title, s.count, s.accent) for s in sections if s.count > 0]
    if not data:
        return '<p class="empty">No results to chart.</p>'
    colors = {
        "info": "#4ea1ff",
        "warn": "#ffb454",
        "high": "#ff5d6c",
        "muted": "#8aa0bd",
        "ok": "#49d19e",
    }
    maxv = max(v for _, v, _ in data) or 1
    row_h, gap, left, w = 26, 10, 220, 760
    height = len(data) * (row_h + gap) + 10
    rows = []
    for i, (label, val, accent) in enumerate(data):
        y = 10 + i * (row_h + gap)
        bw = int((w - left - 60) * val / maxv)
        c = colors.get(accent, "#4ea1ff")
        rows.append(
            f'<text x="{left-12}" y="{y+row_h*0.68:.0f}" text-anchor="end" '
            f'fill="#8aa0bd" font-size="12">{html.escape(label)}</text>'
            f'<rect x="{left}" y="{y}" width="{max(bw,2)}" height="{row_h}" rx="5" fill="{c}" opacity="0.85"/>'
            f'<text x="{left+max(bw,2)+8}" y="{y+row_h*0.68:.0f}" fill="#e6edf6" '
            f'font-size="12" font-weight="700">{val}</text>'
        )
    return (
        f'<svg viewBox="0 0 {w} {height}" width="100%" role="img" '
        f'aria-label="Result counts">{"".join(rows)}</svg>'
    )


def _section_html(s: Section) -> str:
    body = "".join(f"{html.escape(x)}\n" for x in s.items) if s.items else None
    inner = f"<pre>{body}</pre>" if body else '<p class="empty">No entries.</p>'
    note = f" · {html.escape(s.note)}" if s.note else ""
    return (
        f"<details><summary>{html.escape(s.title)}"
        f'<span class="badge">{s.count}{note}</span></summary>{inner}</details>'
    )


def generate_report_from_store(
    store: SessionStore,
    out_dir: Path,
    meta: Dict[str, Any],
    out_name: str = "report.html",
    drift: Optional[SessionDiff] = None,
) -> Path:
    """Generate self-contained HTML report directly from SessionStore records."""
    sections: List[Section] = []

    # 0. Asset & Vulnerability Drift (if comparing with prior session)
    if drift and drift.has_drift():
        drift_items: List[str] = []
        if drift.new_subdomains:
            drift_items.append(f"[+ New Subdomains: {len(drift.new_subdomains)}]")
            drift_items.extend(f"  + {s}" for s in drift.new_subdomains[:MAX_PREVIEW])
        if drift.removed_subdomains:
            drift_items.append(f"[- Removed Subdomains: {len(drift.removed_subdomains)}]")
            drift_items.extend(f"  - {s}" for s in drift.removed_subdomains[:MAX_PREVIEW])
        if drift.new_hosts:
            drift_items.append(f"[+ New Live Hosts: {len(drift.new_hosts)}]")
            drift_items.extend(f"  + {h}" for h in drift.new_hosts[:MAX_PREVIEW])
        if drift.removed_hosts:
            drift_items.append(f"[- Removed Hosts: {len(drift.removed_hosts)}]")
            drift_items.extend(f"  - {h}" for h in drift.removed_hosts[:MAX_PREVIEW])
        if drift.status_changes:
            drift_items.append(f"[* HTTP Status Shifts: {len(drift.status_changes)}]")
            drift_items.extend(f"  * {sc['url']}: HTTP {sc['old_status']} -> HTTP {sc['new_status']}" for sc in drift.status_changes[:MAX_PREVIEW])
        if drift.new_findings:
            drift_items.append(f"[+ New Vulnerabilities: {len(drift.new_findings)}]")
            drift_items.extend(f"  + [{f.severity.upper()}] {f.vuln_type} on {f.target_url}" for f in drift.new_findings)
        if drift.resolved_findings:
            drift_items.append(f"[- Remediated Vulnerabilities: {len(drift.resolved_findings)}]")
            drift_items.extend(f"  - [{f.severity.upper()}] {f.vuln_type} on {f.target_url}" for f in drift.resolved_findings)

        total_drift = sum(drift.summary_counts().values())
        prior_label = Path(drift.prior_db_path).name if drift.prior_db_path else "prior"
        sections.append(Section("Asset & Vuln Drift", "warn", total_drift, drift_items, note=f"delta vs {prior_label}"))

    # 1. WAF Bypasses
    bypasses = store.get_waf_bypasses()
    if bypasses:
        items = [f"[{b['desc']}] -> {b['method']} {b['url']} | HTTP {b['status_code']} (confirmed={b['confirmed']})" for b in bypasses]
        sections.append(Section("WAF Bypasses", "warn", len(items), items[:MAX_PREVIEW]))

    # 2. Subdomains
    subs = store.get_subdomains()
    if subs:
        sections.append(Section("Subdomains", "info", len(subs), subs[:MAX_PREVIEW]))

    # 3. Live hosts
    hosts = store.get_hosts()
    if hosts:
        sections.append(Section("Live hosts", "info", len(hosts), hosts[:MAX_PREVIEW]))

    # 4. URLs
    urls = store.get_urls()
    if urls:
        sections.append(Section("Parameterized URLs", "info", len(urls), urls[:MAX_PREVIEW]))

    # 5. Findings
    findings = store.get_findings()
    if findings:
        for vtype, accent in [("SQLi", "high"), ("XSS", "high"), ("Takeover", "high")]:
            v_findings = [f"[{f.severity.upper()}] {f.target_url} - {f.payload or f.details}" for f in findings if f.vuln_type == vtype]
            if v_findings:
                sections.append(Section(f"Vulnerability: {vtype}", accent, len(v_findings), v_findings))

    # 6. FFUF CSV directories
    ffuf = out_dir / "ffuf_dirs"
    if ffuf.is_dir():
        csvs = sorted(ffuf.glob("*.csv"))
        total_hits = sum(_count_ffuf_hits(p) for p in csvs)
        sections.append(
            Section(
                "Directory fuzz (FFUF)",
                "info",
                total_hits,
                [p.name for p in csvs],
                note=f"across {len(csvs)} host(s)",
            )
        )

    # 7. Stages execution breakdown
    stages = store.get_stages()
    if stages:
        stage_lines = [
            f"{name}: {info['status']} ({info['duration_seconds']}s)"
            + (f" [error: {info['error_message']}]" if info["error_message"] else "")
            for name, info in stages.items()
        ]
        sections.append(Section("Pipeline Stages", "muted", len(stage_lines), stage_lines))

    cards = "".join(
        f'<div class="card {s.accent}"><div class="n">{s.count}</div>'
        f'<div class="t">{html.escape(s.title)}</div></div>'
        for s in sections
    ) or '<p class="empty">No findings recorded in session.</p>'

    meta_html = "".join(
        f"<div><b>{html.escape(k)}</b>{html.escape(str(v))}</div>"
        for k, v in meta.items()
    )

    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShadowRecon v3.0 Report — {html.escape(str(meta.get('Target','')))}</title>
<style>{_CSS}</style></head><body><div class="wrap">
<header><div class="logo"><span class="s">Shadow</span><span class="r">Recon</span> <small style="font-size:14px;color:var(--muted)">v3.0</small></div>
<div class="sub">Tor-anonymized reconnaissance &amp; vulnerability report</div></header>
<section class="meta">{meta_html}</section>
<h2>Summary</h2><section class="cards">{cards}</section>
<div class="chart"><h2>Result counts</h2>{_svg_bar_chart(sections)}</div>
<h2>Details</h2>{''.join(_section_html(s) for s in sections)}
<footer>Generated {datetime.now():%Y-%m-%d %H:%M:%S} · for authorized testing only</footer>
</div></body></html>"""

    out_file = out_dir / out_name
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(doc, encoding="utf-8")
    return out_file
