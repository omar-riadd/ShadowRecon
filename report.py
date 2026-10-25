"""Self-contained HTML report generator (stdlib only).

Aggregates the scattered run artifacts into one polished, offline HTML file —
no external CSS/JS/fonts, so it opens anywhere. This presents results; it adds
no scanning or offensive capability.
"""
from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from utils import read_lines

# (filename, Human Title, severity-ish accent) for line-based artifacts.
LINE_ARTIFACTS = [
    ("200-ok.txt", "WAF-bypass 200 OK", "warn"),
    ("subdomains.txt", "Subdomains", "info"),
    ("live.txt", "Live hosts", "info"),
    ("wayback.txt", "Wayback URLs", "muted"),
    ("params.txt", "Parameterized URLs", "info"),
    ("nuclei_takeover.txt", "Nuclei takeover findings", "high"),
    ("xss_dalfox.txt", "XSS (Dalfox PoC)", "high"),
]
MAX_PREVIEW = 400  # cap lines rendered per section to keep the file light


@dataclass
class Section:
    title: str
    accent: str
    count: int
    items: List[str]
    note: str = ""


def _count_ffuf_hits(csv_path: Path) -> int:
    lines = read_lines(csv_path)
    if not lines:
        return 0
    if "fuzz" in lines[0].lower() or "url" in lines[0].lower():
        return max(0, len(lines) - 1)
    return len(lines)


def collect(run_dir: Path) -> List[Section]:
    sections: List[Section] = []
    for fname, title, accent in LINE_ARTIFACTS:
        p = run_dir / fname
        if not p.exists():
            continue
        lines = read_lines(p)
        note = "" if len(lines) <= MAX_PREVIEW else f"showing first {MAX_PREVIEW} of {len(lines)}"
        sections.append(Section(title, accent, len(lines), lines[:MAX_PREVIEW], note))

    ffuf = run_dir / "ffuf_dirs"
    if ffuf.is_dir():
        csvs = sorted(ffuf.glob("*.csv"))
        total_hits = sum(_count_ffuf_hits(p) for p in csvs)
        sections.append(Section("Directory fuzz (FFUF)", "info", total_hits, [p.name for p in csvs], note=f"across {len(csvs)} host(s)"))

    lfi = run_dir / "ffuf_lfi_ssrf"
    if lfi.is_dir():
        csvs = sorted(lfi.glob("*.csv"))
        total_hits = sum(_count_ffuf_hits(p) for p in csvs)
        sections.append(Section("LFI/SSRF fuzz (FFUF)", "warn", total_hits, [p.name for p in csvs], note=f"across {len(csvs)} host(s)"))

    sqlmap = run_dir / "sqlmap_out"
    if sqlmap.is_dir():
        targets = sorted(p.name for p in sqlmap.iterdir() if p.is_dir())
        sections.append(Section("SQLi (SQLMap targets)", "high", len(targets), targets))

    return sections


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
.card.high::after{background:var(--high)}.card.muted::after{background:var(--muted)}
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


def _svg_bar_chart(sections: List[Section]) -> str:
    data = [(s.title, s.count, s.accent) for s in sections if s.count > 0]
    if not data:
        return '<p class="empty">No results to chart.</p>'
    colors = {"info": "#4ea1ff", "warn": "#ffb454", "high": "#ff5d6c", "muted": "#8aa0bd", "ok": "#49d19e"}
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
    return (f'<svg viewBox="0 0 {w} {height}" width="100%" role="img" '
            f'aria-label="Result counts">{"".join(rows)}</svg>')


def _section_html(s: Section) -> str:
    body = ("".join(f"{html.escape(x)}\n" for x in s.items)
            if s.items else None)
    inner = f"<pre>{body}</pre>" if body else '<p class="empty">No entries.</p>'
    note = f' · {html.escape(s.note)}' if s.note else ""
    return (f"<details><summary>{html.escape(s.title)}"
            f'<span class="badge">{s.count}{note}</span></summary>{inner}</details>')


def generate(run_dir: Path, meta: Dict[str, str],
             out_name: str = "report.html") -> Path:
    sections = collect(run_dir)
    cards = "".join(
        f'<div class="card {s.accent}"><div class="n">{s.count}</div>'
        f'<div class="t">{html.escape(s.title)}</div></div>'
        for s in sections
    ) or '<p class="empty">No artifacts produced yet.</p>'
    meta_html = "".join(
        f"<div><b>{html.escape(k)}</b>{html.escape(str(v))}</div>"
        for k, v in meta.items()
    )
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShadowRecon Report — {html.escape(meta.get('Target',''))}</title>
<style>{_CSS}</style></head><body><div class="wrap">
<header><div class="logo"><span class="s">Shadow</span><span class="r">Recon</span></div>
<div class="sub">Reconnaissance &amp; vulnerability report</div></header>
<section class="meta">{meta_html}</section>
<h2>Summary</h2><section class="cards">{cards}</section>
<div class="chart"><h2>Result counts</h2>{_svg_bar_chart(sections)}</div>
<h2>Details</h2>{''.join(_section_html(s) for s in sections)}
<footer>Generated {datetime.now():%Y-%m-%d %H:%M:%S} · for authorized testing only</footer>
</div></body></html>"""
    out = run_dir / out_name
    out.write_text(doc, encoding="utf-8")
    return out
