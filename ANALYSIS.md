# ShadowRecon — Gap & Vulnerability Analysis + Improvement Plan

Scope of this document: engineering defects, operator-security issues, and
robustness gaps in `main.py`, with the concrete fixes applied in the refactor.
It deliberately does **not** cover ways to make the tool a more effective
attack/evasion instrument — only ways to make it safer, more correct, and
more maintainable software.

---

## A. Security defects in the tool itself (operator-facing)

| # | Issue | Location (orig) | Risk | Fix applied |
|---|-------|-----------------|------|-------------|
| A1 | **Hardcoded Tor control password** `"m06ahmed"` in plaintext | line 26 | Credential leaked in source/VCS; copy-paste reuse | Read from `TOR_CONTROL_PASSWORD` env var (or `--tor-pass`); never stored in code |
| A2 | **`shell=True` with f-string command building** throughout | `run_pc` (75), `run_paramspider` (529), `xss_with_dalfox` (577), `sqli_with_sqlmap` (611) | **Command injection** — a crafted target URL / wordlist path / filename containing `;`, `$()`, `&&`, backticks executes arbitrary shell | All subprocess calls use **argument lists, `shell=False`**; redirections (`>`) replaced by Python-side file writes |
| A3 | **No input validation** on `-u`/`-w` | `main` (680) | Feeds unvalidated strings into shell + builds malformed URLs | URL scheme/host validated; wordlist/payload paths checked to exist; domain extracted safely |
| A4 | **Dynamic dispatch via `globals()[func]`** | `stage_waf` (428) | Any string collision in `waf_map` could call an unintended global; brittle | Replaced with an explicit function **registry dict** (`BYPASS`) — no name-based global lookup |
| A5 | **No scope enforcement** | — | Tool will scan whatever it's pointed at; easy to exceed authorization | **In-scope check**: active requests restricted to the target apex domain + its subdomains; out-of-scope URLs skipped and logged |

## B. Robustness / correctness gaps

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| B1 | Bare `except Exception` swallows errors silently; inconsistent handling across stages | many | Narrow exceptions, log with context, continue per-stage without aborting the run |
| B2 | Output is `print()` only — no persisted log, stdout/stderr mixed | everywhere | Structured `logging` to console **and** a per-run `audit.log` |
| B3 | All artifacts dumped into CWD (`200-ok.txt`, `live.txt`, …) — collisions across runs, no isolation | everywhere | Per-run output dir `runs/<domain>-<timestamp>/`; all artifacts namespaced there |
| B4 | `probe_httpx`/`wayback_urls` read tool-written files with inconsistent existence checks | 457, 471 | Centralized output handling; existence + emptiness checked uniformly |
| B5 | Fixed `time.sleep(10)` after every rotation regardless of need | `rotate_ip` (40) | Kept but made configurable; rotation guarded behind `stem` availability + password present |
| B6 | File opens without consistent encoding (Windows `cp1252` surprises) | several | All text I/O uses `encoding="utf-8"` via `pathlib` |
| B7 | `run_paramspider` reconstructs per-domain filenames by string munging — fragile, silently drops results | 522 | Isolated, documented, failure logged rather than hidden |
| B8 | WAF detection is a single regex over `wafw00f` text; no graceful "unknown" handling difference | `detect_waf` (104) | Preserved behavior, but detection + match are logged and fall back cleanly to generic set |
| B9 | No politeness/throttle — can hammer a target | — | Optional global `--rate-limit` delay between HTTP requests |

## C. Portability / packaging

| # | Issue | Fix |
|---|-------|-----|
| C1 | `requirements.txt` lists `argparse` (stdlib) and bare `requests` | Trimmed to `requests[socks]`, `stem`; versions pinned minimally |
| C2 | Linux-only assumptions (`proxychains`, `tor`, Go tools) not signalled | `check_tools` warns clearly on non-Linux; proxychains auto-skips if absent |
| C3 | Monolithic 730-line file mixing framework + payload data | Split: framework in `main.py`, bypass payloads in `waf_payloads.py` (data/behavior separation) |

## D. Responsible-use guardrails added

These are new, and intentionally make the tool *harder to misuse*:

1. **Authorization gate** — refuses to run active scans unless `--authorized` is
   passed; interactively requires the operator to retype the target domain to
   confirm scope (skippable only with explicit `--yes` for automation).
2. **Dry-run mode** (`--dry-run`) — prints every tool invocation that *would*
   run, executes nothing. Lets you review the whole plan safely.
3. **Scope allowlist** — HTTP payload requests that resolve outside the target
   domain are refused.
4. **Audit log** — every external command and every HTTP action is timestamped
   to `audit.log` for accountability.

## E. Deliberately NOT changed

- The WAF-bypass payload sets are **preserved verbatim** (moved to
  `waf_payloads.py`), not expanded or made more effective.
- No new vulnerability classes, exploit techniques, or evasion methods added.
- Scan aggressiveness (thread counts, levels/risk) left at the original,
  conservative values.

---

## F. Suggested next steps (not implemented here)

- Replace the flat-file artifacts with a single structured JSON/SQLite run
  report for easier triage.
- Add unit tests around URL parsing, scope checks, and output parsing.
- Add a config file (`config.yaml`) so the many knobs aren't all CLI flags.
- Make stages independently resumable (skip stages whose outputs already exist).
