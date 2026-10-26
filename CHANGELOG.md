# Changelog

All notable changes to ShadowRecon are documented here.
This project adheres to [Keep a Changelog](https://keepachangelog.com/).

## [3.4.0] - 2026-10-26

Enterprise hardening and offensive realism: remote DNS leak prevention via `socks5h://`, finding deduplication with SQLite fingerprinting, dynamic worker scaling, modern WAF mutation engine with SQLMap tamper script mapping, progressive producer-consumer pipeline streaming, and in-memory live HTTP integration testbed.

### Security & Anonymity
- **Remote DNS Resolution**: Enforced `socks5h://127.0.0.1:9050` as the default Tor proxy protocol scheme and auto-normalized `socks5://` to `socks5h://` across all configurations and environment variables (`ALL_PROXY`), preventing local DNS query leaks.
- **Proxy Scheme Adaptation**: Automatically converted `socks5h://` down to `socks5://` strictly for `ffuf` (which rejects `socks5h://` URLs), and updated Nuclei proxy parameter to `-proxy`.
- **Ambient Proxy Leak Prevention**: Explicitly bound `proxies={"http": None, "https": None}` in `requests` when proxy routing is disabled, preventing unintended traffic leakage through ambient shell environment variables.

### Architecture & Hygiene
- **Root Entrypoint Bootstrap**: Slimmed root `main.py` from 652 lines of legacy synchronous code down to a clean 49-line bootstrap shim delegating to `shadowrecon.cli:main` while retaining backward-compatible aliases for legacy test suites.
- **Finding Fingerprinting & Deduplication**: Added deterministic finding fingerprinting (`sha256(vuln_type + target_url + payload)[:16]`) with unique SQLite index constraint and automatic migration check for existing session databases.

### Throughput & Performance
- **Dynamic Dalfox Workers**: Replaced hardcoded single-worker execution with dynamic worker scaling mapped to `--concurrency` (clamped to 1 in `--safe-mode`).
- **Concurrent Multi-Host FFUF**: Parallelized directory fuzzing across multiple hosts using `asyncio.Semaphore` and `asyncio.gather`.
- **SQLMap Batch Chunking & Timeouts**: Injected `--timeout=15` and `--retries=1` into single and batch SQLMap commands and capped batch input to top 50 unique parameter templates.
- **Progressive Pipeline Streaming**: Implemented `run_progressive_recon()`, allowing downstream URL harvesting and crawler drivers to consume `host_live` events and extract endpoints concurrently as live hosts are discovered by probing.

### WAF Evasion & Offensive Realism
- **Payload Mutation Engine**: Implemented `url_double_encode()`, `sql_comment_inline()`, `case_alternate()`, and `unicode_normalize_encode()` in `waf_payloads.py`.
- **SQLMap Tamper Integration**: Mapped detected WAF vendors (Cloudflare, AWS, ModSecurity, Imperva, Sucuri, FortiWeb, F5/BIG-IP, Akamai) to recommended SQLMap tamper scripts via `get_recommended_tampers()` and propagated them via `BypassContext.sqlmap_args()`.

### Verification Suite
- **Mock Vulnerable HTTP Target Server**: Built in-memory `MockTargetServer` (`ThreadingHTTPServer`) with simulated WAF rules, reflected XSS, and SQLi endpoints.
- **Live End-to-End Integration Tests**: Created `tests/test_v3_e2e_live.py` verifying real HTTP probe responses, WAF bypass detection, and pipeline CLI execution.
- **Test Coverage**: 197 unit and integration tests passing in ~2.0s with 0 regressions.

## [3.3.0] - 2026-10-26

Hardening and reliability overhaul: strict network isolation & anonymity leak prevention, runtime circuit breaker feedback loop, false-positive-free WAF bypass qualification, progressive event streaming, and safe concurrency controls.

### Security & Anonymity
- **Leak-Proof Proxy Routing**: Injected explicit proxy arguments for `subfinder` (`-proxy`) and `wafw00f` (`-p`).
- **Subprocess Environment Injection**: Automatically injected `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY` (and lower-case equivalents) into all subprocess executions in `AsyncExecutor`, ensuring tools without CLI proxy flags (`waybackpy`, `assetfinder`) strictly route through configured proxies.

### Resilience & Fault Tolerance
- **Runtime Circuit Breaker Feedback**: Connected `HostCircuitBreaker` to direct HTTP probing (`execute_http_probe`) and subprocess timeouts. Consecutive timeouts or connection failures actively trip the circuit to `OPEN`, preventing wasted scanning effort and hanging connections.
- **Adaptive Scanner Proxy Rotation**: Automatically trigger proxy rotation (`Signal.NEWNYM` or proxy pool rotation) when black-box subprocess scanners encounter HTTP 429 rate limits or blocks.
- **Circuit Breaker URL Filtering**: Pre-filtered target lists for `KatanaDriver`, `NucleiDriver`, `DalfoxDriver`, `SqlmapDriver`, and `ParamspiderDriver` using `filter_healthy_urls()`.

### Correctness & Tooling
- **Strict WAF Bypass Qualification**: Eliminated false-positive bypass reporting. `best_bypass` is only assigned when `confirmed=True` (`status_code == 200` after a baseline block). Unblocked targets log informational candidate mutations without overriding downstream scanner contexts.
- **WAF Bypass Header Propagation**: Custom bypass headers are now forwarded to `NucleiDriver` (`-H`) and `HttpxDriver` (`-H`).

### Packaging & Workspace Hygiene
- **ParamSpider Output Scoping**: Isolated ParamSpider endpoint results to `ctx.config.outdir / "paramspider" / f"{domain}.txt"`, automatically removing ephemeral `./results` folders from the working directory.
- **Package Hierarchy Consolidation**: Relocated canonical `waf_payloads.py` and `console.py` into package hierarchy (`src/shadowrecon/waf_payloads.py`, `src/shadowrecon/console.py`), with root files maintained as backward-compatible shims.
- **Clean Package Installation**: Removed top-level `py-modules` from `pyproject.toml` to prevent namespace pollution in `site-packages`.

### Performance & Observability
- **Progressive Event Streaming**: `HttpxDriver` and `run_probing_stage()` publish live hosts on `"host_live"` events. `run_urls_stage()` streams `"param_url"` events.
- **Safe Concurrency Controls**: Added `--concurrency` flag (default: 3) to execute multiple subdomain and URL harvesting drivers concurrently via `asyncio.Semaphore`. Concurrency is automatically clamped to 1 in `--safe-mode`.
- **AsyncEventBus Deadlock Fix**: Added `_closed_topics` tracking and `reopen_topic()` to `AsyncEventBus` to prevent subscriber deadlocks on late registrations.
- **Terminal Observability**: Added `format_status_card()` and enhanced the execution summary table with target URL, active egress proxy URL, and circuit breaker health statistics.
- **Test Suite**: Expanded test coverage to 184 unit tests (100% passing in ~1.4s).

## [3.2.0] - 2026-10-26


Major architecture enhancement implementing pluggable scanner drivers, multi-driver aggregation, enterprise reporting, circuit breaker resilience, and advanced scoping.

### Added
- **Scanner Driver Architecture**: Decoupled `ScannerDriver` base class and concrete drivers for `subfinder`, `amass`, `assetfinder`, `sublist3r`, `httpx`, `gau`, `wayback`, `katana`, `paramspider`, `nuclei`, `dalfox`, and `sqlmap`.
- **Multi-Driver Discovery & URL Aggregation**: Comma-separated driver selection and multi-source aggregation via `--driver-subdomains` and `--driver-urls`.
- **Reporting & Webhook Dispatch**: Portable Markdown report generation (`report.md`, `--export-md`), WeasyPrint executive PDF report export (`--export-pdf`), and Discord/Slack/Generic webhook alerting (`--webhook`, `--webhook-events`).
- **Resilience & Health**: Preflight environment diagnostics (`shadowrecon doctor`), 3-state `HostCircuitBreaker` (`CLOSED`, `OPEN`, `HALF_OPEN`) with dead host fast-failing, and mid-stage cancellation checkpointing.
- **Advanced Scope & Safe Mode**: CIDR range scoping, wildcard pattern matching, negative target exclusions (`--exclude`), active web port matrix sweep (`--ports web`), and production `--safe-mode`.
- **Test Suite**: 167 unit tests covering 100% of modules and drivers.

## [2.0.0] - 2026-10-25

A ground-up engineering, security, and presentation overhaul. **Scanning
capability is unchanged** — no new attack vectors, no expanded WAF-bypass
payloads, no evasion improvements. See [`ANALYSIS.md`](ANALYSIS.md).

### Security
- Removed the hardcoded Tor control password; it now comes from the
  `TOR_CONTROL_PASSWORD` env var or `--tor-pass`.
- Eliminated `shell=True` + f-string command construction (command-injection
  surface, CWE-78). All external tools run via argument lists with no shell.
- Added target-URL validation and a scope allowlist that refuses out-of-scope
  HTTP payload requests.
- `bandit` clean (no Medium/High); documented the residual subprocess advisory.

### Added
- `utils.py` — pure, unit-tested helpers.
- `waf_payloads.py` — explicit payload registry (replaces `globals()` dispatch).
- `report.py` — self-contained, offline HTML report.
- `console.py` — rich-optional banner, logging, and summary table.
- Authorization gate, `--dry-run`, `--rate-limit`, and a per-run audit log.
- Unit test suite, GitHub Actions CI, `pyproject.toml` packaging with a
  `shadowrecon` entry point, and `SECURITY.md`.

### Changed
- Per-run output directory (`runs/<domain>-<timestamp>/`) instead of scattering
  artifacts in the CWD.
- Structured logging to console and file.
- Rewrote the README.

### Fixed
- Brittle `globals()[func]` WAF dispatch, inconsistent error handling, and
  encoding issues on non-UTF-8 consoles.
