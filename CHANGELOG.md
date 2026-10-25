# Changelog

All notable changes to ShadowRecon are documented here.
This project adheres to [Keep a Changelog](https://keepachangelog.com/).

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
