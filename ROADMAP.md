# ShadowRecon Engineering Roadmap (v3.1+)

This document outlines architectural, reliability, and data engineering improvements for the ShadowRecon pipeline.

---

## 1. Executive Summary & Goals

Following the successful implementation of the **v3.0 Async Redesign** (which introduced the SQLite persistence layer, native SOCKS5 routing, streaming event bus, and isolated stage runners), this roadmap focuses on:
- **Resilience & Proxy Rotation**: Smart rate-limiting backoff, multi-provider proxy rotation (residential, datacenter, AWS API Gateway) alongside Tor.
- **Engine Expansion**: Full Nuclei engine integration with CVSS severity filtering (`--severity medium,high,critical`).
- **Asset Intelligence**: Session diffing to detect infrastructure changes over time (drift detection).
- **Interoperability**: Standardized exports (JSON, CSV, SARIF) for integration into dashboards and asset inventories.
- **Extensibility**: Pluggable tool abstraction drivers and CI mock environments.

---

## 2. Gap Analysis & Proposed Initiatives

### Milestone 1: Adaptive Flow Control & Proxy Rotation

#### 1.1 Smart Rate-Limit Backoff
- **Current Limitation**: Rate limiting is currently fixed via `--rate-limit` (seconds between requests). Under bursty conditions or strict upstream limits, fixed delays can either be unnecessarily slow or trigger 429 status codes, immediately burning a Tor circuit.
- **Planned Improvement**:
  - Implement dynamic adaptive rate limiting with a token bucket and jitter.
  - Automatically apply exponential backoff when consecutive `429` (Too Many Requests) or `503` (Service Unavailable) status codes are observed before triggering an IP/circuit rotation.
  - Reset backoff gracefully after sustained successful (`200 OK`) responses.

#### 1.2 Proxy Rotation Beyond Tor
- **Current Limitation**: Tor exit nodes are frequently blacklisted or challenged with CAPTCHAs by major enterprise CDNs and cloud WAFs.
- **Planned Improvement**:
  - Add support for rotating residential and datacenter proxy pools (e.g., AWS API Gateway / ProxyCannon, HTTP/SOCKS5 rotating proxy pools) alongside Tor.
  - Provide a pluggable proxy manager interface allowing operators to choose between Tor, external proxy pools, or multi-cloud egress rotation.

#### 1.3 Tor Circuit Health Checking & Automatic Recovery
- **Current Limitation**: If the SOCKS5 proxy becomes unresponsive or Tor drops a circuit during long runs, subprocess calls may time out without proactive detection.
- **Planned Improvement**:
  - Implement an asynchronous health checker that sends lightweight keepalive probes through the proxy before launching intensive stages.
  - Automatically trigger `NEWNYM` circuit rotation if latency spikes above a configurable threshold.

---

### Milestone 2: Nuclei Engine Expansion & Driver Decoupling

#### 2.1 Nuclei Engine Integration
- **Current Limitation**: Nuclei is currently restricted exclusively to subdomain takeover templates (`http/takeovers`).
- **Planned Improvement**:
  - Expand the Nuclei stage from just `takeovers/` to custom CVSS severity filtering (`--severity medium,high,critical`).
  - Add support for filtering by template tags (e.g. `--tags cve,misconfig,exposure`).
  - Stream Nuclei JSON output directly into the SQLite `findings` table for deduplicated reporting.

#### 2.2 `ScannerDriver` Interface
- **Current Limitation**: External tool execution commands are hardcoded in stage modules (`recon.py`, `vuln.py`).
- **Planned Improvement**:
  - Define an abstract base class `ScannerDriver`:
    ```python
    class ScannerDriver(ABC):
        @abstractmethod
        def is_available(self) -> bool: ...
        @abstractmethod
        async def execute(self, ctx: StageContext) -> ScanResult: ...
    ```
  - Allows swapping implementations (e.g. swapping `subfinder` with `amass`, or `katana` with an internal crawler) without modifying pipeline orchestration.

#### 2.3 Mock Drivers for CI Testing
- **Planned Improvement**:
  - Provide synthetic mock drivers that simulate tool outputs in isolated test environments.
  - Allows full end-to-end integration tests in CI without requiring binary installations of external packages.

---

### Milestone 3: Asset Drift & Differential Analysis

#### 3.1 Cross-Session Diffing (`--diff`)
- **Current Limitation**: Each scan session records independent artifacts in its SQLite database. Tracking what changed on a domain between scans currently requires manual diffing of flat files.
- **Planned Improvement**:
  - Add `--diff <path_to_prior_session.db>`.
  - Compare host lists, subdomains, and status codes between runs.
  - Produce a structured "Drift Summary":
    - Newly discovered subdomains (+).
    - Decommissioned / unreachable hosts (-).
    - Status code changes (e.g. 403 Forbidden -> 200 OK).

#### 3.2 Historical Asset Tracking
- **Planned Improvement**:
  - Add a unified multi-scan view in SQLite, associating records with a unique `scan_id` and timestamp.
  - Track asset discovery trends over time.

---

### Milestone 4: Interoperability & Standardized Exports

#### 4.1 Enterprise Export Formats (JSON & SARIF)
- **Current Limitation**: Exports are currently plain text (`subdomains.txt`, `live.txt`) and a human-readable HTML report.
- **Planned Improvement**:
  - Add `--export-json <output.json>`: Machine-readable summary of all discovered assets, timings, and findings.
  - Add `--export-sarif <output.sarif>`: Static Analysis Results Interchange Format (SARIF) export for ingestion into GitHub Security Advisories or CI vulnerability dashboards.
  - Add `--export-csv <dir/>`: Tabular exports for spreadsheet analysis.

#### 4.2 Finding Standardization (CWE / CVSS Metadata)
- **Planned Improvement**:
  - Normalize findings across all scanner drivers into structured schemas containing standard CWE identifiers, severity scores, and reproduction parameters.

---

### Milestone 5: Configuration Validation & Usability

#### 5.1 TOML Schema Validation
- **Current Limitation**: `shadowrecon.toml` is parsed into a generic dictionary. Invalid keys or wrong data types are silently ignored or cause downstream runtime exceptions.
- **Planned Improvement**:
  - Implement strict configuration schema validation with informative error messages on misconfigured settings.
  - Support environment variable interpolation in configuration files (e.g. `tor_pass = "${TOR_PASS}"`).

---

## 3. Implementation Phasing

| Phase | Milestone | Primary Modules Affected | Deliverables | Status |
|---|---|---|---|---|
| **Phase 1** | Smart Rate-Limit & Proxy Rotation | `src/shadowrecon/core/`, `executor.py` | Adaptive backoff (429/503), residential/datacenter proxy pool support, circuit health telemetry | Completed |
| **Phase 2** | Nuclei Engine Expansion | `src/shadowrecon/modules/takeover.py`, `nuclei.py` | Full Nuclei severity filtering (`--severity medium,high,critical`), tag filtering, structured JSON ingestion | Completed |
| **Phase 3** | Differential Analysis | `src/shadowrecon/storage/`, `cli.py` | `--diff` flag, database comparison engine, drift reporting | Completed |
| **Phase 4** | Enterprise Exports | `src/shadowrecon/reporting/` | SARIF, JSON, and CSV exporters | Completed |
| **Phase 5** | Driver Decoupling & Config | `src/shadowrecon/modules/`, `config.py` | Abstract `ScannerDriver` class, mock test drivers, strict TOML schema validation | Up Next |
