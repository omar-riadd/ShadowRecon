# ShadowRecon Engineering Roadmap (v3.1+)

This document outlines architectural, reliability, and data engineering improvements for the ShadowRecon pipeline.

---

## 1. Executive Summary & Goals

Following the successful implementation of the **v3.0 Async Redesign** (which introduced the SQLite persistence layer, native SOCKS5 routing, streaming event bus, and isolated stage runners), this roadmap focuses on:
- **Resilience**: Adaptive rate-limiting, exponential backoff, and circuit health telemetry.
- **Asset Intelligence**: Session diffing to detect infrastructure changes over time (drift detection).
- **Interoperability**: Standardized exports (JSON, CSV, SARIF) for integration into dashboards and asset inventories.
- **Extensibility**: Pluggable tool abstraction drivers and CI mock environments.

---

## 2. Gap Analysis & Proposed Initiatives

### Milestone 1: Adaptive Flow Control & Network Resilience

#### 1.1 Dynamic Backoff & Token Bucket Rate Limiting
- **Current Limitation**: Rate limiting is currently fixed via `--rate-limit` (seconds between requests). Under bursty network conditions or strict upstream limits, fixed delays can either be too conservative or trigger 429 status codes.
- **Planned Improvement**:
  - Implement a token-bucket rate limiter with jitter.
  - Automatically apply exponential backoff when consecutive `429` (Too Many Requests) or `503` (Service Unavailable) status codes are observed.
  - Reset backoff gracefully after sustained successful (`200 OK`) responses.

#### 1.2 Tor Circuit Health Checking & Automatic Recovery
- **Current Limitation**: If the SOCKS5 proxy becomes unresponsive or Tor drops a circuit during long runs, subprocess calls may time out without proactive detection.
- **Planned Improvement**:
  - Implement an asynchronous health checker that sends lightweight keepalive probes through the proxy before launching intensive stages.
  - Automatically trigger `NEWNYM` circuit rotation if latency spikes above a configurable threshold.

---

### Milestone 2: Asset Drift & Differential Analysis

#### 2.1 Cross-Session Diffing (`--diff`)
- **Current Limitation**: Each scan session records independent artifacts in its SQLite database. Tracking what changed on a domain between scans currently requires manual diffing of flat files.
- **Planned Improvement**:
  - Add `--diff <path_to_prior_session.db>`.
  - Compare host lists, subdomains, and status codes between runs.
  - Produce a structured "Drift Summary":
    - Newly discovered subdomains (+).
    - Decommissioned / unreachable hosts (-).
    - Status code changes (e.g. 403 Forbidden -> 200 OK).

#### 2.2 Historical Asset Tracking
- **Planned Improvement**:
  - Add a unified multi-scan view in SQLite, associating records with a unique `scan_id` and timestamp.
  - Track asset discovery trends over time.

---

### Milestone 3: Interoperability & Standardized Exports

#### 3.1 Enterprise Export Formats (JSON & SARIF)
- **Current Limitation**: Exports are currently plain text (`subdomains.txt`, `live.txt`) and a human-readable HTML report.
- **Planned Improvement**:
  - Add `--export-json <output.json>`: Machine-readable summary of all discovered assets, timings, and findings.
  - Add `--export-sarif <output.sarif>`: Static Analysis Results Interchange Format (SARIF) export for ingestion into GitHub Security Advisories or CI vulnerability dashboards.
  - Add `--export-csv <dir/>`: Tabular exports for spreadsheet analysis.

#### 3.2 Finding Standardization (CWE / CVSS Metadata)
- **Planned Improvement**:
  - Normalize findings across all scanner drivers into structured schemas containing standard CWE identifiers, severity scores, and reproduction parameters.

---

### Milestone 4: Modular Scanner Driver Abstraction

#### 4.1 `ScannerDriver` Interface
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

#### 4.2 Mock Drivers for CI Testing
- **Planned Improvement**:
  - Provide synthetic mock drivers that simulate tool outputs in isolated test environments.
  - Allows full end-to-end integration tests in CI without requiring binary installations of external packages.

---

### Milestone 5: Configuration Validation & Usability

#### 5.1 TOML Schema Validation
- **Current Limitation**: `shadowrecon.toml` is parsed into a generic dictionary. Invalid keys or wrong data types are silently ignored or cause downstream runtime exceptions.
- **Planned Improvement**:
  - Implement strict configuration schema validation with informative error messages on misconfigured settings.
  - Support environment variable interpolation in configuration files (e.g. `tor_pass = "${TOR_PASS}"`).

---

## 3. Implementation Phasing

| Phase | Milestone | Primary Modules Affected | Deliverables |
|---|---|---|---|
| **Phase 1** | Adaptive Flow Control | `src/shadowrecon/core/`, `executor.py` | Token-bucket limiter, backoff logic, circuit health probes |
| **Phase 2** | Differential Analysis | `src/shadowrecon/storage/`, `cli.py` | `--diff` flag, database comparison engine, drift reporting |
| **Phase 3** | Enterprise Exports | `src/shadowrecon/reporting/` | SARIF, JSON, and CSV exporters |
| **Phase 4** | Driver Decoupling | `src/shadowrecon/modules/` | Abstract `ScannerDriver` class, mock test drivers |
| **Phase 5** | Config Validation | `src/shadowrecon/config.py` | Strict schema checks, environment variable substitution |
