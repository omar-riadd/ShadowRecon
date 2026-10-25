# Security Policy

## Responsible use

ShadowRecon performs active scanning and injection testing. Use it **only**
against systems you own or are explicitly authorized to test. Unauthorized use
may be illegal. The authorization gate and scope allowlist are safeguards, not
permission.

## Static analysis (SAST)

The code is scanned with [`bandit`](https://bandit.readthedocs.io/):

```bash
bandit -r main.py waf_payloads.py utils.py report.py console.py
```

Result: **no Medium/High findings.** The remaining Low advisories are inherent
to the tool's purpose and are documented inline with `# nosec`:

| ID | Where | Why it's accepted |
|----|-------|-------------------|
| B404 | `import subprocess` | External recon tools are invoked by design. |
| B603 | `run_tool()` | Every external call uses an **argument list with `shell=False`**; `cmd[0]` is a fixed tool name and the target URL is validated by `utils.parse_target()`. No shell, so there is no shell-injection surface. |

Notably, the original single-file script used `subprocess.run(..., shell=True)`
with f-string-built commands — a High-severity command-injection surface
(B602). The refactor removed it entirely.

## Dependencies

Direct dependencies are minimal: `requests[socks]` and `stem`. Audit with:

```bash
pip-audit -r requirements.txt
```

`requirements.txt` floors `requests>=2.32` so a fresh install resolves a modern
`urllib3`/`certifi` (older pinned versions carry published advisories). Keep
transitive dependencies current.

## Operator hygiene built in

- **No hardcoded secrets** — the Tor control password is read from
  `TOR_CONTROL_PASSWORD` / `--tor-pass`, never stored in source.
- **Scope enforcement** — HTTP payload requests outside the target domain are
  refused.
- **Audit log** — every external command and HTTP action is timestamped to
  `audit.log` in the run directory.

## Reporting a vulnerability

Open a private security advisory on the repository, or contact the maintainer.
Please do not file public issues for undisclosed vulnerabilities.
