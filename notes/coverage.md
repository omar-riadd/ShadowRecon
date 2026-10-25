# Project Coverage Log

Total files in repository: 36 unique files (excluding bytecode `__pycache__` and pytest cache).
All files have been read in full without skipping or truncation.

| File | Status | Lines / Size | Verified Role / Notes |
|---|---|---|---|
| `README.md` | Fully read | 135 lines | Project description, architecture diagram, CLI usage, installation |
| `pyproject.toml` | Fully read | 36 lines | Packaging spec, dependencies (`requests[socks]`, `stem`), entrypoint `shadowrecon = main:main` |
| `requirements.txt` | Fully read | 8 lines | Pinned requirements (`requests[socks]>=2.32`, `stem>=1.8`) |
| `ANALYSIS.md` | Fully read | 74 lines | Gap & vulnerability analysis of legacy v1 vs refactored v2 |
| `SECURITY.md` | Fully read | 55 lines | SAST results (`bandit`), accepted `# nosec` notes, hygiene policies |
| `CHANGELOG.md` | Fully read | 39 lines | Keep a Changelog documentation for v2.0.0 overhaul |
| `words.txt` | Fully read | 4 lines | Sample wordlist (`admin`, `login`, `api`) |
| `.gitignore` | Fully read | 21 lines | Ignores `runs/`, `demo_report/`, pycache, venv, temporary artifacts |
| `.gitattributes` | Fully read | 5 lines | EOL normalization and binary tagging |
| `.github/workflows/ci.yml` | Fully read | 28 lines | GitHub Actions CI matrix (Python 3.9, 3.11, 3.12) running unittest |
| `utils.py` | Fully read | 43 lines | Pure stdlib helpers: `parse_target`, `in_scope`, `slugify`, `read_lines`, `count_lines` |
| `console.py` | Fully read | 73 lines | Presentation layer: banner, log handler, summary table (`rich` optional with ANSI fallback) |
| `waf_payloads.py` | Fully read | 248 lines | Preserved WAF bypass registry (`BYPASS` dict mapping 20 WAFs to functions) + default payloads |
| `report.py` | Fully read | 159 lines | Self-contained HTML report generator with dark CSS and SVG bar chart |
| `main.py` | Fully read | 541 lines | Core pipeline orchestrator, Tor circuit rotation, safe subprocess executor, recon/vuln stages |
| `tests/test_shadowrecon.py` | Fully read | 89 lines | Unittest suite verifying `utils`, `waf_payloads`, and `report` modules (passes 8/8) |
| `_stage/test_v1.py` | Fully read | 49 lines | Initial staging test file covering `TestUtils` |
| `_stage/test_v2.py` | Fully read | 66 lines | Staging test file covering `TestUtils` and `TestWafRegistry` |
| `runs/example.com-20261025-110843/audit.log` | Fully read | 42 lines | Recorded execution log of previous dry-run against example.com |
| `runs/example.com-20261025-110843/subdomains.txt` | Fully read | 2 lines | Subdomain output artifact from dry-run (`example.com`) |
| `runs/example.com-20261025-110843/params.txt` | Fully read | 0 lines | Empty parameter artifact from dry-run |
| `runs/example.com-20261025-110843/200-ok.txt` | Fully read | 0 lines | Empty 200-ok artifact from dry-run |
| `runs/example.com-20261025-110843/report.html` | Fully read | 42 lines | Generated HTML report from dry-run |
| `demo_report/200-ok.txt` | Fully read | 3 lines | Mock WAF bypass 200 OK responses |
| `demo_report/live.txt` | Fully read | 6 lines | Mock discovered live HTTP hosts |
| `demo_report/nuclei_takeover.txt` | Fully read | 2 lines | Mock subdomain takeover finding on dev.example.com |
| `demo_report/params.txt` | Fully read | 15 lines | Mock parameterized URLs |
| `demo_report/subdomains.txt` | Fully read | 11 lines | Mock discovered subdomains |
| `demo_report/wayback.txt` | Fully read | 24 lines | Mock historical archive URLs |
| `demo_report/xss_dalfox.txt` | Fully read | 3 lines | Mock reflected and stored XSS PoC strings |
| `demo_report/ffuf_dirs/*.csv` (3 files) | Fully read | 3 lines each | Mock CSV directory fuzz results |
| `demo_report/report.html` | Fully read | 102 lines | Complete rendered demo HTML report |
| `ship/ShadowRecon Project Presentation.pdf` | Fully read | 5 pages | Slide presentation of authenticated profile XSS finding found via ShadowRecon |
| `ship/` directory contents | Fully verified | — | Mirror of root codebase verified byte-for-byte identical via `diff -rq` (plus the presentation PDF) |
| `/usr/bin/paramspider` | Fully read | 34 lines | System entrypoint script for ParamSpider |
| `/usr/lib/python3/dist-packages/paramspider/client.py` | Fully read | 68 lines | ParamSpider network client and User-Agent rotator |
| `/usr/lib/python3/dist-packages/paramspider/main.py` | Fully read | 168 lines | ParamSpider CLI parser, Wayback scraper, URL cleaner, and output writer (`results/{domain}.txt`) |

