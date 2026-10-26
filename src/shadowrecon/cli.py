"""Command-line interface and entrypoint for ShadowRecon v3.0."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from shadowrecon import __version__
from shadowrecon.config import BypassContext, Config, ConfigValidationError, default_nuclei_templates_dir, load_toml_config
from shadowrecon.core.circuit import HostCircuitBreaker
from shadowrecon.core.executor import AsyncExecutor, resolve_binary
from shadowrecon.core.health import PreflightChecker
from shadowrecon.core.proxy import DirectProxyProvider, ProxyPoolProvider, TorProxyProvider
from shadowrecon.core.ratelimit import AdaptiveRateLimiter
from shadowrecon.core.scope import ScopeManager, parse_target, slugify
from shadowrecon.core.tor import TorManager
from shadowrecon.drivers import global_registry
from shadowrecon.modules.recon import (
    run_fuzzing_stage,
    run_probing_stage,
    run_subdomains_stage,
    run_urls_stage,
)
from shadowrecon.modules.nuclei import run_nuclei_stage
from shadowrecon.modules.takeover import run_takeover_stage
from shadowrecon.modules.vuln import (
    run_lfi_stage,
    run_sqli_stage,
    run_xss_stage,
)
from shadowrecon.modules.waf import run_waf_stage
from shadowrecon.pipeline.queue import AsyncEventBus
from shadowrecon.pipeline.runner import PipelineRunner, StageContext, StageResult
from shadowrecon.reporting import (
    attach_finding_notifier,
    build_completion_payload,
    detect_webhook_type,
    export_csv,
    export_json,
    export_markdown,
    export_pdf,
    export_sarif,
    generate_report_from_store,
    send_webhook,
)
from shadowrecon.reporting.export import build_manifest_dict
from shadowrecon.storage.diff import SessionDiff, diff_sessions
from shadowrecon.storage.session import SessionStore

BANNER = r"""
   ____  __            __               ____                       
  / __/ / /  ___ _ ___/ / ___  _    __ / __ \ ___  ____ ___   ___  
 _\ \  / _ \/ _ `// _  / / _ \| |/|/ // /_/ // -_)/ __// _ \ / _ \ 
/___/ /_//_/\_,_/ \_,_/  \___/|__,__/ \_, _/ \__/ \__/ \___//_//_/ 
                        v3.4 Enterprise Hardening
"""

REQUIRED_TOOLS = {
    "httpx": "ProjectDiscovery HTTP probing tool ('sudo apt install httpx-toolkit' or 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest')",
    "subfinder": "Subdomain enumeration tool ('go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest')",
}

OPTIONAL_TOOLS = {
    "wafw00f": "WAF fingerprinting tool ('sudo apt install wafw00f')",
    "ffuf": "Web fuzzer ('sudo apt install ffuf')",
    "nuclei": "Vulnerability / takeover scanner ('go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest')",
    "dalfox": "XSS scanner ('go install github.com/hahwul/dalfox/v2@latest')",
    "sqlmap": "SQL injection tool ('sudo apt install sqlmap')",
    "katana": "Modern crawler ('go install github.com/projectdiscovery/katana/cmd/katana@latest')",
    "waybackpy": "Wayback Machine API client ('pip install waybackpy')",
    "paramspider": "Parameter discovery tool ('pip install git+https://github.com/devanshbatham/ParamSpider')",
}

log = logging.getLogger("shadowrecon")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)


def check_tooling(dry_run: bool = False) -> None:
    """Verify tool presence, distinguishing required from optional tools."""
    missing_required = []
    for tool, hint in REQUIRED_TOOLS.items():
        resolved = resolve_binary(tool)
        if shutil.which(resolved) or (Path(resolved).is_file() and os.access(resolved, os.X_OK)):
            log.debug("  [OK] %s -> %s", tool, resolved)
        else:
            log.error("  [MISSING REQUIRED] %s - %s", tool, hint)
            missing_required.append(tool)

    for tool, hint in OPTIONAL_TOOLS.items():
        resolved = resolve_binary(tool)
        if shutil.which(resolved) or (Path(resolved).is_file() and os.access(resolved, os.X_OK)):
            log.debug("  [OK] %s -> %s", tool, resolved)
        else:
            log.debug("  [OPTIONAL MISSING] %s - %s", tool, hint)

    if missing_required and not dry_run:
        log.error("Critical tools missing: %s. Please install them or run with --dry-run.", ", ".join(missing_required))
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shadowrecon",
        description="ShadowRecon v3.4 — Tor-anonymized reconnaissance and vulnerability pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-u", "--url", dest="target", help="Target URL (e.g. https://example.com/)")
    p.add_argument("-w", "--wordlist", help="Path to wordlist for directory fuzzing")
    p.add_argument("-l", "--lfi-payloads", dest="lfi_payloads", help="Path to LFI payloads file")
    p.add_argument("-o", "--outdir", help="Output directory for scan session artifacts")
    p.add_argument("--stages", default="all", help="Comma-separated stages to run (default: all)")
    p.add_argument("--skip-stages", default="", help="Comma-separated stages to skip")
    p.add_argument("--force-rerun", action="store_true", help="Rerun stages even if completed in session")
    p.add_argument("--socks", default="socks5h://127.0.0.1:9050", help="Tor SOCKS5 proxy URL (defaults to socks5h:// for remote DNS)")
    p.add_argument("--tor-port", type=int, default=9051, help="Tor control port")
    p.add_argument("--tor-pass", default=os.getenv("TOR_CONTROL_PASSWORD", ""), help="Tor control password")
    p.add_argument("--rotate-wait", type=int, default=10, help="Wait time (seconds) after circuit rotation")
    p.add_argument("--timeout", type=int, default=20, help="HTTP request timeout in seconds")
    p.add_argument("--rate-limit", type=float, default=0.0, help="Delay between requests in seconds")
    p.add_argument("--max-backoff", type=float, default=60.0, help="Maximum exponential backoff in seconds (default: 60)")
    p.add_argument("--threads", type=int, default=5, help="FFUF thread count (low default for Tor)")
    p.add_argument("--severity", "--nuclei-severity", dest="nuclei_severity", default="medium,high,critical", help="Nuclei CVSS severity filter (default: medium,high,critical)")
    p.add_argument("--tags", "--nuclei-tags", dest="nuclei_tags", default="", help="Nuclei template tags filter (e.g. cve,misconfig,exposure)")
    p.add_argument("--nuclei-templates", help="Path to nuclei-templates directory (default: ~/.local/nuclei-templates or ~/nuclei-templates)")
    p.add_argument("--config", help="Path to shadowrecon.toml config file")
    p.add_argument("--diff", dest="diff_db", help="Path to prior session.db for cross-session differential drift analysis")
    p.add_argument("--dry-run", action="store_true", help="Simulate execution without sending live packets")
    p.add_argument("--proxy-provider", default="tor", choices=["tor", "pool", "direct"], help="Proxy provider to use (default: tor)")
    p.add_argument("--proxy-pool", dest="proxy_pool_file", help="Path to file containing rotating proxy URLs")
    p.add_argument("--driver-subdomains", help="Subdomain enumeration driver(s), comma-separated (e.g. subfinder,assetfinder,amass)")
    p.add_argument("--driver-urls", help="URL harvesting driver(s), comma-separated (e.g. wayback,katana,paramspider or gau,katana)")
    p.add_argument("--no-proxy", action="store_true", help="Disable SOCKS proxy routing")
    p.add_argument("--no-report", action="store_true", help="Skip HTML report generation")
    p.add_argument("--export-md", dest="export_md", help="Path to export Markdown executive summary report")
    p.add_argument("--export-pdf", dest="export_pdf", help="Path to export professional PDF executive report")
    p.add_argument("--export-sarif", dest="export_sarif", help="Path to export findings in OASIS SARIF v2.1.0 format")
    p.add_argument("--export-json", dest="export_json", help="Path to export complete session manifest in JSON format")
    p.add_argument("--export-csv", dest="export_csv", help="Directory path to export tabular CSV files")
    p.add_argument("--webhook", dest="webhook_url", help="Slack, Discord, or generic HTTP webhook URL (or set SHADOWRECON_WEBHOOK_URL)")
    p.add_argument("--webhook-events", default="complete,critical", help="Comma-separated events to send to webhook: complete, critical (default: complete,critical)")
    p.add_argument("command", nargs="?", default="", help="Optional subcommand: 'doctor' to execute diagnostic health checks")
    p.add_argument("--doctor", action="store_true", help="Run preflight diagnostic health check suite and exit")
    p.add_argument("--no-circuit-breaker", action="store_true", help="Disable per-host circuit breaker")
    p.add_argument("--circuit-threshold", type=int, default=5, help="Consecutive failure threshold before tripping circuit (default: 5)")
    p.add_argument("--circuit-recovery", type=float, default=30.0, help="Circuit recovery cool-down window in seconds (default: 30.0)")
    p.add_argument("--ports", "--probe-ports", dest="probe_ports", default="default", help="HTTP probing port matrix: 'default' (80,443), 'web' (80,443,8000,8080,8443,8888,9000,9443), or custom list (default: default)")
    p.add_argument("--exclude", default="", help="Comma-separated target exclusion patterns or CIDRs (e.g. 'mail.*,vpn.*,10.0.0.0/8')")
    p.add_argument("--safe-mode", action="store_true", help="Enable production safety guardrails (lock concurrency to 1, delay >= 0.5s, non-destructive scans)")
    p.add_argument("--concurrency", type=int, default=3, help="Maximum concurrent driver / stage tasks (default: 3; locked to 1 in safe-mode)")
    p.add_argument("--authorized", action="store_true", help="Acknowledge you have permission to test target")

    p.add_argument("-y", "--yes", action="store_true", help="Assume yes on interactive prompts")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    p.add_argument("--version", action="version", version=f"ShadowRecon {__version__}")
    return p


async def async_main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    # 0. Check if doctor mode requested
    if args.doctor or args.command == "doctor":
        checker = PreflightChecker()
        report = checker.run_all_checks()
        print(report.format_table())
        return 1 if report.has_critical_failures else 0

    # 1. Load config file if specified or default present
    cfg_file = Path(args.config) if args.config else None
    try:
        toml_cfg = load_toml_config(cfg_file)
    except ConfigValidationError as exc:
        log.error("Configuration validation error: %s", exc)
        return 1

    target_url = args.target or toml_cfg.get("target")
    if not target_url:
        print(BANNER)
        parser.print_help()
        log.error("Missing required target URL (-u/--url).")
        return 1

    try:
        domain = parse_target(target_url)
    except ValueError as exc:
        log.error("Invalid target URL '%s': %s", target_url, exc)
        return 1

    # Resolve output directory
    raw_outdir = args.outdir or toml_cfg.get("outdir") or f"run_{slugify(domain)}_{datetime.now():%Y%m%d_%H%M%S}"
    outdir = Path(raw_outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    # Resolve wordlist
    raw_wl = args.wordlist or toml_cfg.get("wordlist") or "wordlist.txt"
    wordlist = Path(raw_wl).resolve()
    if not wordlist.is_file() and not args.dry_run:
        # Create minimal fallback wordlist if missing
        wordlist = outdir / "default_wordlist.txt"
        if not wordlist.exists():
            wordlist.write_text("admin\napi\nlogin\ndashboard\nrobots.txt\n", encoding="utf-8")
            log.info("Created fallback wordlist at %s", wordlist)

    lfi_file = Path(args.lfi_payloads).resolve() if args.lfi_payloads else None

    proxy_provider_choice = args.proxy_provider or toml_cfg.get("proxy_provider", "tor")
    pool_file = Path(args.proxy_pool_file).resolve() if args.proxy_pool_file else (
        Path(toml_cfg["proxy_pool_file"]).resolve() if toml_cfg.get("proxy_pool_file") else None
    )
    max_backoff = args.max_backoff or toml_cfg.get("max_backoff", 60.0)

    nuclei_tmpl = Path(args.nuclei_templates).resolve() if args.nuclei_templates else (
        Path(toml_cfg["nuclei_templates"]).resolve() if toml_cfg.get("nuclei_templates") else default_nuclei_templates_dir()
    )
    nuclei_sev = args.nuclei_severity or toml_cfg.get("nuclei_severity", "medium,high,critical")
    nuclei_tags = args.nuclei_tags or toml_cfg.get("nuclei_tags", "")

    export_md_path = Path(args.export_md).resolve() if args.export_md else (
        Path(toml_cfg["export_md"]).resolve() if toml_cfg.get("export_md") else None
    )
    export_pdf_path = Path(args.export_pdf).resolve() if args.export_pdf else (
        Path(toml_cfg["export_pdf"]).resolve() if toml_cfg.get("export_pdf") else None
    )
    webhook_url = args.webhook_url or os.getenv("SHADOWRECON_WEBHOOK_URL") or toml_cfg.get("webhook_url")
    webhook_events = args.webhook_events or toml_cfg.get("webhook_events", "complete,critical")

    probe_ports = args.probe_ports if args.probe_ports != "default" else toml_cfg.get("probe_ports", toml_cfg.get("ports", "default"))
    exclude_spec = args.exclude or toml_cfg.get("exclude", "")
    safe_mode = args.safe_mode or toml_cfg.get("safe_mode", False)

    rate_limit = args.rate_limit if args.rate_limit != 0.0 else toml_cfg.get("rate_limit", 0.0)
    ffuf_threads = args.threads if args.threads != 5 else toml_cfg.get("threads", toml_cfg.get("ffuf_threads", 5))
    concurrency = args.concurrency if args.concurrency != 3 else toml_cfg.get("concurrency", 3)

    if safe_mode:
        concurrency = 1
        ffuf_threads = min(ffuf_threads, 2)
        rate_limit = max(rate_limit, 0.5)
        log.warning(
            "[SAFE MODE ENGAGED] Production guardrails active: concurrency locked to 1, FFUF threads clamped to %d, request delay >= %.1fs, non-destructive scanners enforced",
            ffuf_threads,
            rate_limit,
        )

    scope_mgr = ScopeManager(domain=domain, exclude=exclude_spec)

    # Construct Config
    cfg = Config(
        target=target_url,
        domain=domain,
        wordlist=wordlist,
        outdir=outdir,
        lfi_payloads=lfi_file,
        tor_socks=args.socks,
        tor_control_port=args.tor_port,
        tor_control_password=args.tor_pass,
        rotate_wait=args.rotate_wait,
        request_timeout=args.timeout,
        rate_limit=rate_limit,
        max_backoff=max_backoff,
        ffuf_threads=ffuf_threads,
        dry_run=args.dry_run,
        use_proxy=not args.no_proxy,
        proxy_provider=proxy_provider_choice,
        proxy_pool_file=pool_file,
        make_report=not args.no_report,
        force_rerun=args.force_rerun,
        stages=args.stages,
        skip_stages=args.skip_stages,
        nuclei_templates=nuclei_tmpl,
        nuclei_severity=nuclei_sev,
        nuclei_tags=nuclei_tags,
        concurrency=concurrency,

        driver_subdomains=args.driver_subdomains or toml_cfg.get("driver_subdomains", "subfinder"),
        driver_probing=toml_cfg.get("driver_probing", "httpx"),
        driver_crawling=toml_cfg.get("driver_crawling", "katana"),
        driver_urls=args.driver_urls or toml_cfg.get("driver_urls", "wayback,katana,paramspider"),
        driver_nuclei=toml_cfg.get("driver_nuclei", "nuclei"),
        driver_xss=toml_cfg.get("driver_xss", "dalfox"),
        driver_sqli=toml_cfg.get("driver_sqli", "sqlmap"),
        export_md=export_md_path,
        export_pdf=export_pdf_path,
        webhook_url=webhook_url,
        webhook_events=webhook_events,
        circuit_breaker=not args.no_circuit_breaker and toml_cfg.get("circuit_breaker", True),
        circuit_threshold=args.circuit_threshold or toml_cfg.get("circuit_threshold", 5),
        circuit_recovery=args.circuit_recovery or toml_cfg.get("circuit_recovery", 30.0),
        probe_ports=probe_ports,
        exclude=exclude_spec,
        safe_mode=safe_mode,
    )

    # Initialize Circuit Breaker
    cb = HostCircuitBreaker(
        failure_threshold=cfg.circuit_threshold,
        recovery_timeout=cfg.circuit_recovery,
        enabled=cfg.circuit_breaker,
    )

    # Initialize Proxy Provider
    tor = TorManager(
        control_port=cfg.tor_control_port,
        control_password=cfg.tor_control_password,
        rotate_wait=cfg.rotate_wait,
        dry_run=cfg.dry_run,
    )

    if not cfg.use_proxy or cfg.proxy_provider == "direct":
        proxy_provider = DirectProxyProvider()
    elif cfg.proxy_pool_file and cfg.proxy_pool_file.is_file():
        proxy_provider = ProxyPoolProvider.from_file(cfg.proxy_pool_file)
    else:
        proxy_provider = TorProxyProvider(tor, socks_url=cfg.tor_socks)

    # Initialize Adaptive Rate Limiter
    rate_limiter = AdaptiveRateLimiter(
        baseline_delay=cfg.rate_limit,
        max_backoff=cfg.max_backoff,
    )

    print(BANNER)
    log.info("ShadowRecon v%s initialized", __version__)
    log.info("Target: %s (domain: %s)", cfg.target, cfg.domain)
    log.info("Output directory: %s", cfg.outdir)
    log.info("Proxy Provider: %s (active: %s)", proxy_provider.provider_name, proxy_provider.get_proxy_url() or "none")
    log.info("Host Circuit Breaker: %s (threshold: %d, recovery: %.1fs)", "Enabled" if cfg.circuit_breaker else "Disabled", cfg.circuit_threshold, cfg.circuit_recovery)

    # Tor Control Password check (P3.4)
    if not cfg.dry_run and cfg.use_proxy and cfg.proxy_provider == "tor" and not cfg.tor_control_password:
        log.warning(
            "No Tor control password provided (set TOR_CONTROL_PASSWORD or --tor-pass). "
            "Circuit rotation on 403/429 block will be unavailable."
        )

    # Authorization gate
    if not cfg.dry_run and not args.authorized:
        log.error("Active scanning requires --authorized flag. Confirm you have explicit permission to test %s.", cfg.domain)
        return 2

    # Verify tooling
    check_tooling(cfg.dry_run)

    # Verify proxy health
    if cfg.use_proxy and not cfg.dry_run:
        healthy = await proxy_provider.health_check()
        if not healthy:
            log.warning("Proxy provider '%s' failed initial health check; check network/proxy settings.", proxy_provider.provider_name)

    # Initialize State & Session
    db_path = cfg.outdir / "session.db"
    store = SessionStore(db_path)
    store.set_metadata("target", cfg.target)
    store.set_metadata("domain", cfg.domain)
    store.set_metadata("version", __version__)
    store.set_metadata("start_time", datetime.now().isoformat())

    executor = AsyncExecutor(
        socks_proxy=proxy_provider.get_proxy_url() or cfg.tor_socks,
        use_proxy=cfg.use_proxy,
        dry_run=cfg.dry_run,
        proxy_provider=proxy_provider,
        circuit_breaker=cb,
    )
    bus = AsyncEventBus()
    bypass_ctx = BypassContext()

    # Configure active drivers from configuration
    for stage_key, driver_name in [
        ("subdomains", cfg.driver_subdomains),
        ("probing", cfg.driver_probing),
        ("crawling", cfg.driver_crawling),
        ("nuclei", cfg.driver_nuclei),
        ("xss", cfg.driver_xss),
        ("sqli", cfg.driver_sqli),
    ]:
        if "," not in driver_name and driver_name in global_registry.list_drivers(stage_key).get(stage_key, []):
            global_registry.set_active(stage_key, driver_name)

    ctx = StageContext(
        config=cfg,
        store=store,
        executor=executor,
        bus=bus,
        tor=tor,
        bypass_context=bypass_ctx,
        rate_limiter=rate_limiter,
        proxy_provider=proxy_provider,
        circuit_breaker=cb,
        scope=scope_mgr,
        drivers=global_registry,
    )

    # Stage Lifecycle Callbacks
    def on_stage_start(name: str, desc: str) -> None:
        log.info("[STAGE START] %s - %s", name.upper(), desc)

    def on_stage_end(res: StageResult) -> None:
        if res.status == "completed":
            log.info("[STAGE DONE]  %s (%.2fs)", res.name.upper(), res.duration_seconds)
        elif res.status == "resumed":
            log.info("[STAGE CACHED] %s (already completed)", res.name.upper())
        elif res.status == "skipped":
            log.info("[STAGE SKIP]  %s", res.name.upper())
        elif res.status == "failed":
            log.warning("[STAGE FAIL]  %s (%.2fs) - %s", res.name.upper(), res.duration_seconds, res.error_message)

    runner = PipelineRunner(on_stage_start=on_stage_start, on_stage_end=on_stage_end)

    # Register Pipeline Stages in dependency order
    runner.add_stage("waf", "WAF detection and bypass mutation testing", run_waf_stage)
    runner.add_stage("subdomains", "Passive subdomain enumeration", run_subdomains_stage)
    runner.add_stage("probing", "Active HTTP/HTTPS service probing", run_probing_stage)
    runner.add_stage("takeover", "Subdomain takeover analysis", run_takeover_stage)
    runner.add_stage("vuln_nuclei", "Nuclei CVSS vulnerability scanning", run_nuclei_stage)
    runner.add_stage("urls", "Endpoint parameter harvesting & deduplication", run_urls_stage)
    runner.add_stage("fuzzing", "Directory and path fuzzing", run_fuzzing_stage)
    runner.add_stage("vuln_xss", "Reflected XSS vulnerability testing", run_xss_stage)
    runner.add_stage("vuln_sqli", "SQL injection scanning", run_sqli_stage)
    runner.add_stage("vuln_lfi", "LFI/SSRF payload fuzzing", run_lfi_stage)

    # Real-time finding alert webhook listener
    notifier_task: Optional[asyncio.Task] = None
    if cfg.webhook_url and "critical" in cfg.webhook_events:
        notifier_task = await attach_finding_notifier(
            bus=bus,
            webhook_url=cfg.webhook_url,
            target=cfg.target,
            min_severity="high",
        )

    # Execute Pipeline
    log.info("Launching execution pipeline ...")
    try:
        results = await runner.run(ctx)
    finally:
        if notifier_task:
            await bus.close_topic("finding")
            try:
                await asyncio.wait_for(notifier_task, timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                notifier_task.cancel()

    # Export flat artifacts for backward compatibility
    store.export_flat_artifacts(cfg.outdir)

    # Cross-session differential drift analysis (if --diff specified)
    diff_result: Optional[SessionDiff] = None
    if args.diff_db:
        prior_db_path = Path(args.diff_db).resolve()
        if not prior_db_path.is_file():
            log.warning("Prior session database for --diff not found at '%s'. Skipping differential analysis.", prior_db_path)
        else:
            try:
                diff_result = diff_sessions(store, prior_db_path)
                log.info("Calculated cross-session drift against prior run: %s", prior_db_path.name)
                drift_json_path = cfg.outdir / "drift_summary.json"
                drift_txt_path = cfg.outdir / "drift_summary.txt"
                drift_json_path.write_text(json.dumps(diff_result.to_dict(), indent=2) + "\n", encoding="utf-8")
                drift_txt_path.write_text(diff_result.format_console_report() + "\n", encoding="utf-8")
                log.info("Drift summary exported -> %s", drift_json_path.name)
            except Exception as exc:
                log.error("Failed to calculate differential drift: %s", exc)

    report_meta = {
        "Target": cfg.target,
        "Domain": cfg.domain,
        "Version": f"v{__version__}",
        "Scan Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Tor Proxy": cfg.tor_socks if cfg.use_proxy else "Disabled",
        "Output Directory": str(cfg.outdir),
    }

    # Generate HTML & Default Markdown Reports
    if cfg.make_report:
        report_path = generate_report_from_store(store, cfg.outdir, report_meta, drift=diff_result)
        log.info("HTML Report generated -> %s", report_path)
        md_default_path = cfg.outdir / "report.md"
        export_markdown(store, md_default_path, meta=report_meta, diff=diff_result)
        log.info("Markdown Report generated -> %s", md_default_path)

    # Enterprise Exports (SARIF, JSON, CSV, Markdown, PDF)
    if args.export_sarif:
        export_sarif(store, Path(args.export_sarif))
    if args.export_json:
        export_json(store, Path(args.export_json), meta=report_meta)
    if args.export_csv:
        export_csv(store, Path(args.export_csv))
    if cfg.export_md:
        export_markdown(store, cfg.export_md, meta=report_meta, diff=diff_result)
        log.info("Markdown Report exported -> %s", cfg.export_md)
    if cfg.export_pdf:
        export_pdf(store, cfg.export_pdf, meta=report_meta, diff=diff_result)
        log.info("PDF Report exported -> %s", cfg.export_pdf)

    # Send Completion Webhook Notification
    if cfg.webhook_url and "complete" in cfg.webhook_events:
        manifest = build_manifest_dict(store, meta=report_meta)
        manifest["drift"] = diff_result.to_dict() if diff_result else None
        status_str = "completed" if all(r.status in ("completed", "resumed", "skipped") for r in results.values()) else "completed_with_warnings"
        payload = build_completion_payload(
            target=cfg.target,
            manifest=manifest,
            webhook_type=detect_webhook_type(cfg.webhook_url),
            status=status_str,
        )
        wh_ok = await send_webhook(cfg.webhook_url, payload)
        if wh_ok:
            log.info("Completion notification sent to webhook successfully.")
        else:
            log.warning("Failed to send completion notification to webhook.")

    # Print Summary Table
    counts = store.get_summary_counts()
    print("\n" + "=" * 50)
    print(f" ShadowRecon Execution Summary — {cfg.domain}")
    print("=" * 50)
    for k, v in counts.items():
        print(f" {k:<28} : {v}")
    print("=" * 50)
    print(f" Target URL        : {cfg.target}")
    active_proxy_str = proxy_provider.get_proxy_url() or "direct"
    print(f" Proxy Provider    : {proxy_provider.provider_name} ({active_proxy_str})")
    print(f" SQLite Session DB : {db_path}")
    print(f" Artifacts Directory: {cfg.outdir}")

    if diff_result:
        print(f" Drift Summary     : {cfg.outdir / 'drift_summary.json'}")
    if args.export_sarif:
        print(f" SARIF Export      : {args.export_sarif}")
    if args.export_json:
        print(f" JSON Export       : {args.export_json}")
    if args.export_csv:
        print(f" CSV Export Dir    : {args.export_csv}")
    if cfg.export_md:
        print(f" Markdown Export   : {cfg.export_md}")
    if cfg.export_pdf:
        print(f" PDF Export        : {cfg.export_pdf}")
    if cfg.webhook_url:
        print(f" Webhook URL       : {cfg.webhook_url} ({','.join(cfg.webhook_events)})")
    if cfg.circuit_breaker:
        cb_stats = cb.get_stats()
        print(f" Circuit Breaker   : Enabled ({cb_stats['healthy_hosts']} healthy, {cb_stats['tripped_hosts']} tripped)")
        if cb_stats["tripped_list"]:
            print(f" Tripped Hosts     : {', '.join(cb_stats['tripped_list'])}")
    if cfg.safe_mode:
        print(f" Operational Mode   : Safe Mode (Production Guardrails)")
    if cfg.probe_ports != "default":
        print(f" Port Matrix       : {cfg.probe_ports}")
    if cfg.exclude:
        print(f" Scope Exclusions  : {cfg.exclude}")
    print("=" * 50 + "\n")

    # Print Drift Report to console if generated
    if diff_result:
        print(diff_result.format_console_report() + "\n")

    return 0


def main() -> int:
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        log.warning("\nPipeline cancelled by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
