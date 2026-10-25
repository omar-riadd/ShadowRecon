"""Command-line interface and entrypoint for ShadowRecon v3.0."""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from shadowrecon import __version__
from shadowrecon.config import BypassContext, Config, load_toml_config
from shadowrecon.core.executor import AsyncExecutor, resolve_binary
from shadowrecon.core.proxy import DirectProxyProvider, ProxyPoolProvider, TorProxyProvider
from shadowrecon.core.ratelimit import AdaptiveRateLimiter
from shadowrecon.core.scope import parse_target, slugify
from shadowrecon.core.tor import TorManager
from shadowrecon.modules.recon import (
    run_fuzzing_stage,
    run_probing_stage,
    run_subdomains_stage,
    run_urls_stage,
)
from shadowrecon.modules.takeover import run_takeover_stage
from shadowrecon.modules.vuln import (
    run_lfi_stage,
    run_sqli_stage,
    run_xss_stage,
)
from shadowrecon.modules.waf import run_waf_stage
from shadowrecon.pipeline.queue import AsyncEventBus
from shadowrecon.pipeline.runner import PipelineRunner, StageContext, StageResult
from shadowrecon.reporting.html import generate_report_from_store
from shadowrecon.storage.session import SessionStore

BANNER = r"""
   ____  __            __               ____                       
  / __/ / /  ___ _ ___/ / ___  _    __ / __ \ ___  ____ ___   ___  
 _\ \  / _ \/ _ `// _  / / _ \| |/|/ // /_/ // -_)/ __// _ \ / _ \ 
/___/ /_//_/\_,_/ \_,_/  \___/|__,__/ \_, _/ \__/ \__/ \___//_//_/ 
                             v3.0 Async Redesign
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
        description="ShadowRecon v3.0 — Tor-anonymized reconnaissance and vulnerability pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-u", "--url", dest="target", help="Target URL (e.g. https://example.com/)")
    p.add_argument("-w", "--wordlist", help="Path to wordlist for directory fuzzing")
    p.add_argument("-l", "--lfi-payloads", dest="lfi_payloads", help="Path to LFI payloads file")
    p.add_argument("-o", "--outdir", help="Output directory for scan session artifacts")
    p.add_argument("--stages", default="all", help="Comma-separated stages to run (default: all)")
    p.add_argument("--skip-stages", default="", help="Comma-separated stages to skip")
    p.add_argument("--force-rerun", action="store_true", help="Rerun stages even if completed in session")
    p.add_argument("--socks", default="socks5://127.0.0.1:9050", help="Tor SOCKS5 proxy URL")
    p.add_argument("--tor-port", type=int, default=9051, help="Tor control port")
    p.add_argument("--tor-pass", default=os.getenv("TOR_CONTROL_PASSWORD", ""), help="Tor control password")
    p.add_argument("--rotate-wait", type=int, default=10, help="Wait time (seconds) after circuit rotation")
    p.add_argument("--timeout", type=int, default=20, help="HTTP request timeout in seconds")
    p.add_argument("--rate-limit", type=float, default=0.0, help="Delay between requests in seconds")
    p.add_argument("--max-backoff", type=float, default=60.0, help="Maximum exponential backoff in seconds (default: 60)")
    p.add_argument("--threads", type=int, default=5, help="FFUF thread count (low default for Tor)")
    p.add_argument("--config", help="Path to shadowrecon.toml config file")
    p.add_argument("--dry-run", action="store_true", help="Simulate execution without sending live packets")
    p.add_argument("--proxy-provider", default="tor", choices=["tor", "pool", "direct"], help="Proxy provider to use (default: tor)")
    p.add_argument("--proxy-pool", dest="proxy_pool_file", help="Path to file containing rotating proxy URLs")
    p.add_argument("--no-proxy", action="store_true", help="Disable SOCKS proxy routing")
    p.add_argument("--no-report", action="store_true", help="Skip HTML report generation")
    p.add_argument("--authorized", action="store_true", help="Acknowledge you have permission to test target")
    p.add_argument("-y", "--yes", action="store_true", help="Assume yes on interactive prompts")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    p.add_argument("--version", action="version", version=f"ShadowRecon {__version__}")
    return p


async def async_main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    # 1. Load config file if specified or default present
    cfg_file = Path(args.config) if args.config else None
    toml_cfg = load_toml_config(cfg_file)

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
        rate_limit=args.rate_limit,
        max_backoff=max_backoff,
        ffuf_threads=args.threads,
        dry_run=args.dry_run,
        use_proxy=not args.no_proxy,
        proxy_provider=proxy_provider_choice,
        proxy_pool_file=pool_file,
        make_report=not args.no_report,
        force_rerun=args.force_rerun,
        stages=args.stages,
        skip_stages=args.skip_stages,
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
    )
    bus = AsyncEventBus()
    bypass_ctx = BypassContext()

    ctx = StageContext(
        config=cfg,
        store=store,
        executor=executor,
        bus=bus,
        tor=tor,
        bypass_context=bypass_ctx,
        rate_limiter=rate_limiter,
        proxy_provider=proxy_provider,
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
    runner.add_stage("urls", "Endpoint parameter harvesting & deduplication", run_urls_stage)
    runner.add_stage("fuzzing", "Directory and path fuzzing", run_fuzzing_stage)
    runner.add_stage("vuln_xss", "Reflected XSS vulnerability testing", run_xss_stage)
    runner.add_stage("vuln_sqli", "SQL injection scanning", run_sqli_stage)
    runner.add_stage("vuln_lfi", "LFI/SSRF payload fuzzing", run_lfi_stage)

    # Execute Pipeline
    log.info("Launching execution pipeline ...")
    results = await runner.run(ctx)

    # Export flat artifacts for backward compatibility
    store.export_flat_artifacts(cfg.outdir)

    # Generate HTML Report
    if cfg.make_report:
        report_meta = {
            "Target": cfg.target,
            "Domain": cfg.domain,
            "Version": f"v{__version__}",
            "Scan Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Tor Proxy": cfg.tor_socks if cfg.use_proxy else "Disabled",
            "Output Directory": str(cfg.outdir),
        }
        report_path = generate_report_from_store(store, cfg.outdir, report_meta)
        log.info("HTML Report generated -> %s", report_path)

    # Print Summary Table
    counts = store.get_summary_counts()
    print("\n" + "=" * 50)
    print(f" ShadowRecon Execution Summary — {cfg.domain}")
    print("=" * 50)
    for k, v in counts.items():
        print(f" {k:<28} : {v}")
    print("=" * 50)
    print(f" SQLite Session DB : {db_path}")
    print(f" Artifacts Directory: {cfg.outdir}")
    print("=" * 50 + "\n")

    return 0


def main() -> int:
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        log.warning("\nPipeline cancelled by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
