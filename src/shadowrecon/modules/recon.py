"""Reconnaissance stages: subdomains, HTTP probing, URL gathering, and fuzzing."""
from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path
from typing import List, Set

from shadowrecon.core.executor import resolve_binary
from shadowrecon.core.scope import is_in_scope, read_lines, slugify
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import HostRecord

log = logging.getLogger("shadowrecon.modules.recon")


async def run_subdomains_stage(ctx: StageContext) -> List[str]:
    """Discover subdomains via configured driver (default: subfinder) and update session store."""
    driver = ctx.drivers.get_driver("subdomains")
    await driver.execute(ctx)
    stored_subs = ctx.store.get_subdomains()
    out_file = ctx.config.outdir / "subdomains.txt"
    log.info("Subdomains discovered: %d -> %s", len(stored_subs), out_file.name)
    await ctx.bus.close_topic("subdomain")
    return stored_subs


async def run_probing_stage(ctx: StageContext) -> List[str]:
    """Probe subdomains for live HTTP/HTTPS services via configured driver (default: httpx)."""
    driver = ctx.drivers.get_driver("probing")
    await driver.execute(ctx)
    stored_hosts = ctx.store.get_hosts()
    out_file = ctx.config.outdir / "live.txt"
    log.info("Live hosts identified: %d -> %s", len(stored_hosts), out_file.name)
    await ctx.bus.close_topic("host")
    return stored_hosts


async def harvest_wayback(ctx: StageContext) -> List[str]:
    """Query Wayback Machine archives using waybackpy."""
    out_file = ctx.config.outdir / "wayback.txt"
    cmd = ["waybackpy", "--url", ctx.config.domain, "-sub", "-ku"]
    res = await ctx.executor.run(cmd, proxy=True, timeout=900, capture_to=out_file)
    urls = [line.strip() for line in res.stdout.splitlines() if line.strip().startswith("http")]
    log.info("Wayback Machine returned %d URLs", len(urls))
    return urls


async def harvest_katana(ctx: StageContext, live_file: Path) -> List[str]:
    """Crawl live endpoints using katana driver if available."""
    try:
        driver = ctx.drivers.get_driver("crawling")
        if not driver.is_available() and not ctx.config.dry_run:
            return []
        res = await driver.execute(ctx, live_file=live_file)
        urls = res.metadata.get("urls", [])
        log.info("Katana crawler discovered %d URLs", len(urls))
        return urls
    except Exception as exc:
        log.warning("Katana crawler encountered error: %s", exc)
        return []


async def harvest_paramspider(ctx: StageContext, live_file: Path) -> List[str]:
    """Extract parameterized endpoints using ParamSpider."""
    paramspider_bin = resolve_binary("paramspider")
    if not shutil.which(paramspider_bin) and not Path(paramspider_bin).is_file():
        return []

    cmd = ["paramspider", "--list", str(live_file), "--proxy", ctx.config.tor_socks]
    await ctx.executor.run(cmd, proxy=False, timeout=900)

    results_dir = Path("results")
    urls: List[str] = []

    hosts = read_lines(live_file)
    for host in hosts:
        domain = re.sub(r"^https?://", "", host).lower().strip().rstrip("/")
        pf = results_dir / f"{domain}.txt"
        if not pf.exists():
            continue
        for line in read_lines(pf):
            if "=" in line and line.startswith("http") and is_in_scope(line, ctx.config.domain):
                urls.append(line.strip())

    log.info("ParamSpider harvested %d URLs", len(urls))
    return urls


async def run_urls_stage(ctx: StageContext) -> List[str]:
    """Harvest and deduplicate parameterized endpoints across all sources."""
    live_file = ctx.config.outdir / "live.txt"
    all_raw_urls: List[str] = []

    # 1. Wayback Machine
    try:
        wayback_urls = await harvest_wayback(ctx)
        all_raw_urls.extend(wayback_urls)
    except Exception as exc:
        log.warning("Wayback gathering encountered error: %s", exc)

    # 2. Katana Crawler
    if live_file.is_file() and live_file.stat().st_size > 0:
        try:
            katana_urls = await harvest_katana(ctx, live_file)
            all_raw_urls.extend(katana_urls)
        except Exception as exc:
            log.warning("Katana crawler encountered error: %s", exc)

    # 3. ParamSpider
    if live_file.is_file() and live_file.stat().st_size > 0:
        try:
            ps_urls = await harvest_paramspider(ctx, live_file)
            all_raw_urls.extend(ps_urls)
        except Exception as exc:
            log.warning("ParamSpider encountered error: %s", exc)

    # Filter parameterized & in-scope
    valid_param_urls = [
        u for u in all_raw_urls
        if "=" in u and is_in_scope(u, ctx.config.domain)
    ]

    inserted = ctx.store.add_urls(valid_param_urls, source="recon_harvest")
    stored_urls = ctx.store.get_urls()

    params_file = ctx.config.outdir / "params.txt"
    params_file.parent.mkdir(parents=True, exist_ok=True)
    params_file.write_text("\n".join(stored_urls) + ("\n" if stored_urls else ""), encoding="utf-8")
    log.info("Parameterized URLs (unique signatures): %d (new=%d) -> %s", len(stored_urls), inserted, params_file.name)

    for u in stored_urls:
        await ctx.bus.publish("url", u, source="recon")
    await ctx.bus.close_topic("url")

    return stored_urls


async def run_fuzzing_stage(ctx: StageContext) -> None:
    """Run directory and endpoint fuzzing via FFUF."""
    hosts = ctx.store.get_hosts()
    if not hosts:
        log.info("No live hosts available for directory fuzzing. Skipping.")
        return

    if not ctx.config.wordlist.is_file():
        log.warning("Wordlist not found at %s. Skipping fuzzing stage.", ctx.config.wordlist)
        return

    ffuf_dir = ctx.config.outdir / "ffuf_dirs"
    ffuf_dir.mkdir(parents=True, exist_ok=True)

    extra_args = ctx.bypass_context.ffuf_args()

    for host in hosts:
        out_csv = ffuf_dir / f"{slugify(host)}.csv"
        cmd = [
            "ffuf",
            "-w",
            str(ctx.config.wordlist),
            "-u",
            f"{host.rstrip('/')}/FUZZ",
            "-mc",
            "200,301,302",
            "-of",
            "csv",
            "-o",
            str(out_csv),
            "-t",
            str(ctx.config.ffuf_threads),
            *extra_args,
        ]
        await ctx.executor.run(cmd, proxy=True, timeout=900)

    log.info("FFUF directory fuzzing complete -> %s", ffuf_dir.name)
