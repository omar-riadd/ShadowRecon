"""Reconnaissance stages: subdomains, HTTP probing, URL gathering, and fuzzing."""
from __future__ import annotations

import asyncio
import logging
import re
import shutil
from pathlib import Path
from typing import Any, Callable, Coroutine, List, Optional, Set

from shadowrecon.core.executor import resolve_binary
from shadowrecon.core.scope import is_in_scope, read_lines, slugify
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import HostRecord


log = logging.getLogger("shadowrecon.modules.recon")


async def run_subdomains_stage(ctx: StageContext) -> List[str]:
    """Discover subdomains via configured driver(s) and update session store."""
    if "," in ctx.config.driver_subdomains:
        driver_names = [d.strip() for d in ctx.config.driver_subdomains.split(",") if d.strip()]
    else:
        active = ctx.drivers.get_driver(
            "subdomains",
            ctx.config.driver_subdomains if ctx.config.driver_subdomains != "subfinder" else None
        )
        driver_names = [active.name]

    concurrency = max(1, getattr(ctx.config, "concurrency", 1))
    sem = asyncio.Semaphore(concurrency)

    async def _run_subdomain_driver(d_name: str) -> None:
        async with sem:
            try:
                driver = ctx.drivers.get_driver("subdomains", d_name)
                if driver.is_available() or ctx.config.dry_run:
                    log.info("Executing subdomain driver: %s", driver.name)
                    await driver.execute(ctx)
                else:
                    log.warning("Subdomain driver '%s' not available on system, skipping.", d_name)
            except Exception as exc:
                log.warning("Driver '%s' failed in subdomains stage: %s", d_name, exc)

    if len(driver_names) == 1 or concurrency == 1:
        for d_name in driver_names:
            await _run_subdomain_driver(d_name)
    else:
        await asyncio.gather(*[_run_subdomain_driver(d) for d in driver_names])

    stored_subs = ctx.store.get_subdomains()
    out_file = ctx.config.outdir / "subdomains.txt"
    log.info("Subdomains discovered (aggregated): %d -> %s", len(stored_subs), out_file.name)
    await ctx.bus.close_topic("subdomain")
    return stored_subs


async def run_probing_stage(ctx: StageContext) -> List[str]:
    """Probe subdomains for live HTTP/HTTPS services via configured driver (default: httpx)."""
    driver = ctx.drivers.get_driver("probing")
    await driver.execute(ctx)
    stored_hosts = ctx.store.get_hosts()
    out_file = ctx.config.outdir / "live.txt"
    log.info("Live hosts identified: %d -> %s", len(stored_hosts), out_file.name)
    for h in stored_hosts:
        await ctx.bus.publish("host_live", h, source="probing")
    await ctx.bus.close_topic("host")
    await ctx.bus.close_topic("host_live")
    return stored_hosts


async def consume_live_hosts_stream(
    ctx: StageContext,
    callback: Callable[[str], Coroutine[Any, Any, None]],
    queue: Optional[asyncio.Queue[Optional[Event]]] = None,
) -> None:
    """Incrementally consume 'host_live' events from the event bus as they are emitted."""
    if queue is not None:
        while True:
            item = await queue.get()
            if item is None:
                break
            if item.data and isinstance(item.data, str):
                await callback(item.data)
    else:
        async for event in ctx.bus.stream("host_live"):
            if event.data and isinstance(event.data, str):
                await callback(event.data)




async def harvest_wayback(ctx: StageContext) -> List[str]:
    """Query Wayback Machine archives using configured driver."""
    try:
        driver = ctx.drivers.get_driver("urls", "wayback")
        res = await driver.execute(ctx)
        return res.metadata.get("urls", [])
    except Exception as exc:
        log.warning("Wayback gathering encountered error: %s", exc)
        return []


async def harvest_katana(ctx: StageContext, live_file: Path) -> List[str]:
    """Crawl live endpoints using katana driver."""
    try:
        driver = ctx.drivers.get_driver("urls", "katana")
        res = await driver.execute(ctx, live_file=live_file)
        return res.metadata.get("urls", [])
    except Exception as exc:
        log.warning("Katana crawler encountered error: %s", exc)
        return []


async def harvest_paramspider(ctx: StageContext, live_file: Path) -> List[str]:
    """Extract parameterized endpoints using paramspider driver."""
    try:
        driver = ctx.drivers.get_driver("urls", "paramspider")
        res = await driver.execute(ctx, live_file=live_file)
        return res.metadata.get("urls", [])
    except Exception as exc:
        log.warning("ParamSpider encountered error: %s", exc)
        return []


async def run_urls_stage(ctx: StageContext, live_file: Optional[Path] = None) -> List[str]:
    """Harvest and deduplicate parameterized endpoints across configured URL drivers."""
    target_live_file = live_file or (ctx.config.outdir / "live.txt")
    all_raw_urls: List[str] = []

    # Get configured URL harvesting drivers (e.g. "wayback,katana,paramspider" or "gau,katana")
    driver_names = [d.strip() for d in ctx.config.driver_urls.split(",") if d.strip()]
    if not driver_names:
        driver_names = ["wayback", "katana", "paramspider"]

    concurrency = max(1, getattr(ctx.config, "concurrency", 1))
    sem = asyncio.Semaphore(concurrency)

    async def _run_single_url_driver(d_name: str) -> List[str]:
        async with sem:
            try:
                driver = ctx.drivers.get_driver("urls", d_name)
                if not driver.is_available() and not ctx.config.dry_run:
                    log.info("URL driver '%s' not installed/available, skipping.", d_name)
                    return []
                log.info("Executing URL harvesting driver: %s", driver.name)
                res = await driver.execute(ctx, live_file=target_live_file)
                urls = res.metadata.get("urls", [])
                log.info("Driver '%s' discovered %d URLs", driver.name, len(urls))
                return urls
            except Exception as exc:
                log.warning("URL driver '%s' encountered error: %s", d_name, exc)
                return []

    if len(driver_names) == 1 or concurrency == 1:
        for d in driver_names:
            urls = await _run_single_url_driver(d)
            all_raw_urls.extend(urls)
    else:
        results = await asyncio.gather(*[_run_single_url_driver(d) for d in driver_names])
        for urls in results:
            all_raw_urls.extend(urls)

    # Filter parameterized & in-scope
    valid_param_urls = [
        u for u in all_raw_urls
        if "=" in u and ctx.is_in_scope(u)
    ]

    inserted = ctx.store.add_urls(valid_param_urls, source="recon_harvest")
    stored_urls = ctx.store.get_urls()

    params_file = ctx.config.outdir / "params.txt"
    params_file.parent.mkdir(parents=True, exist_ok=True)
    params_file.write_text("\n".join(stored_urls) + ("\n" if stored_urls else ""), encoding="utf-8")
    log.info("Parameterized URLs (unique signatures): %d (new=%d) -> %s", len(stored_urls), inserted, params_file.name)

    for u in stored_urls:
        await ctx.bus.publish("url", u, source="recon")
        if "=" in u:
            await ctx.bus.publish("param_url", u, source="recon")
    await ctx.bus.close_topic("url")
    await ctx.bus.close_topic("param_url")

    return stored_urls



async def run_fuzzing_stage(ctx: StageContext) -> None:
    """Run directory and endpoint fuzzing via FFUF."""
    hosts = ctx.store.get_hosts()
    if ctx.circuit_breaker:
        hosts = ctx.circuit_breaker.filter_healthy_hosts(hosts)

    if not hosts:
        log.info("No live or healthy hosts available for directory fuzzing. Skipping.")
        return

    if not ctx.config.wordlist.is_file():
        log.warning("Wordlist not found at %s. Skipping fuzzing stage.", ctx.config.wordlist)
        return

    ffuf_dir = ctx.config.outdir / "ffuf_dirs"
    ffuf_dir.mkdir(parents=True, exist_ok=True)

    extra_args = ctx.bypass_context.ffuf_args()
    concurrency = 1 if ctx.config.safe_mode else max(1, getattr(ctx.config, "concurrency", 1))
    sem = asyncio.Semaphore(concurrency)

    async def _fuzz_host(host: str) -> None:
        async with sem:
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

    if len(hosts) == 1 or concurrency == 1:
        for host in hosts:
            await _fuzz_host(host)
    else:
        await asyncio.gather(*[_fuzz_host(h) for h in hosts])

    log.info("FFUF directory fuzzing complete -> %s", ffuf_dir.name)
