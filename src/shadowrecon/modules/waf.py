"""WAF detection, baseline probing, and bypass mutation testing."""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.exceptions import RequestException
from shadowrecon import waf_payloads
from shadowrecon.config import BypassContext, Config
from shadowrecon.core.scope import is_in_scope
from shadowrecon.pipeline.runner import StageContext

log = logging.getLogger("shadowrecon.modules.waf")

BLOCK_STATUS_CODES = {403, 429}
PROBE_PARAM = "__shadowrecon_probe=1'OR'1'='1"


def parse_waf_name(output: str) -> Optional[str]:
    """Extract detected WAF product name from wafw00f stdout."""
    m = re.search(r"is behind\s+(.+?)(?:\s+\(|$)", output, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


async def detect_waf(ctx: StageContext) -> Optional[str]:
    """Execute wafw00f against the target URL."""
    res = await ctx.executor.run(
        ["wafw00f", ctx.config.target],
        proxy=True,
        timeout=300,
    )
    if res.stdout:
        log.debug("wafw00f output:\n%s", res.stdout)
    waf_name = parse_waf_name(res.stdout)
    if waf_name:
        log.info("Detected WAF: %s", waf_name)
    else:
        log.info("No WAF detected (or detection inconclusive).")
    return waf_name


def _sync_http_request(
    cfg: Config,
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Any] = None,
    proxy_provider: Optional[Any] = None,
) -> Tuple[int, int]:
    """Execute a single HTTP request through proxy synchronously."""
    if not is_in_scope(url, cfg.domain):
        raise ValueError(f"Refusing out-of-scope request: {url}")

    if cfg.dry_run:
        log.info("[dry-run] %s %s", method, url)
        return 200, 0

    proxies = None
    if cfg.use_proxy:
        proxy_url = proxy_provider.get_proxy_url() if proxy_provider else cfg.tor_socks
        if proxy_url:
            proxies = {"http": proxy_url, "https": proxy_url}

    resp = requests.request(
        method=method,
        url=url,
        headers=headers or {},
        data=data,
        proxies=proxies,
        timeout=cfg.request_timeout,
        allow_redirects=False,
    )
    return resp.status_code, len(resp.content)


async def execute_http_probe(
    ctx: StageContext,
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Any] = None,
) -> Tuple[int, int]:
    """Asynchronously probe an HTTP endpoint with adaptive rate-limiting, circuit-breaking, and proxy routing."""
    if ctx.circuit_breaker and not ctx.circuit_breaker.allow_request(url):
        log.warning("Fast-failing probe to '%s' (host circuit is OPEN)", url)
        raise ConnectionError(f"Host circuit tripped (OPEN) for {url}")

    if ctx.rate_limiter:
        await ctx.rate_limiter.acquire()

    try:
        code, body_len = await asyncio.to_thread(
            _sync_http_request, ctx.config, method, url, headers, data, ctx.proxy_provider
        )
    except Exception as exc:
        if ctx.circuit_breaker:
            ctx.circuit_breaker.record_failure(url, str(exc))
        raise

    if ctx.circuit_breaker:
        if code in (502, 503, 504):
            ctx.circuit_breaker.record_failure(url, f"HTTP {code}")
        elif code < 500:
            ctx.circuit_breaker.record_success(url)

    if ctx.rate_limiter:
        ctx.rate_limiter.record_response(code)
        if ctx.rate_limiter.should_rotate_ip and ctx.proxy_provider:
            log.warning("Rate limit sustained; rotating proxy provider ...")
            await ctx.proxy_provider.rotate()
            ctx.rate_limiter.reset_blocks()

    return code, body_len


async def run_waf_stage(ctx: StageContext) -> BypassContext:
    """Detect WAF, measure active baseline blocking, and test mutation bypasses."""
    waf_name = await detect_waf(ctx)
    if waf_name:
        ctx.store.set_metadata("waf_detected", waf_name)

    # 1. Select payload set from registry
    builder = waf_payloads.default_payloads
    if waf_name:
        for key, fn in waf_payloads.BYPASS.items():
            if key.lower() in waf_name.lower():
                log.info("Using specialized payload set for '%s'", key)
                builder = fn
                break
        else:
            log.info("Unknown WAF '%s' - using generic payload set.", waf_name)
    else:
        log.info("Using generic WAF payload set.")

    payloads = builder(ctx.config.target)

    # 2. Measure baseline response to an active attack probe
    sep = "&" if "?" in ctx.config.target else "?"
    probe_url = f"{ctx.config.target}{sep}{PROBE_PARAM}"
    baseline_blocked = False

    try:
        code, _ = await execute_http_probe(ctx, "GET", probe_url)
        baseline_blocked = code in BLOCK_STATUS_CODES
        log.info("WAF baseline probe (%s): HTTP %d (blocked=%s)", probe_url, code, baseline_blocked)
    except Exception as exc:
        log.info("Baseline probe encounter: %s", exc)

    # 3. Test mutations and record in SQLite session store
    best_bypass: Optional[BypassContext] = None

    for p in payloads:
        test_url = p.get("url", ctx.config.target)
        method = p.get("method", "GET")
        headers = p.get("headers", {})
        data = p.get("data")
        desc = p.get("desc", "mutation")

        if baseline_blocked:
            p_sep = "&" if "?" in test_url else "?"
            eval_url = f"{test_url}{p_sep}{PROBE_PARAM}"
        else:
            eval_url = test_url

        try:
            status_code, body_len = await execute_http_probe(
                ctx, method, eval_url, headers=headers, data=data
            )
        except Exception as exc:
            log.debug("[%s] probe error: %s", desc, exc)
            continue

        confirmed = (status_code == 200 and baseline_blocked)
        candidate = (status_code == 200 and not baseline_blocked)

        if confirmed:
            log.info("  *** CONFIRMED WAF BYPASS: %s (%s) ***", desc, eval_url)
            ctx.store.add_waf_bypass(
                desc=desc,
                method=method,
                url=eval_url,
                headers=headers,
                status_code=status_code,
                confirmed=True,
            )
            if best_bypass is None or best_bypass.desc == "none":
                best_bypass = BypassContext(headers=headers, method_override=method, desc=desc)

        elif candidate:
            log.info("  [Candidate mutation] %s -> %d", desc, status_code)
            ctx.store.add_waf_bypass(
                desc=desc,
                method=method,
                url=eval_url,
                headers=headers,
                status_code=status_code,
                confirmed=False,
            )

    if best_bypass is not None:
        best_bypass.waf_name = waf_name or ""
        if not best_bypass.tamper_scripts and waf_name:
            best_bypass.tamper_scripts = waf_payloads.get_recommended_tampers(waf_name)
        ctx.bypass_context = best_bypass
        log.info("Propagating confirmed WAF bypass to scanners: %s (%s, tampers=%s)", best_bypass.desc, best_bypass.headers, best_bypass.tamper_scripts)
    else:
        if waf_name:
            ctx.bypass_context.waf_name = waf_name
            ctx.bypass_context.tamper_scripts = waf_payloads.get_recommended_tampers(waf_name)
            log.info("Applied vendor tamper scripts for detected WAF '%s': %s", waf_name, ctx.bypass_context.tamper_scripts)
        if not baseline_blocked:
            log.info("Target did not block active baseline probe; no WAF bypass required.")
        else:
            log.info("Target blocked baseline probe, but no bypass mutation succeeded; continuing with standard requests.")

    await ctx.bus.publish(
        "waf",
        {
            "detected": waf_name,
            "baseline_blocked": baseline_blocked,
            "bypass": ctx.bypass_context.desc,
        },
        source="waf_module",
    )

    return ctx.bypass_context
