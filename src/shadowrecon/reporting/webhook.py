"""Webhook notification dispatcher for Slack, Discord, and Generic HTTP endpoints."""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from shadowrecon import __version__
from shadowrecon.pipeline.queue import AsyncEventBus
from shadowrecon.storage.session import FindingRecord

log = logging.getLogger("shadowrecon.reporting.webhook")


def detect_webhook_type(url: str) -> str:
    """Classify webhook URL target into 'discord', 'slack', or 'generic'."""
    url_lower = url.lower()
    if "discord.com/api/webhooks" in url_lower or "discordapp.com/api/webhooks" in url_lower:
        return "discord"
    if "hooks.slack.com" in url_lower:
        return "slack"
    return "generic"


def build_completion_payload(
    manifest: Dict[str, Any],
    webhook_type: str = "generic",
    target: Optional[str] = None,
    status: str = "completed",
) -> Dict[str, Any]:
    """Format scan completion event for the targeted webhook platform."""
    target_info = manifest.get("target", {})
    if isinstance(target_info, dict):
        target_url = target_info.get("url") or target or "unknown"
        domain = target_info.get("domain") or "unknown"
    else:
        target_url = str(target or target_info or "unknown")
        domain = "target"
    summary = manifest.get("summary", {})
    by_sev = summary.get("by_severity", {})

    total_vulns = summary.get("findings", 0)
    has_critical = by_sev.get("critical", 0) > 0
    has_high = by_sev.get("high", 0) > 0

    if webhook_type == "discord":
        color = 0xDC2626 if has_critical else (0xEA580C if has_high else 0x0284C7)
        return {
            "content": f"🛡️ **ShadowRecon Scan Finished ({status}):** `{domain}`",
            "embeds": [
                {
                    "title": f"Security Assessment Summary — {domain}",
                    "url": target_url if target_url.startswith("http") else None,
                    "color": color,
                    "description": f"ShadowRecon finished scanning `{target_url}`.",
                    "fields": [
                        {"name": "Subdomains", "value": str(summary.get("subdomains", 0)), "inline": True},
                        {"name": "Live Hosts", "value": str(summary.get("hosts", 0)), "inline": True},
                        {"name": "URLs", "value": str(summary.get("urls", 0)), "inline": True},
                        {
                            "name": "Findings",
                            "value": (
                                f"🔴 {by_sev.get('critical', 0)} Crit  "
                                f"🟠 {by_sev.get('high', 0)} High  "
                                f"🟡 {by_sev.get('medium', 0)} Med  "
                                f"🔵 {by_sev.get('low', 0)} Low"
                            ),
                            "inline": False,
                        },
                    ],
                    "footer": {"text": f"ShadowRecon v{__version__}"},
                }
            ],
        }

    if webhook_type == "slack":
        return {
            "text": f"🛡️ ShadowRecon scan completed for *{domain}* ({total_vulns} findings)",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"ShadowRecon Assessment — {domain}"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Target:*\n`{target_url}`"},
                        {"type": "mrkdwn", "text": f"*Total Findings:*\n*{total_vulns}*"},
                        {"type": "mrkdwn", "text": f"*Subdomains:*\n{summary.get('subdomains', 0)}"},
                        {"type": "mrkdwn", "text": f"*Live Hosts:*\n{summary.get('hosts', 0)}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Severity Breakdown:*\n"
                            f"🔴 Critical: `{by_sev.get('critical', 0)}` | "
                            f"🟠 High: `{by_sev.get('high', 0)}` | "
                            f"🟡 Medium: `{by_sev.get('medium', 0)}` | "
                            f"🔵 Low: `{by_sev.get('low', 0)}`"
                        ),
                    },
                },
            ],
        }

    # Generic Webhook Format
    return {
        "event": "scan_completed",
        "scanner": "ShadowRecon",
        "version": __version__,
        "status": status,
        "target": target_info,
        "summary": summary,
    }


def build_finding_payload(finding: FindingRecord, target: str, webhook_type: str = "generic") -> Dict[str, Any]:
    """Format real-time vulnerability alert for the targeted platform."""
    sev = finding.severity.lower()
    badge = "🔴" if sev == "critical" else "🟠"

    if webhook_type == "discord":
        color = 0xDC2626 if sev == "critical" else 0xEA580C
        return {
            "content": f"{badge} **Immediate Vulnerability Detected [{finding.severity.upper()}]** on `{target}`",
            "embeds": [
                {
                    "title": f"{finding.vuln_type}",
                    "color": color,
                    "fields": [
                        {"name": "Target URL", "value": f"`{finding.target_url}`", "inline": False},
                        {"name": "Severity", "value": finding.severity.upper(), "inline": True},
                        {"name": "Tool", "value": finding.source_tool, "inline": True},
                        {"name": "Payload / Evidence", "value": f"`{finding.payload[:200]}`" if finding.payload else "_N/A_", "inline": False},
                    ],
                }
            ],
        }

    if webhook_type == "slack":
        return {
            "text": f"{badge} [{finding.severity.upper()}] *{finding.vuln_type}* on `{finding.target_url}`",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{badge} *[{finding.severity.upper()}] {finding.vuln_type}*\n*Target:* `{finding.target_url}`\n*Tool:* `{finding.source_tool}`",
                    },
                }
            ],
        }

    # Generic format
    return {
        "event": "finding_alert",
        "scanner": "ShadowRecon",
        "target": target,
        "finding": {
            "vuln_type": finding.vuln_type,
            "severity": finding.severity,
            "target_url": finding.target_url,
            "payload": finding.payload,
            "source_tool": finding.source_tool,
        },
    }


def _dispatch_http_post(url: str, payload_bytes: bytes, timeout: float = 10.0) -> bool:
    """Synchronous HTTP POST worker for thread executor."""
    req = urllib.request.Request(
        url,
        data=payload_bytes,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"ShadowRecon/{__version__}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            status = resp.status
            return 200 <= status < 300
    except Exception as exc:
        log.warning("Webhook delivery to '%s' failed: %s", url, exc)
        return False


async def send_webhook(url: str, payload: Dict[str, Any], timeout: float = 10.0) -> bool:
    """Asynchronously deliver a JSON payload to a webhook URL without blocking."""
    if not url:
        return False
    payload_bytes = json.dumps(payload).encode("utf-8")
    return await asyncio.to_thread(_dispatch_http_post, url, payload_bytes, timeout)


async def attach_finding_notifier(
    bus: AsyncEventBus,
    webhook_url: str,
    target: str,
    min_severity: str = "high",
) -> asyncio.Task[None]:
    """Start background listener task streaming high/critical findings to webhook."""
    webhook_type = detect_webhook_type(webhook_url)
    sub_q = bus.subscribe("finding")
    severities = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    threshold = severities.get(min_severity.lower(), 1)

    async def _worker() -> None:
        while True:
            event = await sub_q.get()
            if event is None:
                break
            record: FindingRecord = event.data
            rank = severities.get(record.severity.lower(), 5)
            if rank <= threshold:
                payload = build_finding_payload(record, target=target, webhook_type=webhook_type)
                await send_webhook(webhook_url, payload)

    return asyncio.create_task(_worker())
