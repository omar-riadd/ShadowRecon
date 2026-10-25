#!/usr/bin/env python3
"""
ShadowRecon (refactored) — authorized web-application recon & vuln pipeline.

This refactor targets ENGINEERING QUALITY, OPERATOR SECURITY HYGIENE,
RESPONSIBLE-USE GUARDRAILS, and PRESENTATION. It intentionally does not add
attack vectors, expand the WAF-bypass payloads, or improve evasion.

Highlights:
  * No hardcoded secrets — Tor control password comes from env/CLI.
  * No `shell=True` — external tools run via argument lists (removes the
    command-injection surface of the original f-string + shell=True calls).
  * Target validation; scope enforcement on HTTP payload requests.
  * Authorization gate + --dry-run + --rate-limit + structured audit log.
  * Per-run output dir; explicit payload registry (no globals() dispatch).
  * Rich terminal UX (optional) and a self-contained HTML report.

Usage:
    export TOR_CONTROL_PASSWORD=...        # or pass --tor-pass
    python3 main.py -u https://example.com/ -w words.txt --authorized
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import shutil
import subprocess  # nosec B404 - external recon tools are invoked by design; see run_tool() which never uses a shell
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

try:
    from stem import Signal
    from stem.control import Controller
    _STEM_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    _STEM_AVAILABLE = False

import console
import report
import waf_payloads
from utils import count_lines, in_scope, parse_target, read_lines, slugify

log = logging.getLogger("shadowrecon")
VERSION = "2.0"

BLOCK_STATUS_CODES = {403, 429}
TOOLS = {
    "proxychains": "sudo apt install proxychains4",
    "paramspider": "pipx install paramspider",
    "tor": "sudo apt install tor (enable ControlPort + HashedControlPassword in /etc/tor/torrc)",
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx-toolkit": "sudo apt install httpx-toolkit (or: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest)",
    "ffuf": "sudo apt install ffuf",
    "waybackpy": "pipx install waybackpy",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
    "sqlmap": "sudo apt install sqlmap",
    "wafw00f": "pipx install wafw00f",
}


# =======================
#   CONFIG
# =======================

@dataclass
class Config:
    target: str
    domain: str
    wordlist: Path
    outdir: Path
    lfi_payloads: Optional[Path] = None
    tor_socks: str = "socks5://127.0.0.1:9050"
    tor_control_port: int = 9051
    tor_control_password: str = ""
    rotate_wait: int = 10
    max_retries: int = 5
    request_timeout: int = 20
    rate_limit: float = 0.0
    dry_run: bool = False
    use_proxychains: bool = True
    make_report: bool = True
    nuclei_templates: Path = field(default_factory=lambda: Path.home() / "nuclei-templates")

    @property
    def proxies(self) -> dict:
        return {"http": self.tor_socks, "https": self.tor_socks}


@dataclass
class BypassContext:
    """Carries a confirmed WAF-bypass mutation into downstream scanning tools."""
    headers: dict = field(default_factory=dict)
    method_override: str = ""
    desc: str = "none"

    @classmethod
    def from_payload(cls, p: dict) -> "BypassContext":
        return cls(
            headers=p.get("headers", {}),
            method_override=p.get("method", ""),
            desc=p.get("desc", ""),
        )

    def dalfox_args(self) -> list[str]:
        args = []
        for k, v in self.headers.items():
            args.extend(["--header", f"{k}: {v}"])
        return args

    def sqlmap_args(self) -> list[str]:
        if not self.headers:
            return []
        header_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        return ["--headers", header_str]

    def ffuf_args(self) -> list[str]:
        args = []
        for k, v in self.headers.items():
            args.extend(["-H", f"{k}: {v}"])
        return args


class _DryRun(Exception):
    """Sentinel so dry-run short-circuits a request without side effects."""



# =======================
#   TOR + HTTP
# =======================

def rotate_ip(cfg: Config) -> bool:
    if cfg.dry_run:
        log.info("[dry-run] would request a new Tor circuit")
        return True
    if not _STEM_AVAILABLE:
        log.warning("stem not installed; cannot rotate Tor circuit")
        return False
    if not cfg.tor_control_password:
        log.warning("no Tor control password set; cannot rotate circuit "
                    "(set TOR_CONTROL_PASSWORD or --tor-pass)")
        return False
    log.info("Asking Tor for a NEW IDENTITY ...")
    try:
        with Controller.from_port(port=cfg.tor_control_port) as c:
            c.authenticate(cfg.tor_control_password)
            c.signal(Signal.NEWNYM)
        time.sleep(cfg.rotate_wait)
        log.info("Tor circuit changed.")
        return True
    except Exception as e:  # stem raises a variety of control errors
        log.error("Tor rotation failed: %s", e)
        return False


def http_request(cfg: Config, method: str, url: str, **kwargs) -> requests.Response:
    """HTTP through Tor; rotate + retry on 403/429 or connection errors.
    Enforces scope and the optional rate limit."""
    if not in_scope(url, cfg.domain):
        raise ValueError(f"refusing out-of-scope request: {url}")

    kwargs.setdefault("proxies", cfg.proxies)
    kwargs.setdefault("timeout", cfg.request_timeout)
    kwargs.setdefault("allow_redirects", False)

    if cfg.dry_run:
        log.info("[dry-run] %s %s", method, url)
        raise _DryRun()

    if cfg.rate_limit:
        time.sleep(cfg.rate_limit)

    last_exc: Optional[Exception] = None
    for attempt in range(1, cfg.max_retries + 1):
        try:
            r = requests.request(method, url, **kwargs)
            if r.status_code in BLOCK_STATUS_CODES:
                log.info("HTTP %s on %s - rotating (%d/%d)",
                         r.status_code, url, attempt, cfg.max_retries)
                if attempt == cfg.max_retries:
                    return r
                rotate_ip(cfg)
                continue
            return r
        except RequestException as e:
            last_exc = e
            log.info("HTTP error %s - rotating (%d/%d)", e, attempt, cfg.max_retries)
            if attempt == cfg.max_retries:
                raise
            rotate_ip(cfg)
    raise RuntimeError(f"request exhausted retries: {last_exc}")


# =======================
#   SAFE SUBPROCESS
# =======================

def run_tool(cfg: Config, args: Sequence[str], *, proxychain: bool = True,
             timeout: int = 600, capture_to: Optional[Path] = None) -> str:
    """Run an external tool with an ARGUMENT LIST (shell=False).

    Replaces the original `shell=True` + f-string construction, removing the
    command-injection surface. With `capture_to`, stdout is written by Python
    (no shell redirection)."""
    cmd: List[str] = list(args)
    if proxychain and cfg.use_proxychains and shutil.which("proxychains"):
        cmd = ["proxychains", "-q", *cmd]

    printable = " ".join(cmd)
    log.info("$ %s", printable)
    if cfg.dry_run:
        return ""

    try:
        # shell is never used; cmd[0] is a fixed tool name and the target URL
        # is validated by utils.parse_target() before reaching here.
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)  # nosec B603
    except FileNotFoundError:
        log.error("tool not found: %s", cmd[0])
        return ""
    except subprocess.TimeoutExpired:
        log.warning("timeout: %s", printable)
        return ""

    if p.stderr.strip():
        log.debug("[stderr] %s", p.stderr.strip())
    if p.returncode != 0:
        log.warning("%s exited %d", cmd[0], p.returncode)
    if capture_to is not None:
        capture_to.write_text(p.stdout, encoding="utf-8")
    return p.stdout


# =======================
#   WAF DETECTION + BYPASS
# =======================

def detect_waf(cfg: Config) -> Optional[str]:
    out = run_tool(cfg, ["wafw00f", cfg.target], timeout=300)
    if out:
        log.debug(out)
    m = re.search(r"is behind\s+(.+?)(?:\s+\(|$)", out, re.IGNORECASE)
    if m:
        name = m.group(1).strip()
        log.info("Detected WAF: %s", name)
        return name
    log.info("No WAF detected (or detection inconclusive).")
    return None


def run_payloads(cfg: Config, payloads: list) -> list[dict]:
    """Send WAF-bypass payloads via Tor. A bypass is confirmed when the WAF
    actively blocks a probe request (403/429) but returns 200 OK under mutation.

    Returns a list of winning payload dicts for downstream tool injection."""
    probe_param = "__shadowrecon_probe=1'OR'1'='1"
    sep = "&" if "?" in cfg.target else "?"
    probe_url = f"{cfg.target}{sep}{probe_param}"
    baseline_blocked = False

    try:
        baseline_resp = http_request(cfg, "GET", probe_url)
        baseline_blocked = baseline_resp.status_code in BLOCK_STATUS_CODES
        log.info("WAF baseline probe: HTTP %d (blocked=%s)",
                 baseline_resp.status_code, baseline_blocked)
    except _DryRun:
        pass
    except ValueError as e:
        log.warning("Baseline probe out of scope: %s", e)
    except Exception as e:
        log.info("Baseline probe error: %s", e)

    hits = cfg.outdir / "200-ok.txt"
    winning_payloads: list[dict] = []
    with hits.open("a", encoding="utf-8") as fh:
        for p in payloads:
            test_url = p.get("url", cfg.target)
            method = p.get("method", "GET")
            # If baseline was blocked, test the mutation with the probe payload
            if baseline_blocked:
                p_sep = "&" if "?" in test_url else "?"
                eval_url = f"{test_url}{p_sep}{probe_param}"
            else:
                eval_url = test_url

            try:
                resp = http_request(cfg, method, eval_url,
                                    headers=p.get("headers", {}),
                                    data=p.get("data"))
            except _DryRun:
                continue
            except ValueError as e:  # out of scope
                log.warning("%s", e)
                continue
            except Exception as e:
                log.info("[%s] error: %s", p["desc"], e)
                continue

            msg = (f"[{p['desc']}] -> {method} {eval_url} | "
                   f"{resp.status_code} | len={len(resp.text)}")
            log.info(msg)

            # Record bypass when 200 OK is achieved against an active blocking baseline
            if resp.status_code == 200 and baseline_blocked:
                fh.write(msg + "\n")
                winning_payloads.append(p)
                log.info("  *** CONFIRMED WAF BYPASS: %s ***", p["desc"])
            elif resp.status_code == 200 and not baseline_blocked:
                # Target does not block baseline; mutation works but bypass is unconfirmed
                fh.write(f"[candidate] {msg}\n")
                winning_payloads.append(p)

    return winning_payloads


def stage_waf(cfg: Config) -> list[dict]:
    name = detect_waf(cfg)
    builder = waf_payloads.default_payloads
    if name:
        for key, fn in waf_payloads.BYPASS.items():
            if key in name:
                log.info("Running %s payload set ...", key)
                builder = fn
                break
        else:
            log.info("Unknown WAF - using generic payload set.")
    else:
        log.info("Using generic payload set.")
    return run_payloads(cfg, builder(cfg.target))



# =======================
#   RECON STAGES
# =======================

def enum_subdomains(cfg: Config) -> Path:
    out = cfg.outdir / "subdomains.txt"
    raw = run_tool(cfg, ["subfinder", "-silent", "-d", cfg.domain], timeout=600)
    subs = {x.strip() for x in raw.splitlines() if x.strip()}
    if not subs:
        subs.add(cfg.domain)
    out.write_text("\n".join(sorted(subs)) + "\n", encoding="utf-8")
    log.info("Subdomains: %d -> %s", len(subs), out.name)
    return out


def resolve_httpx() -> str:
    """Resolve ProjectDiscovery httpx binary. On Debian/Kali, the package is named
    'httpx-toolkit' to avoid collision with python3-httpx. Elsewhere it may be 'httpx'
    or in ~/go/bin/httpx."""
    if shutil.which("httpx-toolkit"):
        return "httpx-toolkit"
    go_bin = Path.home() / "go" / "bin" / "httpx"
    if go_bin.is_file() and os.access(go_bin, os.X_OK):
        return str(go_bin)
    return "httpx"


def probe_httpx(cfg: Config, subs: Path) -> Path:
    out = cfg.outdir / "live.txt"
    httpx_bin = resolve_httpx()
    run_tool(cfg, [httpx_bin, "-silent", "-l", str(subs),
                   "-mc", "200,301,302", "-o", str(out)], timeout=900)
    log.info("Live hosts: %d -> %s", count_lines(out), out.name)
    return out



def wayback_urls(cfg: Config) -> Path:
    out = cfg.outdir / "wayback.txt"
    run_tool(cfg, ["waybackpy", "--url", cfg.domain, "-ku"],
             timeout=900, capture_to=out)
    log.info("Wayback URLs: %d -> %s", count_lines(out), out.name)
    return out


def fuzz_dirs_ffuf(cfg: Config, live: Path) -> None:
    ffuf_dir = cfg.outdir / "ffuf_dirs"
    ffuf_dir.mkdir(exist_ok=True)
    for host in read_lines(live):
        out_csv = ffuf_dir / f"{slugify(host)}.csv"
        run_tool(cfg, ["ffuf", "-w", str(cfg.wordlist),
                       "-u", f"{host.rstrip('/')}/FUZZ",
                       "-mc", "200,301,302", "-of", "csv",
                       "-o", str(out_csv), "-t", "50"], timeout=900)
    log.info("FFUF directory fuzzing done -> %s", ffuf_dir.name)


def nuclei_takeover(cfg: Config, live: Path) -> Path:
    out = cfg.outdir / "nuclei_takeover.txt"
    templates = cfg.nuclei_templates / "http" / "takeovers"
    if not templates.exists():
        templates = cfg.nuclei_templates / "takeovers"
    run_tool(cfg, ["nuclei", "-l", str(live), "-t", str(templates),
                   "-o", str(out), "-timeout", "50"], timeout=3600)
    log.info("Nuclei takeover scan done -> %s", out.name)
    return out


def build_param_urls(cfg: Config, wayback: Path) -> Path:
    out = cfg.outdir / "params.txt"
    with out.open("w", encoding="utf-8") as fh:
        for u in read_lines(wayback):
            if "=" in u:
                fh.write(u + "\n")
    log.info("Parameterized URLs -> %s", out.name)
    return out


def run_paramspider(cfg: Config, live: Path, params: Path) -> None:
    """ParamSpider writes results/<domain>.txt (raw domain with dots preserved).
    Merge all in-scope parameterized URLs into params.txt."""
    run_tool(cfg, ["paramspider", "--list", str(live), "--proxy", cfg.tor_socks],
             proxychain=False, timeout=900)
    results_dir = Path("results")
    merged = 0
    with params.open("a", encoding="utf-8") as out:
        for host in read_lines(live):
            domain = re.sub(r"^https?://", "", host).lower().strip().rstrip("/")
            pf = results_dir / f"{domain}.txt"
            if not pf.exists():
                log.warning("ParamSpider output not found: %s", pf)
                continue
            for line in read_lines(pf):
                if "=" in line and line.startswith("http") and in_scope(line, cfg.domain):
                    out.write(line + "\n")
                    merged += 1
    log.info("ParamSpider merged %d URLs into %s", merged, params.name)


# =======================
#   VULN STAGES
# =======================

def xss_with_dalfox(cfg: Config, params: Path,
                    bypass: Optional[BypassContext] = None) -> Path:
    out = cfg.outdir / "xss_dalfox.txt"
    extra = bypass.dalfox_args() if bypass else []
    run_tool(cfg, ["dalfox", "file", str(params),
                   "--only-poc", "--worker", "1", "-o", str(out),
                   *extra], timeout=600)
    log.info("Dalfox XSS done -> %s", out.name)
    return out


def sqli_with_sqlmap(cfg: Config, params: Path,
                     bypass: Optional[BypassContext] = None) -> Path:
    out = cfg.outdir / "sqlmap_out"
    out.mkdir(exist_ok=True)
    extra = bypass.sqlmap_args() if bypass else []
    run_tool(cfg, ["sqlmap", "-m", str(params), "--batch", "--random-agent",
                   "--level", "1", "--risk", "1", f"--output-dir={out}",
                   *extra], timeout=3600)
    log.info("SQLMap run finished -> %s", out.name)
    return out


def lfi_ssrf_with_ffuf(cfg: Config, params: Path,
                       bypass: Optional[BypassContext] = None) -> None:
    if not cfg.lfi_payloads:
        return
    out_dir = cfg.outdir / "ffuf_lfi_ssrf"
    out_dir.mkdir(exist_ok=True)
    extra = bypass.ffuf_args() if bypass else []
    for base in read_lines(params):
        if "=" not in base:
            continue
        url = re.sub(r"=([^&]*)", "=FUZZ", base, count=1)
        run_tool(cfg, ["ffuf", "-w", str(cfg.lfi_payloads), "-u", url,
                       "-mc", "200,500", "-of", "csv",
                       "-o", str(out_dir / f"{slugify(url)}.csv"),
                       *extra], timeout=1200)
    log.info("FFUF LFI/SSRF fuzzing -> %s", out_dir.name)



# =======================
#   SETUP / GUARDRAILS
# =======================

def check_tools(cfg: Config) -> None:
    if sys.platform != "linux":
        log.warning("This pipeline targets Linux (Kali/Parrot/Debian). "
                    "proxychains/tor and Go tools may be unavailable on %s.",
                    sys.platform)
    missing = []
    log.info("Tool check:")
    for tool, hint in TOOLS.items():
        bin_path = resolve_httpx() if tool == "httpx-toolkit" else tool
        if shutil.which(bin_path) or (Path(bin_path).is_file() and os.access(bin_path, os.X_OK)):
            log.info("  [OK] %s", tool)
        else:
            log.warning("  [MISSING] %s - install: %s", tool, hint)
            missing.append(tool)
    if missing and not cfg.dry_run:
        log.error("Missing tools: %s. Install them or use --dry-run.", ", ".join(missing))
        sys.exit(1)


def authorization_gate(cfg: Config, authorized_flag: bool, assume_yes: bool) -> None:
    """Guardrail: do not run active scans without explicit authorization."""
    if cfg.dry_run:
        return
    if not authorized_flag:
        log.error("Active scanning requires --authorized. You must have explicit "
                  "permission to test %s. Aborting.", cfg.domain)
        sys.exit(2)
    if assume_yes:
        return
    if not sys.stdin.isatty():
        log.error("No TTY to confirm scope; pass --yes only for authorized automation.")
        sys.exit(2)
    print(f"\nYou are about to actively scan: {cfg.domain}")
    print("Confirm you are authorized by retyping the domain exactly:")
    try:
        typed = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        sys.exit(2)
    if typed != cfg.domain:
        log.error("Confirmation mismatch. Aborting.")
        sys.exit(2)


def build_config(args: argparse.Namespace) -> Config:
    domain = parse_target(args.url)  # raises ValueError on bad input

    wordlist = Path(args.wordlist).expanduser()
    if not wordlist.is_file():
        raise SystemExit(f"wordlist not found: {wordlist}")
    lfi = None
    if args.lfi_payloads:
        lfi = Path(args.lfi_payloads).expanduser()
        if not lfi.is_file():
            raise SystemExit(f"LFI payload list not found: {lfi}")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = Path(args.outdir).expanduser() / f"{domain}-{stamp}"
    outdir.mkdir(parents=True, exist_ok=True)

    return Config(
        target=args.url,
        domain=domain,
        wordlist=wordlist,
        outdir=outdir,
        lfi_payloads=lfi,
        tor_control_port=args.tor_control_port,
        tor_control_password=args.tor_pass or os.environ.get("TOR_CONTROL_PASSWORD", ""),
        rate_limit=args.rate_limit,
        dry_run=args.dry_run,
        use_proxychains=not args.no_proxychains,
        make_report=not args.no_report,
    )


def setup_logging(outdir: Path, verbose: bool) -> None:
    file_h = logging.FileHandler(outdir / "audit.log", encoding="utf-8")
    file_h.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        handlers=[console.log_handler(verbose), file_h])


def finish(cfg: Config, started: datetime) -> None:
    sections = report.collect(cfg.outdir)
    console.summary_table([(s.title, s.count) for s in sections])
    if cfg.make_report:
        meta = {
            "Target": cfg.target,
            "Domain": cfg.domain,
            "Started": started.strftime("%Y-%m-%d %H:%M:%S"),
            "Duration": str(datetime.now() - started).split(".")[0],
            "Mode": "dry-run" if cfg.dry_run else "live",
            "Output dir": cfg.outdir.name,
        }
        path = report.generate(cfg.outdir, meta)
        log.info("HTML report -> %s", path)
    log.info("Done. Artifacts in %s", cfg.outdir)


# =======================
#   MAIN
# =======================

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="ShadowRecon - authorized recon & vuln pipeline (Tor + proxychains)")
    ap.add_argument("-u", "--url", required=True, help="Target URL, e.g. https://example.com/")
    ap.add_argument("-w", "--wordlist", required=True, help="Wordlist for dir fuzzing")
    ap.add_argument("--lfi-payloads", help="Payload list for LFI/SSRF fuzzing (optional)")
    ap.add_argument("--outdir", default="runs", help="Base dir for run artifacts (default: runs/)")
    ap.add_argument("--tor-pass", help="Tor control password (else env TOR_CONTROL_PASSWORD)")
    ap.add_argument("--tor-control-port", type=int, default=9051)
    ap.add_argument("--rate-limit", type=float, default=0.0, help="Seconds between HTTP requests")
    ap.add_argument("--no-proxychains", action="store_true", help="Do not wrap tools in proxychains")
    ap.add_argument("--no-report", action="store_true", help="Skip HTML report generation")
    ap.add_argument("--authorized", action="store_true", help="Assert you may scan the target")
    ap.add_argument("--yes", action="store_true", help="Skip interactive scope confirmation")
    ap.add_argument("--dry-run", action="store_true", help="Print planned actions; execute nothing")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> None:
    args = parse_args(argv)
    console.banner(VERSION)
    cfg = build_config(args)
    setup_logging(cfg.outdir, args.verbose)
    log.info("Target: %s | Domain: %s | Output: %s", cfg.target, cfg.domain, cfg.outdir)

    check_tools(cfg)
    authorization_gate(cfg, args.authorized, args.yes)

    started = datetime.now()
    winning = stage_waf(cfg)                         # 0) WAF detect + bypass payloads
    bypass = BypassContext.from_payload(winning[0]) if winning else None
    if bypass:
        log.info("Active scanners will use WAF bypass: %s", bypass.desc)

    subs = enum_subdomains(cfg)                      # 1) subdomains -> live
    live = probe_httpx(cfg, subs)
    wayback = wayback_urls(cfg)                      # 2) historical URLs + dir fuzz
    fuzz_dirs_ffuf(cfg, live)
    nuclei_takeover(cfg, live)                       # 3) takeover + params
    params = build_param_urls(cfg, wayback)
    run_paramspider(cfg, live, params)
    xss_with_dalfox(cfg, params, bypass=bypass)       # 4) active vuln scans
    sqli_with_sqlmap(cfg, params, bypass=bypass)
    lfi_ssrf_with_ffuf(cfg, params, bypass=bypass)

    finish(cfg, started)



if __name__ == "__main__":
    main()
