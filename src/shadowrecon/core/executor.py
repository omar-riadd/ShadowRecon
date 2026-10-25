"""Asynchronous safe subprocess executor with native SOCKS5 proxy injection."""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Sequence

log = logging.getLogger("shadowrecon.executor")


@dataclass
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str
    command: List[str]

    @property
    def success(self) -> bool:
        return self.returncode == 0


ExecutionResult = ProcessResult


def resolve_binary(tool_name: str) -> str:
    """Resolve executable path, handling tool-specific platform conventions."""
    if tool_name == "httpx":
        if shutil.which("httpx-toolkit"):
            return "httpx-toolkit"
        go_httpx = Path.home() / "go" / "bin" / "httpx"
        if go_httpx.is_file() and os.access(go_httpx, os.X_OK):
            return str(go_httpx)
        return "httpx"

    found = shutil.which(tool_name)
    if found:
        return found

    go_bin = Path.home() / "go" / "bin" / tool_name
    if go_bin.is_file() and os.access(go_bin, os.X_OK):
        return str(go_bin)

    return tool_name


def inject_native_proxy(cmd: Sequence[str], socks_url: str) -> List[str]:
    """Inject tool-specific native SOCKS5 proxy flags without using proxychains."""
    if not cmd:
        return list(cmd)

    full_cmd = list(cmd)
    tool = Path(full_cmd[0]).name

    # Check tool and append its native proxy flag (prevent duplicate flags if already passed)
    if tool in ("httpx", "httpx-toolkit"):
        if "-http-proxy" not in full_cmd:
            return [full_cmd[0], "-http-proxy", socks_url, *full_cmd[1:]]
    elif tool == "subfinder":
        if "-proxy" not in full_cmd:
            return [full_cmd[0], "-proxy", socks_url, *full_cmd[1:]]
    elif tool == "wafw00f":
        if "-p" not in full_cmd and "--proxy" not in full_cmd:
            return [full_cmd[0], "-p", socks_url, *full_cmd[1:]]
    elif tool in ("ffuf", "curl"):
        if "-x" not in full_cmd:
            return [full_cmd[0], "-x", socks_url, *full_cmd[1:]]
    elif tool == "nuclei":
        if "-proxy-socks-url" not in full_cmd:
            return [full_cmd[0], "-proxy-socks-url", socks_url, *full_cmd[1:]]
    elif tool in ("dalfox", "paramspider", "katana", "gau"):
        if "--proxy" not in full_cmd and "-proxy" not in full_cmd:
            return [full_cmd[0], "--proxy", socks_url, *full_cmd[1:]]
    elif tool == "sqlmap":
        if not any(arg.startswith("--proxy") for arg in full_cmd):
            return [full_cmd[0], f"--proxy={socks_url}", *full_cmd[1:]]

    return full_cmd


class AsyncExecutor:
    """Safe async subprocess execution using argument vectors (shell=False)."""

    def __init__(
        self,
        socks_proxy: str = "socks5://127.0.0.1:9050",
        use_proxy: bool = True,
        dry_run: bool = False,
        proxy_provider: Optional[Any] = None,
        circuit_breaker: Optional[Any] = None,
    ) -> None:
        self.socks_proxy = socks_proxy
        self.use_proxy = use_proxy
        self.dry_run = dry_run
        self.proxy_provider = proxy_provider
        self.circuit_breaker = circuit_breaker

    async def run(
        self,
        args: Sequence[str],
        *,
        proxy: bool = True,
        timeout: int = 600,
        capture_to: Optional[Path] = None,
    ) -> ProcessResult:
        if not args:
            raise ValueError("empty command args")

        tool_resolved = resolve_binary(args[0])
        cmd = [tool_resolved, *args[1:]]

        sub_env = os.environ.copy()
        if proxy and self.use_proxy:
            active_proxy = self.proxy_provider.get_proxy_url() if self.proxy_provider else self.socks_proxy
            if active_proxy:
                cmd = inject_native_proxy(cmd, active_proxy)
                sub_env["ALL_PROXY"] = active_proxy
                sub_env["HTTP_PROXY"] = active_proxy
                sub_env["HTTPS_PROXY"] = active_proxy
                sub_env["all_proxy"] = active_proxy
                sub_env["http_proxy"] = active_proxy
                sub_env["https_proxy"] = active_proxy

        printable = " ".join(cmd)
        log.info("$ %s", printable)

        if self.dry_run:
            return ProcessResult(returncode=0, stdout="", stderr="", command=cmd)

        try:
            proc = await asyncio.create_subprocess_exec(  # nosec B603
                cmd[0],
                *cmd[1:],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=sub_env,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            code = proc.returncode or 0

            if stderr.strip():
                log.debug("[%s stderr] %s", Path(cmd[0]).name, stderr.strip())
            if code != 0:
                log.warning("%s exited with status %d", Path(cmd[0]).name, code)
                if self.circuit_breaker:
                    err_lower = stderr.lower()
                    if any(k in err_lower for k in ("connection refused", "timeout", "no route to host", "504 gateway")):
                        for arg in args:
                            if "://" in arg or (arg.count(".") >= 2 and not arg.endswith(".txt")):
                                self.circuit_breaker.record_failure(arg, stderr.strip()[:100])
                                break

            # Rate-limit feedback loop: rotate proxy provider if blocks detected
            combined_out = (stderr + " " + stdout).lower()
            if self.proxy_provider and any(k in combined_out for k in ("429 too many requests", "rate limit exceeded", "tor blocked", "captcha")):
                log.warning("Detected rate-limit block in tool output. Requesting proxy rotation ...")
                await self.proxy_provider.rotate()

            if capture_to is not None:
                capture_to.parent.mkdir(parents=True, exist_ok=True)
                capture_to.write_text(stdout, encoding="utf-8")

            return ProcessResult(returncode=code, stdout=stdout, stderr=stderr, command=cmd)

        except FileNotFoundError:
            log.error("Tool binary not found: %s", cmd[0])
            return ProcessResult(returncode=127, stdout="", stderr="command not found", command=cmd)
        except asyncio.TimeoutError:
            log.warning("Tool execution timed out after %ds: %s", timeout, printable)
            if self.circuit_breaker:
                for arg in args:
                    if "://" in arg or (arg.count(".") >= 2 and not arg.endswith(".txt")):
                        self.circuit_breaker.record_failure(arg, f"Command execution timed out after {timeout}s")
                        break
            return ProcessResult(returncode=124, stdout="", stderr="timeout", command=cmd)
