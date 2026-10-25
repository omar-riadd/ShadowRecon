"""Asynchronous safe subprocess executor with native SOCKS5 proxy injection."""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

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

    # Check tool and append its native proxy flag
    if tool in ("httpx", "httpx-toolkit"):
        return [full_cmd[0], "-http-proxy", socks_url, *full_cmd[1:]]
    if tool == "ffuf":
        return [full_cmd[0], "-x", socks_url, *full_cmd[1:]]
    if tool == "nuclei":
        return [full_cmd[0], "-proxy-socks-url", socks_url, *full_cmd[1:]]
    if tool in ("dalfox", "paramspider", "katana"):
        return [full_cmd[0], "--proxy", socks_url, *full_cmd[1:]]
    if tool == "sqlmap":
        return [full_cmd[0], f"--proxy={socks_url}", *full_cmd[1:]]

    return full_cmd


class AsyncExecutor:
    """Safe async subprocess execution using argument vectors (shell=False)."""

    def __init__(
        self,
        socks_proxy: str = "socks5://127.0.0.1:9050",
        use_proxy: bool = True,
        dry_run: bool = False,
    ) -> None:
        self.socks_proxy = socks_proxy
        self.use_proxy = use_proxy
        self.dry_run = dry_run

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

        if proxy and self.use_proxy:
            cmd = inject_native_proxy(cmd, self.socks_proxy)

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

            if capture_to is not None:
                capture_to.parent.mkdir(parents=True, exist_ok=True)
                capture_to.write_text(stdout, encoding="utf-8")

            return ProcessResult(returncode=code, stdout=stdout, stderr=stderr, command=cmd)

        except FileNotFoundError:
            log.error("Tool binary not found: %s", cmd[0])
            return ProcessResult(returncode=127, stdout="", stderr="command not found", command=cmd)
        except asyncio.TimeoutError:
            log.warning("Tool execution timed out after %ds: %s", timeout, printable)
            return ProcessResult(returncode=124, stdout="", stderr="timeout", command=cmd)
