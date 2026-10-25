"""Configuration dataclass and TOML config file loader."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore


@dataclass
class BypassContext:
    """Carries a confirmed WAF-bypass mutation into downstream scanning tools."""
    headers: Dict[str, str] = field(default_factory=dict)
    method_override: str = ""
    desc: str = "none"

    @classmethod
    def from_payload(cls, p: dict) -> "BypassContext":
        return cls(
            headers=p.get("headers", {}),
            method_override=p.get("method", ""),
            desc=p.get("desc", ""),
        )

    def dalfox_args(self) -> List[str]:
        args = []
        for k, v in self.headers.items():
            args.extend(["--header", f"{k}: {v}"])
        return args

    def sqlmap_args(self) -> List[str]:
        if not self.headers:
            return []
        header_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        return ["--headers", header_str]

    def ffuf_args(self) -> List[str]:
        args = []
        for k, v in self.headers.items():
            args.extend(["-H", f"{k}: {v}"])
        return args


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
    max_backoff: float = 60.0
    ffuf_threads: int = 5
    dry_run: bool = False
    use_proxy: bool = True
    proxy_provider: str = "tor"
    proxy_pool_file: Optional[Path] = None
    make_report: bool = True
    force_rerun: bool = False
    stages: str = "all"
    skip_stages: str = ""
    nuclei_templates: Path = field(default_factory=lambda: Path.home() / "nuclei-templates")

    @property
    def proxies(self) -> dict:
        return {"http": self.tor_socks, "https": self.tor_socks}


def load_toml_config(config_path: Optional[Path]) -> Dict[str, Any]:
    """Load configuration from a TOML file if present."""
    if config_path is None:
        default_path = Path("shadowrecon.toml")
        if default_path.is_file():
            config_path = default_path
        else:
            return {}

    if not config_path.is_file():
        return {}

    try:
        with config_path.open("rb") as f:
            data = tomllib.load(f)
            return data.get("shadowrecon", data)
    except Exception:
        return {}
