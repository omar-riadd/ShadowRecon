"""Configuration dataclass and TOML config file loader."""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

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


def default_nuclei_templates_dir() -> Path:
    """Find default nuclei templates directory, checking ~/.local/nuclei-templates (v3) or ~/nuclei-templates."""
    candidates = [
        Path.home() / ".local" / "nuclei-templates",
        Path.home() / "nuclei-templates",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return candidates[0]


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
    nuclei_templates: Path = field(default_factory=default_nuclei_templates_dir)
    nuclei_severity: str = "medium,high,critical"
    nuclei_tags: str = ""
    driver_subdomains: str = "subfinder"
    driver_probing: str = "httpx"
    driver_crawling: str = "katana"
    driver_urls: str = "wayback,katana,paramspider"
    driver_nuclei: str = "nuclei"
    driver_xss: str = "dalfox"
    driver_sqli: str = "sqlmap"

    @property
    def proxies(self) -> dict:
        return {"http": self.tor_socks, "https": self.tor_socks}


class ConfigValidationError(ValueError):
    """Raised when shadowrecon.toml configuration fails schema validation."""
    pass


_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z0-9_]+)\}|\$([A-Za-z0-9_]+)")


def interpolate_env_vars(data: Any) -> Any:
    """Recursively interpolate ${VAR} and $VAR environment variable references."""
    if isinstance(data, dict):
        return {k: interpolate_env_vars(v) for k, v in data.items()}
    if isinstance(data, list):
        return [interpolate_env_vars(item) for item in data]
    if isinstance(data, str):
        def repl(match: re.Match) -> str:
            var_name = match.group(1) or match.group(2)
            return os.getenv(var_name, "")
        return _ENV_VAR_PATTERN.sub(repl, data)
    return data


# Schema definition: key -> (allowed_types, optional_validator_callable, human_description)
TOML_SCHEMA: Dict[str, Tuple[Union[type, Tuple[type, ...]], Optional[Callable[[Any], bool]], str]] = {
    "target": (str, None, "Target URL"),
    "domain": (str, None, "Target domain"),
    "wordlist": (str, None, "Path to fuzzing wordlist"),
    "outdir": (str, None, "Output directory path"),
    "lfi_payloads": (str, None, "Path to LFI payloads"),
    "tor_socks": (str, None, "Tor SOCKS5 proxy URL"),
    "socks": (str, None, "Tor SOCKS5 proxy URL (alias for tor_socks)"),
    "tor_control_port": (int, lambda v: 1 <= v <= 65535, "Tor control port (1-65535)"),
    "tor_port": (int, lambda v: 1 <= v <= 65535, "Tor control port (alias for tor_control_port)"),
    "tor_control_password": (str, None, "Tor control password"),
    "tor_pass": (str, None, "Tor control password (alias for tor_control_password)"),
    "rotate_wait": (int, lambda v: v >= 0, "Circuit rotation delay (seconds >= 0)"),
    "max_retries": (int, lambda v: v >= 1, "Maximum retries (>= 1)"),
    "request_timeout": (int, lambda v: v > 0, "Request timeout (seconds > 0)"),
    "timeout": (int, lambda v: v > 0, "Request timeout (alias for request_timeout)"),
    "rate_limit": ((int, float), lambda v: v >= 0, "Request delay (seconds >= 0)"),
    "max_backoff": ((int, float), lambda v: v >= 0, "Max backoff (seconds >= 0)"),
    "ffuf_threads": (int, lambda v: v >= 1, "FFUF threads (>= 1)"),
    "threads": (int, lambda v: v >= 1, "Thread count (alias for ffuf_threads)"),
    "dry_run": (bool, None, "Dry run flag"),
    "use_proxy": (bool, None, "Use proxy routing flag"),
    "proxy_provider": (str, lambda v: v in ("tor", "pool", "direct"), "Proxy provider ('tor', 'pool', 'direct')"),
    "proxy_pool_file": (str, None, "Path to rotating proxy pool file"),
    "make_report": (bool, None, "HTML report flag"),
    "force_rerun": (bool, None, "Force rerun stages flag"),
    "stages": (str, None, "Comma-separated stages"),
    "skip_stages": (str, None, "Comma-separated skip stages"),
    "nuclei_templates": (str, None, "Path to nuclei templates directory"),
    "nuclei_severity": (str, None, "Nuclei severity filter"),
    "nuclei_tags": (str, None, "Nuclei tags filter"),
    "export_sarif": (str, None, "SARIF export path"),
    "export_json": (str, None, "JSON export path"),
    "export_csv": (str, None, "CSV export directory"),
    "diff": (str, None, "Prior session.db path for diffing"),
    "driver_subdomains": (str, None, "Driver(s) for subdomains stage (e.g. 'subfinder' or 'subfinder,assetfinder')"),
    "driver_probing": (str, None, "Driver for probing stage (e.g. 'httpx')"),
    "driver_crawling": (str, None, "Driver for crawling stage (e.g. 'katana')"),
    "driver_urls": (str, None, "Driver(s) for URL gathering stage (e.g. 'wayback,katana,paramspider' or 'gau,katana')"),
    "driver_nuclei": (str, None, "Driver for nuclei stage (e.g. 'nuclei')"),
    "driver_xss": (str, None, "Driver for XSS stage (e.g. 'dalfox')"),
    "driver_sqli": (str, None, "Driver for SQLi stage (e.g. 'sqlmap')"),
}


def validate_toml_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a parsed configuration dictionary against the TOML schema."""
    for key, value in cfg.items():
        if key not in TOML_SCHEMA:
            raise ConfigValidationError(
                f"Unknown configuration key '{key}' in shadowrecon.toml. "
                f"Valid keys are: {', '.join(sorted(TOML_SCHEMA.keys()))}"
            )

        expected_type, validator, desc = TOML_SCHEMA[key]
        if not isinstance(value, expected_type):
            type_name = expected_type.__name__ if isinstance(expected_type, type) else "/".join(t.__name__ for t in expected_type)
            raise ConfigValidationError(
                f"Invalid type for key '{key}': expected {type_name}, got {type(value).__name__} ({value!r})"
            )

        if validator is not None and not validator(value):
            raise ConfigValidationError(
                f"Validation failed for key '{key}' with value {value!r}. Requirement: {desc}"
            )

    return cfg


def load_toml_config(config_path: Optional[Path], strict: bool = True) -> Dict[str, Any]:
    """Load, interpolate, and validate configuration from a TOML file."""
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
            section = data.get("shadowrecon", data)
    except Exception as exc:
        if strict:
            raise ConfigValidationError(f"Failed to parse TOML syntax in '{config_path}': {exc}") from exc
        return {}

    interpolated = interpolate_env_vars(section)
    if strict and isinstance(interpolated, dict):
        validate_toml_config(interpolated)

    return interpolated
