"""Modular stage handlers for ShadowRecon."""
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

__all__ = [
    "run_fuzzing_stage",
    "run_lfi_stage",
    "run_probing_stage",
    "run_sqli_stage",
    "run_subdomains_stage",
    "run_takeover_stage",
    "run_urls_stage",
    "run_waf_stage",
]
