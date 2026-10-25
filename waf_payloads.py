"""
Backward-compatibility shim for shadowrecon.waf_payloads.

Preserves existing external imports of `waf_payloads` while maintaining
canonical implementation inside `shadowrecon.waf_payloads`.
"""
try:
    from shadowrecon.waf_payloads import *
    from shadowrecon.waf_payloads import BYPASS, default_payloads, mutate_path
except ModuleNotFoundError:
    import sys
    from pathlib import Path
    _src = str(Path(__file__).resolve().parent / "src")
    if _src not in sys.path:
        sys.path.insert(0, _src)
    from shadowrecon.waf_payloads import *
    from shadowrecon.waf_payloads import BYPASS, default_payloads, mutate_path


