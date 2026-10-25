"""
Backward-compatibility shim for shadowrecon.console.

Preserves existing external imports of `console` while maintaining
canonical implementation inside `shadowrecon.console`.
"""
try:
    from shadowrecon.console import *
    from shadowrecon.console import banner, log_handler, summary_table, format_status_card, print_status_card
except ModuleNotFoundError:
    import sys
    from pathlib import Path
    _src = str(Path(__file__).resolve().parent / "src")
    if _src not in sys.path:
        sys.path.insert(0, _src)
    from shadowrecon.console import *
    from shadowrecon.console import banner, log_handler, summary_table, format_status_card, print_status_card

