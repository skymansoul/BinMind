# Proxy → info_collection/interactive_shell.py. pathlib + runpy strategy.
from pathlib import Path as _P
import runpy as _rp
_real = str(_P(__file__).parent.parent / 'info_collection' / 'interactive_shell.py')
_ns = _rp.run_path(_real)
globals().update({k: v for k, v in _ns.items() if not k.startswith('_')})
