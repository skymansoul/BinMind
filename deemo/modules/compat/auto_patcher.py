# Proxy → patching/auto_patcher.py. sys.modules injection strategy.
import importlib.util as _iu, os as _os, sys as _sys
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'patching', 'auto_patcher.py')
_s = _iu.spec_from_file_location('modules.auto_patcher', _r)
_m = _iu.module_from_spec(_s)
_sys.modules['modules.auto_patcher'] = _m
_s.loader.exec_module(_m)
# Re-export all public symbols.
for _k in dir(_m):
    if not _k.startswith('_'):
        globals()[_k] = getattr(_m, _k)
