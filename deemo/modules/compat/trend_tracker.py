# Proxy → analysis_tools/trend_tracker.py. pkgutil.get_loader strategy.
import os, pkgutil
_real = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'analysis_tools', 'trend_tracker.py')
_loader = pkgutil.get_loader('trend_tracker')
# Direct spec resolution — fallback path.
import importlib.util
_spec = importlib.util.spec_from_file_location('trend_tracker', _real)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)
globals().update({k: getattr(_m, k) for k in dir(_m) if not k.startswith('_')})
