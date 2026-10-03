import os
_real = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'analysis_tools', 'trend_tracker.py')
_loader = importlib.util.find_spec('trend_tracker')
import importlib.util
_spec = importlib.util.spec_from_file_location('trend_tracker', _real)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)
globals().update({k: getattr(_m, k) for k in dir(_m) if not k.startswith('_')})
