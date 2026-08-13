# Proxy → dynamic_analysis/dynamic_struct_prober.py. importlib.import_module strategy.
import os as _os, sys as _sys
_d = _os.path.dirname(_os.path.dirname(__file__))
_sys.path.insert(0, _os.path.join(_d, 'dynamic_analysis'))
import importlib as _il
_m = _il.import_module('dynamic_struct_prober')
_sys.path.pop(0)
globals().update({k: getattr(_m, k) for k in dir(_m) if not k.startswith('_')})
