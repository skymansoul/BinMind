# Proxy → vuln_detection/yara_auto_gen.py. SourceFileLoader direct strategy.
from importlib.machinery import SourceFileLoader as _SFL
import os as _os
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'vuln_detection', 'yara_auto_gen.py')
_loader = _SFL('yara_auto_gen', _r)
_m = _loader.load_module('yara_auto_gen')
globals().update({k: getattr(_m, k) for k in dir(_m) if not k.startswith('_')})
