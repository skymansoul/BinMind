import os as _os, sys as _sys
_d = _os.path.dirname(_os.path.dirname(__file__))
_sys.path.insert(0, _os.path.join(_d, 'binary_analysis'))
_diff = __import__('diff_analysis')
_sys.path.pop(0)
globals().update({k: getattr(_diff, k) for k in dir(_diff) if not k.startswith('_')})
