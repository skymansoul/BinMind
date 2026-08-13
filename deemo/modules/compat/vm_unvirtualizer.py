# Proxy → deobfuscation/vm_unvirtualizer.py. pkg_resources-style resolution strategy.
import os, sys
_dir = os.path.dirname(os.path.dirname(__file__))
_target = os.path.join(_dir, 'deobfuscation')
if _target not in sys.path:
    sys.path.insert(0, _target)
import vm_unvirtualizer as _m
sys.path.remove(_target)
globals().update({k: getattr(_m, k) for k in dir(_m) if not k.startswith('_')})
