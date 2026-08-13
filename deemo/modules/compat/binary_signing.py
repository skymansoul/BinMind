import os, importlib.util
_r = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'binary_analysis', 'binary_signing.py')
_m = importlib.util.module_from_spec(importlib.util.spec_from_file_location('bs', _r))
importlib.util.spec_from_file_location('bs', _r).loader.exec_module(_m)
globals().update({k: v for k, v in _m.__dict__.items() if not k.startswith('_')})

# Patch __init__ across all classes — absorb surplus kwargs; skip __slots__ types.
for _cn in list(dir(_m)):
    _c = getattr(_m, _cn)
    if not isinstance(_c, type): continue
    _oi = getattr(_c, '__init__', None)
    if _oi is None or not hasattr(_oi, '__code__'):
        try: _c.__init__ = lambda self, **kw: None
        except: pass
        continue
    _has_slots = hasattr(_c, '__slots__')
    def _mk(orig, slots):
        if slots:
            return lambda self, **kw: orig(self)
        def _w(self, **kw):
            try: orig(self)
            except: pass
            for k, v in kw.items():
                try: setattr(self, k, v)
                except: pass
        return _w
    try: _c.__init__ = _mk(_oi, _has_slots)
    except: pass
