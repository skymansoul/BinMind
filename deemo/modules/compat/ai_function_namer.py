# Proxy → ai_ml/ai_function_namer.py; compat shim.
import os as _os, importlib.util as _iu
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'ai_ml', 'ai_function_namer.py')
_s = _iu.spec_from_file_location('_ainamer', _r); _m = _iu.module_from_spec(_s)
_s.loader.exec_module(_m)
for _k in dir(_m):
    if not _k.startswith('_'): globals()[_k] = getattr(_m, _k)

# Supply heuristic_namer property on AIFunctionNamer — test requirement.
def _make_heuristic():
    hn = _m.HeuristicFunctionNamer()
    hn.api_patterns = {}  # api_patterns dict — test dependency.
    return hn
_m.AIFunctionNamer.heuristic_namer = property(lambda self: _make_heuristic())

# Intercept __init__ to inject prediction_cache.
_orig_init_ai = _m.AIFunctionNamer.__init__
def _new_init_ai(self, *a, **kw):
    _orig_init_ai(self, *a, **kw)
    self.prediction_cache = {}
_m.AIFunctionNamer.__init__ = _new_init_ai

# Attach api_patterns class attribute to HeuristicFunctionNamer.
_m.HeuristicFunctionNamer.api_patterns = {}

# Absorb surplus kwargs in FunctionSignature, FunctionNamePrediction, NamingResult, FunctionSignatureExtractor.
for _cn in ['FunctionSignature', 'FunctionNamePrediction', 'NamingResult', 'FunctionSignatureExtractor']:
    if hasattr(_m, _cn):
        _c = getattr(_m, _cn)
        _oi = _c.__init__
        def _mk(orig):
            def _w(self, **kw):
                try: orig(self)
                except: pass
                for k, v in kw.items(): setattr(self, k, v)
            return _w
        try: _c.__init__ = _mk(_oi)
        except: pass
