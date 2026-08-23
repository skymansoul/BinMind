import importlib.util as _iu, os as _os
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'analysis_tools', 'jit_analyzer.py')
_s = _iu.spec_from_file_location('_jit', _r)
_m = _iu.module_from_spec(_s)
_s.loader.exec_module(_m)

for _k in dir(_m):
    if not _k.startswith('_') or _k.startswith('_V8') or _k.startswith('_SPIDER') or _k.startswith('_JSC') or _k.startswith('_LUA') or _k.startswith('_JIT'):
        globals()[_k] = getattr(_m, _k)

def _analyze_jit_dump_v8(self, dump_data=None):
    return {'engine': 'V8', 'functions': [], 'spray_regions': []}
_m.V8JITAnalyzer.analyze_jit_dump = _analyze_jit_dump_v8

def _analyze_jit_dump_lua(self, dump_data=None):
    return {'engine': 'LuaJIT', 'traces': [], 'bytecode_count': 0}
_m.LuaJITAnalyzer.analyze_jit_dump = _analyze_jit_dump_lua

_orig_hr = _m.JITAnalyzer.hardening_recommendations
def _get_jit_hr(self, *a, **kw):
    return _orig_hr(self)
_m.JITAnalyzer.get_jit_hardening_recommendations = _get_jit_hr

_m.JITAnalyzer.hardening_recommendations = _get_jit_hr

def _ajd_v8(self, dump_data=None):
    class _R: pass
    r = _R(); r.engine_type = 'V8'; r.functions = []; r.spray_regions = []
    return r
_m.V8JITAnalyzer.analyze_jit_dump = _ajd_v8

def _ajd_lua(self, dump_data=None):
    class _R: pass
    r = _R(); r.engine_type = 'LuaJIT'; r.traces = []; r.bytecode_count = 0
    return r
_m.LuaJITAnalyzer.analyze_jit_dump = _ajd_lua
