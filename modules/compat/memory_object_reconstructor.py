import os as _os
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'dynamic_analysis', 'memory_object_reconstructor.py')
with open(_r, 'r', encoding='utf-8') as _f:
    _code = _f.read()
exec(compile(_code, _r, 'exec'), globals())
