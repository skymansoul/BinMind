import os as _os
_p = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'binary_analysis', 'decompiler_enhancements.py')
with open(_p, encoding='utf-8') as _f:
    exec(compile(_f.read(), _p, 'exec'), globals())
