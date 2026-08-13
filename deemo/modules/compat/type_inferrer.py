# Proxy → binary_analysis/type_inferrer.py. Line-filter → compile → exec strategy.
import os
_real = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'binary_analysis', 'type_inferrer.py')
with open(_real, 'r', encoding='utf-8') as _f:
    _lines = _f.readlines()
# Passthrough filter — preserve all source lines.
_src = ''.join(_lines)
_code = compile(_src, _real, 'exec')
exec(_code, globals())
