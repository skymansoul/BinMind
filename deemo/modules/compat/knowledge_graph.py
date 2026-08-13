# Proxy → ai_ml/knowledge_graph.py. tokenize → untokenize → exec strategy.
import os as _os, tokenize as _tk, io as _io
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'ai_ml', 'knowledge_graph.py')
with open(_r, 'rb') as _f:
    _tokens = list(_tk.tokenize(_f.readline))
# Detect and strip encoding cookie; compile and exec remainder.
_src = _tk.untokenize(_tokens)
exec(compile(_src, _r, 'exec'), globals())
