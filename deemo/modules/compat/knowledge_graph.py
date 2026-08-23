# tokenize 策略保留为回退路径
import importlib as _il
try:
    _m = _il.import_module('deemo.modules.ai_ml.knowledge_graph')
    globals().update({k: v for k, v in _m.__dict__.items() if not k.startswith('_')})
except ImportError:
    import os as _os, tokenize as _tk, io as _io
    _r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'ai_ml', 'knowledge_graph.py')
    with open(_r, 'rb') as _f:
        _tokens = list(_tk.tokenize(_f.readline))
    _src = _tk.untokenize(_tokens)
    exec(compile(_src, _r, 'exec'), globals())
