import importlib as _il
try:
    _m = _il.import_module('deemo.modules.deobfuscation.string_unobfuscator')
    globals().update({k: v for k, v in _m.__dict__.items() if not k.startswith('_')})
except ImportError:
    # 兼容专用加载器注入路径: 包上下文缺失时回退按文件路径执行
    import os, types, importlib.util
    _real = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'deobfuscation', 'string_unobfuscator.py')
    _spec = importlib.util.spec_from_file_location('string_unobfuscator', _real)
    _mod = types.ModuleType('string_unobfuscator')
    _mod.__dict__.update({k: v for k, v in globals().items() if k.startswith('_')})
    _spec.loader.exec_module(_mod)
    globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith('_')})
