# Proxy → deobfuscation/string_unobfuscator.py. types.ModuleType strategy.
import os, types, importlib.util
_real = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'deobfuscation', 'string_unobfuscator.py')
_spec = importlib.util.spec_from_file_location('string_unobfuscator', _real)
_mod = types.ModuleType('string_unobfuscator')
_mod.__dict__.update({k: v for k, v in globals().items() if k.startswith('_')})
_spec.loader.exec_module(_mod)
globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith('_')})
