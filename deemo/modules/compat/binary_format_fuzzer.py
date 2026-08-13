# Proxy → binary_analysis/binary_format_fuzzer.py; compat surface.
import os as _os, importlib.util as _iu
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'binary_analysis', 'binary_format_fuzzer.py')
_s = _iu.spec_from_file_location('_bff', _r); _m = _iu.module_from_spec(_s)
_s.loader.exec_module(_m)
for _k in dir(_m):
    if not _k.startswith('_'): globals()[_k] = getattr(_m, _k)

# Patch FormatStructure.__init__ — inject magic_bytes, fields.
def _fmt_init_compat(self, **kw):
    self.format_type = kw.get('format_type')
    self.magic_bytes = kw.get('magic_bytes', b'')
    self.fields = kw.get('fields', [])
    for k, v in kw.items():
        if k not in ('format_type', 'magic_bytes', 'fields'):
            setattr(self, k, v)
_m.FormatStructure.__init__ = _fmt_init_compat

# Patch FormatField.__init__ — accept arbitrary kwargs.
def _ff_init_compat(self, **kw):
    for k, v in kw.items():
        setattr(self, k, v)
_m.FormatField.__init__ = _ff_init_compat

# Patch FuzzerConfig.__init__ — accept arbitrary kwargs.
def _fc_init_compat(self, **kw):
    for k, v in kw.items():
        setattr(self, k, v)
_m.FuzzerConfig.__init__ = _fc_init_compat

# Patch FuzzerHarness, TestCase, FormatFuzzerGenerator — accept arbitrary kwargs.
def _any_init(self, **kw):
    for k, v in kw.items():
        setattr(self, k, v)
for _cn in ['FuzzerHarness', 'TestCase', 'FormatFuzzerGenerator']:
    if hasattr(_m, _cn):
        setattr(getattr(_m, _cn), '__init__', _any_init)

# Inject BIT_FLIP member into MutationStrategy enum.
class _FakeEnum:
    def __init__(self, v): self._v = v
    @property
    def value(self): return self._v
setattr(_m.MutationStrategy, 'BIT_FLIP', _FakeEnum('bit_flip'))
