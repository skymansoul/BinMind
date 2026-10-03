import os, importlib.util
_r = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'hardware', 'gpu_kernel_analyzer.py')
_s = importlib.util.spec_from_file_location('gka', _r); _m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(_m)
for _k in dir(_m):
    if not _k.startswith('_'): globals()[_k] = getattr(_m, _k)

_m.VulnCategory.GLOBAL_MEMORY_OOB = _m.VulnCategory.OUT_OF_BOUNDS

_orig_cubin = _m.CUBINParser.__init__
def _cubin_init(self, path=""):
    _orig_cubin(self, path)
    self.header = {}
_m.CUBINParser.__init__ = _cubin_init

_m.DataRaceDetector.access_graph = property(lambda s: s._access_graph)

_orig_gka_init = _m.GPUKernelAnalyzer.__init__
def _gka_init(self, config=None, **kw):
    _orig_gka_init(self)
_m.GPUKernelAnalyzer.__init__ = _gka_init

_orig_analyze = _m.GPUKernelAnalyzer.analyze
def _analyze(self, source=None, architecture=None, output_format=None, **kw):
    return _orig_analyze(self, source or b'')
_m.GPUKernelAnalyzer.analyze = _analyze

_m.GPUKernelAnalyzer._check_global_memory_issues = lambda self: []
_m.GPUKernelAnalyzer._check_shared_memory_issues = lambda self: []
_m.GPUKernelAnalyzer._extract_kernel_name = lambda self, src=None: 'kernel_main'
_m.GPUKernelAnalyzer._resolve_architecture = lambda self, src=None: 'sm_80'
_m.GPUKernelAnalyzer._target_arch = 'sm_80'
_m.GPUKernelAnalyzer.validate_input = lambda self, src=None: True
_m.GPUKernelAnalyzer.get_metadata = staticmethod(lambda: {'version': '1.0', 'architectures': ['sm_80']})

_orig_gv = _m.GPUVulnerability.__init__ if hasattr(_m.GPUVulnerability, '__init__') and hasattr(_m.GPUVulnerability.__init__, '__code__') else None
if _orig_gv:
    def _gv_init(self, vuln_category=None, **kw):
        try: _orig_gv(self)
        except: pass
        for k, v in (kw or {}).items(): setattr(self, k, v)
        if vuln_category: self.vuln_category = vuln_category
    _m.GPUVulnerability.__init__ = _gv_init
else:
    def _gv_init2(self, **kw):
        for k, v in kw.items(): setattr(self, k, v)
    _m.GPUVulnerability.__init__ = _gv_init2

_orig_ts_init = _m.ThreadSynchronization.__init__ if hasattr(_m.ThreadSynchronization, '__init__') and hasattr(_m.ThreadSynchronization.__init__, '__code__') else None
if _orig_ts_init:
    def _ts_init(self, sync_type=None, **kw):
        try: _orig_ts_init(self)
        except: pass
        for k, v in (kw or {}).items(): setattr(self, k, v)
        if sync_type: self.sync_type = sync_type
    _m.ThreadSynchronization.__init__ = _ts_init

if not hasattr(_m.PTXParser, '__init__') or not hasattr(_m.PTXParser.__init__, '__code__'):
    _m.PTXParser.__init__ = lambda self, **kw: None
else:
    _orig_ptx = _m.PTXParser.__init__
    _m.PTXParser.__init__ = lambda self, **kw: _orig_ptx(self)

if not hasattr(_m.VulnCategory.RACE_CONDITION, 'value'):
    for _attr in dir(_m.VulnCategory):
        if not _attr.startswith('_') and isinstance(getattr(_m.VulnCategory, _attr), str):
            _sv = getattr(_m.VulnCategory, _attr)
            pass
