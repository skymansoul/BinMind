# re-export from compat/ — 二进制格式模糊测试桩
# 参考: Checksum-Aware Fuzzing (Wang et al., 2011, ACM TISSEC) &
#   SemFuzz (You et al., 2017, CCS) — 语义引导的格式感知变异
import os as _os, importlib.util as _iu
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'binary_format_fuzzer.py')
_s = _iu.spec_from_file_location('_bff', _r); _m = _iu.module_from_spec(_s); _s.loader.exec_module(_m)
for _k in dir(_m):
    if not _k.startswith('_'): globals()[_k] = getattr(_m, _k)
