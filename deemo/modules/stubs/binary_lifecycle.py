# re-export from compat/ — 二进制生命周期管理桩
# 参考: Vestige (Ji et al., 2021) 二进制来源追踪 &
#   Trend Tracker — 版本漂移的时间序列建模
import os as _os, importlib.util as _iu
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'binary_lifecycle.py')
_s = _iu.spec_from_file_location('_blc', _r); _m = _iu.module_from_spec(_s); _s.loader.exec_module(_m)
for _k in dir(_m):
    if not _k.startswith('_'): globals()[_k] = getattr(_m, _k)
