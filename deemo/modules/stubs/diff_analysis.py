# re-export from compat/ — 差异分析桩
# 参考: VulHawk (Luo et al., 2023, NDSS) 跨架构熵搜索 &
#   αDiff — DNN 驱动的跨版本二进制代码相似性 &
#   BinDiff 方法论 — 补丁前后对比是漏洞定位的核心手段
import os as _os, importlib.util as _iu
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'diff_analysis.py')
_s = _iu.spec_from_file_location('_diff', _r); _m = _iu.module_from_spec(_s); _s.loader.exec_module(_m)
for _k in dir(_m):
    if not _k.startswith('_'): globals()[_k] = getattr(_m, _k)

# VulHawk 的熵引导方法 — N-gram 熵差作为跨架构相似性的代理指标
import math as _math
from collections import Counter as _Ctr

def ngram_entropy_diff(bytes_a: bytes, bytes_b: bytes, n: int = 4) -> float:
    if len(bytes_a) < n or len(bytes_b) < n: return 1.0
    def _ngram_entropy(data):
        grams = [data[i:i+n] for i in range(len(data)-n+1)]
        freq = list(_Ctr(grams).values())
        total = sum(freq)
        return -sum((f/total)*_math.log2(f/total) for f in freq)
    e_a, e_b = _ngram_entropy(bytes_a), _ngram_entropy(bytes_b)
    return abs(e_a - e_b) / max(e_a, e_b, 0.001)
