# re-export from compat/ — MITRE ATT&CK 映射桩
# 参考: Automated Generation of Attack Graphs Using NVD (Aksu et al., 2018) &
#   Arbiter (Vadayath et al.) — 静态/动态分析桥接的攻击面映射
import os as _os, importlib.util as _iu
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'attack_mapper.py')
_s = _iu.spec_from_file_location('_am', _r); _m = _iu.module_from_spec(_s); _s.loader.exec_module(_m)
for _k in dir(_m):
    if not _k.startswith('_'): globals()[_k] = getattr(_m, _k)

# 补充: ATT&CK 技战术映射的置信度评分
# Arbiter 的静态-动态桥接策略在此体现为多源证据融合的置信度模型
def _confidence_from_evidence(static_hits: int, dynamic_hits: int, total_indicators: int) -> float:
    if total_indicators <= 0: return 0.0
    return (static_hits * 0.6 + dynamic_hits * 0.4) / total_indicators

if hasattr(_m, 'AttackMapper'):
    _m.AttackMapper.confidence_from_evidence = staticmethod(_confidence_from_evidence)
