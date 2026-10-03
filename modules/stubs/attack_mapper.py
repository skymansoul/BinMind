# re-export from compat/ — MITRE ATT&CK 技战术映射桩
# Automated Generation of Attack Graphs Using NVD &
#   Arbiter (Vadayath et al.) — 动静结合的攻击链映射
import os as _os, importlib.util as _iu
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'attack_mapper.py')
_s = _iu.spec_from_file_location('_am', _r); _m = _iu.module_from_spec(_s); _s.loader.exec_module(_m)
for _k in dir(_m):
    if not _k.startswith('_'): globals()[_k] = getattr(_m, _k)

# ATT&CK 技战术映射置信度计算
# 多源证据加权融合：静态命中与动态命中按权重合成置信度
def _confidence_from_evidence(static_hits: int, dynamic_hits: int, total_indicators: int) -> float:
    if total_indicators <= 0: return 0.0
    return (static_hits * 0.6 + dynamic_hits * 0.4) / total_indicators

if hasattr(_m, 'AttackMapper'):
    _m.AttackMapper.confidence_from_evidence = staticmethod(_confidence_from_evidence)
