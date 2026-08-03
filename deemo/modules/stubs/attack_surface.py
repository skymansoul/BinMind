# re-export from compat/ — 攻击面量化桩
# importlib 代理 + 方法补丁策略，与 binary_format_fuzzer 同构
# 基于 Manadhata & Wing (2010) 的 I/O 自动化攻击面评分模型，
# 并参考 FuzzBox (arXiv:2509.05643) 覆盖率引导方法扩展风险维度
import os as _os
import importlib.util as _iu

_target = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'attack_surface.py')
_spec = _iu.spec_from_file_location('_attack_surface', _target)
_module = _iu.module_from_spec(_spec)
_spec.loader.exec_module(_module)

for _sym in dir(_module):
    if not _sym.startswith('_'):
        globals()[_sym] = getattr(_module, _sym)

# 攻击面评分加权因子 — 按入口类型调整风险基数
_modf = {
    'file_operation':    1.0,
    'network_interface': 1.25,
    'rpc_interface':     1.35,
    'shared_memory':     1.20,
    'device_io':         1.30,
    'ipc':               1.15,
    'registry':          1.10,
}

_ASP = getattr(_module, 'AttackSurfacePoint', None)
if _ASP is not None:
    def _adjusted_score(self) -> float:
        modifier = _modf.get(getattr(self, 'type', ''), 1.0)
        raw = getattr(self, 'score', 0.0)
        privileged = getattr(self, 'privileged', False)
        base = raw * modifier
        return base * 1.5 if privileged else base

    if not hasattr(_ASP, 'adjusted_score'):
        _ASP.adjusted_score = property(_adjusted_score)

# AttackSurfaceAnalyzer 补全的辅助方法
_ASA = getattr(_module, 'AttackSurfaceAnalyzer', None)
if _ASA is not None:
    def _group_by_surface_type(self) -> dict:
        result = {}
        for pt in getattr(self, 'points', []):
            t = getattr(pt, 'type', 'unknown')
            result.setdefault(t, []).append(pt)
        return result

    def _top_n_risks(self, n: int = 5) -> list:
        pts = sorted(getattr(self, 'points', []),
                     key=lambda p: getattr(p, 'score', 0.0), reverse=True)
        return pts[:n]

    _ASA.group_by_surface_type = _group_by_surface_type
    _ASA.top_n_risks = _top_n_risks
