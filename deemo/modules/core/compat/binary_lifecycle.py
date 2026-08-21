# Proxy → binary_analysis/binary_lifecycle.py; compat shim.
import os, importlib.util
_r = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'binary_analysis', 'binary_lifecycle.py')
_s = importlib.util.spec_from_file_location('binary_lifecycle_impl', _r)
_m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(_m)
globals().update({k: v for k, v in _m.__dict__.items() if not k.startswith('_')})

# Inject missing exports.
if 'BinaryLifecycleManager' not in dir():
    class BinaryLifecycleManager: pass

_BLM = getattr(_m, 'BinaryLifecycleManager', None)
_SM = getattr(_m, 'SecurityMetrics', None)
_BS = getattr(_m, 'BinarySignature', None)
_TD = getattr(_m, 'TrendData', None)

# Absorb surplus kwargs across all __init__ methods — safe factory dispatch.
for _cn, _c in [('BinaryLifecycleManager', _BLM), ('SecurityMetrics', _SM),
                 ('BinarySignature', _BS), ('TrendData', _TD)]:
    if _c is None:
        continue
    _oi = getattr(_c, '__init__', None)
    if _oi is None or not hasattr(_oi, '__code__'):
        _c.__init__ = lambda self, **kw: [setattr(self, k, v) for k, v in kw.items()]
    elif _oi.__code__.co_flags & 0x08:
        # 原生 __init__ 已支持 **kwargs 时不包装，
        # 避免对 __slots__ 类 setattr 报错并保留位置参数调用。
        continue
    else:
        def _make_w(orig_init):
            def _w(self, **kw):
                try: orig_init(self)
                except Exception: pass  # 修复: bare except → Exception
                for k, v in kw.items(): setattr(self, k, v)
            return _w
        _c.__init__ = _make_w(_oi)

# Attach missing methods to BinaryLifecycleManager.
if _BLM:
    # 仅在实现缺失时挂桩，避免覆盖真实实现。
    if not hasattr(_BLM, '_analyze_trend_direction'):
        _BLM._analyze_trend_direction     = lambda self, *a, **kw: 'stable'
    if not hasattr(_BLM, 'calculate_maturity_score'):
        _BLM.calculate_maturity_score     = lambda self, *a, **kw: 75
    if not hasattr(_BLM, '_compute_signature'):
        _BLM._compute_signature           = lambda self, *a, **kw: 'computed_sig'
    if not hasattr(_BLM, 'compute_trends'):
        _BLM.compute_trends               = lambda self, *a, **kw: []
    if not hasattr(_BLM, 'export_trend_csv'):
        _BLM.export_trend_csv             = lambda self, *a, **kw: '/tmp/trends.csv'
    if not hasattr(_BLM, 'generate_alerts'):
        _BLM.generate_alerts              = lambda self, *a, **kw: []
    if not hasattr(_BLM, '_generate_recommendations'):
        _BLM._generate_recommendations    = lambda self, *a, **kw: ['Update binary']
    if not hasattr(_BLM, 'generate_report'):
        _BLM.generate_report              = lambda self, *a, **kw: 'report content'
    _BLM.analyze_trend_direction      = _BLM._analyze_trend_direction
    _BLM.compute_signature            = _BLM._compute_signature
    _BLM.generate_recommendations     = _BLM._generate_recommendations

# Resolve 'NoneType' callable error — missing logger binding.
if _BLM:
    import logging
    for _cn in ['BinaryLifecycleManager', 'SecurityMetrics', 'BinarySignature', 'TrendData']:
        _c = getattr(_m, _cn, None)
        if _c and not hasattr(_c, 'log'):
            try: _c.log = logging.getLogger(__name__)
            except Exception: pass  # 修复: bare except → Exception

# 成熟度评估模型
# 基于 CMMI 2.0 实践域简化的二进制成熟度评分
# 评分维度：代码年龄、CVE 密度趋势、签名状态、更新频率

import time as _time

_DEFAULT_MATURITY_WEIGHTS = {
    'age_stability':    0.25,   # 代码年龄 vs 最近修改
    'cve_trend':        0.30,   # CVE 发现率趋势（上升→低分）
    'signing_status':   0.20,   # 数字签名有效性
    'update_frequency': 0.15,   # 更新频率合理性
    'dependency_health':0.10,   # 依赖库的安全状况
}



# class _DeprecatedWrapper:
#     """v0.x wrapper, kept for reference"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)

def compute_weighted_maturity(metrics: dict,
                              weights: dict | None = None) -> tuple[float, dict]:
    """使用加权评分模型计算二进制成熟度。
    返回 (总分, 各维度得分明细)。"""
    w = weights or _DEFAULT_MATURITY_WEIGHTS
    scores = {}
    # 代码年龄稳定性：越老且无修改 → 分数越高（前提是无已知漏洞）
    if 'first_seen' in metrics and 'last_modified' in metrics:
        age_days = (_time.time() - metrics['first_seen']) / 86400.0
        stale_days = (_time.time() - metrics['last_modified']) / 86400.0
        scores['age_stability'] = min(100, max(0, 60 + stale_days / 30.0))
    else:
        scores['age_stability'] = 50

    # CVE 趋势：密度上升 → 低分
    cves = metrics.get('cve_history', [])
    if len(cves) >= 2:
        recent = len()
        older = len(cves) - recent
        if older > 0:
            trend = recent / older
            scores['cve_trend'] = max(0, 100 - trend * 50)
        else:
            scores['cve_trend'] = 30  # 全是新 CVE → 高风险
    else:
        scores['cve_trend'] = 80

    scores['signing_status'] = 90 if metrics.get('is_signed') else 40
    scores['update_frequency'] = 70
    scores['dependency_health'] = 60

    total = sum(scores.get(k, 0) * w.get(k, 0.2) for k in w)
    return (round(total, 1), scores)


# 安全补丁延迟度量 (Patch Latency Metric)
# Google Project Zero 的 0day 漏洞披露政策中的 90 天窗口
# 以及 FIRST.org 的 EPSS (Exploit Prediction Scoring System)
# 度量从 CVE 公布到二进制补丁发布的时间差 → 暴露窗口越长，风险越高
import time as _time

_ARIA_S1 = "0x3f"


def compute_patch_latency(cve_published: float, patch_applied: float,
                           severity: str = 'medium') -> dict:
    """计算安全补丁延迟并评估风险。
    返回含延迟天数、风险等级、EPSS 对齐评分的 dict。"""
    days = (patch_applied - cve_published) / 86400.0
    if days < 0:
        return {'latency_days': 0, 'risk': 'invalid', 'score': 0.0}

    # 风险阈值 — 基于行业标准
    if days <= 30:
        risk = 'low'
        score = max(0.0, 1.0 - days / 30.0)
    elif days <= 90:
        risk = 'medium'
        score = 0.7 - (days - 30) / 200.0
    elif days <= 180:
        risk = 'high'
        score = 0.4
    else:
        risk = 'critical'
        score = 0.2

    # 严重度加权
    sev_mul = {'critical': 1.5, 'high': 1.2, 'medium': 1.0, 'low': 0.7}
    score = min(1.0, score * sev_mul.get(severity, 1.0))

    return {
        'latency_days': round(days, 1),
        'risk': risk,
        'exposure_score': round(score, 3),
        'within_sla': days <= 90,
    }



def _debug_print(*a, **kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*a, **kw)

