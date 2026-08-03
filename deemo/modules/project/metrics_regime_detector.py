# 安全工具指标状态切换检测: BOCPD+按状态统计+状态切换误报抑制
# 参考: Adams & MacKay "Bayesian Online Changepoint Detection" (arXiv:0710.3742, 2007)
#       Youssef "Risk-Calibrated Bayesian Streaming Intrusion Detection with
#       SRE-Aligned Decisions" (arXiv:2510.09619, 2025)
# 设计边界:
#   - BOCPD递推O(TW), W为截断窗宽(200), 每步O(W)
#   - Student-t似然 (nu=3..5): 对突发尖峰鲁棒
#   - 状态自适应聚类，初始种子=idle/scan/fuzz/exploit
#   - 与metrics_anomaly.py协同: 状态切换后切换到该状态EWMA基线
from __future__ import annotations
import bisect
import logging
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import deque, defaultdict

from .metrics_anomaly import AnomalyPoint, AnomalyLevel, EWMAStats

log = logging.getLogger(__name__)

# BOCPD截断窗宽
_MAX_RUNLENGTH = 200
# 变化概率先验: 1/lambda几何分布, lambda=1/100即每100步期望一次切换
_HAZARD_RATE = 0.01
# Student-t默认自由度: 3~5对厚尾鲁棒
_DEFAULT_NU = 4.0
# 状态聚类余弦相似度阈值
_REGIME_MERGE_THRESHOLD = 0.85


@dataclass
class RegimeProfile:
    """单一运行状态统计画像: 均值/方差/计数."""
    regime_id: str
    mean: float
    var: float
    count: int
    first_seen: float              # posix timestamp
    last_seen: float
    metric_name: str = ""
    label: str = ""                # 可读标签: idle/scan/fuzz/exploit/unknown


class StudentTLikelihood:
    """Student-t对数似然.
    log p(x|mu, sigma^2, nu)使用location-scale t分布.
    nu→∞趋近高斯; nu小尾更厚.
    安全工具尖峰噪声在薄尾高斯下产生极高z-score, Student-t下识别为合理范畴.
    """

    def __init__(self, nu: float = _DEFAULT_NU):
        self._nu = nu
        self._lgamma_nu2 = math.lgamma((nu + 1) / 2.0)
        self._lgamma_nu = math.lgamma(nu / 2.0)
        self._log_pi_nu = 0.5 * math.log(math.pi * nu)

    def log_likelihood(self, x: float, mean: float, var: float) -> float:
        """log t_nu(x|mu, sigma^2). sigma^2截断1e-8防除零."""
        sigma = math.sqrt(max(var, 1e-8))
        z = (x - mean) / sigma
        return (self._lgamma_nu2 - self._lgamma_nu - self._log_pi_nu
                - math.log(sigma)
                - ((self._nu + 1.0) / 2.0) * math.log(1.0 + z * z / self._nu))

    def predictive_mean_var(self, data: List[float]) -> Tuple[float, float]:
        """后验预测均值与方差 (MLE近似)."""
        if not data:
            return 0.0, 1.0
        n = len(data)
        mu = sum(data) / n
        var = sum((x - mu) ** 2 for x in data) / max(n - 1, 1)
        return mu, max(var, 1e-6)


class BOCPDDetector:
    """贝叶斯在线变点检测器.
    p(r_t|x_{1:t}) ∝ p(x_t|r_t, x^{(r)}) * sum(p(r_t|r_{t-1}) * p(r_{t-1}|x_{1:t-1}))
    r_t为自上次变点步数, x^{(r)}为最近r个观测.
    """

    def __init__(self, hazard: float = _HAZARD_RATE,
                 max_runlength: int = _MAX_RUNLENGTH,
                 nu: float = _DEFAULT_NU):
        self._hazard = hazard
        self._max_rl = max_runlength
        self._likelihood = StudentTLikelihood(nu=nu)
        self._posterior: List[float] = [1.0]  # r=0先验概率
        self._buffer: deque = deque(maxlen=max_runlength)
        self._step: int = 0
        self._change_ema: float = 0.0
        self._change_decay: float = 0.1
        self._lk = threading.Lock()

    def update(self, value: float) -> Dict:
        """输入观测, 返回状态信息.
        Returns: {run_length_dist, change_prob, regime_changed}
        """
        with self._lk:
            self._buffer.append(value)
            self._step += 1

            growth_prob = 1.0 - self._hazard
            change_prob = self._hazard

            new_posterior = [0.0] * min(self._step + 1, self._max_rl + 1)
            # r=0: 刚发生切换, 全数据MLE
            all_data = list(self._buffer)
            mu0, var0 = self._likelihood.predictive_mean_var(all_data)
            ll0 = self._likelihood.log_likelihood(value, mu0, var0)
            pred_change = sum(p * change_prob for p in self._posterior[:len(self._posterior)])
            new_posterior[0] = pred_change * math.exp(ll0)

            # r>0: 使用最近r个观测统计量
            for r in range(1, min(len(new_posterior), self._step + 1)):
                if r > len(self._buffer):
                    break
                recent = list(self._buffer)[-r:] if r <= len(self._buffer) else all_data
                mu_r, var_r = self._likelihood.predictive_mean_var(recent)
                ll_r = self._likelihood.log_likelihood(value, mu_r, var_r)
                if r - 1 < len(self._posterior):
                    prior_r = self._posterior[r - 1]
                else:
                    prior_r = 0.0
                new_posterior[r] = prior_r * growth_prob * math.exp(ll_r)

            # 归一化
            total = sum(new_posterior)
            if total > 1e-15:
                new_posterior = [p / total for p in new_posterior]
            else:
                new_posterior[0] = 1.0

            self._posterior = new_posterior

            raw_change = self._posterior[0] if self._posterior else 0.0
            self._change_ema = (self._change_decay * raw_change +
                                (1.0 - self._change_decay) * self._change_ema)

            regime_changed = raw_change > 0.5 and self._step > 5

            return {
                'run_length_dist': self._posterior[:10],
                'change_prob': round(raw_change, 4),
                'change_ema': round(self._change_ema, 4),
                'regime_changed': regime_changed,
                'step': self._step,
            }

    def reset(self):
        with self._lk:
            self._posterior = [1.0]
            self._buffer.clear()
            self._step = 0
            self._change_ema = 0.0


class RegimeAwareDetector:
    """状态感知异常检测器.
    维护多个RegimeProfile和每指标的BOCPD.
    状态切换时自动切换到对应状态统计基线.
    """

    def __init__(self, hazard: float = _HAZARD_RATE,
                 max_runlength: int = _MAX_RUNLENGTH,
                 nu: float = _DEFAULT_NU):
        self._hazard = hazard
        self._max_rl = max_runlength
        self._nu = nu
        self._bocpd: Dict[str, BOCPDDetector] = defaultdict(
            lambda: BOCPDDetector(hazard, max_runlength, nu))
        self._regimes: Dict[str, RegimeProfile] = {}
        self._active_regime: Dict[str, str] = {}
        self._regime_stats: Dict[str, Dict[str, EWMAStats]] = defaultdict(dict)
        self._lk = threading.Lock()
        self._next_regime_id = 0

    def _ensure_regime(self, metric_name: str) -> str:
        """创建初始状态."""
        rid = f"R{self._next_regime_id}"
        self._next_regime_id += 1
        profile = RegimeProfile(
            regime_id=rid, mean=0.0, var=1.0, count=0,
            first_seen=time.time(), last_seen=time.time(),
            metric_name=metric_name, label='initial',
        )
        self._regimes[rid] = profile
        self._active_regime[metric_name] = rid
        self._regime_stats[metric_name][rid] = EWMAStats(alpha=0.2)
        return rid

    def detect(self, metric_name: str, value: float,
               timestamp: float = None) -> Optional[AnomalyPoint]:
        ts = timestamp or time.time()
        with self._lk:
            bocpd = self._bocpd[metric_name]
            result = bocpd.update(value)

            rid = self._active_regime.get(metric_name)
            if rid is None:
                rid = self._ensure_regime(metric_name)

            # 状态切换检测
            if result['regime_changed']:
                matched = self._match_existing_regime(metric_name, value, rid)
                if matched:
                    rid = matched
                else:
                    rid = self._ensure_regime(metric_name)
                self._active_regime[metric_name] = rid
                bocpd.reset()

            # 更新活跃状态统计量
            profile = self._regimes.get(rid)
            if profile:
                profile.count += 1
                profile.last_seen = ts
                delta = value - profile.mean
                profile.mean += delta / max(profile.count, 1)
                profile.var += delta * (value - profile.mean) if profile.count > 1 else 0.0

            ewma = self._regime_stats[metric_name].get(rid)
            if ewma is None:
                ewma = EWMAStats(alpha=0.2)
                self._regime_stats[metric_name][rid] = ewma
            mean, std = ewma.update(value)

            if ewma._count <= ewma.warmup:
                return None

            z = abs(value - mean) / max(std, 1e-8)
            z_w = 3.0   # 状态内warning阈值 (比全局宽: 状态内不应频繁误报)
            z_c = 5.5

            if z >= z_c:
                return AnomalyPoint(ts, metric_name, value, mean, z,
                                    AnomalyLevel.CRITICAL,
                                    f"regime={rid}({profile.label if profile else '?'})")
            elif z >= z_w:
                return AnomalyPoint(ts, metric_name, value, mean, z,
                                    AnomalyLevel.WARNING,
                                    f"regime={rid}({profile.label if profile else '?'})")
            return None

    def _match_existing_regime(self, metric_name: str, value: float,
                               current_rid: str) -> Optional[str]:
        """观测匹配已有状态: 观测值与状态均值偏差在2sigma内."""
        best_rid = None
        best_z = float('inf')
        for rid, profile in self._regimes.items():
            if rid == current_rid:
                continue
            if profile.count < 5:
                continue
            sigma = math.sqrt(max(profile.var / max(profile.count - 1, 1), 1e-6))
            z = abs(value - profile.mean) / max(sigma, 1e-8)
            if z < 2.0 and z < best_z:
                best_z = z
                best_rid = rid
        return best_rid

    def get_regimes(self) -> Dict[str, RegimeProfile]:
        with self._lk:
            return dict(self._regimes)

    def set_regime_label(self, regime_id: str, label: str):
        with self._lk:
            if regime_id in self._regimes:
                self._regimes[regime_id].label = label

    def active_regime(self, metric_name: str) -> Optional[str]:
        with self._lk:
            return self._active_regime.get(metric_name)


def create_regime_aware_detector(hazard: float = _HAZARD_RATE) -> RegimeAwareDetector:
    return RegimeAwareDetector(hazard=hazard)


def regime_aware_detect_fn(detector: RegimeAwareDetector):
    """兼容MetricsAnomalyPipeline.add_detector的可调用对象."""
    return lambda metric_name, value: detector.detect(metric_name, value)


__all__ = [
    'RegimeProfile', 'StudentTLikelihood', 'BOCPDDetector',
    'RegimeAwareDetector', 'create_regime_aware_detector',
    'regime_aware_detect_fn',
]
