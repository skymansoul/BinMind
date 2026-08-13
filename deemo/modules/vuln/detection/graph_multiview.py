# coding: utf-8
# 创建: 2026-04-19  |  多视图对抗检测
# 修改: 2026-04-19  |  审计后补充文件头与错误处理
#
"""
多视图一致性对抗检测器——检测图级对抗性结构扰动。

核心假设: 对抗性图扰动破坏视图间联合一致性。CFG边翻转主要影响
结构视图，对语义/序列视图的影响非线性且不完全耦合。
此非对称影响在JS散度上产生可检测信号。

三视图: 结构(边集统计) / 语义(指令直方图) / 序列(随机游走)
防御纵深: Certifier(前摄认证) + Detector(反应拦截)
"""

import math
import hashlib
import random as _random
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable
from collections import Counter

_log = logging.getLogger(__name__)


@dataclass
class GraphView:
    """图的单一视图——从特定角度观察图结构"""
    view_name: str
    feature_vector: List[float] = field(default_factory=list)
    extracted_features: Dict[str, float] = field(default_factory=dict)
    view_signature: str = ""


class MultiViewDecomposer:
    """三视图分解器——结构/语义/序列互补表示。

    每个视图由对应的FeatureExtractor生成（复用graph_binary_embedder）。
    三个视图覆盖不同的不变性属性——对抗扰动难以同时欺骗全部。
    """

    def __init__(self, rng_seed: int = 0):
        self._rng = _random.Random(rng_seed or None)

    def decompose(self, graph,
                   stats_ext=None, insn_ext=None,
                   rw_ext=None) -> List[GraphView]:
        """将函数图分解为[结构, 语义, 序列]视图。

        参数为graph_binary_embedder中的对应提取器实例。
        无提取器时跳过对应视图。
        """
        views = []
        if stats_ext:
            feats = stats_ext.extract(graph)
            views.append(GraphView(
                view_name="structural", feature_vector=list(feats.values()),
                extracted_features=feats,
                view_signature=_sig(feats)))
        if insn_ext:
            feats = insn_ext.extract(graph)
            views.append(GraphView(
                view_name="semantic", feature_vector=list(feats.values()),
                extracted_features=feats,
                view_signature=_sig(feats)))
        if rw_ext:
            feats = rw_ext.extract(graph)
            views.append(GraphView(
                view_name="sequential", feature_vector=list(feats.values()),
                extracted_features=feats,
                view_signature=_sig(feats)))
        return views


def _sig(feats: Dict[str, float], precision: int = 4) -> str:
    """特征字典的紧凑哈希"""
    items = sorted(feats.items())
    payload = '|'.join(f'{k}:{v:.{precision}f}' for k, v in items)
    return hashlib.blake2b(payload.encode(), digest_size=8).hexdigest()


# 分歧度量


def jensen_shannon_divergence(vecs: List[List[float]]) -> float:
    """多向量平均成对JS散度——主分歧指标。

    对每对视图计算JS散度取均值，归一化至[0, 1]。
    JS散度对称且在[0, ln(2)]——适合衡量概率分布差异。
    """
    n = len(vecs)
    if n < 2:
        return 0.0
    total = 0.0
    pairs = 0
    for i in range(n):
        for j in range(i + 1, n):
            total += _pair_jsd(vecs[i], vecs[j])
            pairs += 1
    return min(1.0, total / (pairs * math.log(2))) if pairs else 0.0


def _pair_jsd(p: List[float], q: List[float]) -> float:
    """两向量Jensen-Shannon散度——对称KL散度变体"""
    if len(p) != len(q):
        return float('inf')
    sp = sum(p) or 1.0
    sq = sum(q) or 1.0
    pn = [max(v / sp, 1e-12) for v in p]
    qn = [max(v / sq, 1e-12) for v in q]
    m = [(a + b) / 2 for a, b in zip(pn, qn)]
    return 0.5 * (_kl(pn, m) + _kl(qn, m))


def _kl(p: List[float], q: List[float]) -> float:
    """KL散度 D_KL(p||q)"""
    r = 0.0
    for pi, qi in zip(p, q):
        if pi > 0 and qi > 0:
            r += pi * math.log(pi / qi)
    return max(0.0, r)


def energy_distance(vecs: List[List[float]]) -> float:
    """多向量能量距离——无需归一化的辅助分歧指标。

    Székely & Rizzo: 对零值维度鲁棒，补充JS散度。
    """
    n = len(vecs)
    if n < 2:
        return 0.0
    total = 0.0
    for i in range(n):
        for j in range(i + 1, n):
            total += math.sqrt(sum((x - y) ** 2 for x, y in zip(vecs[i], vecs[j])))
    return total / (n * (n - 1) / 2) if n > 1 else 0.0


# 检测器


@dataclass
class AdversarialDetectionResult:
    """对抗检测结果"""
    is_adversarial: bool
    discord_score: float
    energy_distance: float
    view_count: int
    threshold_used: float
    per_view_pair_discords: Dict[str, float] = field(default_factory=dict)
    detection_method: str = "multi_view_consensus"
    confidence: float = 0.0


class GraphAdversarialDetector:
    """图对抗样本检测器——多视图一致性检验。

    自适应阈值标定:
      在干净样本集上估计JS散度基线分布。
      阈值 = min(μ + 3σ, P95)——兼顾正态假设与长尾鲁棒性。
      标定应与ANVIL v2共形校准并行，共享数据集以降低维护成本。
    """

    def __init__(self, jsd_threshold: float = 0.35,
                  energy_threshold: float = 0.20):
        self._jsd_thresh = jsd_threshold
        self._energy_thresh = energy_threshold
        self._decomposer = MultiViewDecomposer()
        self._clean_jsd: List[float] = []
        self._calibrated: Optional[float] = None

    def detect(self, graph, stats_ext=None, insn_ext=None,
               rw_ext=None) -> AdversarialDetectionResult:
        """对输入函数图执行对抗性检测。

        返回AdversarialDetectionResult含判决、分歧分数及置信度。
        """
        views = self._decomposer.decompose(graph, stats_ext, insn_ext, rw_ext)
        if len(views) < 2:
            return AdversarialDetectionResult(
                is_adversarial=False, discord_score=0.0,
                energy_distance=0.0, view_count=len(views),
                threshold_used=self._jsd_thresh,
                detection_method="insufficient_views")

        vecs = [v.feature_vector for v in views]
        jsd = jensen_shannon_divergence(vecs)
        energy = energy_distance(vecs)

        pair_discords = {}
        names = [v.view_name for v in views]
        for i in range(len(vecs)):
            for j in range(i + 1, len(vecs)):
                pair_discords[f"{names[i]}_vs_{names[j]}"] = round(
                    _pair_jsd(vecs[i], vecs[j]), 4)

        threshold = self._calibrated if self._calibrated is not None else self._jsd_thresh
        is_adv = jsd > threshold or energy > self._energy_thresh

        if is_adv:
            conf = min(1.0, (jsd - threshold) / max(1.0 - threshold, 0.01) + 0.5)
        else:
            conf = min(1.0, (threshold - jsd) / max(threshold, 0.01) + 0.5)

        return AdversarialDetectionResult(
            is_adversarial=is_adv, discord_score=round(jsd, 4),
            energy_distance=round(energy, 4), view_count=len(views),
            threshold_used=threshold, per_view_pair_discords=pair_discords,
            confidence=round(conf, 4))

    def calibrate(self, clean_graphs: List,
                   stats_ext=None, insn_ext=None, rw_ext=None,
                   sigma_mult: float = 3.0):
        """在干净样本上标定自适应阈值——μ + kσ vs P95取保守值。

        需≥10个样本，否则保持默认阈值。
        """
        if len(clean_graphs) < 10:
            _log.warning("标定样本不足(%d)——保持默认阈值", len(clean_graphs))
            return
        jsd_vals = []
        for g in clean_graphs:
            r = self.detect(g, stats_ext, insn_ext, rw_ext)
            jsd_vals.append(r.discord_score)

        mu = sum(jsd_vals) / len(jsd_vals)
        sigma = math.sqrt(sum((x - mu) ** 2 for x in jsd_vals) / max(len(jsd_vals) - 1, 1))
        p95 = sorted(jsd_vals)[int(len(jsd_vals) * 0.95)]
        sigma_based = mu + sigma_mult * sigma

        self._calibrated = min(sigma_based, p95)
        self._clean_jsd = jsd_vals
        _log.info("对抗检测阈值标定: μ=%.4f σ=%.4f σ-based=%.4f p95=%.4f → %.4f",
                   mu, sigma, sigma_based, p95, self._calibrated)

    def get_threshold_info(self) -> Dict:
        """阈值标定信息——审计/调试"""
        info = {'default_jsd': self._jsd_thresh,
                'calibrated': self._calibrated,
                'energy': self._energy_thresh,
                'n_cal_samples': len(self._clean_jsd)}
        if self._clean_jsd:
            info['clean_mean'] = sum(self._clean_jsd) / len(self._clean_jsd)
            info['clean_max'] = max(self._clean_jsd)
        return info


# 联合防御管线


@dataclass
class RobustPrediction:
    """联合认证+检测防御输出"""
    certified_radius: float = 0.0
    certification_confidence: float = 0.999
    certification_abstain: bool = False
    is_adversarial: bool = False
    adversarial_confidence: float = 0.0
    discord_score: float = 0.0
    accepted: bool = False
    rejection_reason: str = ""


def robust_predict(certified, detection, require_cert: bool = False) -> RobustPrediction:
    """联合认证+检测——防御纵深判定。

    决策逻辑:
      certification_abstain + require_cert → 拒绝
      is_adversarial                      → 拒绝
      均通过                              → 接受
    """
    accepted = True
    reason = "none"
    if certified.abstain and require_cert:
        accepted = False
        reason = "certification_abstain"
    elif detection.is_adversarial:
        accepted = False
        reason = "adversarial"
    elif certified.abstain:
        reason = "certification_abstain_soft"
    return RobustPrediction(
        certified_radius=certified.certified_radius,
        certification_confidence=certified.confidence_level,
        certification_abstain=certified.abstain,
        is_adversarial=detection.is_adversarial,
        adversarial_confidence=detection.confidence,
        discord_score=detection.discord_score,
        accepted=accepted, rejection_reason=reason)


__all__ = [
    "GraphView", "MultiViewDecomposer",
    "AdversarialDetectionResult", "GraphAdversarialDetector",
    "jensen_shannon_divergence", "energy_distance",
    "RobustPrediction", "robust_predict",
]
