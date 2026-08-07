# 漏洞知识图谱时间感知扩展: 时变边权重/对抗鲁棒消息传递/CVE时效排序
# Liao et al. "ATPF: An Adaptive Temporal Perturbation Framework for
#       Adversarial Attacks on Temporal Knowledge Graph"
#       APT-ST-AN: Enhanced Small-Scale APT Knowledge Graph Embedding via
#       Spatio-Temporal Attribute Reasoning
#       Dai et al. "MemFreezing: A Novel Adversarial Attack on Temporal
#       Graph Neural Networks"
# 设计边界:
# 时间衰减仅作用于DEPENDS_ON和CORRELATED边
# AFFECTS/BELONGS_TO边不受时间衰减 (事实关系)
# 对抗扰动仅在消息聚合阶段生效 (训练时注入，推理时关闭)
from __future__ import annotations
import logging
import math
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

from .vuln_knowledge_graph import (
    HeteroGraph, Node, Edge, NodeType, EdgeType,
    VulnerabilityGraphBuilder, CascadePredictor, CWECorrelationFinder,
)

log = logging.getLogger(__name__)

# Weibull衰减: k<1→初期快速衰减后放缓, 适合CVE生命周期 [EPSS v3统计]
_DECAY_LAMBDA = 90.0   # 尺度(天), ~3个月
_DECAY_K = 0.6          # 形状, <1产生重尾
# 对抗扰动幅度上限, 按边类型差异化
_PERTURB_EPSILON = {
    EdgeType.DEPENDS_ON: 0.15,
    EdgeType.CORRELATED: 0.25,
    EdgeType.CALLS: 0.10,
}
# 时间衰减生效的边类型
_TEMPORAL_EDGE_TYPES = {EdgeType.DEPENDS_ON, EdgeType.CORRELATED}


def weibull_decay(age_days: float, lam: float = _DECAY_LAMBDA,
                  k: float = _DECAY_K) -> float:
    """Weibull生存函数: exp(-(t/lambda)^k).
    t=0→1.0; t→∞→0.0.
    k<1时近期衰减比指数更快，符合CVE关注度初期快速下降的观测.
    """
    if age_days <= 0:
        return 1.0
    return math.exp(-((age_days / lam) ** k))


class TemporalEdgeWeight:
    """时间感知边权重: base_weight * temporal_factor + perturbation_noise.
    temporal_factor∈[0,1]由Weibull衰减计算.
    perturbation_noise仅对抗训练模式注入.
    """

    def __init__(self, adversarial: bool = False, seed: int = 20250722):
        self._adversarial = adversarial
        self._rng = random.Random(seed)
        self._perturb_count = 0
        self._now_ref: Optional[float] = None  # 外部注入的当前时间基准

    def set_reference_time(self, timestamp: float):
        """时间基准设置. 不设置则用time.time()."""
        self._now_ref = timestamp

    def set_adversarial(self, enabled: bool):
        self._adversarial = enabled

    def compute(self, base_weight: float, edge_type: str,
                cve_timestamp: Optional[float] = None) -> float:
        """时间衰减后边权重.
        cve_timestamp=None→无时间戳，时间因子默认1.0.
        """
        now = self._now_ref if self._now_ref is not None else time.time()
        if cve_timestamp is not None and edge_type in _TEMPORAL_EDGE_TYPES:
            age_days = (now - cve_timestamp) / 86400.0
            temporal_factor = weibull_decay(max(age_days, 0.0))
        else:
            temporal_factor = 1.0

        weight = base_weight * temporal_factor

        # 对抗扰动: 消息传递训练阶段注入乘性噪声
        if self._adversarial and edge_type in _PERTURB_EPSILON:
            eps = _PERTURB_EPSILON[edge_type]
            noise = self._rng.uniform(1.0 - eps, 1.0 + eps)
            weight *= noise
            self._perturb_count += 1

        return max(weight, 0.001)

    @property
    def perturb_count(self) -> int:
        return self._perturb_count


class TemporalVulnerabilityGraphBuilder(VulnerabilityGraphBuilder):
    """时间感知漏洞图构建器. 继承VulnerabilityGraphBuilder，记录CVE时间戳."""

    def __init__(self):
        super().__init__()
        self._cve_timestamps: Dict[str, float] = {}  # vuln_id→posix timestamp
        self._temporal_weight = TemporalEdgeWeight()

    def ingest_findings_with_time(self, findings: List[Dict],
                                  component_name: str = ""):
        """与ingest_findings相同，但提取CVE发布时间."""
        super().ingest_findings(findings, component_name)
        for f in findings:
            vid = f.get('rule_id') or ''
            pub = f.get('published_date') or f.get('disclosure_date') or ''
            if pub and vid:
                try:
                    ts = self._parse_date_to_timestamp(pub)
                    if ts:
                        self._cve_timestamps[vid] = ts
                except (ValueError, OverflowError):
                    pass

    @staticmethod
    def _parse_date_to_timestamp(date_str: str) -> Optional[float]:
        """日期解析: ISO 8601/YYYY-MM-DD/YYYY-MM-DDTHH:MM:SS.
        仅使用标准库time模块.
        """
        import time as _time_module
        clean = date_str.strip().replace('Z', '+00:00')
        patterns = [
            '%Y-%m-%dT%H:%M:%S%z',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d',
        ]
        for fmt in patterns:
            try:
                parsed = _time_module.strptime(clean, fmt)
                return _time_module.mktime(parsed)
            except (ValueError, OverflowError):
                continue
        return None

    def get_temporal_weight(self,
                            base_weight: float,
                            edge_type: str,
                            vuln_id: str = "") -> float:
        cve_ts = self._cve_timestamps.get(vuln_id)
        return self._temporal_weight.compute(base_weight, edge_type, cve_ts)

    def set_adversarial_mode(self, enabled: bool):
        self._temporal_weight.set_adversarial(enabled)

    @property
    def cve_timestamps(self) -> Dict[str, float]:
        return dict(self._cve_timestamps)


class TemporalCascadePredictor(CascadePredictor):
    """时间感知级联预测器. 路径评分引入时间衰减因子.
    近期漏洞级联风险高于远期.
    """

    def __init__(self, graph: HeteroGraph,
                 cve_timestamps: Optional[Dict[str, float]] = None,
                 temporal_weight: Optional[TemporalEdgeWeight] = None):
        super().__init__(graph)
        self._cve_ts = cve_timestamps or {}
        self._tw = temporal_weight or TemporalEdgeWeight()

    def predict_cascades_temporal(self, seed_vuln: str,
                                  max_hops: int = 3) -> List[Dict]:
        """级联路径预测，边权重经时间衰减.
        路径原始score乘以各边temporal_factor积，包含旧CVE的路径被降权.
        """
        base_results = self.predict_cascades(seed_vuln, max_hops)
        temporal_results = []
        for r in base_results:
            target = r['target']
            ts_seed = self._cve_ts.get(seed_vuln)
            ts_target = self._cve_ts.get(target)
            if ts_seed is not None and ts_target is not None:
                now = time.time()
                age_seed = max(0.0, (now - ts_seed) / 86400.0)
                age_target = max(0.0, (now - ts_target) / 86400.0)
                age = max(age_seed, age_target)
                temporal_factor = weibull_decay(age)
            else:
                temporal_factor = 0.8  # 无时间戳默认略降权

            r_copy = dict(r)
            r_copy['score'] = round(r['score'] * temporal_factor, 4)
            r_copy['temporal_factor'] = round(temporal_factor, 3)
            temporal_results.append(r_copy)

        return sorted(temporal_results, key=lambda x: x['score'], reverse=True)


class TemporalRelevanceRanker:
    """CVE时效相关性排序. 严重度×时效衰减联合建模为当前风险分数."""

    def __init__(self, cve_timestamps: Optional[Dict[str, float]] = None):
        self._cve_ts = cve_timestamps or {}
        self._now = time.time()

    def current_risk_score(self, cve_id: str, cvss_score: float,
                           severity: str = 'medium') -> float:
        """当前风险 = CVSS * time_decay.
        高危近期CVE > 高危远期CVE > 低危近期 > 低危远期.
        """
        ts = self._cve_ts.get(cve_id)
        if ts is not None:
            age_days = max(0.0, (self._now - ts) / 86400.0)
        else:
            sev_age_map = {'critical': 10.0, 'high': 45.0,
                           'medium': 120.0, 'low': 365.0, 'info': 500.0}
            age_days = sev_age_map.get(severity.lower(), 180.0)

        decay = weibull_decay(age_days)
        return cvss_score * decay

    def rank(self, vulns: List[Dict],
             key_id: str = 'cve_id',
             key_cvss: str = 'cvss',
             key_severity: str = 'severity') -> List[Dict]:
        """current_risk_score降序排列漏洞列表."""
        ranked = []
        for v in vulns:
            vid = v.get(key_id, '')
            cvss = float(v.get(key_cvss, 5.0))
            sev = str(v.get(key_severity, 'medium'))
            score = self.current_risk_score(vid, cvss, sev)
            entry = dict(v)
            entry['temporal_risk_score'] = round(score, 2)
            ranked.append(entry)
        return sorted(ranked, key=lambda x: x['temporal_risk_score'], reverse=True)


__all__ = [
    'weibull_decay', 'TemporalEdgeWeight',
    'TemporalVulnerabilityGraphBuilder', 'TemporalCascadePredictor',
    'TemporalRelevanceRanker',
]
