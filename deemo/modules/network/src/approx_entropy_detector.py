# 创建: 2026-08-08  修改: 2026-08-14 (增加Cross-ApEn互近似熵, 从自可预测性升级为跨序列模式匹配)
# 近似熵+互近似熵网络异常检测 —— 自可预测性+跨序列同步性量化。
#
# 香农熵(LZ复杂度)检测符号频率(序列结构)异常，
# 近似熵检测序列的可预测性——"过去值在多大程度上预测未来值"。
#
# ApEn(m,r,N): 对长度为N的序列, 嵌入维度m, 容忍度r,
# 计算两个在m维相近的子序列在m+1维也相近的条件概率的负对数。
# ApEn ∈ [0, ~2.5]: 低值=规律可预测(C2信标/心跳), 高值=随机。
#
# 与香农熵/LZ复杂度的互补:
#   - 香农熵: 符号频率分布(IP/端口DDoS检测)
#   - LZ复杂度: 序列结构冗余(扫描模式/隧道)
#   - ApEn: 时序可预测性(信标/心跳/定时任务)
#
# ApEn对短序列(N=50-500)的偏差比样本熵(SampEn)大,
# 但对信标检测的灵敏度反而更高——偏差本身放大了规律性信号。
#
# 未见2024-2025文献涉及ApEn用于网络流量异常检测。

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ApEnProfile:
    """单序列的ApEn剖面"""
    sequence_id: str
    approx_entropy: float
    sample_count: int
    embed_dim: int          # m
    tolerance: float        # r
    predictability: float   # [0,1] 1-ApEn/max_ApEn, 1=高度可预测
    sample_type: str = ""


@dataclass
class ApEnAlert:
    """ApEn异常告警"""
    sequence_id: str
    sample_type: str
    approx_entropy: float
    baseline_apen: float
    deviation_sigma: float
    attack_hypothesis: str  # "c2_beacon"/"heartbeat"/"scheduled_task"
    confidence: float
    evidence: str = ""


def approximate_entropy(sequence: List[float], m: int = 2,
                         r_factor: float = 0.2) -> float:
    """计算序列的近似熵。

    m: 嵌入维度(通常2-3)
    r_factor: 容忍度因子, r = r_factor × std(sequence)

    算法复杂度O(N²), 对N≤500的流量序列窗口可行。
    对更大序列使用分窗或下采样。
    """
    n = len(sequence)
    if n < m + 2:
        return 0.0

    # 容忍度r = r_factor × 序列标准差
    mean_s = sum(sequence) / n
    std_s = math.sqrt(sum((x - mean_s) ** 2 for x in sequence) / n)
    r = r_factor * std_s if std_s > 1e-9 else r_factor * 0.01

    # 计算C_i^m(r): 在r内与模板i匹配的模板数比例
    def _phi(dim: int) -> float:
        count = 0
        for i in range(n - dim + 1):
            # 对模板i, 计数在容差r内匹配的模板j
            matches = 0
            for j in range(n - dim + 1):
                if i == j:
                    continue
                # Chebyshev距离(max|·|)
                dist_ok = True
                for k in range(dim):
                    if abs(sequence[i + k] - sequence[j + k]) > r:
                        dist_ok = False
                        break
                if dist_ok:
                    matches += 1
            if matches > 0:
                count += math.log(matches / max(n - dim, 1))
        return count / max(n - dim + 1, 1)

    phi_m = _phi(m)
    phi_m1 = _phi(m + 1)

    return phi_m - phi_m1


def cross_approximate_entropy(seq_a: List[float], seq_b: List[float],
                                m: int = 2, r_factor: float = 0.2) -> float:
    """互近似熵 Cross-ApEn(A,B): 用A的模板在容差r内匹配B的子序列。

    与ApEn(A,A)(自可预测性)不同, Cross-ApEn(A,B)量化"A的模式在B中
    出现的程度"——即两个序列的同步性/模式共享度。
    低Cross-ApEn→两序列高度同步(信标模板与实际IAT匹配)。
    高Cross-ApEn→两序列模式不共享(随机流量与预期信标无关)。

    应用于C2检测: 构造合成周期信标模板B_beacon=
    [ε,ε,...,T,ε,ε,...,T,...] (周期T处放置大IAT, 其余为小抖动)。
    计算Cross-ApEn(IAT_actual, B_beacon):
      低值→实际IAT与信标模板高度同步→C2信标。
      高值→实际IAT与信标模式无关→正常流量。

    复杂度O(N²), 与ApEn相同。对N≤500可行。
    """
    na, nb = len(seq_a), len(seq_b)
    n = min(na, nb)
    if n < m + 2:
        return 2.0  # 高值=不相似

    # 用seq_a的标准差设置容差
    mean_a = sum(seq_a[:n]) / n
    std_a = math.sqrt(sum((x - mean_a) ** 2 for x in seq_a[:n]) / n)
    r = r_factor * std_a if std_a > 1e-9 else r_factor * 0.01

    def _cross_phi(dim: int) -> float:
        count = 0
        valid_templates = 0
        for i in range(n - dim + 1):
            matches = 0
            for j in range(n - dim + 1):
                dist_ok = True
                for k in range(dim):
                    if abs(seq_a[i + k] - seq_b[j + k]) > r:
                        dist_ok = False
                        break
                if dist_ok:
                    matches += 1
            if matches > 0:
                count += math.log(matches / max(n - dim, 1))
                valid_templates += 1
        return count / max(valid_templates, 1) if valid_templates > 0 else 0.0

    phi_m = _cross_phi(m)
    phi_m1 = _cross_phi(m + 1)
    cross_apen = phi_m - phi_m1

    return max(0.0, cross_apen)


def generate_beacon_template(n: int, period: int,
                               burst_len: int = 3,
                               burst_iat: float = 0.01,
                               gap_iat: float = 1.0) -> List[float]:
    """生成合成周期信标模板序列。

    period: 信标间隔(包数)
    burst_len: 突发长度(连续短IAT数)
    burst_iat: 突发内IAT
    gap_iat: 突发间长IAT
    """
    template = []
    for i in range(n):
        pos_in_cycle = i % period
        if pos_in_cycle < burst_len:
            template.append(burst_iat)
        else:
            template.append(gap_iat)
    return template


class ApEnAnomalyDetector:
    """ApEn异常检测器 —— EWMA基线+σ偏差告警。

    对每种序列类型(iat/ports/sizes)维护ApEn基线,
    低ApEn(高规律性)→C2信标/心跳/定时任务告警。
    """

    def __init__(self, anomaly_sigma: float = 2.0,
                 min_seq_len: int = 30,
                 ewma_alpha: float = 0.1):
        self._sigma = anomaly_sigma
        self._min_len = min_seq_len
        self._alpha = ewma_alpha
        self._baseline: Dict[str, Tuple[float, float, int]] = {}
        self._alerts: List[ApEnAlert] = []

    def analyze(self, seq_id: str, sample_type: str,
                values: List[float], m: int = 2
                ) -> Optional[ApEnAlert]:
        n = len(values)
        if n < self._min_len:
            return None

        apen = approximate_entropy(values, m=m)
        predictability = max(0.0, 1.0 - apen / 2.5)

        profile = ApEnProfile(
            sequence_id=seq_id, approx_entropy=round(apen, 5),
            sample_count=n, embed_dim=m, tolerance=0.2,
            predictability=round(predictability, 3),
            sample_type=sample_type,
        )

        # 基线初始化
        if sample_type not in self._baseline:
            self._baseline[sample_type] = (apen, 0.01, 1)
            return None

        em, ev, cnt = self._baseline[sample_type]
        new_em = self._alpha * apen + (1 - self._alpha) * em
        new_ev = (self._alpha * (apen - new_em) ** 2 +
                  (1 - self._alpha) * ev)
        self._baseline[sample_type] = (new_em, new_ev, cnt + 1)

        sigma = math.sqrt(max(new_ev, 1e-8))
        z = (apen - new_em) / sigma if sigma > 0 else 0.0

        # 低ApEn(高可预测性)→异常
        if z < -self._sigma:
            if apen < 0.3:
                attack, conf = "c2_beacon", min(1.0, (0.3 - apen) * 5.0)
            elif apen < 0.6:
                attack, conf = "heartbeat", min(1.0, (0.6 - apen) * 3.0)
            else:
                attack, conf = "scheduled_task", min(abs(z) / 5.0, 1.0)

            # Cross-ApEn增强: 对疑似信标用合成信标模板做模式匹配确认
            if sample_type == "iat" and attack == "c2_beacon" and n >= 30:
                for period in [5, 10, 20, 30, 60]:  # 常见C2信标间隔
                    template = generate_beacon_template(n, period)
                    x_apen = cross_approximate_entropy(values, template, m=m)
                    if x_apen < 0.5:  # 与信标模板高度同步
                        conf = max(conf, min(1.0, (0.5 - x_apen) * 3.0 + 0.5))
                        attack = "c2_beacon"
                        evidence_prefix = f"Cross-ApEn={x_apen:.4f}(period={period}) "
                        break
                else:
                    evidence_prefix = ""
            else:
                evidence_prefix = ""

            alert = ApEnAlert(
                sequence_id=seq_id, sample_type=sample_type,
                approx_entropy=round(apen, 5),
                baseline_apen=round(new_em, 5),
                deviation_sigma=round(abs(z), 2),
                attack_hypothesis=attack,
                confidence=round(conf, 3),
                evidence=(evidence_prefix +
                         f"ApEn={apen:.4f}(基线{new_em:.4f}), "
                         f"z={z:.1f}, 可预测性={predictability:.2f}"),
            )
            self._alerts.append(alert)
            return alert

        return None

    def summary(self) -> Dict[str, Any]:
        return {
            "total_alerts": len(self._alerts),
            "by_type": {t: sum(1 for a in self._alerts if a.attack_hypothesis == t)
                       for t in set(a.attack_hypothesis for a in self._alerts)},
        }


def detect_apen_anomaly(values: List[float], sample_type: str = "iat",
                         seq_id: str = "s0") -> Optional[ApEnAlert]:
    return ApEnAnomalyDetector().analyze(seq_id, sample_type, values)


__all__ = [
    "ApEnProfile", "ApEnAlert", "approximate_entropy",
    "cross_approximate_entropy", "generate_beacon_template",
    "ApEnAnomalyDetector", "detect_apen_anomaly",
]
