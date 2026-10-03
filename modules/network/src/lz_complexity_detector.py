# Lempel-Ziv复杂度网络异常检测 —— 序列结构可压缩性分析。
#
# 香农熵检测符号频率异常(DDoS改变IP分布熵), LZ复杂度检测
# 序列结构异常——捕获熵盲区的规律性模式:
# C2信标: 小尺度上IAT序列有重复模式→低LZ复杂度
# DNS隧道: 域名序列的结构规律→低LZ复杂度(基域名重复+子域编码)
# 端口扫描: 端口序列系统递增→LZ复杂度异常低(高度可压缩)
#
# LZ76算法: 从左到右扫描序列, 构建"生产复杂度"C(n):
#   初始化: 字典={S[0]}, C=1, i=1
#   扫描: 寻找S[i:j]是否已在字典中
#     若在: j++
#     若不在: 字典+=S[i:j], C++, i=j
#   归一化: LZC = C(n) / (n/log₂n) ∈ [0,1+ε]
#   随机序列→LZC≈1; 规律序列→LZC≪1
#
# 与香农熵的互补: 熵对符号频率敏感; LZ对序列结构敏感。
# 二者组合可覆盖更广泛的攻击模式。
#
# 未见2024-2025文献涉及LZ复杂度用于网络流量序列异常检测。

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class LzProfile:
    """LZ复杂度剖面"""
    sequence_id: str
    sequence_length: int
    lz_complexity: int          # 原始C(n)
    normalized_lzc: float       # C(n)/(n/log₂n) ∈ [0,1+]
    shannon_entropy: float      # 对比用: 同序列的香农熵
    pattern_score: float        # [0,1] 0=纯随机, 1=高度规律(可疑)
    sample_type: str = ""       # "iat"/"ports"/"domains"/"payloads"


@dataclass
class LzAnomalyAlert:
    """LZ复杂度异常告警"""
    sequence_id: str
    sample_type: str
    normalized_lzc: float
    expected_lzc_range: Tuple[float, float]  # (low, high)
    attack_hypothesis: str     # "c2_beacon"/"dns_tunnel"/"port_scan"/"data_exfil"
    confidence: float          # [0,1]
    evidence: str = ""


class LempelZivComplexity:
    """LZ76复杂度计算器 —— O(n)滑动字典构建。

    归一化: LZC = C(n) / (n / log₂n)。
    随机序列→LZC→1; 完全重复序列(如AAAA)→LZC→(log₂n)/n→0。
    """

    @staticmethod
    def compute(sequence: List[int]) -> float:
        """计算整数序列的归一化LZ复杂度。"""
        n = len(sequence)
        if n < 2:
            return 0.0

        # LZ76: 字典构建
        # 使用字符串键加速子序列查找(对小序列足够快)
        seq_str = [str(x) for x in sequence]
        seen: Set[str] = {seq_str[0]}
        complexity = 1
        i = 1

        while i < n:
            j = i
            current = seq_str[j]
            while j < n and current in seen:
                j += 1
                if j < n:
                    current = ",".join(seq_str[i:j+1])
            complexity += 1
            seen.add(current)
            i = j if j > i else i + 1
            if i >= n:
                break
            seen.add(seq_str[i])
            i += 1

        # 归一化: C(n) / (n / log₂n)
        if n <= 1:
            return 0.0
        expected_random = n / math.log2(n) if n > 1 else 1.0
        return complexity / expected_random

    @staticmethod
    def shannon_entropy(sequence: List[int]) -> float:
        if not sequence:
            return 0.0
        from collections import Counter
        ctr = Counter(sequence)
        n = len(sequence)
        return -sum((v/n) * math.log2(v/n) for v in ctr.values())


class LzAnomalyDetector:
    """LZ复杂度异常检测器。

    对不同类型的序列(IAT/端口/域名/载荷)维护LZC基线,
    检测显著偏离(下降>2σ→规律性异常)。
    """

    def __init__(self, anomaly_sigma: float = 2.0,
                 min_sequence_length: int = 30):
        self._anomaly_sigma = anomaly_sigma
        self._min_len = min_sequence_length
        # EWMA基线: 每种sample_type的(mean_lzc, var_lzc)
        self._baseline: Dict[str, Tuple[float, float, int]] = {}
        # (ewma_mean, ewma_var, count)
        self._alpha = 0.1
        self._alerts: List[LzAnomalyAlert] = []

    def analyze_sequence(self, seq_id: str, sample_type: str,
                          values: List[int]) -> Optional[LzAnomalyAlert]:
        """分析单条序列, 返回异常告警或None。"""
        n = len(values)
        if n < self._min_len:
            return None

        lzc_norm = LempelZivComplexity.compute(values)
        entropy = LempelZivComplexity.shannon_entropy(values)

        # 模式得分: LZC越低→越规律→越可疑
        pattern_score = max(0.0, 1.0 - lzc_norm)

        profile = LzProfile(
            sequence_id=seq_id, sequence_length=n,
            lz_complexity=0,  # 原始C(n)不存储
            normalized_lzc=round(lzc_norm, 4),
            shannon_entropy=round(entropy, 4),
            pattern_score=round(pattern_score, 3),
            sample_type=sample_type,
        )

        # 基线对比
        if sample_type not in self._baseline:
            self._baseline[sample_type] = (lzc_norm, 0.01, 1)
            return None

        ewma_mean, ewma_var, count = self._baseline[sample_type]
        new_mean = self._alpha * lzc_norm + (1 - self._alpha) * ewma_mean
        new_var = (self._alpha * (lzc_norm - new_mean) ** 2 +
                   (1 - self._alpha) * ewma_var)
        self._baseline[sample_type] = (new_mean, new_var, count + 1)

        sigma = math.sqrt(max(new_var, 1e-6))
        if sigma < 1e-6:
            return None
        z_score = (lzc_norm - new_mean) / sigma

        # LZ复杂度显著低于基线→序列过于规律→异常
        if z_score < -self._anomaly_sigma:
            return self._build_alert(seq_id, sample_type, profile, z_score)

        return None

    def _build_alert(self, seq_id: str, sample_type: str,
                      profile: LzProfile, z_score: float
                      ) -> LzAnomalyAlert:
        # 推断攻击类型
        if sample_type == "iat" and profile.normalized_lzc < 0.4:
            attack = "c2_beacon"
            conf = min(1.0, (0.6 - profile.normalized_lzc) * 2.5)
        elif sample_type == "domains" and profile.normalized_lzc < 0.3:
            attack = "dns_tunnel"
            conf = min(1.0, (0.5 - profile.normalized_lzc) * 3.0)
        elif sample_type == "ports" and profile.normalized_lzc < 0.3:
            attack = "port_scan"
            conf = min(1.0, (0.5 - profile.normalized_lzc) * 3.0)
        else:
            attack = "unknown_pattern"
            conf = min(abs(z_score) / 5.0, 1.0)

        ewma_mean = self._baseline[sample_type][0]
        return LzAnomalyAlert(
            sequence_id=seq_id,
            sample_type=sample_type,
            normalized_lzc=profile.normalized_lzc,
            expected_lzc_range=(round(ewma_mean - 2*math.sqrt(
                self._baseline[sample_type][1]), 3),
                               round(ewma_mean + 2*math.sqrt(
                self._baseline[sample_type][1]), 3)),
            attack_hypothesis=attack,
            confidence=round(conf, 3),
            evidence=(f"LZC={profile.normalized_lzc:.3f} (基线"
                     f"{ewma_mean:.3f}), z={z_score:.1f}, "
                     f"香农熵={profile.shannon_entropy:.3f}"),
        )

    def summary(self) -> Dict[str, Any]:
        return {
            "total_alerts": len(self._alerts),
            "by_type": defaultdict(int, **{
                t: sum(1 for a in self._alerts if a.attack_hypothesis == t)
                for t in set(a.attack_hypothesis for a in self._alerts)}),
            "mean_confidence": (sum(a.confidence for a in self._alerts) /
                               max(len(self._alerts), 1)),
        }


def detect_lz_anomaly(values: List[int], sample_type: str = "iat",
                       seq_id: str = "seq_0") -> Optional[LzAnomalyAlert]:
    """便捷入口: 序列→LZ复杂度→异常检测。"""
    detector = LzAnomalyDetector()
    return detector.analyze_sequence(seq_id, sample_type, values)


__all__ = [
    "LzProfile", "LzAnomalyAlert", "LempelZivComplexity",
    "LzAnomalyDetector", "detect_lz_anomaly",
]
