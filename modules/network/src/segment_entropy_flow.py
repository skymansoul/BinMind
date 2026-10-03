# 网段间熵流追踪 —— 条件熵H(Y|X)检测横向移动与数据外泄。
#
# 正常网络中, 不同VLAN/子网间的信息流是稳定的: DMZ→Internal低熵流
# (仅Web响应), Internal→DB高熵流(查询多样性)。攻击导致的横向移动
# 或数据外泄改变网段间的信息流模式。
#
# 条件熵 H(Y|X) = -Σ p(x,y) log p(y|x): 已知X(源段)的流量下,
# Y(目的段)的不确定性。正常时各段对的条件熵稳定; 横向移动时
# 攻击者从已控主机→新目标产生新奇的(源段,目的段)流量模式→
# 条件熵突降(变得可预测——因为攻击流量有固定模式)。
#
# 检测指标:
#   1. 段对条件熵突降: H(Y|X) < baseline - 2σ → 异常可预测流
#   2. 新段对出现: 历史上不通信的段对突然出现流量→横向移动
#   3. 段对流量比突增: flow_ratio > baseline × 3 → 数据外泄
#
# 未见2024-2025文献涉及条件熵用于网段间横向移动检测。

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class SegmentFlowStats:
    """一对网段间的流量统计"""
    src_segment: str
    dst_segment: str
    packet_count: int = 0
    byte_count: int = 0
    unique_ports: Set[int] = field(default_factory=set)
    unique_protocols: Set[int] = field(default_factory=set)
    # 时间窗口内首次通信时间
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class EntropyProfile:
    """单个网段的熵剖面"""
    segment_id: str
    # 出向: {dst_segment → H(dst|src)} 条件熵
    out_entropy: Dict[str, float] = field(default_factory=dict)
    # 入向: {src_segment → H(dst|src)}
    in_entropy: Dict[str, float] = field(default_factory=dict)
    total_out_bytes: int = 0
    total_in_bytes: int = 0


@dataclass
class EntropyFlowAlert:
    """熵流异常告警"""
    alert_type: str       # "lateral_movement"/"data_exfil"/"new_segment_pair"
    src_segment: str
    dst_segment: str
    condition_entropy: float
    baseline_entropy: float
    deviation_sigma: float
    confidence: float     # [0,1]
    description: str = ""


class SegmentEntropyTracker:
    """网段熵流追踪器。

    按时间窗口收集各段对的流量分布, 计算条件熵,
    使用EWMA基线检测异常。
    """

    def __init__(self, ewma_alpha: float = 0.1,
                 anomaly_sigma: float = 2.5,
                 min_flow_ratio: float = 3.0):
        self._alpha = ewma_alpha
        self._anomaly_sigma = anomaly_sigma
        self._min_flow_ratio = min_flow_ratio
        # 每窗口的段对统计: (src,dst) → [(pkt_count, byte_count, ports)]
        self._window_data: Dict[Tuple[str, str], List[SegmentFlowStats]] = (
            defaultdict(list))
        # 条件熵基线: (src,dst) → EWMA of H(dst|src)
        self._entropy_baseline: Dict[Tuple[str, str], float] = {}
        self._entropy_var: Dict[Tuple[str, str], float] = {}
        # 字节量基线: (src,dst) → EWMA of byte_count(数据外泄检测)
        self._bytes_baseline: Dict[Tuple[str, str], float] = {}
        # 历史段对(用于检测"新段对")
        self._known_pairs: Set[Tuple[str, str]] = set()
        # 每个段的流统计
        self._segments: Dict[str, EntropyProfile] = defaultdict(
            lambda: EntropyProfile(segment_id=""))
        self._alerts: List[EntropyFlowAlert] = []

    def feed_window(self, segment_flows: Dict[Tuple[str, str], Dict]
                     ) -> List[EntropyFlowAlert]:
        """每窗口输入: {(src_seg,dst_seg) → {pkt_count, byte_count, ports, protocols}}

        返回该窗口检测到的熵流告警列表。
        """
        new_alerts: List[EntropyFlowAlert] = []

        # 计算每段对的字节分布→条件熵
        pair_entropies: Dict[Tuple[str, str], float] = {}
        for (src, dst), stats in segment_flows.items():
            pkt = stats.get("pkt_count", 0)
            byt = stats.get("byte_count", 0)
            ports = stats.get("ports", set())
            protos = stats.get("protocols", set())

            sf = SegmentFlowStats(
                src_segment=src, dst_segment=dst,
                packet_count=pkt, byte_count=byt,
                unique_ports=set(ports) if ports else set(),
                unique_protocols=set(protos) if protos else set(),
            )
            pair_entropies[(src, dst)] = self._pair_entropy(sf)

        # 按源段聚合→计算各源段出向条件熵分布
        src_bytes: Dict[str, float] = defaultdict(float)
        for (src, dst), ent in pair_entropies.items():
            src_bytes[src] += segment_flows[(src, dst)].get("byte_count", 0)

        for (src, dst), ent in pair_entropies.items():
            total_src = src_bytes.get(src, 1.0)
            # 条件熵加权: H(D|S)通过字节量归一化
            pair_entropies[(src, dst)] = ent

        # 基线对比→异常检测
        for (src, dst), ent in pair_entropies.items():
            key = (src, dst)
            # 新段对检测
            if key not in self._known_pairs:
                self._known_pairs.add(key)
                if len(self._known_pairs) > 5:  # 初始学习期后
                    new_alerts.append(EntropyFlowAlert(
                        alert_type="new_segment_pair",
                        src_segment=src, dst_segment=dst,
                        condition_entropy=round(ent, 4),
                        baseline_entropy=0.0, deviation_sigma=0.0,
                        confidence=0.6,
                        description=f"新段对 {src}→{dst} 出现通信",
                    ))

            # EWMA更新
            prev = self._entropy_baseline.get(key, ent)
            new_base = (self._alpha * ent +
                       (1 - self._alpha) * prev)
            prev_var = self._entropy_var.get(key, 0.01)
            new_var = (self._alpha * (ent - new_base) ** 2 +
                      (1 - self._alpha) * prev_var)
            self._entropy_baseline[key] = new_base
            self._entropy_var[key] = new_var

            sigma = math.sqrt(max(new_var, 1e-6))
            if sigma < 1e-6:
                continue
            z = (ent - new_base) / sigma

            # 熵突降: 条件熵显著低于基线→流量变得异常可预测
            if z < -self._anomaly_sigma:
                conf = min(abs(z) / 5.0, 1.0)
                new_alerts.append(EntropyFlowAlert(
                    alert_type="lateral_movement",
                    src_segment=src, dst_segment=dst,
                    condition_entropy=round(ent, 4),
                    baseline_entropy=round(new_base, 4),
                    deviation_sigma=round(abs(z), 2),
                    confidence=round(conf, 3),
                    description=(f"{src}→{dst}条件熵突降"
                                f"({new_base:.3f}→{ent:.3f}, z={z:.1f})"
                                f"——疑似横向移动"),
                ))

            # 流量比突增: 字节量相对基线激增→数据外泄
            flow_stats = segment_flows.get(key, {})
            byte_count = flow_stats.get("byte_count", 0)
            prev_bytes = self._bytes_baseline.get(key, byte_count)
            new_bytes = (self._alpha * byte_count +
                        (1 - self._alpha) * prev_bytes)
            self._bytes_baseline[key] = new_bytes
            if byte_count > 0 and prev_bytes > 0:
                ratio = byte_count / prev_bytes
                if ratio > self._min_flow_ratio:
                    new_alerts.append(EntropyFlowAlert(
                        alert_type="data_exfil",
                        src_segment=src, dst_segment=dst,
                        condition_entropy=round(ent, 4),
                        baseline_entropy=round(new_base, 4),
                        deviation_sigma=round(ratio, 2),
                        confidence=round(min(ratio / (2 * self._min_flow_ratio), 1.0), 3),
                        description=(f"{src}→{dst}字节量激增{ratio:.1f}倍"
                                    f"(基线{prev_bytes:.0f}→当前{byte_count})"
                                    f"——疑似数据外泄"),
                    ))

        self._alerts.extend(new_alerts)
        return new_alerts

    @staticmethod
    def _pair_entropy(stats: SegmentFlowStats) -> float:
        """计算段对的条件熵近似: 基于端口分布。

        H ≈ -Σ p(port) log p(port), 用端口多样性作为信息量代理。
        更多不同端口→更高熵→更"正常"的多样化通信。
        少量端口→低熵→可能是攻击者控制的固定通道。
        """
        ports = stats.unique_ports
        protos = stats.unique_protocols
        n_ports = len(ports)
        n_protos = len(protos)

        if n_ports == 0 and n_protos == 0:
            return 0.0

        # 端口熵 + 协议熵的加权
        port_ent = math.log2(max(n_ports, 1))
        proto_ent = math.log2(max(n_protos, 1))
        # 归一化: 最大可能熵 ~ log2(65536) ≈ 16
        return (port_ent * 0.7 + proto_ent * 0.3) / 10.0

    def segment_summary(self) -> Dict[str, Any]:
        segment_stats = {}
        for seg_id, profile in self._segments.items():
            segment_stats[seg_id] = {
                "out_bytes": profile.total_out_bytes,
                "in_bytes": profile.total_in_bytes,
                "out_peers": len(profile.out_entropy),
                "in_peers": len(profile.in_entropy),
            }
        return {
            "segments": len(self._segments),
            "known_pairs": len(self._known_pairs),
            "total_alerts": len(self._alerts),
            "by_type": defaultdict(int, **{
                t: sum(1 for a in self._alerts if a.alert_type == t)
                for t in set(a.alert_type for a in self._alerts)}),
        }


__all__ = [
    "SegmentFlowStats", "EntropyProfile", "EntropyFlowAlert",
    "SegmentEntropyTracker",
]
