# 自适应协议感知流量重放引擎 —— 状态追踪+语义分歧检测+自适应调速。
#
# 现有traffic_replayer是静态重放: 按序发包, 字节级比较响应。
# 两个关键缺陷:
#   1. 无状态感知: 若目标跳过协议状态(如TLS握手未完成即收到数据),
#      响应异常被简单归类为"响应差异", 无法推断根因。
#   2. 无自适应调速: 固定速率重放在目标过载时产生误报超时,
#      在目标快速恢复时遗漏窗口期漏洞。
#
# 本模块三重增强:
#   1. 协议状态追踪: 维护轻量协议状态模型, 追踪预期状态转移,
#      检测目标状态偏离。
#   2. 语义分歧评分: 区分"预期响应差异"(版本号/timestamp)和
#      "语义级分歧"(状态码跳变/字段消失/结构改变)。
#   3. 自适应调速: 基于目标响应延迟的EWMA估计动态调整发包速率,
#      在保持压力与避免超时误报间平衡。
#
# 与现有工作差异:
# tcpreplay: 纯字节重放, 无状态感知
# 现有traffic_replayer: 字节级diff, 固定速率
# 未见2024-2025文献涉及自适应协议感知+语义分歧的流量重放方向

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


from .protocol_state_tracker import ProtoState, ProtocolStateTracker


@dataclass
class ReplayState:
    """单次重放会话的状态追踪"""
    protocol: str
    current_state: ProtoState = ProtoState.INIT
    state_history: List[Tuple[float, ProtoState]] = field(default_factory=list)
    packets_sent: int = 0
    responses_received: int = 0
    anomalies_detected: int = 0
    # EWMA响应延迟估计
    ewma_latency: float = 0.05   # 初始估计50ms
    ewma_alpha: float = 0.2


@dataclass
class DivergenceRecord:
    """语义分歧记录"""
    packet_index: int
    expected_state: ProtoState
    observed_behavior: str       # 响应特征描述
    divergence_type: str         # "state_skip"/"unexpected_response"/"protocol_violation"/"timeout"
    severity: float              # [0,1]
    detail: str = ""


@dataclass
class AdaptiveReplayReport:
    """自适应重放完整报告"""
    session_id: str
    protocol: str
    packets_sent: int
    responses_received: int
    state_coverage: float        # 状态覆盖率 = 访问状态数/协议状态总数
    divergences: List[DivergenceRecord]
    state_path: List[Tuple[float, str]]  # [(timestamp, state_name)]
    vulnerability_score: float   # [0,1] 综合漏洞评分
    recommendation: str = ""


class AdaptiveReplayEngine:
    """自适应重放引擎。

    核心循环: 取包→发送→接收响应→分类→状态转移→分歧检测→调速。
    状态追踪和调速均不影响发包内容, 仅影响观测和调度。
    """

    def __init__(self, protocol: str = "TCP",
                 initial_pacing_ms: float = 10.0,
                 min_pacing_ms: float = 1.0,
                 max_pacing_ms: float = 500.0):
        self._tracker = ProtocolStateTracker(protocol)
        self._pacing = initial_pacing_ms
        self._pacing_min = min_pacing_ms
        self._pacing_max = max_pacing_ms
        self._latency_ewma = 0.05
        self._latency_alpha = 0.2
        self._divergences: List[DivergenceRecord] = []
        self._packets_sent = 0
        self._responses_received = 0
        self._send_fn: Optional[Callable[[bytes], Optional[bytes]]] = None
        self._session_id = ""

    def set_send_function(self, fn: Callable[[bytes], Optional[bytes]]
                           ) -> None:
        """注入发包函数 —— 解耦网络层与重放逻辑"""
        self._send_fn = fn

    @property
    def pacing_ms(self) -> float:
        return self._pacing

    @property
    def divergences(self) -> List[DivergenceRecord]:
        return list(self._divergences)

    def replay_packet(self, payload: bytes,
                       packet_index: int = 0) -> Optional[bytes]:
        """重放单个包: 发送→接收→状态追踪→分歧检测。

        返回目标响应字节(或None表示无响应)。
        同时更新延迟EWMA和自适应调速。
        """
        if self._send_fn is None:
            return None

        self._packets_sent += 1
        t0 = time.time()

        # 协议状态过渡: 发包自身可能触发状态转移
        if self._tracker.current_state == ProtoState.INIT:
            self._tracker.transition("request_sent")

        # 执行发送+接收
        try:
            response = self._send_fn(payload)
        except Exception as e:
            self._divergences.append(DivergenceRecord(
                packet_index=packet_index,
                expected_state=self._tracker.current_state,
                observed_behavior="send_error",
                divergence_type="protocol_violation",
                severity=1.0,
                detail=str(e),
            ))
            return None

        dt = time.time() - t0
        if dt > 0:
            self._latency_ewma = (
                (1 - self._latency_alpha) * self._latency_ewma +
                self._latency_alpha * dt
            )

        if response is not None:
            self._responses_received += 1
            label = self._tracker.classify_response(response, payload)
            ok, anomaly = self._tracker.transition(label)

            if not ok:
                self._divergences.append(DivergenceRecord(
                    packet_index=packet_index,
                    expected_state=self._tracker.current_state,
                    observed_behavior=label,
                    divergence_type="state_skip",
                    severity=0.8,
                    detail=anomaly or "",
                ))

            # 自适应调速: 延迟低→加速, 延迟高→减速
            # 目标延迟 = pacing_ms的一半, 使系统在响应性和稳定性间平衡
            target_latency = self._pacing / 2000.0  # ms→s, 取半
            if self._latency_ewma < target_latency * 0.5:
                # 目标响应很快 → 加速发包
                self._pacing = max(self._pacing_min,
                                   self._pacing * 0.85)
            elif self._latency_ewma > target_latency * 2.0:
                # 目标响应慢 → 减速发包, 避免超时误报
                self._pacing = min(self._pacing_max,
                                   self._pacing * 1.2)
        else:
            # 无响应: 记录超时分歧
            self._divergences.append(DivergenceRecord(
                packet_index=packet_index,
                expected_state=self._tracker.current_state,
                observed_behavior="no_response",
                divergence_type="timeout",
                severity=0.6,
                detail=f"发包{packet_index}后{dl:.2f}s无响应",
            ))
            # 无响应时减速
            self._pacing = min(self._pacing_max, self._pacing * 1.5)

        return response

    def replay_sequence(self, payloads: List[bytes],
                         inter_packet_sleep: bool = True
                         ) -> AdaptiveReplayReport:
        """重放整个载荷序列。

        inter_packet_sleep: True=按pacing间隔发包, False=连续发包(用于本地测试)。
        """
        for i, payload in enumerate(payloads):
            self.replay_packet(payload, i)
            if inter_packet_sleep and self._pacing > 0:
                time.sleep(self._pacing / 1000.0)

        return self._build_report()

    def _build_report(self) -> AdaptiveReplayReport:
        state_cov = self._tracker.state_coverage()
        n_div = len(self._divergences)
        n_packets = max(self._packets_sent, 1)

        # 漏洞评分: 分歧密度 × 严重度均值
        sev_mean = (sum(d.severity for d in self._divergences) /
                    max(n_div, 1)) if n_div else 0.0
        vuln_score = min((n_div / n_packets) * 0.6 + sev_mean * 0.4, 1.0)

        if vuln_score > 0.7:
            rec = "高概率存在协议实现缺陷——建议人工审查分歧点"
        elif vuln_score > 0.3:
            rec = "存在可疑状态转移——可能为版本差异或配置变更"
        else:
            rec = "重放行为与预期一致——无明显协议异常"

        return AdaptiveReplayReport(
            session_id=self._session_id or "replay_session",
            protocol=self._tracker._proto,
            packets_sent=self._packets_sent,
            responses_received=self._responses_received,
            state_coverage=round(state_cov, 4),
            divergences=self._divergences,
            state_path=self._tracker.state_path,
            vulnerability_score=round(vuln_score, 4),
            recommendation=rec,
        )


def create_replay_engine(protocol: str = "TCP",
                          pacing_ms: float = 10.0) -> AdaptiveReplayEngine:
    """工厂函数: 按协议类型创建预配置的重放引擎。

    HTTP建议pacing=20ms(避免触发rate limiting),
    DNS建议pacing=5ms(无连接开销)。
    """
    defaults = {"HTTP": 20.0, "DNS": 5.0, "TLS": 15.0, "TCP": 10.0}
    pacing = pacing_ms if pacing_ms != 10.0 else defaults.get(protocol, 10.0)
    return AdaptiveReplayEngine(protocol=protocol, initial_pacing_ms=pacing)


__all__ = [
    "ProtoState", "ReplayState", "DivergenceRecord",
    "AdaptiveReplayReport", "ProtocolStateTracker",
    "AdaptiveReplayEngine", "create_replay_engine",
]
