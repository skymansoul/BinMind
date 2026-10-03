# 多预言机共识融合引擎 — 加权投票降低差分测试的误报率
#
# 核心问题:
#   AccuOracle 证明: 差分测试中 >90% 的差异报告是误报。
#   本模块已有五种独立的预言机:
# diff_oracle.py: 语义规范断言 (规则+LLM)
#     - statistical_oracle.py: 非参数统计检验 (Mann-Whitney U + Cliff's Delta)
# metamorphic_oracle.py: 蜕变关系检查
# exploit_primitive.py: 利用原语分类
# trace_invariant_miner.py: 执行不变量违反检测
#   每种预言机从不同维度评估程序行为, 但各自独立运行——无机制综合它们的判断。
#
#   单预言机的问题:
# diff_oracle 高召回但低精度 (LLM幻觉→误报)
# statistical_oracle 对样本量敏感 (小样本→假阴性)
#     - metamorphic_oracle 依赖关系设计的完备性 (遗漏的关系→假阴性)
# 任一单独使用都有盲区
#
# 本模块的方法 — 加权多预言机共识融合:
#   1. 收集所有预言机的输出, 归一化为统一格式 (OracleVerdict)
#   2. 对每个预言机维护在线精度估计 (precision EWMA)
#   3. 融合公式: consensus_score = Σ(w_i × s_i) / Σ(w_i)
#      其中 w_i = precision_i / (1 - precision_i + ε)  (精度越高, 权重越高)
#   4. consensus_score > 阈值 → 报告; 否则标记为"需人工审核"或静默丢弃
#   5. 在线反馈更新: 当人工确认某差异为真/假后, 更新相关预言机的精度
#
# 为什么用精度加权而非等权:
# 不同预言机对不同类别的差异效果不同
# diff_oracle 对崩溃类差异精度高, 对输出差异精度低
# 精度自适应的权重使融合引擎自动学习"该信谁"
#
# 文献:
#   AccuOracle — 四层过滤消除JIT fuzzing误报;
#     本项目取其"多层过滤"思想但以多预言机加权替代固定过滤管道
#   — 多源证据合成为AI/安全领域的通用设计模式,
#     本模块以统计方法实现而非LLM pipeline, 降低延迟与成本

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class OracleKind(str, Enum):
    """预言机类型——与现有模块一一对应"""
    DIFF_SPEC = "diff_spec"            # diff_oracle 的规范断言
    STATISTICAL = "statistical"        # statistical_oracle 的假设检验
    METAMORPHIC = "metamorphic"        # metamorphic_oracle 的蜕变检查
    EXPLOIT = "exploit"                # exploit_primitive 的利用评估
    INVARIANT = "invariant"            # trace_invariant_miner 的不变量违反
    UNKNOWN = "unknown"


@dataclass
class OracleVerdict:
    """单条预言机的判断——统一数据格式"""
    oracle: OracleKind
    # 判定
    is_violation: bool                 # 该预言机是否认为存在异常
    severity: float                     # [0, 1] 该预言机给出的严重度
    confidence: float                   # [0, 1] 该预言机自身的置信度
    # 元数据
    evidence: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    timestamp: float = 0.0


@dataclass
class FusionResult:
    """融合后的共识判定"""
    # 输入
    verdicts: List[OracleVerdict] = field(default_factory=list)
    # 融合输出
    consensus_score: float = 0.0        # [0, 1]
    weighted_severity: float = 0.0      # [0, 1] 加权严重度
    is_consensus: bool = False          # 是否达成共识
    # 各预言机贡献
    oracle_contributions: Dict[str, float] = field(default_factory=dict)
    # 判定
    verdict: str = ""                   # "confirmed" | "suspicious" | "likely_false"
    recommendation: str = ""


class OraclePrecisionTracker:
    """在线追踪各预言机的历史精度——用于动态权重计算。

    使用 Beta 后验 (α=真阳性+1, β=假阳性+1), 精度 = α/(α+β)。
    """

    def __init__(self, prior_alpha: float = 2.0, prior_beta: float = 2.0):
        self._alpha: Dict[OracleKind, float] = defaultdict(
            lambda: prior_alpha)
        self._beta: Dict[OracleKind, float] = defaultdict(
            lambda: prior_beta)

    def record(self, oracle: OracleKind, was_correct: bool) -> None:
        if was_correct:
            self._alpha[oracle] += 1.0
        else:
            self._beta[oracle] += 1.0

    def precision(self, oracle: OracleKind) -> float:
        a, b = self._alpha[oracle], self._beta[oracle]
        return a / (a + b)

    def weight(self, oracle: OracleKind) -> float:
        """精度驱动的权重: w = p / (1-p + ε)。
        当 p=0.5 时 w=1.0; p→1 时 w→∞; p→0 时 w→0。
        """
        p = self.precision(oracle)
        epsilon = 0.05
        return p / (1.0 - p + epsilon)

    def stats(self) -> Dict[str, Dict[str, float]]:
        return {
            kind.value: {
                "precision": round(self.precision(kind), 4),
                "weight": round(self.weight(kind), 3),
                "samples": int(self._alpha[kind] + self._beta[kind] - 4),
            }
            for kind in OracleKind if kind != OracleKind.UNKNOWN
        }


class OracleFusionEngine:
    """多预言机共识融合引擎。

    典型用法:
        fusion = OracleFusionEngine()
        verdicts = [
            OracleVerdict(OracleKind.DIFF_SPEC, True, 0.8, 0.7,
                          evidence={'violation': 'output_mismatch'}),
            OracleVerdict(OracleKind.STATISTICAL, False, 0.1, 0.9),
            OracleVerdict(OracleKind.METAMORPHIC, True, 0.6, 0.5),
        ]
        result = fusion.fuse(verdicts)
        if result.is_consensus:
            report(result)
        # 反馈:
        fusion.feedback(result, was_true_positive=True)
    """

    def __init__(self, consensus_threshold: float = 0.45,
                 min_oracles: int = 2):
        """
        consensus_threshold: 共识分数超过此值→达成共识
        min_oracles: 至少需要多少预言机参与才做判定
        """
        self._threshold = consensus_threshold
        self._min_oracles = min_oracles
        self._tracker = OraclePrecisionTracker()
        self._history: List[FusionResult] = []

    def fuse(self, verdicts: List[OracleVerdict]) -> FusionResult:
        """融合多条预言机的判断——产出加权共识分数"""
        result = FusionResult(verdicts=list(verdicts))

        if len(verdicts) < self._min_oracles:
            result.verdict = "likely_false"
            result.recommendation = f"预言机不足 ({len(verdicts)} < {self._min_oracles})"
            return result

        # 计算加权共识
        total_weight = 0.0
        weighted_score = 0.0
        weighted_sev = 0.0

        for v in verdicts:
            w = self._tracker.weight(v.oracle)
            # 若该预言机报告违例, 贡献为正; 否则为负
            sign = 1.0 if v.is_violation else -0.5
            s = sign * v.severity * v.confidence
            weighted_score += w * s
            weighted_sev += w * v.severity * v.confidence
            total_weight += w
            result.oracle_contributions[v.oracle.value] = round(w * s, 4)

        if total_weight > 0:
            result.consensus_score = max(0.0, min(1.0,
                (weighted_score / total_weight + 1.0) / 2.0))
            result.weighted_severity = weighted_sev / total_weight
        else:
            result.consensus_score = 0.5

        # 判定
        result.is_consensus = result.consensus_score >= self._threshold

        violating_count = sum(1 for v in verdicts if v.is_violation)
        if result.is_consensus and violating_count >= 2:
            result.verdict = "confirmed"
            result.recommendation = "多预言机共识确认——高置信度真阳性"
        elif result.consensus_score >= 0.3:
            result.verdict = "suspicious"
            result.recommendation = "部分预言机报告异常——建议人工复核"
        else:
            result.verdict = "likely_false"
            result.recommendation = "多数预言机未报告——高概率误报, 可静默丢弃"

        self._history.append(result)
        return result

    def feedback(self, result: FusionResult,
                  was_true_positive: bool) -> None:
        """人工反馈——更新各预言机的精度估计。

        was_true_positive: 人工确认该差异是否为真实缺陷。
        """
        for v in result.verdicts:
            # 若该预言机报告了违例且真实为真 → 正确
            # 若未报告违例且真实为假 → 正确
            oracle_correct = (v.is_violation == was_true_positive)
            self._tracker.record(v.oracle, oracle_correct)

    # 诊断

    def oracle_weights(self) -> Dict[str, float]:
        return {
            k.value: round(self._tracker.weight(k), 3)
            for k in OracleKind if k != OracleKind.UNKNOWN
        }

    def stats(self) -> Dict[str, Any]:
        return {
            "history_size": len(self._history),
            "consensus_threshold": self._threshold,
            "precision_tracking": self._tracker.stats(),
            "recent_consensus_rate": (
                sum(1 for r in self._history[-20:] if r.is_consensus)
                / max(1, len(self._history[-20:]))
            ) if self._history else 0.0,
        }

    def reset(self) -> None:
        self._tracker = OraclePrecisionTracker()
        self._history.clear()


def quick_fuse(diff_violation: bool = False,
                stat_divergence: bool = False,
                meta_violation: bool = False,
                exploit_esa: float = 0.0,
                invariant_violation: bool = False,
                ) -> FusionResult:
    """便捷入口: 用最简参数做快速融合判定"""
    verdicts = []
    if diff_violation:
        verdicts.append(OracleVerdict(
            OracleKind.DIFF_SPEC, True, 0.7, 0.6,
            timestamp=time.monotonic()))
    else:
        verdicts.append(OracleVerdict(
            OracleKind.DIFF_SPEC, False, 0.1, 0.8,
            timestamp=time.monotonic()))

    verdicts.append(OracleVerdict(
        OracleKind.STATISTICAL, stat_divergence,
        0.5 if stat_divergence else 0.1, 0.7,
        timestamp=time.monotonic()))

    if meta_violation:
        verdicts.append(OracleVerdict(
            OracleKind.METAMORPHIC, True, 0.6, 0.5,
            timestamp=time.monotonic()))

    if exploit_esa > 0.3:
        verdicts.append(OracleVerdict(
            OracleKind.EXPLOIT, True, exploit_esa, 0.7,
            timestamp=time.monotonic()))

    if invariant_violation:
        verdicts.append(OracleVerdict(
            OracleKind.INVARIANT, True, 0.5, 0.4,
            timestamp=time.monotonic()))

    engine = OracleFusionEngine()
    return engine.fuse(verdicts)
