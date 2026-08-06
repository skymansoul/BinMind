"""鞅制导模糊测试评估器 — 随时有效统计推断在 fuzzing 中的应用.

修改记录:
2025-08-02 10:15 - 测试鞅 + e-value 框架用于覆盖停滞检测
2025-08-03 13:42 - SPRT 策略比较: 两种突变策略的随时有效对比
2025-08-05 09:08 - 覆盖平台早期预警: 鞅增长速率映射为终止建议

参考:
  Shafer & Vovk (2019) "Game-Theoretic Foundations for Probability and Finance"
  Ramdas et al. (2023) "Anytime-Valid Inference" (Statistical Science)

在 fuzzing 中无先例。fuzzing 基准测试长期受困于"运行多久才算够",
因为传统固定样本检验需要预设停止时间且不能 peeking。
测试鞅解决了这个问题 — 可在任何时刻 peeking/停止, 统计推断有效。
这使 fuzzing 基准测试从固定时长转向证据驱动。

核心创新:
  1. 覆盖平台检测: 鞅持续监测新覆盖速率, 自动判定何时已穷尽探索
  2. SPRT 策略对比: 不预设执行次数, 证据充分时自动终止并给出结论
  3. 终止建议: 鞅 log₁₀ 映射为可操作的停止/继续决策
"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .martingale_tester import TestMartingale, SequentialProbabilityRatioTest


_DECISION_WINDOW = 500        # 覆盖平台检测的窗口大小
_LOG10_THRESHOLD_WARN = 1.5   # log10 证据 >1.5 → 警告覆盖可能停滞
_LOG10_THRESHOLD_STOP = 2.5   # log10 证据 >2.5 → 建议停止


@dataclass
class FuzzingEvidence:
    """fuzzing 过程的累积统计证据."""
    total_executions: int
    total_new_edges: int
    martingale_value: float
    log10_evidence: float
    plateau_detected: bool
    recommended_action: str       # "continue" | "warn" | "stop"
    strategy_comparison: Optional[str]  # SPRT 结论


class MartingaleFuzzingAssessor:
    """鞅制导模糊测试评估器 — 随时有效的统计推断.

    三个并行的评估通道:
      1. 覆盖平台检测鞅: 新覆盖是否已停滞
      2. 策略对比 SPRT: 策略 A vs 策略 B 的发现率
      3. 全局 e-value 追踪: 累积所有"意外"事件的证据
    """

    def __init__(self, window_size: int = _DECISION_WINDOW):
        self.window_size = window_size
        # 覆盖平台检测
        self._plateau_martingale = TestMartingale(
            rejection_threshold=10.0 ** _LOG10_THRESHOLD_STOP)
        self._edges_this_window: int = 0
        self._execs_this_window: int = 0
        # 全局证据追踪
        self._global_martingale = TestMartingale()
        self._total_execs: int = 0
        self._total_edges: int = 0
        # SPRT 策略对比
        self._sprt: Optional[SequentialProbabilityRatioTest] = None
        self._strategy_a_wins: int = 0
        self._strategy_b_wins: int = 0
        # 历史
        self._evidence_history: List[FuzzingEvidence] = []
        self._last_assessment_time: float = 0.0

    # //// 观测收集 ////
    def observe_execution(self, new_edges: int, is_strategy_a: bool = True,
                          is_surprising: bool = False) -> None:
        """记录一次执行结果.

        new_edges: 本次执行发现的新边数
        is_strategy_a: 是否来自策略 A (与 SPRT 比较相关)
        is_surprising: 是否发生了意外事件 (崩溃、异常覆盖跳跃等)
        """
        self._total_execs += 1
        self._total_edges += new_edges
        self._edges_this_window += new_edges
        self._execs_this_window += 1

        # 窗口满时更新覆盖平台鞅
        if self._execs_this_window >= self.window_size:
            self._update_plateau_martingale()
            self._edges_this_window = 0
            self._execs_this_window = 0

        # 全局鞅: 意外事件提供证据
        if is_surprising:
            # 意外事件在零假设 (正常行为) 下概率低
            self._global_martingale.update(p_null=0.05, p_alt=0.5)

        # SPRT 更新
        if self._sprt is not None and new_edges > 0:
            if is_strategy_a:
                self._strategy_a_wins += 1
            else:
                self._strategy_b_wins += 1
            self._sprt.update(success_H1=(self._strategy_a_wins > self._strategy_b_wins))

        # 定期评估
        if (self._total_execs % (self.window_size * 2) == 0
                and time.time() - self._last_assessment_time > 5.0):
            self._update_assessment()

    def _update_plateau_martingale(self) -> None:
        """用当前窗口的新边数更新覆盖平台鞅.

        零假设: 仍在发现 (λ₀ = 2%), 备择: 已停滞 (λ₁ = 0.2%)
        """
        n = self._execs_this_window
        k = self._edges_this_window
        lambda_0 = 0.02
        lambda_1 = 0.002
        # 二项似然
        def binom_lik(lam):
            return (lam ** k) * ((1 - lam) ** (n - k))
        p_null = binom_lik(lambda_0) if k <= n else 1e-15
        p_alt = binom_lik(lambda_1) if k <= n else 1e-15
        self._plateau_martingale.update(max(p_null, 1e-15), max(p_alt, 1e-15))

    # //// 策略对比 ////
    def start_strategy_comparison(self) -> None:
        """启动 SPRT 策略对比."""
        self._sprt = SequentialProbabilityRatioTest(alpha=0.05, beta=0.10)
        self._strategy_a_wins = 0
        self._strategy_b_wins = 0

    def strategy_comparison_result(self) -> Optional[str]:
        """策略对比结论: 'A_better' | 'B_better' | 'no_difference' | None(未决)."""
        if self._sprt is None:
            return None
        if self._sprt.decision == "reject_H0":
            return "A_better" if self._strategy_a_wins > self._strategy_b_wins else "B_better"
        if self._sprt.decision == "accept_H0":
            return "no_difference"
        return None

    # //// 评估 ////
    def _update_assessment(self) -> None:
        """生成当前的评估快照."""
        log10_ev = self._plateau_martingale.log10_evidence()
        plateau = self._plateau_martingale.is_rejected()
        if log10_ev >= _LOG10_THRESHOLD_STOP:
            action = "stop"
        elif log10_ev >= _LOG10_THRESHOLD_WARN:
            action = "warn"
        else:
            action = "continue"

        spr_result = self.strategy_comparison_result()
        evidence = FuzzingEvidence(
            total_executions=self._total_execs,
            total_new_edges=self._total_edges,
            martingale_value=self._plateau_martingale.martingale,
            log10_evidence=log10_ev,
            plateau_detected=plateau,
            recommended_action=action,
            strategy_comparison=spr_result,
        )
        self._evidence_history.append(evidence)
        if len(self._evidence_history) > 50:
            self._evidence_history = self._evidence_history[-30:]
        self._last_assessment_time = time.time()

    def assess(self) -> FuzzingEvidence:
        """获取当前评估."""
        self._update_assessment()
        return (self._evidence_history[-1] if self._evidence_history
                else FuzzingEvidence(0, 0, 1.0, 0.0, False, "continue", None))

    def plateau_risk(self) -> float:
        """覆盖停滞风险 [0,1] — 越高越可能已停滞."""
        log10_ev = self._plateau_martingale.log10_evidence()
        return min(1.0, log10_ev / _LOG10_THRESHOLD_STOP)

    # //// 统计 ////
    def stats(self) -> dict:
        self._update_assessment()
        ev = self._evidence_history[-1] if self._evidence_history else None
        return {
            "total_executions": self._total_execs,
            "total_new_edges": self._total_edges,
            "plateau_martingale": round(self._plateau_martingale.martingale, 2),
            "plateau_log10_evidence": round(self._plateau_martingale.log10_evidence(), 3),
            "plateau_detected": self._plateau_martingale.is_rejected(),
            "recommended_action": ev.recommended_action if ev else "continue",
            "strategy_comparison": ev.strategy_comparison if ev else None,
            "global_martingale": round(self._global_martingale.martingale, 2),
            "window_size": self.window_size,
        }

    def clear(self) -> None:
        self._plateau_martingale.reset()
        self._global_martingale.reset()
        self._sprt = None
        self._edges_this_window = 0
        self._execs_this_window = 0
        self._total_execs = 0
        self._total_edges = 0
        self._strategy_a_wins = 0
        self._strategy_b_wins = 0
        self._evidence_history.clear()
