"""
整数溢出循环归纳变量追踪器 — 基于 Cousot 抽象解释的循环溢出分析.

核心问题:
  现有 IntOverflowVerifier 的值范围传播在遇到循环时发散:
    for (i = 0; i < n; i++) { sum += val; }
  简单传播: i→[0,∞), sum→[0,∞) — 完全无法判定溢出.

  本模块引入循环归纳变量追踪 (Loop Induction Variable Tracking):
    1. 识别基础归纳变量: i = i ± stride
    2. 识别派生归纳变量: j = c1*i + c2
    3. 在循环头做 widening (外推): [0,0] → [0,1] → [0,+∞]
    4. 用守卫条件 narrowing (精化): i < n → i ∈ [0, n-1]
    5. 检测循环内累积操作的溢出风险: sum ∈ [0, val_hi * (n-1)]

理论基础:
  - Cousot & Cousot: widening/narrowing 保证不动点迭代终止
  - 对整数域: widening 到 [min, +∞) 或 (-∞, max]
  - narrowing 用守卫条件精化到具体区间

循环提取/归纳变量识别 → 已提取至 analysis.int_loop_extract.
类型定义 + I-GUARD 集成 → 已提取至 analysis.int_loop_types.

  - Mine: "The Octagon Abstract Domain"
  - Dietz et al.: "Understanding Integer Overflow in C/C++"
  - CWE-190 (Integer Overflow) → CWE-122 (Heap Overflow) 因果链
"""

import re
from typing import Dict, List

import logging
_log = logging.getLogger(__name__)

# 类型定义 + I-GUARD 集成 → 已提取至 analysis.int_loop_types
from analysis.int_loop_types import (
    InductionKind, InductionVar, LoopInfo, LoopOverflowRisk,
    integrate_loop_analysis_with_iguard,
)
# 循环提取 → 已提取至 analysis.int_loop_extract
from analysis.int_loop_extract import (
    extract_loops_from_source,
)

class LoopInductionTracker:
    """循环归纳变量追踪器 — Cousot 式 widening/narrowing.

    使用方式:
      tracker = LoopInductionTracker()
      loops = tracker.extract_loops(source_code)
      for loop in loops:
          risks = tracker.analyze_overflow_risk(loop, source_code)
          for risk in risks:
              if risk.risk_level == "OVERFLOW":
                  print(f"Loop overflow: {risk.var_name} → {risk.max_value}")
    """

    def __init__(self, max_widening: int = 2**31 - 1):
        self._max_widening = max_widening
        self._var_init: Dict[str, int] = {}

    def clear(self):
        self._var_init.clear()

    # 循环提取 (委托给 int_loop_extract)

    def extract_loops(self, source_code: str) -> List[LoopInfo]:
        """从源码提取所有循环结构 (委托给 int_loop_extract)."""
        return extract_loops_from_source(source_code, self._var_init)

    # 溢出风险分析

    def analyze_overflow_risk(self, loop: LoopInfo,
                               source_code: str = "") -> List[LoopOverflowRisk]:
        """分析单个循环的溢出风险."""
        risks = []
        threshold = self._max_widening

        for name, iv in loop.induction_vars.items():
            max_val = self._compute_max_after_loop(iv)
            min_val = iv.init_val
            risk = self._classify_risk(
                loop, name, "induction", min_val, max_val, threshold)
            risks.append(risk)

        for name, acc in loop.accumulators.items():
            max_per_iter = self._infer_max_per_iter(acc, source_code)
            max_iter = self._get_max_iterations(loop)
            if max_iter > 0:
                max_val = acc.init_val + max_iter * max_per_iter
                risk = self._classify_risk(
                    loop, name, "accumulator", acc.init_val, max_val, threshold)
                risks.append(risk)

        return risks

    def _compute_max_after_loop(self, iv: InductionVar) -> int:
        """计算循环后变量的最大可能值 (widening 到 bound)."""
        if iv.bound_val >= 0:
            if iv.bound_op == '<':
                return iv.bound_val - 1
            elif iv.bound_op == '<=':
                return iv.bound_val
            elif iv.bound_op == '>':
                return self._max_widening
        if iv.stride > 0:
            return self._max_widening
        else:
            return iv.init_val

    def _infer_max_per_iter(self, acc: InductionVar,
                             source_code: str = "") -> int:
        """推断每次迭代的最大累积值."""
        if acc.derived_from:
            try:
                return int(acc.derived_from)
            except ValueError:
                pass
            if source_code:
                m = re.search(
                    rf'{re.escape(acc.derived_from)}\s*=\s*(\d+)\s*;', source_code)
                if m:
                    return int(m.group(1))
        return 100  # 保守默认值

    def _get_max_iterations(self, loop: LoopInfo) -> int:
        """获取循环的最大迭代次数."""
        for iv in loop.induction_vars.values():
            if iv.max_iterations > 0:
                return iv.max_iterations
        return 1000

    def _classify_risk(self, loop: LoopInfo, var_name: str,
                        var_kind: str, min_val: int, max_val: int,
                        threshold: int) -> LoopOverflowRisk:
        """分类溢出风险等级."""
        risk = LoopOverflowRisk(
            loop=loop, var_name=var_name, var_kind=var_kind,
            max_value=max_val, overflow_threshold=threshold,
        )

        if max_val <= threshold:
            risk.risk_level = "SAFE"
            risk.confidence = 0.85
            risk.reason = f"max({max_val}) ≤ threshold({threshold})"
        elif min_val > threshold:
            risk.risk_level = "OVERFLOW"
            risk.confidence = 0.90
            risk.reason = f"min({min_val}) > threshold({threshold}), 必然溢出"
        elif loop.has_known_bound:
            risk.risk_level = "LIKELY_OVERFLOW"
            risk.confidence = 0.60
            risk.reason = (f"max({max_val}) > threshold({threshold}), "
                          f"但受 loop bound 约束, 部分输入溢出")
        else:
            risk.risk_level = "CONDITIONAL"
            risk.confidence = 0.40
            risk.reason = (f"max({max_val}) > threshold, "
                          f"无 loop bound → widening 到 ∞, 需运行时判定")

        return risk

__all__ = [
    'InductionKind', 'InductionVar', 'LoopInfo', 'LoopOverflowRisk',
    'LoopInductionTracker', 'integrate_loop_analysis_with_iguard',
]
