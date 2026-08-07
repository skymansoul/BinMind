"""
整数溢出循环归纳变量 — 类型定义 + I-GUARD 集成入口.

"""


from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class InductionKind(Enum):
    """归纳变量类型."""
    BASIC = "BASIC"       # i = i + c (或 i = i - c)
    DERIVED = "DERIVED"   # j = a*i + b (依赖基础归纳变量)
    ACCUMULATOR = "ACCUM" # sum += x (循环累积)


@dataclass
class InductionVar:
    """循环归纳变量."""
    name: str
    kind: InductionKind
    init_val: int = 0          # 初始值
    stride: int = 1            # 步长 (+1 或 -1)
    bound_var: str = ""        # 绑定变量 (如 loop 的 n)
    bound_val: int = -1        # 绑定值 (-1=未知)
    bound_op: str = "<"        # 绑定操作符 (< <= > >=)
    derived_from: str = ""     # 派生来源 (用于 DERIVED 类型)
    derived_coef: int = 1      # 派生系数 c1
    derived_offset: int = 0    # 派生偏移 c2
    line_no: int = 0

    @property
    def max_iterations(self) -> int:
        """最大迭代次数 (基于守卫条件)."""
        if self.bound_val < 0:
            return -1  # 未知
        if self.stride == 0:
            return 0
        if self.bound_op in ('<', '<='):
            n = self.bound_val - self.init_val
            if self.bound_op == '<':
                n -= 1
            if self.stride > 0:
                return max(0, n // self.stride + 1)
            else:
                return -1  # stride<0 时 bound 下界
        return -1


@dataclass
class LoopInfo:
    """循环信息."""
    start_line: int            # 循环开始行
    end_line: int              # 循环结束行
    header_line: int           # 循环头行 (for/while)
    induction_vars: Dict[str, InductionVar] = field(default_factory=dict)
    accumulators: Dict[str, InductionVar] = field(default_factory=dict)
    guard_condition: str = ""  # 守卫条件文本
    body_lines: List[str] = field(default_factory=list)

    @property
    def has_known_bound(self) -> bool:
        return any(v.bound_val >= 0 for v in self.induction_vars.values())


@dataclass
class LoopOverflowRisk:
    """循环溢出风险评估."""
    loop: LoopInfo
    var_name: str              # 可能溢出的变量
    var_kind: str              # induction | accumulator
    max_value: int             # 循环后最大可能值
    overflow_threshold: int    # 溢出阈值
    risk_level: str = "UNKNOWN"
    confidence: float = 0.5
    reason: str = ""


def integrate_loop_analysis_with_iguard(
    source_code: str,
    existing_findings: Optional[List[dict]] = None,
) -> Tuple[List[LoopOverflowRisk], List[dict]]:
    """将循环归纳变量分析注入 I-GUARD 管线.

    Args:
        source_code: C源码
        existing_findings: I-GUARD 现有检测结果

    Returns:
        (loop_risks, enhanced_findings)
    """
    from analysis.int_loop_induction import LoopInductionTracker

    tracker = LoopInductionTracker()
    loops = tracker.extract_loops(source_code)
    all_risks = []
    for loop in loops:
        risks = tracker.analyze_overflow_risk(loop, source_code)
        all_risks.extend(risks)

    enhanced = list(existing_findings) if existing_findings else []

    # 将循环溢出风险注入到 findings 中
    for risk in all_risks:
        if risk.risk_level in ("OVERFLOW", "LIKELY_OVERFLOW"):
            enhanced.append({
                'source': 'loop_induction',
                'var': risk.var_name,
                'kind': risk.var_kind,
                'max_value': risk.max_value,
                'threshold': risk.overflow_threshold,
                'risk_level': risk.risk_level,
                'confidence': risk.confidence,
                'reason': risk.reason,
                'loop_start': risk.loop.start_line,
                'loop_end': risk.loop.end_line,
            })

    return all_risks, enhanced


__all__ = [
    'InductionKind', 'InductionVar', 'LoopInfo', 'LoopOverflowRisk',
    'integrate_loop_analysis_with_iguard',
]
