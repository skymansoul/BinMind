"""
C源码级整数溢出检测 — 融合 LoopInductionTracker + CWE-190 模式识别.

发现问题: 原 I-GUARD 管线依赖汇编码 (ir_lines/insns),
对 C 源码的直接调用返回空列表. 本模块提供 C源码直接入口,
识别以下 CWE-190 关键模式:
  1. malloc(n * sizeof(T)) — 乘法溢出导致分配不足
  2. for (i=0; i<n; i++) sum += ... — 循环累积溢出
  3. n * sizeof(T) 无溢出守卫 — 全局检测

与现有模块的关系:
  - IntOverflowVerifier: 汇编码值范围传播 (保留, 二进制分析路径)
  - LoopInductionTracker: 循环归纳变量 (本模块调用)
  - IntRangeConstraintChecker: 汇编级约束检查 (保留)
  - 本模块: C 源码 → 结构化的溢出风险评估

▎IntOverflowFinding + 正则模式 → analysis.int_overflow_patterns
▎行扫描器 + 辅助函数 → analysis.int_overflow_scanner
"""


from typing import List

from analysis.int_overflow_patterns import IntOverflowFinding
from analysis.int_overflow_scanner import scan_lines_for_int_overflow


def detect_int_overflow_c_source(source: str) -> List[IntOverflowFinding]:
    """C源码级整数溢出检测 — 主入口.

    覆盖 CWE分类:
      CWE-190: malloc(n * sizeof(T)) 乘法溢出 → 分配不足
      CWE-680: (int)size_t 截断 → 溢出
      CWE-681: malloc(signed_int) → -1→SIZE_MAX 分配
      CWE-191: malloc(n - c) 下溢
      CWE-190: malloc(n + c) 加溢出
      循环累积: total += val 无守卫

    三遍扫描:
      1. 识别不可信输入源 (atoi/argv/scanf/recv)
      2. 逐行模式匹配 + 溢出分析
      3. LoopInductionTracker 循环增强

    返回按置信度降序的 IntOverflowFinding 列表。
    """
    findings: List[IntOverflowFinding] = []

    # 第一+二遍: 逐行模式匹配
    scan_lines_for_int_overflow(source, findings)

    # 第三步: LoopInductionTracker 循环增强
    try:
        from analysis.int_loop_induction import LoopInductionTracker
        tracker = LoopInductionTracker()
        loops = tracker.extract_loops(source)
        for loop in loops:
            risks = tracker.analyze_overflow_risk(loop, source)
            for risk in risks:
                if risk.risk_level in ("OVERFLOW", "LIKELY_OVERFLOW"):
                    findings.append(IntOverflowFinding(
                        line=loop.start_line + 1,
                        pattern="loop_induction_overflow",
                        expression=f"loop: {risk.var_name} max→{risk.max_value}",
                        lhs_var=risk.var_name,
                        has_guard=loop.has_known_bound,
                        overflow_possible=True,
                        confidence=risk.confidence,
                        reason=risk.reason,
                    ))
    except ImportError:
        pass

    # 去重 + 排序
    seen = set()
    unique = []
    for f in findings:
        key = (f.line, f.pattern, f.expression[:40])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: -f.confidence)
    return unique


def detect_int_overflow_quick(source: str) -> dict:
    """快速检测入口 — 返回字典格式 (兼容现有管线)."""
    findings = detect_int_overflow_c_source(source)
    confirmed = [f for f in findings if f.confidence >= 0.60]
    conditional = [f for f in findings if 0.25 < f.confidence < 0.60]
    safe = [f for f in findings if f.confidence <= 0.25]

    return {
        'detected': len(confirmed) > 0,
        'findings': [
            {
                'line': f.line,
                'pattern': f.pattern,
                'expression': f.expression,
                'has_guard': f.has_guard,
                'confidence': f.confidence,
                'reason': f.reason,
            }
            for f in findings
        ],
        'confirmed': len(confirmed),
        'conditional': len(conditional),
        'safe': len(safe),
        'total': len(findings),
    }


__all__ = [
    'IntOverflowFinding',
    'detect_int_overflow_c_source',
    'detect_int_overflow_quick',
]
