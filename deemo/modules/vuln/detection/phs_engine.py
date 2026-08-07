# coding: utf-8
# 创建: 2026-08-07  |  PHS编排引擎
# 修改: 2026-08-07  |  审计后补充文件头与错误处理
#
"""
指针危险评分——编排引擎与批量分析。

管线:
  1. 对二进制中每个函数执行PointerHazardAnalyzer
  2. 聚合所有指针操作的危险评分
  3. 按危险等级分组(CRITICAL/HIGH/MEDIUM/LOW)
  4. 输出Top-K最危险指针操作+每函数危险摘要

与模糊测试的协同:
  高PHS分数的指针操作→DABSS种子合成的优先目标
  →模糊测试引擎分配的变异预算倾斜
  →提高发现新崩溃的概率

与补丁验证的协同:
  补丁前后的PHS分数比较→补丁是否真正降低了指针操作的危险
  →SPCV语义完备性验证的辅助信号
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .phs_analyzer import PointerHazardAnalyzer, HazardScore, PointerOperation

_log = logging.getLogger(__name__)


@dataclass
class FunctionHazardSummary:
    """单个函数的指针危险摘要"""
    function_name: str
    total_ptr_ops: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    max_hazard: float = 0.0
    avg_hazard: float = 0.0
    # 此函数中最危险的3个操作
    top_hazards: List[HazardScore] = field(default_factory=list)


@dataclass
class PhsReport:
    """PHS完整报告——二进制指针危险全景"""
    binary_name: str
    total_functions: int = 0
    total_ptr_ops: int = 0
    # 危险分布
    critical_ops: int = 0
    high_ops: int = 0
    medium_ops: int = 0
    # 函数摘要
    function_summaries: List[FunctionHazardSummary] = field(
        default_factory=list)
    # Top-K最危险指针操作
    top_hazards: List[HazardScore] = field(default_factory=list)
    # 模糊测试目标推荐
    fuzzing_targets: List[str] = field(default_factory=list)


# PHS引擎


class PhsEngine:
    """指针危险评分引擎——批量函数分析+聚合报告。

    使用示例:
        engine = PhsEngine()
        report = engine.analyze({
            'func_a': [...instructions...],
            'func_b': [...instructions...],
        }, binary_name='/bin/target')
    """

    def __init__(self):
        self._analyzer = PointerHazardAnalyzer()

    def analyze(self, functions: Dict[str, List[str]],
                 binary_name: str = ""
                 ) -> PhsReport:
        """对二进制所有函数执行指针危险分析。

        参数:
          functions: {函数名: [反汇编行]}
          binary_name: 二进制名称

        返回PhsReport。
        """
        all_scores = []
        summaries = []

        for func_name, insns in functions.items():
            scores = self._analyzer.analyze_function(insns, func_name)
            if not scores:
                continue

            all_scores.extend(scores)

            critical = sum(1 for s in scores if s.hazard_level == 'CRITICAL')
            high = sum(1 for s in scores if s.hazard_level == 'HIGH')
            medium = sum(1 for s in scores if s.hazard_level == 'MEDIUM')
            max_h = max(s.overall_hazard for s in scores) if scores else 0.0
            avg_h = (sum(s.overall_hazard for s in scores) / len(scores)
                     if scores else 0.0)

            summaries.append(FunctionHazardSummary(
                function_name=func_name,
                total_ptr_ops=len(scores),
                critical_count=critical, high_count=high,
                medium_count=medium,
                max_hazard=round(max_h, 3),
                avg_hazard=round(avg_h, 3),
                top_hazards=scores[:3]))

        # 全局排序
        all_scores.sort(key=lambda s: s.overall_hazard, reverse=True)

        # 模糊测试目标——危险操作最多的函数
        summaries.sort(key=lambda s: s.max_hazard, reverse=True)
        fuzz_targets = [s.function_name for s in summaries[:5]
                        if s.max_hazard >= 0.5]

        return PhsReport(
            binary_name=binary_name,
            total_functions=len(functions),
            total_ptr_ops=len(all_scores),
            critical_ops=sum(1 for s in all_scores if s.hazard_level == 'CRITICAL'),
            high_ops=sum(1 for s in all_scores if s.hazard_level == 'HIGH'),
            medium_ops=sum(1 for s in all_scores if s.hazard_level == 'MEDIUM'),
            function_summaries=summaries,
            top_hazards=all_scores[:10],
            fuzzing_targets=fuzz_targets)


# 便捷入口


def analyze_pointer_hazards(functions: Dict[str, List[str]],
                              binary_name: str = ""
                              ) -> PhsReport:
    """指针危险分析便捷入口"""
    return PhsEngine().analyze(functions, binary_name)


__all__ = [
    "FunctionHazardSummary",
    "PhsReport",
    "PhsEngine",
    "analyze_pointer_hazards",
]
