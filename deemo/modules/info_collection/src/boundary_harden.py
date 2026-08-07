"""
合成边界加固 (SBH) —— 边界刺探查询生成与分类器加固。

Constitutional Classifiers 用合成数据训练安全护栏,
Boundary Point Jailbreaking 用课程学习识别决策边界。
本模块将两者结合: 生成跨越分类边界的合成查询,
测试分类器在边界附近的一致性, 不一致的边界点用于加固规则权重。

工作流:
1. 对每对邻近类别生成边界刺探查询 (关键词交叉、部分替换)
2. 记录 LLM 和规则分类器在边界查询上的输出
3. 识别不一致边界点 (LLM 和规则分类结果不同, 或 confidence 剧烈跳变)
4. 对不一致点的关键词做规则权重微调: 增强正确方向的权重, 削弱错误方向
5. 边界一致性评分作为分类器鲁棒性指标
"""

# File: boundary_harden.py  |  2026-07-31 create SBH

from __future__ import annotations

import itertools
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .intent_route import IntentCategory


@dataclass
class BoundaryQuery:
    """一条边界刺探查询。"""
    text: str
    expected_category: IntentCategory   # 预期类别 (合成时已知)
    adjacent_category: IntentCategory   # 邻近类别
    generation_method: str             # "keyword_mix" | "partial_replace" | "negation"


@dataclass
class BoundaryTestResult:
    """单条边界查询的测试结果。"""
    query: BoundaryQuery
    llm_category: IntentCategory
    rule_category: IntentCategory
    llm_confidence: float
    rule_confidence: float
    consistent: bool          # LLM 和规则输出一致
    correct: bool             # 分类正确 (匹配预期类别)


@dataclass
class HardeningReport:
    """加固报告。"""
    total_queries: int
    consistent_count: int
    correct_count: int
    boundary_stability: float    # 边界稳定性 [0, 1]
    weak_boundaries: List[Tuple[IntentCategory, IntentCategory, float]]
    # 弱边界: (类别A, 类别B, 不一致率)
    weight_adjustments: List[Tuple[str, IntentCategory, float]]
    # 建议的权重调整: (关键词, 类别, 调整量)


# 邻接类别对: 语义上易混淆的类别对

_ADJACENT_PAIRS: List[Tuple[IntentCategory, IntentCategory]] = [
    (IntentCategory.STATIC_COLLECTION, IntentCategory.DYNAMIC_INTERACTION),
    (IntentCategory.INTEL_CORRELATION, IntentCategory.FILE_ANALYSIS),
    (IntentCategory.STATIC_COLLECTION, IntentCategory.INTEL_CORRELATION),
    (IntentCategory.FILE_ANALYSIS, IntentCategory.DYNAMIC_INTERACTION),
]

# 每个类别的核心关键词种子
_SEEDS: Dict[IntentCategory, List[str]] = {
    IntentCategory.STATIC_COLLECTION: ["scan", "enumerate", "whoami", "netstat", "端口", "进程", "ipconfig"],
    IntentCategory.DYNAMIC_INTERACTION: ["ioctl", "probe", "interact", "fuzz", "inject", "hook", "驱动"],
    IntentCategory.INTEL_CORRELATION: ["CVE", "IOC", "lookup", "intel", "osint", "hash", "情报", "溯源"],
    IntentCategory.FILE_ANALYSIS: ["PE", "analyze", "strings", "decompile", "binary", "样本", "反编译"],
}

# 模板句型
_TEMPLATES: List[str] = [
    "对 {target} 进行 {action}",
    "请{action} {target}",
    "帮我{action}一下 {target}",
    "{action} {target} 并返回结果",
    "需要{action} {target}的信息",
]


class BoundaryHardener:
    """
    边界加固器。

    生成合成查询以探测分类边界, 记录不一致点, 输出权重调整建议。
    不直接修改分类器参数, 而是输出可审计的调整建议,
    由人工或上层编排逻辑决定是否应用。
    """

    def __init__(self, max_queries_per_pair: int = 30):
        self._max_per_pair = max_queries_per_pair
        self._results: List[BoundaryTestResult] = []
        self._boundary_stability_history: List[float] = []

    def generate_queries(self) -> List[BoundaryQuery]:
        """生成边界刺探查询集。"""
        queries: List[BoundaryQuery] = []

        for cat_a, cat_b in _ADJACENT_PAIRS:
            seeds_a = _SEEDS.get(cat_a, [])
            seeds_b = _SEEDS.get(cat_b, [])
            count = 0

            # 方法1: 关键词混合 — 取 A 的 target 模板 + B 的 action 关键词
            for templ in _TEMPLATES:
                for sa in seeds_a:
                    for sb in seeds_b:
                        if count >= self._max_per_pair:
                            break
                        text = templ.format(target=f"target_{count}", action=f"{sa} {sb}")
                        queries.append(BoundaryQuery(
                            text=text, expected_category=cat_a,
                            adjacent_category=cat_b,
                            generation_method="keyword_mix",
                        ))
                        count += 1

            # 方法2: 部分替换 — 取 A 的种子, 用 B 的种子替换其中一个词
            for sa in seeds_a[:3]:
                for sb in seeds_b[:3]:
                    if count >= self._max_per_pair:
                        break
                    text = f"对 target_{count} 进行 {sa} 和 {sb} 操作"
                    queries.append(BoundaryQuery(
                        text=text, expected_category=cat_a,
                        adjacent_category=cat_b,
                        generation_method="partial_replace",
                    ))
                    count += 1

            # 方法3: 否定型查询 — 明确排除某类别但仍含其关键词
            for sa in seeds_a[:2]:
                if count >= self._max_per_pair:
                    break
                text = f"不要做 {sa}, 只需要基本扫描 target_{count}"
                queries.append(BoundaryQuery(
                    text=text, expected_category=cat_a,
                    adjacent_category=cat_b,
                    generation_method="negation",
                ))
                count += 1

        return queries

    def test(
        self,
        queries: List[BoundaryQuery],
        llm_classify: Callable[[str], Tuple[IntentCategory, float]],
        rule_classify: Callable[[str], Tuple[IntentCategory, float]],
    ) -> List[BoundaryTestResult]:
        """
        对边界查询集执行测试。

        llm_classify: text → (category, confidence)
        rule_classify: text → (category, confidence)
        """
        results: List[BoundaryTestResult] = []
        for q in queries:
            llm_cat, llm_conf = llm_classify(q.text)
            rule_cat, rule_conf = rule_classify(q.text)
            consistent = (llm_cat == rule_cat)
            correct = (llm_cat == q.expected_category)
            results.append(BoundaryTestResult(
                query=q, llm_category=llm_cat, rule_category=rule_cat,
                llm_confidence=llm_conf, rule_confidence=rule_conf,
                consistent=consistent, correct=correct,
            ))
        self._results = results
        return results

    def analyze(self) -> HardeningReport:
        """分析测试结果, 生成加固建议。"""
        if not self._results:
            return HardeningReport(
                total_queries=0, consistent_count=0, correct_count=0,
                boundary_stability=1.0, weak_boundaries=[],
                weight_adjustments=[],
            )

        n = len(self._results)
        consistent = sum(1 for r in self._results if r.consistent)
        correct = sum(1 for r in self._results if r.correct)

        # 边界稳定性: 一致率 + 正确率的调和平均
        cons_rate = consistent / n
        corr_rate = correct / n
        if cons_rate + corr_rate > 0:
            stability = 2 * cons_rate * corr_rate / (cons_rate + corr_rate)
        else:
            stability = 0.0

        self._boundary_stability_history.append(stability)

        # 识别弱边界: 按类别对聚合不一致率
        pair_inconsistencies: Dict[Tuple[IntentCategory, IntentCategory], List[float]] = {}
        for r in self._results:
            pair = (r.query.expected_category, r.query.adjacent_category)
            if pair not in pair_inconsistencies:
                pair_inconsistencies[pair] = []
            pair_inconsistencies[pair].append(0.0 if r.consistent else 1.0)

        weak_boundaries: List[Tuple[IntentCategory, IntentCategory, float]] = []
        weight_adjustments: List[Tuple[str, IntentCategory, float]] = []

        for (cat_a, cat_b), vals in pair_inconsistencies.items():
            avg_incons = sum(vals) / len(vals)
            if avg_incons > 0.25:
                weak_boundaries.append((cat_a, cat_b, round(avg_incons, 4)))
                # 针对弱边界生成权重调整建议
                for seed in _SEEDS.get(cat_a, [])[:3]:
                    weight_adjustments.append((seed, cat_a, 0.05 * avg_incons))
                for seed in _SEEDS.get(cat_b, [])[:2]:
                    weight_adjustments.append((seed, cat_b, -0.03 * avg_incons))

        return HardeningReport(
            total_queries=n,
            consistent_count=consistent,
            correct_count=correct,
            boundary_stability=round(stability, 4),
            weak_boundaries=weak_boundaries,
            weight_adjustments=weight_adjustments,
        )

    def current_stability_trend(self) -> float:
        """稳定性趋势: 最新 vs 历史均值的差值。"""
        if len(self._boundary_stability_history) < 2:
            return 0.0
        recent = self._boundary_stability_history[-1]
        avg = sum(self._boundary_stability_history[:-1]) / (len(self._boundary_stability_history) - 1)
        return round(recent - avg, 4)

    def reset(self) -> None:
        self._results.clear()
        self._boundary_stability_history.clear()


__all__ = [
    "BoundaryQuery",
    "BoundaryTestResult",
    "HardeningReport",
    "BoundaryHardener",
]
