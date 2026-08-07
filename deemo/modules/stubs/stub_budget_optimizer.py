# stub_budget_optimizer.py — Token预算约束下的实现优化分配
# 当 LLM API 有 token 配额限制时，将有限预算分配到价值最高的函数上。
# 建模为分数背包问题: 每函数有 token 成本与质量收益，
# 在预算约束下最大化总收益。
#
# 问题:
#   GradualEngine 对每模块全量调用 LLM（若启用），不感知 token 成本。
#   实际部署中 API 配额有限（如 100K tokens/day）。
#   全量 LLM 调用可能在 5 个模块后耗尽配额，导致后续模块只能使用模板。
#   更好的策略: 对每模块的每函数评估 token 成本，按成本效益比分配。
#
# 方法:
#   1. 估计每函数的 LLM token 成本（基于参数数、复杂度、docstring 长度）
#   2. 估计每函数的实现价值（调用量 × 依赖深度 × 缺口度）
#   3. 分数背包: 按价值/成本比降序选择，直到预算耗尽
#   4. 未分配到 LLM 预算的函数 → 回退到 TemplateGenerator
#   5. 输出: 预算分配方案 + 预估总价值
#
# 建模细节:
#   分数背包允许"部分使用" → 本场景中对应 LLM 仅生成部分函数 body，
#   剩余由模板补齐。这比 0/1 背包更贴合实际:
#   LLM 可只生成函数的核心逻辑骨架，模板填充类型检查和边界处理。
import math as _math
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    FuncContract as _FuncContract,
    StubContract as _StubContract,
)


@_dc
class BudgetItem:
    """单个函数的预算条目。"""
    module_name: str
    func_name: str
    complexity: str = 'low'
    # 成本估算
    estimated_tokens: int = 0       # LLM 生成所需 token 数
    # 价值估算
    call_volume: int = 0
    dependency_depth: int = 0
    gap_score: float = 0.0
    value_score: float = 0.0        # 综合价值 = weighted(value_factors)
    # 分配结果
    allocated: bool = False          # 是否分配到 LLM 预算
    allocation_ratio: float = 0.0    # 分数背包的分配比例 [0,1]
    strategy: str = 'template'       # 最终使用的策略


@_dc
class BudgetPlan:
    """一次预算优化分配的完整方案。"""
    total_budget: int = 0
    items: list = _field(default_factory=list)   # list[BudgetItem]
    allocated_items: int = 0
    total_estimated_tokens: int = 0
    total_value: float = 0.0
    budget_utilization: float = 0.0  # 预算使用率
    unallocated_functions: list = _field(default_factory=list)


class BudgetOptimizer:
    """基于分数背包的 token 预算分配优化器。

    成本估计模型:
      base_cost = 200 (system prompt + overhead)
      per_param = 30 tokens / parameter
      per_complexity = {'low': 80, 'medium': 200, 'high': 500}
      per_doc_line = 20 tokens

    价值估计模型:
      value = 0.4 × norm(gap) + 0.3 × norm(call_vol) + 0.3 × norm(depth)
    """

    COST_BASE = 200
    COST_PER_PARAM = 30
    COST_COMPLEXITY = {'low': 80, 'medium': 200, 'high': 500}

    def __init__(self, total_budget: int = 100000):
        self.total_budget = total_budget

    def optimize(self, contracts: dict[str, _StubContract],
                 call_volumes: dict[str, int] = None,
                 dep_depths: dict[str, int] = None,
                 ) -> BudgetPlan:
        """在 token 预算约束下优化多模块函数分配。

        contracts: {module_name: StubContract}
        call_volumes: {module_name: call_count}
        dep_depths: {module_name: topo_depth}
        """
        call_volumes = call_volumes or {}
        dep_depths = dep_depths or {}

        # 1. 构建所有函数条目
        items = []
        for mod_name, contract in contracts.items():
            for fc in contract.functions:
                if fc.complexity == 'low' and self._type_coverage(fc) >= 0.8:
                    # 低复杂度高类型覆盖 → 模板已足够，不分配 LLM 预算
                    items.append(BudgetItem(
                        module_name=mod_name, func_name=fc.name,
                        complexity=fc.complexity,
                        estimated_tokens=0, value_score=0.0,
                        allocated=False, strategy='template'))
                    continue

                cost = self._estimate_cost(fc)
                value = self._estimate_value(
                    fc, mod_name, call_volumes, dep_depths)
                items.append(BudgetItem(
                    module_name=mod_name, func_name=fc.name,
                    complexity=fc.complexity,
                    estimated_tokens=cost,
                    call_volume=call_volumes.get(mod_name, 0),
                    dependency_depth=dep_depths.get(mod_name, 0),
                    gap_score=self._gap_score(fc),
                    value_score=value,
                    allocated=False, strategy='template'))

        # 2. 按价值/成本比降序排列（仅正成本条目）
        allocatable = [it for it in items if it.estimated_tokens > 0
                      and it.value_score > 0]
        allocatable.sort(key=lambda it: -it.value_score / it.estimated_tokens)

        # 3. 分数背包分配
        remaining = self.total_budget
        allocated = []

        for it in allocatable:
            if remaining <= 0:
                it.strategy = 'template'
                continue
            if it.estimated_tokens <= remaining:
                # 完全分配
                it.allocated = True
                it.allocation_ratio = 1.0
                it.strategy = 'llm'
                remaining -= it.estimated_tokens
                allocated.append(it)
            else:
                # 部分分配: LLM 生成核心逻辑，模板填充其余
                it.allocated = True
                it.allocation_ratio = remaining / it.estimated_tokens
                it.strategy = 'llm_partial'
                remaining = 0
                allocated.append(it)

        # 4. 汇总
        plan = BudgetPlan(total_budget=self.total_budget, items=items)
        plan.allocated_items = sum(1 for it in items if it.allocated)
        plan.total_estimated_tokens = sum(
            it.estimated_tokens for it in items if it.allocated)
        plan.total_value = round(sum(it.value_score for it in allocated), 3)
        plan.budget_utilization = round(
            1.0 - (remaining / self.total_budget), 3)
        plan.unallocated_functions = [
            f'{it.module_name}.{it.func_name}'
            for it in items if not it.allocated and it.value_score > 0
        ]

        return plan

    def optimize_module(self, contract: _StubContract,
                        call_volume: int = 0,
                        dep_depth: int = 0) -> BudgetPlan:
        """对单个模块执行预算优化（便捷接口）。"""
        return self.optimize(
            {contract.module_name: contract},
            {contract.module_name: call_volume},
            {contract.module_name: dep_depth},
        )

# 成本估算
    def _estimate_cost(self, fc: _FuncContract) -> int:
        params = [p for p in fc.params if p.kind not in ('varargs', 'varkw')]
        cost = self.COST_BASE
        cost += len(params) * self.COST_PER_PARAM
        cost += self.COST_COMPLEXITY.get(fc.complexity, 200)
        if fc.doc_summary:
            cost += len(fc.doc_summary.split()) * 2
        if fc.raises:
            cost += len(fc.raises) * 15
        return cost

# 价值估算
    @staticmethod
    def _estimate_value(fc: _FuncContract, module_name: str,
                        call_volumes: dict, dep_depths: dict) -> float:
        gap = BudgetOptimizer._gap_score(fc)
        vol = min(call_volumes.get(module_name, 0), 100) / 100.0
        depth = min(dep_depths.get(module_name, 0), 10) / 10.0
        return 0.4 * gap + 0.3 * vol + 0.3 * depth

    @staticmethod
    def _gap_score(fc: _FuncContract) -> float:
        if fc.is_placeholder:
            return 0.9
        if fc.complexity == 'high':
            return 0.7
        if fc.complexity == 'medium':
            return 0.5
        return 0.2

    @staticmethod
    def _type_coverage(fc: _FuncContract) -> float:
        params = [p for p in fc.params if p.kind not in ('varargs', 'varkw')]
        if not params:
            return 1.0
        annotated = sum(1 for p in params if p.annotation and p.annotation.strip())
        return annotated / len(params)

# 报告
    def plan_report(self, plan: BudgetPlan) -> str:
        """生成 Markdown 预算分配报告。"""
        lines = [
            '# Token 预算分配报告',
            f'总预算: {plan.total_budget:,} tokens',
            f'已分配: {plan.allocated_items} 个函数',
            f'预算使用率: {plan.budget_utilization:.1%}',
            f'预估总价值: {plan.total_value:.3f}',
            '',
        ]
        if plan.items:
            lines.append('| 模块 | 函数 | 复杂度 | Token | 策略 |')
            lines.append('|------|------|--------|------:|------|')
            for it in sorted(plan.items, key=lambda x: -x.value_score)[:20]:
                lines.append(
                    f'| {it.module_name} | {it.func_name} | '
                    f'{it.complexity} | {it.estimated_tokens} | '
                    f'{it.strategy} |')
        if plan.unallocated_functions:
            lines.append(f'\n未分配预算的函数 ({len(plan.unallocated_functions)}):')
            for f in plan.unallocated_functions[:10]:
                lines.append(f'- {f}')
        return '\n'.join(lines)


__all__ = ['BudgetItem', 'BudgetPlan', 'BudgetOptimizer']
