# stub_degradation_planner.py — 优雅降级规划器
# 当关键桩不可用时，沿依赖图+能力图搜索替代路径，
# 输出受影响的能力范围与推荐恢复顺序。
#
# 问题:
#   桩系统中某些模块可能处于 MISSING/PLACEHOLDER 状态。
#   当这些模块被上游依赖时，整个能力链断裂。
#   当前系统仅告知"某模块不可用"，不回答:
#     "哪些能力受影响？"
#     "有没有替代路径？"
#     "按什么顺序恢复能最快恢复最多能力？"
#
# 方法:
#   1. 以不可用模块为起点，沿 depended_by 边向下游传播影响
#   2. 对每条受影响的能力链，搜索替代路径（绕过不可用模块）
#   3. 替代路径评分: 路径长度 × 替代模块的实现状态
#   4. 输出降级计划: 能力损失清单 + 替代路径 + 推荐恢复顺序
#      （恢复顺序 = 按"恢复该模块后能解除多少下游阻塞"排序）
import os as _os
from collections import defaultdict as _dd
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt


@_dc
class DegradationImpact:
    """单条能力链的降级影响。"""
    capability: str = ''           # 能力标签
    blocked_module: str = ''       # 不可用的模块
    affected_downstream: list = _field(default_factory=list)
    has_alternative: bool = False
    alternative_path: list = _field(default_factory=list)
    alternative_quality: float = 0.0  # 替代路径质量 [0,1]


@_dc
class RecoveryItem:
    """单条恢复建议。"""
    module_name: str
    unblocks_downstream: int = 0  # 恢复后可解除阻塞的下游模块数
    restores_capabilities: list = _field(default_factory=list)
    priority: float = 0.0          # 恢复优先级 (越高越优先)


@_dc
class DegradationPlan:
    """完整的降级与恢复计划。"""
    unavailable_modules: list = _field(default_factory=list)
    impacts: list = _field(default_factory=list)     # list[DegradationImpact]
    recovery_order: list = _field(default_factory=list)  # list[RecoveryItem]
    total_capabilities_lost: int = 0
    total_capabilities_degraded: int = 0


class DegradationPlanner:
    """优雅降级规划器。"""

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir

    def plan(self) -> DegradationPlan:
        """生成完整的降级与恢复计划。"""
        plan = DegradationPlan()

        # 1. 发现不可用模块
        unavailable = self._find_unavailable()
        plan.unavailable_modules = list(unavailable)
        if not unavailable:
            return plan

        # 2. 获取依赖图与能力图
        dep_graph = self._get_dep_graph()
        cap_clusters = self._get_capability_clusters()

        # 3. 对每个不可用模块分析影响
        for mod in unavailable:
            impact = self._analyze_impact(mod, dep_graph, cap_clusters)
            if impact:
                plan.impacts.append(impact)

        # 4. 统计
        plan.total_capabilities_lost = sum(
            1 for imp in plan.impacts if not imp.has_alternative)
        plan.total_capabilities_degraded = sum(
            1 for imp in plan.impacts if imp.has_alternative)

        # 5. 计算恢复顺序
        plan.recovery_order = self._compute_recovery_order(
            unavailable, dep_graph, cap_clusters)
        return plan

# 内部
    def _find_unavailable(self) -> set[str]:
        """查找所有不可用模块 (MISSING/PLACEHOLDER/UNPARSEABLE)。"""
        try:
            from modules.stubs.stub_contract import (
                StubContractor, ImplementationStatus)
            ctor = StubContractor(stubs_dir=self.stubs_dir)
            contracts = ctor.scan_all()
            unavailable = set()
            for name, c in contracts.items():
                if name.startswith('stub_'):
                    continue
                if c.status in (ImplementationStatus.MISSING.value,
                               ImplementationStatus.PLACEHOLDER.value,
                               ImplementationStatus.UNPARSEABLE.value):
                    unavailable.add(name)
            return unavailable
        except ImportError:
            return set()

    @staticmethod
    def _get_dep_graph() -> dict:
        try:
            from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
            g = ModuleDependencyGraph()
            g.build()
            return {name: {
                'depended_by': set(node.depended_by),
                'imports_from': set(node.imports_from),
            } for name, node in g.nodes.items()}
        except ImportError:
            return {}

    @staticmethod
    def _get_capability_clusters() -> dict[str, set[str]]:
        """返回 {capability_tag: {module_names}}"""
        try:
            from modules.stubs.stub_capability_graph import CapabilityAnalyzer
            ca = CapabilityAnalyzer()
            clusters = ca.analyze()
            return {c.name: set(c.modules) for c in clusters}
        except ImportError:
            return {}

    @staticmethod
    def _analyze_impact(mod: str, dep_graph: dict,
                        cap_clusters: dict) -> _Opt[DegradationImpact]:
        """分析单个不可用模块的影响。"""
        node = dep_graph.get(mod, {})
        downstream = list(node.get('depended_by', set()))

        # 确定受影响的能力
        affected_caps = []
        for cap, members in cap_clusters.items():
            if mod in members:
                affected_caps.append(cap)

        if not downstream and not affected_caps:
            return None

        # 搜索替代路径: 对每个下游模块，查找是否可通过其他路径访问
        cap_name = affected_caps[0] if affected_caps else 'unknown'
        impact = DegradationImpact(
            capability=cap_name,
            blocked_module=mod,
            affected_downstream=downstream,
        )

        # 简单替代: 同一能力簇中是否有已实现的替代模块
        if cap_name in cap_clusters:
            cluster = cap_clusters[cap_name]
            alternatives = [
                m for m in cluster
                if m != mod and m not in downstream
            ]
            if alternatives:
                impact.has_alternative = True
                impact.alternative_path = alternatives[:3]
                # 质量 = 替代模块中有多少是已实现的
                try:
                    from modules.stubs.stub_contract import (
                        StubContractor, ImplementationStatus)
                    ctor = StubContractor()
                    impl_count = 0
                    for alt in alternatives[:3]:
                        c = ctor.get(alt)
                        if c and c.status in (ImplementationStatus.IMPLEMENTED.value,
                                             ImplementationStatus.MIXED.value):
                            impl_count += 1
                    impact.alternative_quality = round(
                        impl_count / max(len(alternatives[:3]), 1), 2)
                except ImportError:
                    pass

        return impact

    @staticmethod
    def _compute_recovery_order(unavailable: set, dep_graph: dict,
                                cap_clusters: dict) -> list[RecoveryItem]:
        """按"恢复后解除多少下游阻塞"排序。"""
        items = []
        for mod in unavailable:
            node = dep_graph.get(mod, {})
            downstream = node.get('depended_by', set())
            unblocks = len(downstream)

            restores = []
            for cap, members in cap_clusters.items():
                if mod in members:
                    restores.append(cap)

            priority = unblocks * 0.7 + len(restores) * 0.3
            items.append(RecoveryItem(
                module_name=mod,
                unblocks_downstream=unblocks,
                restores_capabilities=restores,
                priority=round(priority, 2),
            ))

        items.sort(key=lambda r: -r.priority)
        return items

# 报告
    def degradation_report(self,
                           plan: DegradationPlan = None) -> str:
        if plan is None:
            plan = self.plan()

        lines = [
            '# 优雅降级计划',
            f'不可用模块: {len(plan.unavailable_modules)}',
            f'能力完全丧失: {plan.total_capabilities_lost}',
            f'能力降级可用: {plan.total_capabilities_degraded}',
            '',
        ]

        if plan.recovery_order:
            lines.append('## 推荐恢复顺序')
            lines.append('| 优先级 | 模块 | 解除阻塞 | 恢复能力 |')
            lines.append('|-------:|------|---------:|----------|')
            for r in plan.recovery_order[:10]:
                caps = ', '.join(r.restores_capabilities[:3])
                lines.append(
                    f'| {r.priority:.1f} | {r.module_name} | '
                    f'{r.unblocks_downstream} | {caps} |')

        if plan.impacts:
            lines.append('')
            lines.append('## 影响分析')
            for imp in plan.impacts[:15]:
                alt = (f'alternatives: {", ".join(imp.alternative_path[:2])}'
                      if imp.has_alternative else 'no alternative')
                lines.append(
                    f'- **{imp.blocked_module}** → {imp.capability}: '
                    f'{alt} (quality={imp.alternative_quality:.0%})')

        return '\n'.join(lines)


__all__ = ['DegradationImpact', 'RecoveryItem', 'DegradationPlan',
           'DegradationPlanner']
