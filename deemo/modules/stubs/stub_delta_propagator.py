# stub_delta_propagator.py — 合约变更沿依赖链传播引擎
# 当桩模块的接口契约变更时，沿依赖有向图向下游传递变更影响，
# 为每个受影响的模块生成合约级适配建议。
#
# 问题:
#   一个模块的契约变更（如新增函数参数、改返回类型）通过
#   import 链向下游扩散。当前工作流中，下游适配完全依赖
#   人工追踪—这在 60+ 模块的桩系统中不可规模化。
#
# 方案:
#   1. Merkle 树检测契约变更（对接 stub_contract_merkle）
#   2. 依赖图查找传递闭包（对接 stub_dependency_graph）
#   3. 对每个受影响模块生成适配建议:
#      a) 参数变更 → 调用点需增加/删除/改类型 → 建议补默认值或包装函数
#      b) 返回类型变更 → 建议更新类型注解或插入类型适配层
#      c) 函数删除 → 建议 stub 内创建转发包装或直接适配
#   4. 建议以结构化 diff 输出，可直接供 GradualEngine 消费
#
# 区别于已有工作:
#   - SEAM: 智能合约升级，非通用 stub 系统
# CMU API Refactoring: 从文档/PR 学习迁移规则，非图传播
# 本模块: 图传播 + Merkle 锚定 + 合约级 patch 生成
import os as _os
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    StubContract as _StubContract,
    FuncContract as _FuncContract,
    ParamSpec as _ParamSpec,
    StubContractor as _StubContractor,
)


@_dc
class ContractDelta:
    """单条合约级变更描述。"""
    module_name: str
    change_kind: str        # param_added | param_removed | param_type_changed
                            # return_type_changed | func_added | func_removed
    func_name: str = ''
    param_name: str = ''
    old_signature: str = ''
    new_signature: str = ''
    detail: str = ''


@_dc
class PropagationPatch:
    """对单个下游模块的合约适配建议。"""
    target_module: str
    source_delta: ContractDelta
    # 建议操作: add_param | remove_param | update_annotation | add_wrapper | no_action
    action: str = 'no_action'
    # 可读的建议描述
    suggestion: str = ''
    # 适配优先级: 1(critical) - 5(cosmetic)
    priority: int = 3
    # 建议修改的具体函数/类名
    affected_symbol: str = ''
    # 是否可自动执行（供 GradualEngine 自动适配）
    auto_applicable: bool = False


@_dc
class PropagationPlan:
    """一次合约变更的完整传播计划。"""
    source_delta: ContractDelta
    # 按拓扑深度的传播层 — depths[0] = 直接依赖方
    propagation_layers: list = _field(default_factory=list)
    patches: list = _field(default_factory=list)    # list[PropagationPatch]
    total_affected: int = 0
    auto_applicable_count: int = 0


class DeltaPropagator:
    """合约变更传播引擎。

    核心算法:
      1. 从 Merkle 树 diff 提取 ContractDelta 集合
      2. BFS 沿依赖图遍历，每层收集受影响模块
      3. 对每个受影响模块的合约做假设性适配分析
      4. 按拓扑深度分层输出 PropagationPatch 序列
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.contractor = _StubContractor(stubs_dir=stubs_dir)
        self._dep_graph = None

    @property
    def dep_graph(self):
        if self._dep_graph is None:
            try:
                from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
                self._dep_graph = ModuleDependencyGraph(stubs_dir=self.stubs_dir)
                self._dep_graph.build()
            except ImportError:
                self._dep_graph = None
        return self._dep_graph

    def propagate(self, delta: ContractDelta) -> PropagationPlan:
        """对单条合约变更执行依赖链传播分析。"""
        plan = PropagationPlan(source_delta=delta)

        if self.dep_graph is None:
            return plan

        # BFS 分层遍历
        visited = {delta.module_name}
        source_node = self.dep_graph.nodes.get(delta.module_name)
        if source_node is None:
            return plan
        current_layer = set(source_node.depended_by)

        while current_layer:
            layer_patches = []
            next_layer = set()
            for module_name in sorted(current_layer):
                if module_name in visited:
                    continue
                visited.add(module_name)
                patch = self._analyze_impact(delta, module_name)
                if patch is not None:
                    layer_patches.append(patch)

                node = self.dep_graph.nodes.get(module_name)
                if node is not None:
                    for dep_by in node.depended_by:
                        if dep_by not in visited:
                            next_layer.add(dep_by)

            if layer_patches:
                plan.propagation_layers.append(layer_patches)
                plan.patches.extend(layer_patches)
                plan.total_affected += len(layer_patches)
                plan.auto_applicable_count += sum(
                    1 for p in layer_patches if p.auto_applicable)
            current_layer = next_layer

        return plan

    def propagate_all(self, deltas: list[ContractDelta]) -> list[PropagationPlan]:
        """批量传播多条变更。按变更严重性排序输出。"""
        plans = [self.propagate(d) for d in deltas]
        plans.sort(key=lambda p: (
            p.source_delta.change_kind in ('func_removed', 'param_removed'),
            p.source_delta.change_kind in ('return_type_changed', 'param_type_changed'),
            p.total_affected,
        ), reverse=True)
        return plans

# 影响分析
    def _analyze_impact(self, delta: ContractDelta,
                        target_module: str) -> _Opt[PropagationPatch]:
        """分析目标模块如何受源变更影响，生成一条适配建议。"""
        contract = self.contractor.get(target_module)
        if contract is None:
            return None

        # 检查目标模块是否直接引用变更的函数
        referenced = self._find_referenced_function(contract, delta)
        if not referenced:
            # 间接依赖（仅 import 模块但未调用变更函数）
            if delta.change_kind in ('func_removed', 'param_removed'):
                return PropagationPatch(
                    target_module=target_module, source_delta=delta,
                    action='no_action', priority=5,
                    suggestion='间接依赖，变更函数未被直接调用；持续监控',
                    auto_applicable=True,
                )
            return None

        return self._suggest_patch(delta, target_module, contract, referenced)

    def _find_referenced_function(self, contract: _StubContract,
                                  delta: ContractDelta) -> _Opt[_FuncContract]:
        """在目标模块合约中查找引用了变更函数的函数。"""
        # 检查 import 模式
        for imp in contract.imports:
            if delta.module_name in imp:
                # 遍历函数，找与变更函数签名相似的
                for fc in contract.functions:
                    if self._might_call(fc, delta.func_name):
                        return fc
                # 找不到精确匹配，返回第一个函数作为代理
                if contract.functions:
                    return contract.functions[0]
        return None

    @staticmethod
    def _might_call(fc: _FuncContract, func_name: str) -> bool:
        """启发式判定函数是否可能调用目标函数。"""
        # 函数名暗示关系
        if func_name in fc.name:
            return True
        # docstring 中提及
        if fc.doc_summary and func_name in fc.doc_summary:
            return True
        # 参数类型中含有目标模块相关类型
        for p in fc.params:
            if func_name in p.annotation:
                return True
        return False

    def _suggest_patch(self, delta: ContractDelta, target_module: str,
                       contract: _StubContract,
                       affected_func: _FuncContract) -> PropagationPatch:
        """生成适配建议。"""
        patch = PropagationPatch(
            target_module=target_module,
            source_delta=delta,
            affected_symbol=affected_func.name,
        )

        if delta.change_kind == 'func_removed':
            patch.action = 'add_wrapper'
            patch.priority = 1
            patch.suggestion = (
                f'{target_module}.{affected_func.name}: '
                f'依赖的函数 {delta.func_name} 已从 {delta.module_name} 删除。'
                f'建议: 在本模块内创建兼容包装函数，或迁移到替代 API')
            patch.auto_applicable = False

        elif delta.change_kind == 'param_added':
            patch.action = 'update_annotation'
            # 检查 affected_func 是否有兼容参数
            existing = {p.name for p in affected_func.params}
            if delta.param_name not in existing:
                patch.priority = 2
                patch.suggestion = (
                    f'{target_module}.{affected_func.name}: '
                    f'上游 {delta.module_name}.{delta.func_name} 新增参数 '
                    f'{delta.param_name}。建议: 透传该参数或提供默认值')
                patch.auto_applicable = self._has_default_in_contract(delta)
            else:
                patch.priority = 5
                patch.suggestion = '参数已存在，无需适配'
                patch.auto_applicable = True

        elif delta.change_kind == 'param_removed':
            patch.action = 'remove_param'
            patch.priority = 1
            patch.suggestion = (
                f'{target_module}.{affected_func.name}: '
                f'上游 {delta.module_name}.{delta.func_name} 删除了参数 '
                f'{delta.param_name}。建议: 从调用中移除该参数，评估功能影响')
            patch.auto_applicable = False

        elif delta.change_kind == 'param_type_changed':
            patch.action = 'update_annotation'
            patch.priority = 3
            patch.suggestion = (
                f'{target_module}.{affected_func.name}: '
                f'上游参数 {delta.param_name} 类型从 {delta.old_signature} '
                f'变更为 {delta.new_signature}。建议: 审查类型兼容性，更新注解')
            patch.auto_applicable = self._is_widening_conversion(
                delta.old_signature, delta.new_signature)

        elif delta.change_kind == 'return_type_changed':
            patch.action = 'update_annotation'
            patch.priority = 2
            patch.suggestion = (
                f'{target_module}.{affected_func.name}: '
                f'上游返回类型从 {delta.old_signature} 变更为 '
                f'{delta.new_signature}。建议: 更新依赖该返回值的代码路径')
            patch.auto_applicable = False

        elif delta.change_kind == 'func_added':
            patch.action = 'no_action'
            patch.priority = 5
            patch.suggestion = '新增函数，下游无需立即适配'
            patch.auto_applicable = True

        return patch

# 适配自动化判定
    @staticmethod
    def _has_default_in_contract(delta: ContractDelta) -> bool:
        """新增参数是否有默认值（从而调用方无需立即修改）。"""
        return '=' in delta.new_signature

    @staticmethod
    def _is_widening_conversion(old_type: str, new_type: str) -> bool:
        """检查是否为拓宽类型转换（旧类型是新类型的子类型）。

        如 int→float, str→Union[str,bytes] 是拓宽；
        float→int, List[int]→str 是窄化或不相容。
        """
        import re

        def base(t: str) -> str:
            m = re.match(r'([a-z_][a-z0-9_]*)', (t or '').strip().lower())
            return m.group(1) if m else ''

        old_base, new_base = base(old_type), base(new_type)

        # 类型层次（简化）
        widening_pairs = {
            ('int', 'float'), ('int', 'complex'),
            ('bool', 'int'),
            ('str', 'bytes'),  # 有争议，保留
        }
        if (old_base, new_base) in widening_pairs:
            return True

        # Union/Optional 检查
        if 'optional' in new_type.lower() or 'union' in new_type.lower():
            return True

        return old_base == new_base

# 报告
    def propagation_report(self, plans: list[PropagationPlan]) -> str:
        """生成 Markdown 传播分析报告。"""
        lines = ['# 合约变更传播分析报告', '']
        for plan in plans:
            d = plan.source_delta
            lines.append(f'## {d.module_name}: {d.change_kind}')
            lines.append(f'- 变更函数: {d.func_name}')
            lines.append(f'- 影响模块: {plan.total_affected}')
            lines.append(f'- 可自动适配: {plan.auto_applicable_count}')
            lines.append('')
            for i, layer in enumerate(plan.propagation_layers):
                lines.append(f'### 传播层 {i+1} (距离={i+1})')
                for p in layer:
                    auto = '[auto]' if p.auto_applicable else '[manual]'
                    lines.append(f'- **{p.target_module}** {auto} P{p.priority}: '
                               f'{p.suggestion}')
                lines.append('')
        return '\n'.join(lines)


# 与 Merkle 树的集成入口
def propagate_from_merkle_diff(module_name: str,
                               old_contract: _StubContract,
                               new_contract: _StubContract) -> list[PropagationPlan]:
    """从两个版本的合约 Merkle 差异自动生成传播计划。

    对接 stub_contract_merkle.diff_contracts 的差异输出，
    将每条差异转换为 ContractDelta 并传播。
    """
    try:
        from modules.stubs.stub_contract_merkle import diff_contracts
    except ImportError:
        return []

    diffs = diff_contracts(old_contract, new_contract)
    deltas = []

    for d in diffs:
        if d.change_type == 'added':
            deltas.append(ContractDelta(
                module_name=module_name, change_kind='func_added',
                func_name=d.func_name,
                new_signature=d.new_hash[:12] if d.new_hash else ''))
        elif d.change_type == 'removed':
            deltas.append(ContractDelta(
                module_name=module_name, change_kind='func_removed',
                func_name=d.func_name,
                old_signature=d.old_hash[:12] if d.old_hash else ''))
        elif d.change_type == 'modified':
            # 从 detail 字符串解析具体变更类型
            detail = d.detail
            if 'removed_params' in detail:
                for pname in _parse_param_list(detail, 'removed_params'):
                    deltas.append(ContractDelta(
                        module_name=module_name, change_kind='param_removed',
                        func_name=d.func_name, param_name=pname))
            if 'added_params' in detail:
                for pname in _parse_param_list(detail, 'added_params'):
                    deltas.append(ContractDelta(
                        module_name=module_name, change_kind='param_added',
                        func_name=d.func_name, param_name=pname))
            if 'return_ann' in detail:
                parts = detail.split('return_ann:')
                if len(parts) > 1:
                    type_change = parts[1].split(';')[0].strip()
                    old_new = type_change.split('→')
                    deltas.append(ContractDelta(
                        module_name=module_name,
                        change_kind='return_type_changed',
                        func_name=d.func_name,
                        old_signature=old_new[0].strip() if len(old_new) > 0 else '',
                        new_signature=old_new[1].strip() if len(old_new) > 1 else ''))
            if '.ann:' in detail or '.default:' in detail or '.kind:' in detail:
                deltas.append(ContractDelta(
                    module_name=module_name,
                    change_kind='param_type_changed',
                    func_name=d.func_name, detail=detail))

    propagator = DeltaPropagator()
    return propagator.propagate_all(deltas)


def _parse_param_list(detail: str, key: str) -> list[str]:
    """从 diff detail 字符串中解析参数名列表。"""
    import re
    m = re.search(rf'{key}:\s*([^;]+)', detail)
    if m:
        return [x.strip() for x in m.group(1).split(',') if x.strip()]
    return []


__all__ = [
    'ContractDelta', 'PropagationPatch', 'PropagationPlan',
    'DeltaPropagator', 'propagate_from_merkle_diff',
]
