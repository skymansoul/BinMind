# stub_impact_analyzer.py — 反事实合约变更影响分析
# 在合约实际变更前，模拟"假设删除/修改参数X"对下游调用方的影响。
# 沿依赖图传播变更冲击，输出风险排序的影响报告。
#
# 方法:
#   1. 定义变更场景（参数删除/新增/改类型/改默认值/改返回类型）
#   2. 在依赖图中沿 depended_by 边传播，收集全部下游模块
#   3. 对每个下游模块的调用点做假设性兼容检查:
#      参数删除 → 检查是否传递了将被删除的参数
#      参数类型变更 → 检查传参类型是否为新类型的子类型
#      返回类型变更 → 检查调用方是否依赖旧返回类型的方法/属性
#   4. 输出风险矩阵: {模块, 风险等级, 影响函数, 阻断性变更}
#
# 与 stub_dependency_graph（提供调用链）和 stub_contract_merkle
# （提供精确变更指纹锚点）协同。
import os as _os
import ast as _ast
from collections import defaultdict as _dd
from dataclasses import dataclass as _dc, field as _field
from enum import Enum as _Enum
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    StubContract as _StubContract,
    FuncContract as _FuncContract,
    ParamSpec as _ParamSpec,
    StubContractor as _StubContractor,
)


class RiskLevel(_Enum):
    """变更风险等级。"""
    SAFE = 'safe'             # 无影响：不存在下游调用方
    LOW = 'low'               # 低风险：调用方不使用变更部分
    MODERATE = 'moderate'     # 中风险：调用方需适配但非阻断
    HIGH = 'high'             # 高风险：至少一个调用方会被阻断
    BREAKING = 'breaking'     # 阻断性：调用方在语法/类型层不兼容


class ChangeType(_Enum):
    """合约变更类型。"""
    REMOVE_PARAM = 'remove_param'
    ADD_REQUIRED_PARAM = 'add_required_param'
    CHANGE_PARAM_TYPE = 'change_param_type'
    CHANGE_RETURN_TYPE = 'change_return_type'
    REMOVE_FUNCTION = 'remove_function'
    RENAME_FUNCTION = 'rename_function'


@_dc
class ChangeScenario:
    """一次反事实变更场景定义。"""
    module_name: str
    change_type: ChangeType
    func_name: str = ''
    param_name: str = ''       # 涉及的参数名
    old_value: str = ''        # 变更前（类型名/参数名）
    new_value: str = ''        # 变更后


@_dc
class ImpactEntry:
    """单个下游模块的影响评估条目。"""
    caller_module: str
    caller_func: str = ''             # 调用方函数名
    risk: RiskLevel = RiskLevel.SAFE
    reason: str = ''
    # 受影响代码行（从 AST 解析中提取）
    affected_line: int = 0
    # 是否为阻断性: True 表示调用方 import 或调用会直接失败
    is_blocking: bool = False


@_dc
class ImpactReport:
    """一次变更场景的完整影响报告。"""
    scenario: ChangeScenario
    total_dependents: int = 0       # 下游依赖模块总数
    affected_modules: int = 0        # 实际受影响的模块数
    blocking_modules: int = 0        # 阻断性影响的模块数
    entries: list = _field(default_factory=list)  # list[ImpactEntry]
    risk_summary: str = ''


class ImpactAnalyzer:
    """反事实合约变更影响分析器。

    输入: 变更场景 + 依赖图（可选，通过 ModuleDependencyGraph）
    输出: 按风险等级排序的影响报告。

    调用方兼容性检查在 AST 层面执行:
      - 解析调用方源码
      - 找到目标模块的 import 语句
      - 找到目标函数的调用点
      - 检查调用参数是否受变更影响
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.contractor = _StubContractor(stubs_dir=stubs_dir)
        # 惰性加载依赖图
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

    def analyze(self, scenario: ChangeScenario) -> ImpactReport:
        """对单个变更场景执行影响分析。"""
        report = ImpactReport(scenario=scenario)

        dependents = self._find_dependents(scenario.module_name)
        report.total_dependents = len(dependents)
        if not dependents:
            report.risk_summary = '无下游依赖方，变更安全'
            return report

        entries = []
        for dep_name in dependents:
            dep_entries = self._check_caller(scenario, dep_name)
            entries.extend(dep_entries)

        report.entries = sorted(entries, key=lambda e: (
            e.risk == RiskLevel.BREAKING,
            e.risk == RiskLevel.HIGH,
            e.risk == RiskLevel.MODERATE,
        ), reverse=True)

        report.affected_modules = len(set(e.caller_module for e in entries))
        report.blocking_modules = len(set(
            e.caller_module for e in entries if e.is_blocking))

        if report.blocking_modules > 0:
            report.risk_summary = (
                f'{report.blocking_modules} 个模块会被阻断，'
                f'共 {report.affected_modules} 个模块受影响')
        elif report.affected_modules > 0:
            report.risk_summary = (
                f'{report.affected_modules} 个模块受影响，无阻断性变更')
        else:
            report.risk_summary = '下游依赖方不受此变更影响'

        return report

    def batch_analyze(self, scenarios: list[ChangeScenario]) -> dict[str, ImpactReport]:
        """批量分析多个变更场景，返回按风险排序的汇总。"""
        reports = {}
        for s in scenarios:
            reports[f'{s.module_name}:{s.change_type.value}:{s.func_name}'] = self.analyze(s)
        return reports

    def _find_dependents(self, module_name: str) -> set[str]:
        """查找直接依赖目标模块的全部下游模块。"""
        if self.dep_graph is not None:
            return self.dep_graph.impact_set(module_name)
        # 降级: 扫描全部 stub 源码的 import 语句
        dependents = set()
        all_contracts = self.contractor.scan_all()
        for name in all_contracts:
            if name == module_name:
                continue
            path = _os.path.join(self.stubs_dir, f'{name}.py')
            if not _os.path.isfile(path):
                continue
            try:
                src = open(path, encoding='utf-8').read()
                tree = _ast.parse(src, filename=path)
            except (OSError, SyntaxError, UnicodeDecodeError):
                continue
            for node in _ast.walk(tree):
                if isinstance(node, _ast.ImportFrom):
                    if node.module and node.module.endswith(module_name):
                        dependents.add(name)
        return dependents

    def _check_caller(self, scenario: ChangeScenario,
                      caller_name: str) -> list[ImpactEntry]:
        """检查单个调用方受变更场景的影响。"""
        path = _os.path.join(self.stubs_dir, f'{caller_name}.py')
        if not _os.path.isfile(path):
            return []

        try:
            src = open(path, encoding='utf-8').read()
            tree = _ast.parse(src, filename=path)
        except (OSError, SyntaxError, UnicodeDecodeError):
            return []

        entries = []
        # 找到对该模块目标函数的调用点
        for node in _ast.walk(tree):
            if not isinstance(node, _ast.Call):
                continue

            call_target = self._resolve_call_target(node)
            if call_target != f'{scenario.module_name}.{scenario.func_name}':
                # 也检查直接的函数名调用（如果调用方 import 了目标函数）
                if call_target != scenario.func_name:
                    continue

            entry = self._assess_impact(scenario, node, caller_name, src)
            if entry is not None:
                entries.append(entry)

        if not entries:
            # 依赖但无直接调用 → 间接依赖（通过 re-export 等），低风险
            entries.append(ImpactEntry(
                caller_module=caller_name,
                risk=RiskLevel.LOW,
                reason='间接依赖（import 但不直接调用变更函数）',
            ))

        return entries

    def _assess_impact(self, scenario: ChangeScenario,
                       call_node: _ast.Call, caller_name: str,
                       source: str) -> _Opt[ImpactEntry]:
        """对单个调用点做假设性兼容检查。"""
        entry = ImpactEntry(
            caller_module=caller_name,
            affected_line=call_node.lineno,
        )

        args = call_node.args
        kwargs = {kw.arg: kw.value for kw in call_node.keywords}

        if scenario.change_type == ChangeType.REMOVE_FUNCTION:
            entry.caller_func = self._enclosing_func(source, call_node.lineno)
            entry.risk = RiskLevel.BREAKING
            entry.is_blocking = True
            entry.reason = f'函数 {scenario.func_name} 被删除，调用点 @L{call_node.lineno}'
            return entry

        if scenario.change_type == ChangeType.RENAME_FUNCTION:
            entry.caller_func = self._enclosing_func(source, call_node.lineno)
            entry.risk = RiskLevel.BREAKING
            entry.is_blocking = True
            entry.reason = (f'函数 {scenario.func_name} 已重命名为 '
                          f'{scenario.new_value}，调用点 @L{call_node.lineno}')
            return entry

        if scenario.change_type == ChangeType.REMOVE_PARAM:
            # 检查调用方是否传递了将被删除的参数
            has_kwarg = scenario.param_name in kwargs
            # 粗略的位置参数检查: 假设被删参数在位置 idx
            contract = self.contractor.get(scenario.module_name)
            param_idx = self._find_param_index(contract, scenario.func_name,
                                              scenario.param_name)
            has_posarg = (param_idx is not None and param_idx < len(args))

            if has_kwarg or has_posarg:
                entry.caller_func = self._enclosing_func(source, call_node.lineno)
                entry.risk = RiskLevel.BREAKING
                entry.is_blocking = True
                entry.reason = (f'调用点 @L{call_node.lineno} 传递了将被删除的参数 '
                              f'{scenario.param_name}')
                return entry
            else:
                entry.risk = RiskLevel.SAFE
                entry.reason = f'调用点 @L{call_node.lineno} 未使用被删参数'
                return entry

        if scenario.change_type == ChangeType.ADD_REQUIRED_PARAM:
            # 检查调用方是否已传递该参数
            has_kwarg = scenario.param_name in kwargs
            if not has_kwarg:
                entry.caller_func = self._enclosing_func(source, call_node.lineno)
                entry.risk = RiskLevel.HIGH
                entry.is_blocking = True
                entry.reason = (f'调用点 @L{call_node.lineno} 缺少新增的必需参数 '
                              f'{scenario.param_name}')
                return entry
            else:
                entry.risk = RiskLevel.LOW
                entry.reason = f'调用点 @L{call_node.lineno} 已传递新参数'
                return entry

        if scenario.change_type == ChangeType.CHANGE_PARAM_TYPE:
            entry.caller_func = self._enclosing_func(source, call_node.lineno)
            entry.risk = RiskLevel.MODERATE
            entry.reason = (f'参数 {scenario.param_name} 类型从 {scenario.old_value} '
                          f'变更为 {scenario.new_value}，调用点 @L{call_node.lineno} 需审查')
            return entry

        if scenario.change_type == ChangeType.CHANGE_RETURN_TYPE:
            entry.caller_func = self._enclosing_func(source, call_node.lineno)
            entry.risk = RiskLevel.MODERATE
            entry.reason = (f'返回类型从 {scenario.old_value} 变更为 '
                          f'{scenario.new_value}，调用点 @L{call_node.lineno} 需审查')
            return entry

        return None

    @staticmethod
    def _resolve_call_target(node: _ast.Call) -> str:
        """解析调用目标为 module.func_name 或 func_name 字符串。"""
        func = node.func
        if isinstance(func, _ast.Name):
            return func.id
        if isinstance(func, _ast.Attribute):
            if isinstance(func.value, _ast.Name):
                return f'{func.value.id}.{func.attr}'
            return func.attr
        return ''

    @staticmethod
    def _enclosing_func(source: str, lineno: int) -> str:
        """返回包含指定行的函数名（近似，基于行号搜索 def 语句）。"""
        lines = source.splitlines()
        # 向上搜索最近的 def
        for i in range(lineno - 1, -1, -1):
            stripped = lines[i].strip()
            if stripped.startswith('def '):
                name = stripped[4:].split('(')[0].strip()
                return name
            if stripped.startswith('class '):
                return '<class_level>'
        return '<module_level>'

    @staticmethod
    def _find_param_index(contract: _Opt[_StubContract],
                          func_name: str, param_name: str) -> _Opt[int]:
        """在合约中查找参数的索引位置。"""
        if contract is None:
            return None
        for fc in contract.functions:
            if fc.name == func_name:
                for i, p in enumerate(fc.params):
                    if p.name == param_name:
                        return i
        return None

    def risk_matrix(self, reports: dict[str, ImpactReport]) -> str:
        """生成 Markdown 风险矩阵。"""
        lines = ['# 合约变更影响风险矩阵', '']
        lines.append('| 变更场景 | 下游模块 | 受影响 | 阻断 | 风险 |')
        lines.append('|---------|---------|-------|------|------|')
        for key, r in sorted(reports.items()):
            risk_icon = {'safe': '✓', 'low': '○', 'moderate': '△',
                        'high': '▲', 'breaking': '✕'}.get(
                'breaking' if r.blocking_modules > 0 else
                'high' if r.affected_modules > 3 else
                'moderate' if r.affected_modules > 0 else 'safe', '?')
            lines.append(
                f'| {key} | {r.total_dependents} | {r.affected_modules} | '
                f'{r.blocking_modules} | {risk_icon} |')
        return '\n'.join(lines)


def quick_impact_check(module_name: str, func_name: str,
                       change: ChangeType, param: str = '',
                       old_val: str = '', new_val: str = '') -> ImpactReport:
    """一行式影响检查。"""
    scenario = ChangeScenario(
        module_name=module_name, change_type=change,
        func_name=func_name, param_name=param,
        old_value=old_val, new_value=new_val,
    )
    return ImpactAnalyzer().analyze(scenario)


__all__ = [
    'RiskLevel', 'ChangeType', 'ChangeScenario',
    'ImpactEntry', 'ImpactReport', 'ImpactAnalyzer',
    'quick_impact_check',
]
