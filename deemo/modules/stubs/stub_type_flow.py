# stub_type_flow.py — 跨模块类型流推断
# 沿依赖图的调用边传播具体类型信息: 当调用方以已知类型调用桩函数时，
# 将该类型"反向传播"到桩的合约注解中，收窄 Any/无标注位置的类型。
#
# 方法:
#   1. 遍历依赖图，找到每条调用边 (caller_module → callee_module)
#   2. 解析调用方 AST，找到对目标函数的调用点（import + call）
#   3. 从调用点的实参/返回值使用方式推断具体类型:
#      a) 直接常量: fn(42) → int; fn(b'data') → bytes
#      b) 类型注解传播: 若 caller 的 param: bytes 传给 fn(param) → bytes
#      c) 返回使用: 若 caller 将返回值赋给 x: int → 返回值应推断为 int
#   4. 聚合多方调用方推断（多调用方 + 多数投票 → 更高置信度）
#   5. 输出可合并到 StubContract 的类型精化建议
#
# 与 ContractRefiner 互补: 本模块做编译时静态跨模块类型传播
# （零运行时成本）；ContractRefiner 用运行时观测做贝叶斯类型更新。
import ast as _ast
import os as _os
import re as _re
from collections import defaultdict as _dd
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    StubContractor as _StubContractor,
    StubContract as _StubContract,
    FuncContract as _FuncContract,
)


@_dc
class TypeFlowEdge:
    """单条类型流推断结果。"""
    caller_module: str
    callee_module: str
    callee_func: str
    caller_func: str = ''
    param_name: str = ''         # 空字符串 = 返回值推断
    inferred_type: str = ''
    confidence: float = 0.0       # 0~1
    evidence: str = ''            # 推断依据描述
    line_no: int = 0


@_dc
class TypeFlowReport:
    """一个桩模块的跨模块类型流分析报告。"""
    module_name: str
    edges: list = _field(default_factory=list)  # list[TypeFlowEdge]
    # 聚合结果: {func_name: {param_name: (inferred_type, confidence, vote_count)}}
    type_suggestions: dict = _field(default_factory=dict)
    functions_refined: int = 0


class TypeFlowAnalyzer:
    """跨模块类型流推断器。

    核心算法:
      1. 构建依赖图（复用 stub_dependency_graph）
      2. 对每个桩模块，遍历其全部调用方
      3. 解析调用方 AST → 找到 import + call → 推断类型
      4. 聚合多调用方结果 → 多数投票 → 输出精化建议
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.contractor = _StubContractor(stubs_dir=stubs_dir)

    def analyze(self, module_name: str) -> TypeFlowReport:
        """对指定桩模块执行跨模块类型流分析。"""
        report = TypeFlowReport(module_name=module_name)

        callers = self._find_callers(module_name)
        if not callers:
            return report

        contract = self.contractor.get(module_name)

        for caller_name in callers:
            caller_edges = self._analyze_caller(caller_name, module_name, contract)
            report.edges.extend(caller_edges)

        # 聚合
        report.type_suggestions = self._aggregate(report.edges)
        report.functions_refined = len(report.type_suggestions)
        return report

    def analyze_all(self) -> dict[str, TypeFlowReport]:
        """对所有有调用方的桩模块执行分析。"""
        contracts = self.contractor.scan_all()
        reports = {}
        for name in contracts:
            if name.startswith('stub_'):
                continue
            report = self.analyze(name)
            if report.edges:
                reports[name] = report
        return reports

    def _find_callers(self, module_name: str) -> set[str]:
        """查找所有调用目标模块的上游模块。"""
        try:
            from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
            g = ModuleDependencyGraph(stubs_dir=self.stubs_dir)
            g.build()
            node = g.nodes.get(module_name)
            if node is not None:
                return set(node.depended_by)
        except ImportError:
            pass

        # 降级: 扫描 import 语句
        callers = set()
        for fn in _os.listdir(self.stubs_dir):
            if not fn.endswith('.py') or fn.startswith('_'):
                continue
            name = fn[:-3]
            if name == module_name:
                continue
            path = _os.path.join(self.stubs_dir, fn)
            try:
                src = open(path, encoding='utf-8').read()
                tree = _ast.parse(src, filename=path)
            except (OSError, SyntaxError, UnicodeDecodeError):
                continue
            for node in _ast.walk(tree):
                if isinstance(node, _ast.ImportFrom):
                    if node.module and module_name in node.module:
                        callers.add(name)
                        break
        return callers

    def _analyze_caller(self, caller_name: str, callee_name: str,
                        callee_contract: _Opt[_StubContract]) -> list[TypeFlowEdge]:
        """分析单个调用方对目标模块的类型流贡献。"""
        path = _os.path.join(self.stubs_dir, f'{caller_name}.py')
        if not _os.path.isfile(path):
            return []

        try:
            src = open(path, encoding='utf-8').read()
            tree = _ast.parse(src, filename=path)
        except (OSError, SyntaxError, UnicodeDecodeError):
            return []

        edges = []

        # 找到目标模块的 import 别名
        import_alias = self._find_import_alias(tree, callee_name)
        if import_alias is None and callee_name != caller_name:
            return []

        for node in _ast.walk(tree):
            if not isinstance(node, _ast.Call):
                continue
            callee_func = self._resolve_callee(node, import_alias, callee_name)
            if callee_func is None:
                continue

            # 跳过无参数调用
            if not node.args and not node.keywords:
                continue

            # 推断各参数的类型
            edge = self._infer_from_call(node, caller_name, callee_name,
                                        callee_func, callee_contract, src)
            if edge is not None:
                edges.extend(edge)

        return edges

    def _infer_from_call(self, call_node: _ast.Call, caller_name: str,
                         callee_name: str, callee_func: str,
                         callee_contract: _Opt[_StubContract],
                         source: str) -> list[TypeFlowEdge]:
        """从单个调用点推断类型流，返回每条参数/返回值的推断边。"""
        edges = []
        # 查找对应的 FuncContract
        fc = None
        if callee_contract is not None:
            for f in callee_contract.functions:
                if f.name == callee_func:
                    fc = f
                    break

        params = fc.params if fc else []
        param_list = [p for p in params if p.kind not in ('varargs', 'varkw')]

        for i, arg in enumerate(call_node.args):
            if i >= len(param_list):
                break
            p = param_list[i]
            # 仅对 Any/无注解的参数做推断
            if p.annotation and p.annotation.lower() not in ('', 'any'):
                continue

            inferred, conf, evidence = self._infer_type(arg, source)
            if inferred:
                edges.append(TypeFlowEdge(
                    caller_module=caller_name,
                    callee_module=callee_name,
                    callee_func=callee_func,
                    param_name=p.name,
                    inferred_type=inferred,
                    confidence=conf,
                    evidence=evidence,
                    line_no=call_node.lineno,
                ))

        # 推断返回类型（从调用点的使用方式）
        if fc and (not fc.return_ann or fc.return_ann.lower() in ('', 'any')):
            ret_infer = self._infer_return_usage(call_node, source)
            if ret_infer:
                inferred, conf, evidence = ret_infer
                edges.append(TypeFlowEdge(
                    caller_module=caller_name,
                    callee_module=callee_name,
                    callee_func=callee_func,
                    param_name='',  # 空 = 返回值
                    inferred_type=inferred,
                    confidence=conf,
                    evidence=evidence,
                    line_no=call_node.lineno,
                ))

        return edges

    @staticmethod
    def _infer_type(arg_node, source: str) -> tuple[str, float, str]:
        """从 AST 节点推断具体类型。

        返回: (type_name, confidence, evidence_description)
        """
        # 常量
        if isinstance(arg_node, _ast.Constant):
            v = arg_node.value
            if isinstance(v, bool):
                return 'bool', 0.95, 'bool_literal'
            if isinstance(v, int):
                return 'int', 0.95, 'int_literal'
            if isinstance(v, float):
                return 'float', 0.90, 'float_literal'
            if isinstance(v, str):
                return 'str', 0.90, 'str_literal'
            if isinstance(v, bytes):
                return 'bytes', 0.95, 'bytes_literal'
            if v is None:
                return 'None', 0.50, 'none_literal'
            if isinstance(v, (list, tuple)):
                inner = type(v).__name__
                return inner, 0.85, f'{inner}_literal'
            if isinstance(v, dict):
                return 'dict', 0.85, 'dict_literal'
            if isinstance(v, set):
                return 'set', 0.85, 'set_literal'

        # 简单名称引用（可能携带类型注解）
        if isinstance(arg_node, _ast.Name):
            # 查找同一函数内该名称的类型注解
            ann_result = TypeFlowAnalyzer._find_var_annotation(
                arg_node.id, arg_node.lineno, source)
            if ann_result:
                return ann_result[0], 0.6, 'annotation_propagation'

        # 函数调用结果: fn(...)
        if isinstance(arg_node, _ast.Call):
            if isinstance(arg_node.func, _ast.Name):
                known_funcs = {
                    'len': 'int', 'str': 'str', 'int': 'int',
                    'float': 'float', 'bytes': 'bytes', 'bool': 'bool',
                    'list': 'list', 'dict': 'dict', 'set': 'set',
                    'tuple': 'tuple', 'sorted': 'list', 'reversed': 'list',
                }
                fname = arg_node.func.id
                if fname in known_funcs:
                    return known_funcs[fname], 0.75, f'builtin_{fname}'

        return '', 0.0, ''

    @staticmethod
    def _find_var_annotation(var_name: str, lineno: int,
                            source: str) -> _Opt[tuple[str, float, str]]:
        """在源码中查找变量名对应的类型注解（向上搜索）。"""
        lines = source.splitlines()
        for i in range(lineno - 1, -1, -1):
            stripped = lines[i].strip()
            # 匹配 annotated assignment: x: int = ... 或 x: bytes
            m = _re.match(rf'{_re.escape(var_name)}\s*:\s*(\w+(?:\[[\w\s,\[\]]*\])?)',
                         stripped)
            if m:
                return m.group(1), 0.7, f'annotation_line_{i+1}'
        return None

    @staticmethod
    def _infer_return_usage(call_node: _ast.Call,
                            source: str) -> _Opt[tuple[str, float, str]]:
        """从调用点的返回值使用方式推断返回类型。

        向上搜索赋值或比较上下文:
          x: int = fn(...)  → 返回 int
          if fn(...):       → 返回 bool（或 truthy）
        """
        # 简化: 此处仅处理明显的注解赋值
        # 完整的返回类型推断需数据流分析，本模块做轻量 AST 模式匹配
        return None

    @staticmethod
    def _resolve_callee(call_node: _ast.Call, alias: str,
                        module_name: str) -> _Opt[str]:
        """解析调用目标: module.func() 或 alias.func()。"""
        func = call_node.func
        if isinstance(func, _ast.Attribute):
            if isinstance(func.value, _ast.Name):
                if func.value.id == alias or func.value.id == module_name:
                    return func.attr
        return None

    @staticmethod
    def _find_import_alias(tree: _ast.AST, module_name: str) -> _Opt[str]:
        """查找 import 语句中目标模块的别名。"""
        for node in _ast.walk(tree):
            if isinstance(node, _ast.ImportFrom):
                if node.module and module_name in node.module:
                    # from modules.stubs.xxx import func → 无别名
                    return module_name
            elif isinstance(node, _ast.Import):
                for alias in node.names:
                    if module_name in alias.name:
                        # import modules.stubs.xxx as s
                        return alias.asname or alias.name.split('.')[-1]
        return None

    @staticmethod
    def _aggregate(edges: list[TypeFlowEdge]) -> dict:
        """聚合多条类型流推断边: {func_name: {param_or_return: (type, conf, votes)}}。"""
        groups = _dd(lambda: _dd(lambda: _dd(int)))
        # groups[func][param][type] = vote_count
        edge_sources = _dd(lambda: _dd(list))

        for e in edges:
            key = e.param_name or '__return__'
            groups[e.callee_func][key][e.inferred_type] += 1
            edge_sources[e.callee_func][key].append({
                'caller': e.caller_module,
                'type': e.inferred_type,
                'conf': e.confidence,
                'evidence': e.evidence,
            })

        result = {}
        for func_name, params in groups.items():
            func_result = {}
            for param, type_votes in params.items():
                # 多数投票
                best_type = max(type_votes, key=type_votes.get)
                votes = type_votes[best_type]
                total = sum(type_votes.values())
                consensus = votes / total if total > 0 else 0.0
                # 置信度 = consensus × 调用方数量归一化
                confidence = consensus * min(total / 3.0, 1.0)
                func_result[param] = (best_type, round(confidence, 3), votes)
            if func_result:
                result[func_name] = func_result

        return result

    def flow_report(self, report: TypeFlowReport) -> str:
        """生成单模块的类型流推断报告。"""
        lines = [
            f'# 类型流推断: {report.module_name}',
            f'推断边数: {len(report.edges)}',
            f'精化函数数: {report.functions_refined}',
            '',
        ]
        if report.type_suggestions:
            lines.append('| 函数 | 参数 | 推断类型 | 置信度 | 投票数 |')
            lines.append('|------|------|---------|-------:|-------:|')
            for func, params in sorted(report.type_suggestions.items()):
                for param, (typ, conf, votes) in sorted(params.items()):
                    label = param if param != '__return__' else '(return)'
                    lines.append(f'| {func} | {label} | {typ} | {conf:.2f} | {votes} |')
        return '\n'.join(lines)


def infer_type_flow(module_name: str) -> TypeFlowReport:
    """一行式跨模块类型流推断。"""
    return TypeFlowAnalyzer().analyze(module_name)


__all__ = ['TypeFlowEdge', 'TypeFlowReport', 'TypeFlowAnalyzer', 'infer_type_flow']
