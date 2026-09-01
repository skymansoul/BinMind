# stub_sibling_inferrer.py — 姐妹函数合约推断
# 当模块中有部分函数已实现、部分仍为占位时，
# 从已实现函数的模式推断未实现函数的合约细节。
#
# 问题:
#   许多桩模块处于 MIXED 状态: 部分函数已手动实现，部分仍为占位。
#   已实现函数包含丰富的模式信息（命名约定、错误处理风格、类型使用习惯、
#   导入依赖），这些信息对推断同模块未实现函数的合约有参考价值。
#   当前合约构建仅基于 AST 解析 + 文档，忽略了姐妹函数的实现模式。
#
# 方法:
#   1. 解析模块源码 → 分离已实现函数与占位函数
#   2. 从已实现函数提取模式:
#      a) 命名前缀 (detect_*, extract_*, is_*, parse_*)
#      b) 返回类型偏好 (该模块倾向于返回 dict 还是自定义类？)
#      c) 错误处理模式 (raise XxxError vs return None vs assert)
#      d) 参数命名约定 (data vs input vs payload)
#      e) 导入依赖 (已 import 的模块暗示未实现函数可能也需要)
#   3. 将推断结果合并到占位函数的 FuncContract 中
#
# 区别于 specification mining:
#   该论文用 trace slicing 为智能合约挖掘规约。
#   本模块用同模块已实现代码的模式推断未实现部分的合约，
#   不需要执行 trace，基于静态 AST 模式匹配。
import ast as _ast
import os as _os
import re as _re
from collections import Counter as _Ctr
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    StubContract as _StubContract,
    FuncContract as _FuncContract,
    ParamSpec as _ParamSpec,
    StubContractor as _StubContractor,
)


@_dc
class SiblingInference:
    """单个占位函数的姐妹推断结果。"""
    func_name: str
    # 推断的返回类型（来自姐妹函数中最常见的返回类型模式）
    inferred_return_type: str = ''
    return_confidence: float = 0.0
    # 推断的参数名（来自姐妹函数中最常见的参数命名）
    suggested_param_names: list = _field(default_factory=list)
    # 推断的异常（姐妹函数中 raise 的异常类型）
    likely_raises: list = _field(default_factory=list)
    # 推断的必需 import
    suggested_imports: list = _field(default_factory=list)


class SiblingInferrer:
    """姐妹函数合约推断器。"""

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.contractor = _StubContractor(stubs_dir=stubs_dir)

    def infer(self, module_name: str) -> dict[str, SiblingInference]:
        """为模块中所有占位函数执行姐妹推断。"""
        contract = self.contractor.get(module_name)
        if contract is None:
            return {}

        source = self._read_source(module_name)
        if source is None:
            return {}

        # 分离已实现函数与占位函数
        implemented, placeholders = self._classify_functions(source, contract)
        if not implemented:
            return {}

        # 提取姐妹函数的模式
        patterns = self._extract_patterns(implemented, source)

        # 为每个占位函数推断
        results = {}
        for ph in placeholders:
            results[ph.name] = self._infer_for(ph, patterns)

        return results

    @staticmethod
    def _classify_functions(source: str,
                            contract: _StubContract) -> tuple[list, list]:
        """将函数分为已实现与占位两组。"""
        try:
            tree = _ast.parse(source)
        except SyntaxError:
            return [], []

        func_nodes = {}
        for node in tree.body:
            if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                func_nodes[node.name] = node

        implemented = []
        placeholders = []

        for fc in contract.functions:
            node = func_nodes.get(fc.name)
            if node is None:
                placeholders.append(fc)
                continue
            # 判定实现状态: 函数体是否有非占位语句
            meaningful = [
                s for s in node.body
                if not isinstance(s, _ast.Pass)
                and not (isinstance(s, _ast.Expr)
                        and isinstance(getattr(s, 'value', None),
                                      _ast.Constant)
                        and (isinstance(s.value.value, str)
                            or s.value.value is ...))
            ]
            if meaningful:
                implemented.append((fc, node))
            else:
                placeholders.append(fc)

        return implemented, placeholders

    @staticmethod
    def _extract_patterns(implemented: list[tuple],
                          source: str) -> dict:
        """从已实现函数中提取模式字典。"""
        patterns = {
            'return_types': _Ctr(),
            'param_names': _Ctr(),
            'raises': _Ctr(),
            'prefixes': _Ctr(),
            'imports': _Ctr(),
            'decorators': _Ctr(),
        }

        # 收集模块级 import
        try:
            tree = _ast.parse(source)
            for node in tree.body:
                if isinstance(node, _ast.Import):
                    for alias in node.names:
                        patterns['imports'][alias.name.split('.')[0]] += 1
                elif isinstance(node, _ast.ImportFrom):
                    if node.module:
                        patterns['imports'][node.module.split('.')[0]] += 1
        except SyntaxError:
            pass

        for fc, node in implemented:
            # 返回类型
            if node.returns:
                try:
                    ret = _ast.unparse(node.returns)
                    patterns['return_types'][ret] += 1
                except Exception:
                    pass

            # 参数名
            for arg in node.args.args:
                patterns['param_names'][arg.arg] += 1

            # raise 语句
            for child in _ast.walk(node):
                if isinstance(child, _ast.Raise):
                    exc = SiblingInferrer._extract_exception(child)
                    if exc:
                        patterns['raises'][exc] += 1

            # 函数名前缀 (detect_, extract_, parse_, is_, has_, get_, set_, ...)
            m = _re.match(r'^([a-z]+)_', fc.name)
            if m:
                patterns['prefixes'][m.group(1)] += 1

        return patterns

    @staticmethod
    def _infer_for(ph: _FuncContract, patterns: dict) -> SiblingInference:
        """为单个占位函数生成推断。"""
        si = SiblingInference(func_name=ph.name)

        # 返回类型: 最常用的类型（排除 Any/None 若可能）
        if patterns['return_types']:
            total = sum(patterns['return_types'].values())
            top = patterns['return_types'].most_common(1)[0]
            si.inferred_return_type = top[0]
            si.return_confidence = round(top[1] / total, 2)

        # 参数名建议: 占位函数缺少的参数名
        existing_params = {p.name for p in ph.params}
        suggestions = [
            name for name, _ in patterns['param_names'].most_common(5)
            if name not in existing_params and not name.startswith('_')
        ]
        si.suggested_param_names = suggestions[:3]

        # 异常: 最常 raised 的异常类型
        si.likely_raises = [
            exc for exc, _ in patterns['raises'].most_common(3)
        ]

        # import: 最常用的 import
        si.suggested_imports = [
            imp for imp, _ in patterns['imports'].most_common(3)
        ]

        return si

    @staticmethod
    def _extract_exception(raise_node: _ast.Raise) -> _Opt[str]:
        """从 raise 语句提取异常类名。"""
        exc = raise_node.exc
        if isinstance(exc, _ast.Call):
            if isinstance(exc.func, _ast.Name):
                return exc.func.id
        elif isinstance(exc, _ast.Name):
            return exc.id
        return None

    def apply_to_contract(self, module_name: str) -> _Opt[_StubContract]:
        """将姐妹推断结果应用到合约，返回精化后的合约副本。"""
        inferences = self.infer(module_name)
        if not inferences:
            return None

        contract = self.contractor.get(module_name)
        if contract is None:
            return None

        for fc in contract.functions:
            si = inferences.get(fc.name)
            if si is None:
                continue
            # 仅对无返回注解的占位函数应用推断
            if not fc.return_ann and si.return_confidence >= 0.5:
                fc.return_ann = si.inferred_return_type
            # 补充缺失的异常声明
            for exc in si.likely_raises:
                if exc not in fc.raises:
                    fc.raises.add(exc)

        return contract

    @staticmethod
    def _read_source(module_name: str) -> _Opt[str]:
        path = _os.path.join(
            _os.path.dirname(_os.path.abspath(__file__)),
            f'{module_name}.py')
        if not _os.path.isfile(path):
            return None
        try:
            return open(path, encoding='utf-8').read()
        except (OSError, UnicodeDecodeError):
            return None


__all__ = ['SiblingInference', 'SiblingInferrer']
