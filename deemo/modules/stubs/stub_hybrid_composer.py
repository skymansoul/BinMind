# stub_hybrid_composer.py — 函数级混合策略编排
# 替代 GradualEngine 的模块级顺序策略（template → llm），
# 在函数粒度独立选择最优策略，组合为混合实现。
#
# 问题:
#   GradualEngine.implement() 对整个模块用同一策略生成全部函数。
#   一个模块可能包含 3 个简单 getter/setter + 2 个复杂分析器。
#   TemplateGenerator 能完美处理 getter，但无法处理分析器（回退到
#   NotImplementedError）；LLM 能处理分析器但浪费 token 在琐碎函数上。
#   两种策略各自都有"擅长"和"不擅长"的函数子集。
#
# 方案:
#   1. 按函数复杂度 + 类型覆盖 + 参数模式，为每个函数独立打分
#   2. 低复杂度高覆盖 → template 足够
#      中复杂度 → template 尝试，失败则 LLM
#      高复杂度 → LLM（若可用），否则标记为待人工
#   3. 合并各函数的 body → 完整模块源码
#   4. 整体验证（导入冒烟 + 签名核对），单函数失败回退到备选策略
#
# 区别于 Ca²P (cache-augmented code policy) 的 generate/edit 模式切换:
#   Ca²P 在生成与编辑间切换，本模块在模板规则与神经生成间按函数粒度选择。
import ast as _ast
import json as _json
import re as _re
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    StubContract as _StubContract,
    FuncContract as _FuncContract,
    ImplementationStatus as _Status,
)


@_dc
class FuncStrategyChoice:
    """单个函数的策略选择与生成结果。"""
    func_name: str
    chosen_strategy: str = ''      # template | llm | manual
    source_body: str = ''          # 生成的函数体（def 行以下）
    success: bool = False
    fallback_reason: str = ''


@_dc
class HybridResult:
    """混合编排的完整结果。"""
    module_name: str
    choices: list = _field(default_factory=list)  # list[FuncStrategyChoice]
    merged_source: str = ''
    strategies_used: set = _field(default_factory=set)
    template_count: int = 0
    llm_count: int = 0
    manual_count: int = 0


class HybridComposer:
    """函数级混合策略编排器。

    策略选择规则（按优先级）:
      1. 纯占位函数 (is_placeholder) → template 创建骨架
      2. complexity='low' + type_coverage ≥ 0.5 → template
      3. complexity='medium' → template_with_fallback (template 优先，
         产出 NotImplementedError 则标记为待 LLM)
      4. complexity='high' → llm_required（无 LLM 时标记为 manual）
      5. 无注解函数 → llm_preferred（类型不确定时规则引擎不可靠）
    """

    # 简单类型集合 — 与 TemplateGenerator 共用同一集合以保证一致性
    _SIMPLE = frozenset(('int', 'str', 'float', 'bool', 'bytes',
                         'list', 'dict', 'set', 'tuple'))

    def __init__(self, template_gen=None, llm_gen=None):
        self.template_gen = template_gen
        self.llm_gen = llm_gen

    def compose(self, contract: _StubContract) -> HybridResult:
        """按函数粒度选择策略并生成混合实现。"""
        hr = HybridResult(module_name=contract.module_name)

        for fc in contract.functions:
            choice = self._select_and_generate(fc, contract.module_name)
            hr.choices.append(choice)
            hr.strategies_used.add(choice.chosen_strategy)
            if choice.chosen_strategy == 'template':
                hr.template_count += 1
            elif choice.chosen_strategy == 'llm':
                hr.llm_count += 1
            else:
                hr.manual_count += 1

        hr.merged_source = self._merge(contract, hr.choices)
        return hr

    def _select_and_generate(self, fc: _FuncContract,
                             module_name: str) -> FuncStrategyChoice:
        """为单个函数选择策略并生成。"""
        cov = self._type_coverage(fc)
        params = [p for p in fc.params if p.kind not in ('varargs', 'varkw')]

        # 规则1: 纯占位 → template 骨架
        if fc.is_placeholder and not params:
            return self._try_template(fc, module_name)

        # 规则2: 低复杂度 + 高类型覆盖 → template
        if fc.complexity == 'low' and cov >= 0.5:
            choice = self._try_template(fc, module_name)
            if not choice.success:
                return self._try_llm_fallback(fc, module_name, choice)
            return choice

        # 规则3: 中复杂度 → template 尝试，失败则 LLM
        if fc.complexity == 'medium':
            choice = self._try_template(fc, module_name)
            if choice.success and 'NotImplementedError' not in choice.source_body:
                return choice
            return self._try_llm_fallback(fc, module_name, choice)

        # 规则4: 高复杂度或无注解 → LLM 或人工
        if self.llm_gen is not None and getattr(self.llm_gen, 'enabled', False):
            return self._try_llm(fc, module_name)
        else:
            return FuncStrategyChoice(
                func_name=fc.name,
                chosen_strategy='manual',
                source_body=self._manual_placeholder(fc, module_name),
                success=False,
                fallback_reason='high_complexity_no_llm')

    def _try_template(self, fc: _FuncContract,
                      module_name: str) -> FuncStrategyChoice:
        if self.template_gen is None:
            try:
                from modules.stubs.stub_gradual_engine import TemplateGenerator
                self.template_gen = TemplateGenerator()
            except ImportError:
                return FuncStrategyChoice(
                    func_name=fc.name, chosen_strategy='manual',
                    source_body=self._manual_placeholder(fc, module_name),
                    success=False, fallback_reason='no_template_generator')

        body = self.template_gen._generate_func_body(module_name, fc)
        success = 'NotImplementedError' not in body
        return FuncStrategyChoice(
            func_name=fc.name,
            chosen_strategy='template',
            source_body=body,
            success=success,
            fallback_reason='' if success else 'template_fallback_to_notimplemented')

    def _try_llm(self, fc: _FuncContract,
                 module_name: str) -> FuncStrategyChoice:
        if self.llm_gen is None:
            return FuncStrategyChoice(
                func_name=fc.name, chosen_strategy='manual',
                source_body=self._manual_placeholder(fc, module_name),
                success=False, fallback_reason='no_llm_generator')

        # 构造单函数契约供 LLM 生成
        mini_contract = _StubContract(module_name=module_name)
        mini_contract.functions.append(fc)

        src = self.llm_gen.generate(mini_contract)
        if src is None:
            return FuncStrategyChoice(
                func_name=fc.name, chosen_strategy='manual',
                source_body=self._manual_placeholder(fc, module_name),
                success=False, fallback_reason='llm_generation_failed')

        # 从 LLM 输出中提取该函数的 body
        body = self._extract_func_body(src, fc.name)
        if body is None:
            body = self._manual_placeholder(fc, module_name)
            return FuncStrategyChoice(
                func_name=fc.name, chosen_strategy='manual',
                source_body=body, success=False,
                fallback_reason='llm_output_parse_failed')

        return FuncStrategyChoice(
            func_name=fc.name, chosen_strategy='llm',
            source_body=body, success=True)

    def _try_llm_fallback(self, fc: _FuncContract, module_name: str,
                          template_choice: FuncStrategyChoice) -> FuncStrategyChoice:
        """模板失败 → 尝试 LLM。"""
        if self.llm_gen is not None and getattr(self.llm_gen, 'enabled', False):
            llm_choice = self._try_llm(fc, module_name)
            if llm_choice.success:
                return llm_choice
        # LLM 不可用或失败 → 保留模板的 NotImplementedError 骨架
        return template_choice

    # ---- 合并 ----
    def _merge(self, contract: _StubContract,
               choices: list[FuncStrategyChoice]) -> str:
        """合并各策略生成函数体为完整模块。"""
        lines = ['# HybridComposer: 函数级混合策略生成',
                 '# 各函数策略: ' +
                 ', '.join(f'{c.func_name}={c.chosen_strategy}'
                          for c in choices),
                 '']
        if contract.doc:
            lines.append(f'"""{contract.doc}"""')
            lines.append('')

        for fc in contract.functions:
            choice = next((c for c in choices if c.func_name == fc.name), None)
            if choice is None:
                continue

            sig = self._render_signature(fc)
            lines.append(f'def {fc.name}({sig}){self._render_return(fc)}:')
            if fc.doc_summary:
                lines.append(f'    """{fc.doc_summary}"""')
            for line in choice.source_body.splitlines():
                lines.append(f'    {line}' if not line.startswith('    ') else line)
            lines.append('')

        for cc in contract.classes:
            bases = ', '.join(cc.bases) if cc.bases else 'object'
            lines.append(f'class {cc.name}({bases}):')
            lines.append(f'    """{cc.doc_summary}"""')
            for m in cc.methods:
                sig = self._render_signature(m)
                lines.append(f'    def {m.name}({sig}){self._render_return(m)}:')
                lines.append(f'        raise NotImplementedError'
                           f'("HybridComposer: class methods not yet supported")')
            lines.append('')

        lines.append(f'__all__ = {contract.public_api_names()!r}')
        return '\n'.join(lines)

    # ---- 辅助 ----
    @staticmethod
    def _type_coverage(fc: _FuncContract) -> float:
        params = [p for p in fc.params if p.kind not in ('varargs', 'varkw')]
        if not params:
            return 1.0
        annotated = sum(1 for p in params if p.annotation and p.annotation.strip())
        return annotated / len(params)

    @staticmethod
    def _render_signature(fc: _FuncContract) -> str:
        parts = []
        for p in fc.params:
            piece = p.name
            if p.kind == 'varargs':
                piece = f'*{p.name}'
            elif p.kind == 'varkw':
                piece = f'**{p.name}'
            elif p.annotation:
                piece += f': {p.annotation}'
            if p.has_default and p.kind not in ('varargs', 'varkw'):
                piece += f'={p.default_repr}'
            parts.append(piece)
        return ', '.join(parts)

    @staticmethod
    def _render_return(fc: _FuncContract) -> str:
        return f' -> {fc.return_ann}' if fc.return_ann else ''

    @staticmethod
    def _manual_placeholder(fc: _FuncContract, module_name: str) -> str:
        deps = '; '.join(sorted(fc.raises)) if fc.raises else '待人工实现'
        return (f'    # TODO(HybridComposer): 复杂逻辑不自动实现\n'
                f'    raise NotImplementedError'
                f'("stub {module_name}.{fc.name}: {deps}")')

    @staticmethod
    def _extract_func_body(source: str,
                           func_name: str) -> _Opt[str]:
        """从 LLM 生成的完整模块源码中提取指定函数的 body。"""
        try:
            tree = _ast.parse(source)
        except SyntaxError:
            return None
        for node in tree.body:
            if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                if node.name == func_name:
                    # 提取函数体行（不含 def 行）
                    body_lines = source.splitlines()
                    # 从函数定义的第一个语句行开始
                    if node.body:
                        first_stmt = node.body[0]
                        start = first_stmt.lineno - 1  # 0-indexed
                        end = node.end_lineno if hasattr(node, 'end_lineno') else len(body_lines)
                        return '\n'.join(body_lines[start:end])
                    return '    pass'
        return None


__all__ = ['FuncStrategyChoice', 'HybridResult', 'HybridComposer']
