# stub_gradual_engine.py — 渐进实现引擎 (StubGradual)
# 对可自动实现的简单桩用启发式规则构造实现体；复杂逻辑不强制自动实现，
# 标注 TODO 与依赖项；可选远端模型（无 API 时降级为规则）；产出结果经
# "导入冒烟 + 输入输出契约检查"验证，失败则回退并记录原因。
# 设计意图：将"桩从占位到可用"变为可增量、可验证、可回退的工程闭环。
# 输出目录 stubs/_gradual_out 仅含产出物，不触碰既有桩文件
# （安全边界：只新建，不修改）。
import ast as _ast
import json as _json
import os as _os
import re as _re
import sys as _sys
import types as _types
import urllib.error as _urlerr
import urllib.request as _urlreq
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

# 简单类型白名单 — 规则引擎与契约验证共用的可判定类型集合
_SIMPLE_TYPES = frozenset(('int', 'str', 'float', 'bool', 'bytes',
                           'list', 'dict', 'set', 'tuple'))


def _base_type(ann: str) -> str:
    """取类型注解的最外层基础类型名。
    处理 Optional/Union 包装：list[int]→list, Optional[bytes]→bytes,
    Union[list, int]→list。避免子串匹配在复合泛型上误判。"""
    a = (ann or '').strip().lower()
    while a.startswith(('optional[', 'union[')):
        inner = a[a.index('[') + 1:]
        a = inner.split(',')[0] if inner else ''
    m = _re.match(r'([a-z_][a-z0-9_]*)', a)
    return m.group(1) if m else ''

from modules.stubs.stub_contract import (
    ImplementationStatus as _Status,
    StubContract as _StubContract,
    FuncContract as _FuncContract,
    StubContractor as _StubContractor,
)
from modules.stubs.stub_prioritizer import ImplementationPrioritizer as _Prioritizer
from modules.stubs.stub_health_monitor import StubHealthMonitor

@_dc
class GradualConfig:
    """渐进引擎配置。远端模型为可选依赖；llm_enabled=False 时纯规则降级。"""
    base_url: str = ''              # OpenAI 兼容端点
    model: str = ''                 # 模型标识
    api_key: str = ''               # 鉴权密钥（可选）
    llm_enabled: bool = False       # 无 API 时保持 False，走规则路径
    llm_timeout: float = 30.0
    output_dir: str = ''            # 空字符串 → 默认 stubs/_gradual_out
    dry_run: bool = False           # 仅产出+验证，不落盘
    safety_mode: str = 'strict'     # strict | permissive
    run_io_checks: bool = True      # 验证阶段是否执行输入输出检查
    max_functions_auto: int = 6     # 超此函数数则不自动实现

@_dc
class GeneratedModule:
    """一次实现尝试的结果。written=False 表示验证失败，未落盘。"""
    module_name: str
    status: str = 'pending'         # generated | failed | skipped
    source: str = ''
    path: str = ''
    strategy: str = ''              # template | llm | none
    written: bool = False
    partial: bool = False           # 部分函数仍为 NotImplementedError
    todo_deps: list = _field(default_factory=list)
    verification: _Opt['VerificationResult'] = None

@_dc
class VerificationResult:
    """契约验证结论 — 导入冒烟 + 签名核对 + 输入输出检查。"""
    module_name: str
    ok: bool = False
    import_error: str = ''
    signature_violations: list = _field(default_factory=list)
    io_violations: list = _field(default_factory=list)
    not_implemented: list = _field(default_factory=list)   # 仍为 NotImplementedError 的函数
    feedback: str = ''

    def to_dict(self) -> dict:
        return {
            'module_name': self.module_name, 'ok': self.ok,
            'import_error': self.import_error,
            'signature_violations': self.signature_violations,
            'io_violations': self.io_violations,
            'not_implemented': self.not_implemented,
            'feedback': self.feedback,
        }


# 规则引擎（符号层）
# 仅在明确可推断的简单场景构造真实体；其余场景输出
# NotImplementedError 骨架 + TODO 依赖标注，恪守"复杂逻辑不自动实现"边界。
class TemplateGenerator:

    def __init__(self, safety_mode: str = 'strict', max_functions_auto: int = 6):
        self.safety_mode = safety_mode
        self.max_functions_auto = max_functions_auto

    def can_generate(self, contract: _StubContract) -> bool:
        """安全边界判定：仅 MISSING/PLACEHOLDER/UNPARSEABLE 且规模可控。"""
        if contract.status not in (_Status.MISSING.value, _Status.PLACEHOLDER.value,
                                   _Status.UNPARSEABLE.value):
            return False
        if contract.has_compat_target:
            # compat 目标已存在 — 转发路径有效，无需另行构造
            return False
        if len(contract.functions) > self.max_functions_auto:
            return False
        # high 复杂度函数一律禁止自动实现
        if any(f.complexity == 'high' for f in contract.functions):
            return False
        return True

    def _safe_param_list(self, fc: _FuncContract) -> list:
        """筛选可安全构造测试输入的参数（有类型注解且为简单类型）。"""
        safe = []
        for p in fc.params:
            if p.kind in ('varargs', 'varkw'):
                continue
            if p.annotation and self._simple_type(p.annotation):
                safe.append(p.name)
        return safe

    def _simple_type(self, ann: str) -> bool:
        return _base_type(ann) in _SIMPLE_TYPES

    def _default_for(self, ann: str) -> str:
        base = _base_type(ann)
        return {
            'list': '[]', 'dict': '{}', 'set': 'set()', 'tuple': '()',
            'bytes': 'b""', 'str': '""', 'float': '0.0',
            'int': '0', 'bool': 'False',
        }.get(base, 'None')

    def _render_signature(self, fc: _FuncContract) -> str:
        """渲染函数括号内参数列表（不含返回注解）。"""
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
        """返回值注解后缀。"""
        return f' -> {fc.return_ann}' if fc.return_ann else ''

    def _generate_func_body(self, module: str, fc: _FuncContract) -> str:
        """按可推断模式构造函数体；不可推断时输出 NotImplementedError。"""
        base = _base_type(fc.return_ann)
        params = [p for p in fc.params if p.kind not in ('varargs', 'varkw')]

        # 规则1: 无参数 → 返回类型默认值
        if not params:
            if base in _SIMPLE_TYPES:
                return f'    return {self._default_for(base)}'
        # 规则2: 单参数标准化 — 缺省则返回默认值；同类型则透传
        elif len(params) == 1:
            p = params[0]
            if p.has_default and p.default_repr in ('None', ''):
                if self._simple_type(base) or self._simple_type(p.annotation):
                    return (f'    if {p.name} is None:\n'
                            f'        return {self._default_for(base or p.annotation)}\n'
                            f'    return {p.name}')
            if self._same_type(p.annotation, fc.return_ann):
                return f'    return {p.name}'
            if base == 'bool':
                return f'    return bool({p.name})'
        # 规则3: permissive 模式下的语义空实现
        if self.safety_mode == 'permissive':
            if self._simple_type(base):
                return (f'    # TODO(StubGradual): 语义未实现，返回类型默认值\n'
                        f'    return {self._default_for(base)}')
        # 回退: 复杂逻辑骨架 — 标注依赖并抛 NotImplementedError
        deps = self._dependency_note(fc)
        return (f'    # TODO(StubGradual): 复杂逻辑不自动实现，依赖: {deps}\n'
                f'    raise NotImplementedError("stub {module}.{fc.name} 尚未实现")')

    @staticmethod
    def _same_type(a: str, b: str) -> bool:
        """比较最外层基础类型是否一致（忽略 Optional/Union/泛型参数）。"""
        ba, bb = _base_type(a), _base_type(b)
        return bool(ba) and bool(bb) and ba == bb

    @staticmethod
    def _dependency_note(fc: _FuncContract) -> str:
        notes = []
        if fc.raises:
            notes.append('异常:' + ','.join(sorted(fc.raises)))
        if fc.complexity == 'medium':
            notes.append('中等复杂度')
        return ';'.join(notes) or '待人工分析'

    def generate(self, contract: _StubContract) -> str:
        """构造完整模块源码（仅 stdlib，不引入外部依赖）。"""
        lines = []
        lines.append('# 由 StubGradual 渐进引擎按规则/启发式构造')
        lines.append('# 仅作安全分析占位骨架；复杂逻辑保留 NotImplementedError 标注。')
        lines.append('')
        if contract.doc:
            lines.append(f'"""{contract.doc}"""')
            lines.append('')
        for fc in contract.functions:
            body = self._generate_func_body(contract.module_name, fc)
            lines.append(f'def {fc.name}({self._render_signature(fc)})'
                         f'{self._render_return(fc)}:')
            if fc.doc_summary:
                lines.append(f'    """{fc.doc_summary}"""')
            lines.append(body)
            lines.append('')
        for cc in contract.classes:
            base = ', '.join(cc.bases) if cc.bases else 'object'
            lines.append(f'class {cc.name}({base}):')
            lines.append(f'    """{cc.doc_summary}"""')
            for m in cc.methods:
                body = self._generate_func_body(contract.module_name, m)
                lines.append(f'    def {m.name}({self._render_signature(m)})'
                             f'{self._render_return(m)}:')
                if m.doc_summary:
                    lines.append(f'        """{m.doc_summary}"""')
                lines.extend(f'        {ln}' for ln in body.splitlines())
                lines.append('')
            lines.append('')
        lines.append(f'__all__ = {contract.public_api_names()!r}')
        lines.append('')
        return '\n'.join(lines)

    def todo_deps(self, contract: _StubContract) -> list:
        """列出仍需人工实现的函数及其依赖项，供摘要报告使用。"""
        out = []
        for fc in contract.functions:
            if fc.is_placeholder or fc.complexity != 'low':
                out.append({'func': fc.name, 'complexity': fc.complexity,
                            'raises': sorted(fc.raises)})
        return out


# 远端模型引擎（神经层，可选）
# OpenAI 兼容 chat/completions 协议。网络/协议/鉴权异常一律返回 None，
# 由引擎降级到规则引擎。不做重试 — 验证闭环才是正确性守门员。
class LLMGenerator:

    def __init__(self, config: GradualConfig):
        self.config = config

    @property
    def enabled(self) -> bool:
        return bool(self.config.llm_enabled and self.config.base_url)

    def _endpoint(self) -> str:
        url = self.config.base_url.rstrip('/')
        if url.endswith('/chat/completions'):
            return url
        return f'{url}/chat/completions'

    def generate(self, contract: _StubContract) -> _Opt[str]:
        if not self.enabled:
            return None
        prompt = (
            f'你是二进制安全分析框架的桩实现工程师。依据接口契约，'
            f'用纯标准库实现模块 {contract.module_name}，'
            f'输出完整可运行的 Python 源码（仅代码块）。\n'
            f'契约: {_json.dumps(contract.to_dict(), ensure_ascii=False)}\n'
            f'约束: 只允许 import 标准库；复杂逻辑处可保留 '
            f'raise NotImplementedError("TODO: ...") 并注明依赖。')
        payload = {
            'model': self.config.model,
            'messages': [
                {'role': 'system', 'content': '你输出仅含 Python 标准库的安全分析桩实现。'},
                {'role': 'user', 'content': prompt},
            ],
            'temperature': 0.2,
        }
        headers = {'Content-Type': 'application/json'}
        if self.config.api_key:
            headers['Authorization'] = f'Bearer {self.config.api_key}'
        req = _urlreq.Request(
            self._endpoint(), data=_json.dumps(payload).encode('utf-8'),
            headers=headers, method='POST')
        try:
            with _urlreq.urlopen(req, timeout=self.config.llm_timeout) as resp:
                data = _json.loads(resp.read().decode('utf-8'))
            content = data['choices'][0]['message']['content']
        except (KeyError, IndexError, _urlerr.URLError, _json.JSONDecodeError,
                OSError, TimeoutError):
            return None
        return self._extract_code(content)

    @staticmethod
    def _extract_code(content: str) -> str:
        """从模型回复中提取 ```python ... ``` 代码块；无标记则取全文。"""
        block = _re_search_block(content)
        if block is not None:
            return block
        return content

    def __repr__(self) -> str:
        return (f'LLMGenerator(enabled={self.enabled}, '
                f'base_url={self.config.base_url!r}, model={self.config.model!r})')


def _re_search_block(content: str) -> _Opt[str]:
    m = _re.search(r'```(?:python)?\s*\n(.*?)```', content, _re.DOTALL)
    return m.group(1).strip() if m else None


# 契约验证器
# 验证闭环三阶段：
#   1. 导入冒烟 — 产出文件能否干净加载（含 stdlib 限制检查）
#   2. 签名核对 — 产出函数参数名/数量与契约一致
#   3. 输入输出检查 — 对可构造输入的简单函数喂边界值，核对返回类型
# NotImplementedError 视为"未实现"而非"失败"，记入 not_implemented 列表。
class ContractVerifier:

    def __init__(self, run_io_checks: bool = True, run_metamorphic: bool = False):
        self.run_io_checks = run_io_checks
        self.run_metamorphic = run_metamorphic

    def verify(self, source: str, contract: _StubContract) -> VerificationResult:
        result = VerificationResult(module_name=contract.module_name)

        # 语法检查（导入冒烟的前置条件）
        try:
            _ast.parse(source)
        except SyntaxError as e:
            result.import_error = f'syntax: {e.msg} (line {e.lineno})'
            result.feedback = '产出源码语法错误，回退'
            return result

        mod = self._import_smoke(source, contract.module_name)
        if mod is None:
            result.import_error = 'import 冒烟失败'
            result.feedback = '导入失败，回退'
            return result

        # 签名核对 — 参数名与数量匹配契约
        import inspect as _inspect
        for fc in contract.functions:
            fn = getattr(mod, fc.name, None)
            if fn is None:
                result.signature_violations.append(f'{fc.name}: missing')
                continue
            try:
                sig = _inspect.signature(fn)
            except (ValueError, TypeError):
                continue
            got = [p.name for p in sig.parameters.values()
                   if p.kind in (_inspect.Parameter.POSITIONAL_OR_KEYWORD,
                                 _inspect.Parameter.POSITIONAL_ONLY)]
            want = [p.name for p in fc.params if p.kind not in ('varargs', 'varkw')]
            if got != want:
                result.signature_violations.append(
                    f'{fc.name}: params {got} != contract {want}')

        # 输入输出契约检查
        if self.run_io_checks:
            for fc in contract.functions:
                fn = getattr(mod, fc.name, None)
                if fn is None:
                    continue
                if not self._io_testable(fc):
                    continue
                outcome = self._io_call(fn, fc)
                if outcome == 'not_implemented':
                    result.not_implemented.append(fc.name)
                elif outcome:
                    result.io_violations.append(f'{fc.name}: {outcome}')

        # 蜕变关系 Oracle 检查（可选，语义级验证）
        mr_anomalies = []
        if self.run_metamorphic:
            try:
                from modules.stubs.stub_metamorphic_verifier import MetamorphicVerifier as _MRV
                _mrv = _MRV()
                for fc in contract.functions:
                    fn = getattr(mod, fc.name, None)
                    if fn is None:
                        continue
                    mr_outcome = _mrv.verify(fn, fc)
                    if mr_outcome.get('status') == 'anomalies_found':
                        for a in mr_outcome.get('anomalies', []):
                            mr_anomalies.append(f'{fc.name}: MR_{a["category"]} '
                                               f'fail_rate={a["fail_rate"]} '
                                               f'conf={a["confidence"]}')
            except ImportError:
                pass

        result.ok = (not result.import_error and not result.signature_violations
                     and not result.io_violations and not mr_anomalies)
        if not result.ok:
            result.feedback = '契约验证失败，回退或降级'
        elif result.not_implemented:
            result.feedback = '验证通过，部分函数仍为未实现骨架'
        elif mr_anomalies:
            result.feedback = f'语义级MR异常: {"; ".join(mr_anomalies[:3])}'
        else:
            result.feedback = '契约验证通过'
        return result

    def _import_smoke(self, source: str, module_name: str):
        spec_name = f'_stubgradual_{module_name}'
        try:
            mod = _types.ModuleType(spec_name)
            exec(compile(source, f'<stubgradual-{module_name}>', 'exec'), mod.__dict__)
            return mod
        except NotImplementedError:
            return None
        except Exception:
            return None
        finally:
            _sys.modules.pop(spec_name, None)

    @staticmethod
    def _io_testable(fc: _FuncContract) -> bool:
        # 验证对象限定为引擎产出源码；调用无副作用风险，
        # 因此允许对 is_placeholder 函数做 IO 检查以记录仍未实现的函数。
        return all(p.annotation and p.kind not in ('varargs', 'varkw')
                   for p in fc.params)

    def _io_call(self, fn, fc: _FuncContract) -> str:
        """构造边界输入并调用。返回 ''=通过, 'not_implemented', 或违规描述。"""
        args = []
        for p in fc.params:
            if p.kind in ('varargs', 'varkw'):
                continue
            args.append(self._edge_value(p.annotation))
        try:
            out = fn(*args)
        except NotImplementedError:
            return 'not_implemented'
        except Exception as e:
            return f'raised {type(e).__name__}: {e}'
        # 返回类型核对 — return_ann 为简单类型时校验
        if fc.return_ann and self._is_simple_return(fc.return_ann):
            if out is not None and not self._type_matches(out, fc.return_ann):
                return f'bad return type {type(out).__name__} for {fc.return_ann}'
        return ''

    @staticmethod
    def _edge_value(ann: str) -> object:
        base = _base_type(ann)
        return {
            'bytes': b'', 'str': '', 'int': 0, 'float': 0.0, 'bool': False,
            'list': [], 'dict': {}, 'set': set(), 'tuple': (),
        }.get(base)

    @staticmethod
    def _is_simple_return(ann: str) -> bool:
        return _base_type(ann) in _SIMPLE_TYPES

    @staticmethod
    def _type_matches(out, ann: str) -> bool:
        base = _base_type(ann)
        mapping = {'int': int, 'str': str, 'float': float, 'bool': bool,
                   'bytes': bytes, 'list': list, 'dict': dict, 'set': set,
                   'tuple': tuple}
        typ = mapping.get(base)
        return typ is None or isinstance(out, typ)


class GradualEngine:
    """编排实现 → 验证 → 回溯闭环。失败记录持久化，供后续策略迭代。"""

    def __init__(self, config: _Opt[GradualConfig] = None,
                 contractor: _Opt[_StubContractor] = None,
                 prior: _Opt[_Prioritizer] = None,
                 monitor: _Opt['StubHealthMonitor'] = None):
        self.config = config or GradualConfig()
        self.contractor = contractor or _StubContractor()
        self.prior = prior or _Prioritizer(monitor=monitor,
                                           contractor=self.contractor)
        self.template_gen = TemplateGenerator(
            safety_mode=self.config.safety_mode,
            max_functions_auto=self.config.max_functions_auto)
        self.llm_gen = LLMGenerator(self.config)
        self.verifier = ContractVerifier(run_io_checks=self.config.run_io_checks)
        self._failures: dict[str, dict] = {}
        self._results: dict[str, GeneratedModule] = {}

    @property
    def output_dir(self) -> str:
        if self.config.output_dir:
            return self.config.output_dir
        return _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '_gradual_out')

    def _attempt_generate(self, contract: _StubContract, strategy: str,
                          source: _Opt[str]) -> _Opt[VerificationResult]:
        if not source:
            return None
        return self.verifier.verify(source, contract)

    def implement(self, module_name: str, docs: str = '',
                  api_hints: dict = None) -> GeneratedModule:
        """端到端单模块实现：构造 → 验证 → 回溯 → 落盘或记录失败。"""
        contract = self.contractor.build_contract(module_name, docs=docs,
                                                  api_hints=api_hints)
        gen = GeneratedModule(module_name=module_name, status='failed',
                              todo_deps=self.template_gen.todo_deps(contract))

        if not self.template_gen.can_generate(contract):
            gen.status = 'skipped'
            reason = ('已有 compat 转发实现' if contract.has_compat_target
                      else '复杂度超限或非简单可推断契约')
            self._record_failure(module_name, f'跳过自动实现: {reason}',
                                 ['status=%s' % contract.status,
                                  'complexity 超限或已有实现'])
            return gen

        # 尝试1: 规则引擎（符号层）
        attempted = ['template']
        src = self.template_gen.generate(contract)
        result = self._attempt_generate(contract, 'template', src)
        if result is not None and result.ok:
            # 若同时有 LLM 产物，运行双策略非相干性校验
            if self.llm_gen.enabled:
                llm_src = self.llm_gen.generate(contract)
                if llm_src:
                    inc_result = self._run_incoherence_check(
                        contract, src, llm_src)
                    if inc_result:
                        gen.incoherence = inc_result
            return self._finalize(gen, src, 'template', result)

        # 尝试2: 远端模型（神经层，可选）
        if self.llm_gen.enabled:
            attempted.append('llm')
            llm_src = self.llm_gen.generate(contract)
            if llm_src:
                result2 = self._attempt_generate(contract, 'llm', llm_src)
                if result2 is not None and result2.ok:
                    return self._finalize(gen, llm_src, 'llm', result2)
                result = result2 or result

        # 回溯: 不落盘，记录失败链（借鉴 Agentic Repair 验证-回溯原则）
        feedback = result.feedback if result else '无可用实现策略'
        self._record_failure(module_name, feedback,
                             [f'attempted={"|".join(attempted)}',
                              f'import_error={result.import_error if result else "n/a"}'])
        gen.verification = result
        gen.status = 'failed'
        self._results[module_name] = gen
        return gen

    def _finalize(self, gen: GeneratedModule, src: str, strategy: str,
                  result: VerificationResult) -> GeneratedModule:
        gen.source = src
        gen.strategy = strategy
        gen.verification = result
        gen.partial = bool(result.not_implemented)
        gen.todo_deps = self._refresh_todo(gen.module_name, result.not_implemented)
        if not self.config.dry_run:
            gen.path = self._write(gen.module_name, src)
            gen.written = True
        gen.status = 'generated'
        self._results[gen.module_name] = gen
        return gen

    def _refresh_todo(self, module_name: str, not_implemented: list) -> list:
        contract = self.contractor.get(module_name)
        deps = []
        if contract:
            for fc in contract.functions:
                if fc.name in not_implemented:
                    deps.append({'func': fc.name, 'complexity': fc.complexity,
                                 'raises': sorted(fc.raises)})
        return deps

    def _write(self, module_name: str, source: str) -> str:
        out_dir = self.output_dir
        _os.makedirs(out_dir, exist_ok=True)
        path = _os.path.join(out_dir, f'{module_name}.py')
        with open(path, 'w', encoding='utf-8') as f:
            f.write(source)
        return path

    def _record_failure(self, module_name: str, reason: str, details: list) -> None:
        self._failures[module_name] = {'reason': reason, 'details': details}

    def _run_incoherence_check(self, contract: _StubContract,
                               src_template: str, src_llm: str) -> _Opt[dict]:
        """双策略非相干性校验 — 无 oracle 的一致性信号。
        两条独立策略均编译通过时，比较相同输入下的输出。
        不一致 → 至少一侧有误（可证明的下界）。
        """
        try:
            from modules.stubs.stub_incoherence_check import (
                IncoherenceChecker, DualImplementation)
            dual = DualImplementation(
                module_name=contract.module_name,
                strategy_a='template', source_a=src_template,
                strategy_b='llm', source_b=src_llm,
            )
            checker = IncoherenceChecker()
            result = checker.check(contract, dual)
            return result.get('__summary__')
        except ImportError:
            return None

    def failure_report(self) -> list:
        """失败记录快照 — 供人工 review 与策略改进。"""
        return [{'module_name': k, **v} for k, v in sorted(self._failures.items())]

    def implement_top(self, n: int = 5) -> list:
        """按实现缺口优先级处理前 n 个模块（can_generate 内部再做安全判定）。"""
        backlog = self.prior.implementation_backlog()
        out = []
        for p in backlog:
            if len(out) >= n:
                break
            out.append(self.implement(p.module_name))
        return out

    def summary(self) -> str:
        """输出一次执行的摘要文本。"""
        lines = [f'# StubGradual 执行摘要', f'产出结果: {len(self._results)}',
                 f'失败记录: {len(self._failures)}', '']
        for name, gen in sorted(self._results.items()):
            lines.append(f'- {name}: {gen.status} (strategy={gen.strategy}, '
                         f'written={gen.written}, partial={gen.partial})')
        if self._failures:
            lines.append('')
            lines.append('## 失败原因')
            for rec in self.failure_report():
                lines.append(f'- {rec["module_name"]}: {rec["reason"]} '
                             f'({";".join(rec["details"])})')
        return '\n'.join(lines)


def run_gradual_plan(top_n: int = 5, config: _Opt[GradualConfig] = None) -> GradualEngine:
    """一键渐进实现：契约扫描 → 优先级排序 → 增量实现 → 摘要。"""
    engine = GradualEngine(config=config)
    engine.implement_top(top_n)
    return engine


__all__ = ['GradualConfig', 'GeneratedModule', 'VerificationResult',
           'TemplateGenerator', 'LLMGenerator', 'ContractVerifier',
           'GradualEngine', 'run_gradual_plan']
