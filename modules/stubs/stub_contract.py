# stub_contract.py — 接口契约抽取引擎
# 为 stubs/ 下每个模块提取接口契约：签名 + 参数约束 + 异常语义。
# 契约是 StubGradual 渐进实现引擎的输入基座：
#   1. 排序依据（见 stub_prioritizer.py）
#   2. 渐进实现的目标规格与校验基准（见 stub_gradual_engine.py）
# 设计意图：将桩模块的可判定性从"能否 import"升级为"签名/约束/异常"三层规格，
# 使未实现占位可被程序化识别并增量补齐。
import ast as _ast
import os as _os
import re as _re
from dataclasses import dataclass as _dc, field as _field
from enum import Enum as _Enum
from typing import Optional as _Opt

# 实现状态枚举 — 渐进引擎只对 PLACEHOLDER / MISSING 构造实现体，
# RE_EXPORT / MIXED / IMPLEMENTED 保持只读，不覆盖已有实现。
class ImplementationStatus(_Enum):
    MISSING = 'missing'          # 模块文件在磁盘上不存在
    PLACEHOLDER = 'placeholder'  # 文件存在但无函数/类体
    RE_EXPORT = 're_export'      # 纯转发 compat，无自有实现
    MIXED = 'mixed'              # 转发 compat 且附加自有扩展
    IMPLEMENTED = 'implemented'  # 自带完整实现体
    UNPARSEABLE = 'unparseable'  # 源码语法损坏，无法解析

@_dc
class ParamSpec:
    """参数契约：名称、缺省值、类型注解、参数种类。"""
    name: str
    has_default: bool = False
    default_repr: str = ''
    annotation: str = ''
    kind: str = 'positional'     # positional | keyword | varargs | varkw

@_dc
class FuncContract:
    """函数级契约：签名、文档摘要、异常声明、复杂度评估。"""
    name: str
    params: list = _field(default_factory=list)      # list[ParamSpec]
    return_ann: str = ''
    doc_summary: str = ''
    raises: set = _field(default_factory=set)        # 文档声明的异常类型
    is_placeholder: bool = False                     # 函数体为 pass/...
    complexity: str = 'low'                          # low | medium | high
    stmt_count: int = 0
    has_imports: bool = False
    line_no: int = 0

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'params': [_dc_dict(p) for p in self.params],
            'return_ann': self.return_ann,
            'doc_summary': self.doc_summary,
            'raises': sorted(self.raises),
            'is_placeholder': self.is_placeholder,
            'complexity': self.complexity,
            'stmt_count': self.stmt_count,
        }

@_dc
class ClassContract:
    """类级契约：方法签名与类文档，不深入 MRO 语义。"""
    name: str
    bases: list = _field(default_factory=list)
    methods: list = _field(default_factory=list)     # list[FuncContract]
    doc_summary: str = ''

@_dc
class StubContract:
    """模块级契约 — 供给排序器与渐进引擎的结构化规格。"""
    module_name: str
    status: str = 'missing'
    source_path: str = ''
    doc: str = ''
    imports: list = _field(default_factory=list)     # 顶层 import 目标
    functions: list = _field(default_factory=list)   # list[FuncContract]
    classes: list = _field(default_factory=list)     # list[ClassContract]
    compat_target: str = ''                          # 对应 compat 模块名
    has_compat_target: bool = False
    parse_error: str = ''
    raw_source_len: int = 0

    def public_api_names(self) -> list:
        """对外符号清单：函数 + 类 + 非私有顶层常量。"""
        names = [f.name for f in self.functions]
        names += [c.name for c in self.classes]
        return sorted(set(names))

    def to_dict(self) -> dict:
        return {
            'module_name': self.module_name,
            'status': self.status,
            'source_path': self.source_path,
            'doc': self.doc,
            'imports': self.imports,
            'functions': [f.to_dict() for f in self.functions],
            'classes': [{'name': c.name, 'bases': c.bases,
                         'methods': [m.to_dict() for m in c.methods],
                         'doc_summary': c.doc_summary} for c in self.classes],
            'compat_target': self.compat_target,
            'has_compat_target': self.has_compat_target,
            'parse_error': self.parse_error,
            'raw_source_len': self.raw_source_len,
        }

def _dc_dict(p) -> dict:
    return {'name': p.name, 'has_default': p.has_default,
            'default_repr': p.default_repr, 'annotation': p.annotation, 'kind': p.kind}

# 异常声明提取
# 从 docstring 中识别声明的异常。支持中英文两种标注约定：
#   "Raises:" / "异常:" 后跟随行，或行内 "raise XxxError" / "抛XxxError"。
_RAISES_LINE_RE = _re.compile(
    r'(?:raises|raise|抛出?|异常)\s*[:：]?\s*(?:\*\*)?([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)',
    _re.IGNORECASE)

def _extract_raises(doc: str) -> set:
    if not doc:
        return set()
    out = set()
    for m in _RAISES_LINE_RE.finditer(doc):
        exc = m.group(1)
        # 排除误匹配的自然语言词（非 Error/Exception 后缀且首字母非大写）
        if exc.lower().endswith(('error', 'exception')) or exc[0].isupper():
            out.add(exc)
    return out

# 函数体占位判定
def _body_is_placeholder(body: list) -> bool:
    """判定函数体是否为纯占位：仅含 pass / Ellipsis / docstring。"""
    stmts = [s for s in body if not isinstance(s, _ast.Expr) or
             not isinstance(getattr(s, 'value', None), _ast.Constant) or
             not isinstance(getattr(s.value, 'value', None), str)]
    if not stmts:
        return True
    for s in stmts:
        if isinstance(s, _ast.Pass):
            continue
        if isinstance(s, _ast.Expr) and isinstance(s.value, _ast.Constant) and s.value.value is ...:
            continue
        return False
    return True

# 复杂度启发式计算
# 复杂度仅用于排序权重计算，不作为安全判定的唯一输入。
# 安全判定（是否允许自动实现）在 stub_gradual_engine 内有独立的保守约束。
def _estimate_complexity(stmts: list) -> tuple:
    """按分支/循环/调用/嵌套深度加权，返回 (标签, 语句数)。"""
    depth = 0
    branches = 0
    calls = 0

    def walk(node, d):
        nonlocal depth, branches, calls
        depth = max(depth, d)
        for child in _ast.iter_child_nodes(node):
            if isinstance(child, (_ast.If, _ast.For, _ast.While, _ast.Try,
                                  _ast.With, _ast.comprehension)):
                branches += 1
            if isinstance(child, _ast.Call):
                calls += 1
            walk(child, d + 1 if isinstance(
                child, (_ast.If, _ast.For, _ast.While, _ast.Try, _ast.With,
                        _ast.Lambda, _ast.comprehension)) else d)

    for s in stmts:
        walk(s, 0)
    stmt_count = sum(1 for s in stmts for _ in _ast.walk(s))
    score = branches * 3 + calls * 2 + depth * 4
    if score >= 30 or stmt_count >= 60:
        return 'high', stmt_count
    if score >= 10:
        return 'medium', stmt_count
    return 'low', stmt_count

# AST 源码解析
def parse_contract_from_source(source: str, module_name: str,
                               source_path: str = '') -> StubContract:
    """从桩源码解析接口契约。语法错误时返回 UNPARSEABLE 状态。"""
    contract = StubContract(module_name=module_name, source_path=source_path,
                            raw_source_len=len(source))
    try:
        tree = _ast.parse(source, filename=source_path or module_name)
    except SyntaxError as e:
        contract.status = ImplementationStatus.UNPARSEABLE.value
        contract.parse_error = f'{e.msg} (line {e.lineno})'
        return contract

    # 提取模块级 docstring
    if tree.body and isinstance(tree.body[0], _ast.Expr) and \
       isinstance(tree.body[0].value, _ast.Constant) and \
       isinstance(tree.body[0].value.value, str):
        contract.doc = tree.body[0].value.value.strip()

    # 提取顶层 import 语句目标
    for node in tree.body:
        if isinstance(node, _ast.Import):
            contract.imports.extend(alias.name for alias in node.names)
        elif isinstance(node, _ast.ImportFrom):
            contract.imports.append(node.module or '')

    re_export_star = any(
        isinstance(n, _ast.ImportFrom) and n.module and
        any(a.name == '*' for a in n.names) for n in tree.body)

    # 遍历函数与类节点，构建 FuncContract / ClassContract
    has_own_impl = False
    for node in tree.body:
        if isinstance(node, _ast.FunctionDef) or isinstance(node, _ast.AsyncFunctionDef):
            fc = _func_to_contract(node)
            contract.functions.append(fc)
            if not fc.is_placeholder:
                has_own_impl = True
        elif isinstance(node, _ast.ClassDef):
            cc = _class_to_contract(node)
            contract.classes.append(cc)
            if cc.methods:
                has_own_impl = True

    # 按转发+自有实现组合判定状态
    if re_export_star and has_own_impl:
        contract.status = ImplementationStatus.MIXED.value
    elif re_export_star and not has_own_impl:
        contract.status = ImplementationStatus.RE_EXPORT.value
    elif not contract.functions and not contract.classes:
        contract.status = ImplementationStatus.PLACEHOLDER.value
    else:
        contract.status = ImplementationStatus.IMPLEMENTED.value
    return contract

def _func_to_contract(node) -> FuncContract:
    """AST FunctionDef 节点映射为 FuncContract。提取参数签名、默认值、异常。"""
    params = []
    all_args = list(node.args.posonlyargs) + list(node.args.args)
    defaults = [None] * (len(all_args) - len(node.args.defaults)) + list(node.args.defaults)
    for i, arg in enumerate(all_args):
        ann = ''
        if arg.annotation is not None:
            try:
                ann = _ast.unparse(arg.annotation)
            except Exception:
                ann = ''
        dflt = defaults[i]
        has_dflt = dflt is not None
        dflt_repr = _ast.unparse(dflt) if has_dflt else ''
        params.append(ParamSpec(name=arg.arg, has_default=has_dflt,
                                default_repr=dflt_repr, annotation=ann))
    if node.args.vararg:
        params.append(ParamSpec(name=node.args.vararg.arg, kind='varargs',
                                annotation=_ast.unparse(node.args.vararg.annotation)
                                if node.args.vararg.annotation else ''))
    if node.args.kwarg:
        params.append(ParamSpec(name=node.args.kwarg.arg, kind='varkw',
                                annotation=_ast.unparse(node.args.kwarg.annotation)
                                if node.args.kwarg.annotation else ''))

    return_ann = _ast.unparse(node.returns) if node.returns else ''
    doc = _ast.get_docstring(node) or ''
    raises = _extract_raises(doc)
    complexity, stmt_count = _estimate_complexity(node.body)
    return FuncContract(
        name=node.name, params=params, return_ann=return_ann,
        doc_summary=doc.splitlines()[0] if doc else '',
        raises=raises, is_placeholder=_body_is_placeholder(node.body),
        complexity=complexity, stmt_count=stmt_count, line_no=node.lineno)

def _class_to_contract(node) -> ClassContract:
    bases = []
    for b in node.bases:
        try:
            bases.append(_ast.unparse(b))
        except Exception:
            bases.append('')
    methods = []
    for child in node.body:
        if isinstance(child, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            methods.append(_func_to_contract(child))
    return ClassContract(name=node.name, bases=bases, methods=methods,
                         doc_summary=(_ast.get_docstring(node) or '').splitlines()[0]
                         if _ast.get_docstring(node) else '')

# 文档驱动的最小契约构造
# 模块文件缺失时，以文档 + 调用点线索构造最小契约，
# 保证渐进引擎仍可产出可运行的骨架，而非直接放弃该模块。
def generate_contract_from_docs(module_name: str, docs: str,
                                api_hints: dict = None) -> StubContract:
    """从文档和调用点线索构造最小接口契约。
    api_hints: {func_name: "param:type -> rettype"} 格式。
    无文件且无 api_hints → MISSING；有 api_hints → PLACEHOLDER。"""
    status = (ImplementationStatus.PLACEHOLDER.value if api_hints
              else ImplementationStatus.MISSING.value)
    contract = StubContract(module_name=module_name, status=status,
                            doc=docs.strip())
    for hint_name, hint_sig in (api_hints or {}).items():
        fc = FuncContract(name=hint_name, is_placeholder=True, complexity='low')
        # 解析 "a:bytes, b:int -> bool" 形式的调用点签名提示
        sig_part, _, ret_part = hint_sig.partition('->')
        for chunk in sig_part.split(','):
            chunk = chunk.strip()
            if not chunk:
                continue
            pname, _, ann = chunk.partition(':')
            fc.params.append(ParamSpec(name=pname.strip(),
                                       annotation=ann.strip()))
        if ret_part:
            fc.return_ann = ret_part.strip()
        contract.functions.append(fc)
    return contract

# 契约目录扫描器
class StubContractor:
    """扫描 stubs/ 目录，为各模块建立接口契约并判定实现状态。"""

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self._compat_dir = _os.path.join(_os.path.dirname(stubs_dir), 'core', 'compat')
        self._contracts: dict[str, StubContract] = {}
        self._errors: dict[str, str] = {}

    def _compat_exists(self, name: str) -> bool:
        return _os.path.isfile(_os.path.join(self._compat_dir, f'{name}.py'))

    def build_contract(self, module_name: str,
                       docs: str = '', api_hints: dict = None) -> StubContract:
        """单模块契约构建：源码存在则解析，否则按文档回退构造。"""
        path = _os.path.join(self.stubs_dir, f'{module_name}.py')
        if _os.path.isfile(path):
            try:
                src = open(path, encoding='utf-8').read()
            except (OSError, UnicodeDecodeError) as e:
                self._errors[module_name] = f'read: {e}'
                contract = StubContract(module_name=module_name,
                                        status=ImplementationStatus.MISSING.value,
                                        source_path=path, parse_error=str(e))
            else:
                contract = parse_contract_from_source(src, module_name, path)
        else:
            contract = generate_contract_from_docs(module_name, docs, api_hints)
        contract.compat_target = module_name if self._compat_exists(module_name) else ''
        contract.has_compat_target = bool(contract.compat_target)
        self._contracts[module_name] = contract
        return contract

    def scan_all(self, docs_map: dict = None, hints_map: dict = None) -> dict:
        """遍历目录下全部 .py 模块构建契约（跳过 _ 前缀内部文件）。"""
        docs_map = docs_map or {}
        hints_map = hints_map or {}
        for fn in sorted(_os.listdir(self.stubs_dir)):
            if fn.startswith('_') or not fn.endswith('.py'):
                continue
            name = fn[:-3]
            self.build_contract(name, docs=docs_map.get(name, ''),
                                api_hints=hints_map.get(name))
        return self._contracts

    def get(self, module_name: str) -> _Opt[StubContract]:
        return self._contracts.get(module_name)

    def by_status(self, status: str) -> list:
        return [c for c in self._contracts.values() if c.status == status]

    def all(self) -> list:
        return list(self._contracts.values())


# 顶层便捷入口
def get_contractor() -> StubContractor:
    """进程级懒加载契约扫描器（与 stub_registry.get_registry 风格统一）。"""
    global _contractor
    if _contractor is None:
        _contractor = StubContractor()
        _contractor.scan_all()
    return _contractor

_contractor: _Opt[StubContractor] = None

__all__ = [
    'ImplementationStatus', 'ParamSpec', 'FuncContract', 'ClassContract',
    'StubContract', 'parse_contract_from_source', 'generate_contract_from_docs',
    'StubContractor', 'get_contractor',
]
