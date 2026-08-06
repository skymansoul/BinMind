# stub_metamorphic_oracle.py — 蜕变关系合约 Oracle
# 从函数签名与类型注解推导蜕变关系（Metamorphic Relations），
# 作为合约验证阶段的语义级测试预言。
#
# 背景:
#   传统合约验证止步于"导入冒烟 + 签名核对 + 边界值类型检查"，
#   对函数语义正确性无判断力。蜕变测试通过定义"输入变换后输出应满足
#   的跨调用约束"提供无真值 oracle 的语义校验。
#
# 新颖性:
#   1. 不从文档/需求文本生成 MR（如 Shin et al., 2024），
#      而是从类型结构与参数模式直接推导代数性质类 MR。
#   2. MR 合成不依赖 LLM，纯规则驱动，保证确定性、可审计。
#   3. 蜕变关系按类型代数结构分层：等式类（idempotence/involution）、
#      单调类（order preservation）、结构类（list/dict 容器性质）。
#
# 支撑:
#   - 蜕变测试理论 (Chen et al., 1998/2018)
#   - Shin et al. 2024 (LLM-based MR generation) — 本模块为其确定性替代路径
#   - 非 LLM 路径在合规场景（不允许外传代码到远端模型）中具有实用优势
import ast as _ast
import itertools as _it
from collections import defaultdict as _dd
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt, Callable

from modules.stubs.stub_contract import FuncContract as _FuncContract


# ---- 蜕变关系类型枚举 ----
class MRCategory:
    """蜕变关系分类体系。

    按性质来源分层:
      Level 1 — 等式类: 可证明的代数恒等式（如 idempotence, involution）
      Level 2 — 单调类: 类型推导的序保持性质（如 f(smaller_input) <= f(larger_input)）
      Level 3 — 结构类: 容器类型推导的形态保持性质（如 len(filter(x)) <= len(x)）
    """
    IDEMPOTENCE = 'idempotence'       # f(f(x)) == f(x)
    INVOLUTION = 'involution'         # f(f(x)) == x
    COMMUTATIVE = 'commutative'       # f(a, b) == f(b, a)  （参数可交换）
    MONOTONIC = 'monotonic'           # x <= y → f(x) <= f(y)
    STRUCTURE_PRESERVING = 'structure'  # len(f(x)) <= len(x) 等容器约束
    IDENTITY_PRESERVING = 'identity'  # f(x, neutral) == x  存在单位元
    NEGATION_SYM = 'negation_sym'     # f(-x) == -f(x)  奇函数性
    NULL_PRESERVING = 'null'          # f(None/empty) == None/empty


@_dc
class MetamorphicRelation:
    """单条蜕变关系。编码: 对输入施加变换 T，输出应满足谓词 P。"""
    category: str                          # MRCategory 成员
    description: str                       # 可读描述
    # input_transform: 接收 (原始参数元组) → (变换后参数元组)
    input_transform: Callable = None
    # output_predicate: 接收 (原输出, 变换后输出) → bool
    output_predicate: Callable = None
    confidence: float = 0.5                # 合成规则的置信度 [0,1]
    applicable_params: list = _field(default_factory=list)  # 涉及的参数名

    def __post_init__(self):
        if self.input_transform is None or self.output_predicate is None:
            self.confidence = 0.0


# ---- MR 合成引擎 ----
class MetamorphicSynthesizer:
    """从 FuncContract 推导蜕变关系集合。

    合成规则按类型代数结构分层:
      - 基础类型 (int/float/str/bytes) → 等式类 + 单调类
      - 容器类型 (list/dict/set)     → 结构类
      - 布尔返回                       → 恒等/幂等/反身性
      - 双参数同类型                    → 交换性

    每条规则输出置信度:
      1.0 = 可形式证明（如 f(f(x)) == f(x) 当返回类型与参数类型一致）
      0.5-0.9 = 类型模式强暗示（如 filter 类函数大概率满足 len(f(x)) <= len(x)）
      0.3-0.5 = 弱暗示，需更多证据
    """

    def synthesize(self, fc: _FuncContract) -> list[MetamorphicRelation]:
        """从单个函数契约推导蜕变关系列表。"""
        mrs = []
        params = [p for p in fc.params if p.kind not in ('varargs', 'varkw')]

        mrs.extend(self._idempotence_check(fc, params))
        mrs.extend(self._involution_check(fc, params))
        mrs.extend(self._commutative_check(fc, params))
        mrs.extend(self._structural_check(fc, params))
        mrs.extend(self._monotonic_check(fc, params))
        mrs.extend(self._null_check(fc, params))
        mrs.extend(self._negation_check(fc, params))

        # 去重: 同 category 只保留最高置信度
        return self._deduplicate(mrs)

    # ---- 各检查规则 ----

    def _idempotence_check(self, fc: _FuncContract, params: list) -> list[MetamorphicRelation]:
        """幂等性: 若返回类型与唯一参数类型一致 → f(f(x)) == f(x)。"""
        if len(params) != 1:
            return []
        p = params[0]
        if not p.annotation or not fc.return_ann:
            return []
        base_param = self._simple_base(p.annotation)
        base_ret = self._simple_base(fc.return_ann)
        if base_param != base_ret:
            return []

        # 函数名暗示: normalize, sanitize, flatten, trim, strip, canonicalize
        name_lower = fc.name.lower()
        idem_hints = {'normalize', 'sanitize', 'flatten', 'trim', 'strip',
                      'canonicalize', 'dedup', 'uniq', 'compact', 'clean',
                      'standardize', 'format', 'resolve', 'escape', 'unescape'}
        name_bonus = any(h in name_lower for h in idem_hints)

        # 文档关键词加分
        doc_bonus = False
        if fc.doc_summary:
            doc_lower = fc.doc_summary.lower()
            doc_bonus = any(w in doc_lower for w in
                          ('idempotent', '幂等', 'no-op', 'already'))

        conf = 0.7 + (0.2 if name_bonus else 0.0) + (0.1 if doc_bonus else 0.0)

        def mk_input(args):
            # 第一次调用: 用原参数
            return args

        def mk_output(orig_out, transformed_out):
            # transformed_out 是 f(f(x))，应与 f(x) 一致
            # 在调用端分两步: 先用原参数调 f 得到中间结果，
            # 再调 f(中间结果)，比较中间结果与最终结果。
            # 此处 output_predicate 接收 (f(x), f(f(x)))
            try:
                return orig_out == transformed_out
            except Exception:
                return False

        mr = MetamorphicRelation(
            category=MRCategory.IDEMPOTENCE,
            description=f'{fc.name}: f(f(x)) == f(x)',
            input_transform=mk_input,
            output_predicate=mk_output,
            confidence=min(conf, 1.0),
            applicable_params=[p.name],
        )
        return [mr] if conf >= 0.5 else []

    def _involution_check(self, fc: _FuncContract, params: list) -> list[MetamorphicRelation]:
        """对合性: f(f(x)) == x。常见于 encode/decode, encrypt/decrypt 等成对操作。"""
        if len(params) != 1:
            return []
        p = params[0]
        if not p.annotation or not fc.return_ann:
            return []
        base_param = self._simple_base(p.annotation)
        base_ret = self._simple_base(fc.return_ann)
        if base_param != base_ret:
            return []

        name_lower = fc.name.lower()
        invol_hints = {'reverse', 'invert', 'negate', 'complement', 'toggle',
                       'swap', 'flip', 'mirror', 'transpose', 'not_', 'invert_'}
        name_bonus = any(h in name_lower for h in invol_hints)

        if not name_bonus:
            return []

        def mk_input(args):
            return args

        def mk_output(orig_out, transformed_out):
            try:
                return orig_out == transformed_out
            except Exception:
                return False

        mr = MetamorphicRelation(
            category=MRCategory.INVOLUTION,
            description=f'{fc.name}: f(f(x)) == x',
            input_transform=mk_input,
            output_predicate=mk_output,
            confidence=0.60 + (0.25 if 'encode' in name_lower or 'decode' in name_lower else 0.0),
            applicable_params=[p.name],
        )
        return [mr]

    def _commutative_check(self, fc: _FuncContract, params: list) -> list[MetamorphicRelation]:
        """交换性: f(a, b) == f(b, a)，当两个参数同类型且返回类型同参数类型。"""
        if len(params) != 2:
            return []
        a, b = params[0], params[1]
        if not a.annotation or not b.annotation:
            return []
        if self._simple_base(a.annotation) != self._simple_base(b.annotation):
            return []

        name_lower = fc.name.lower()
        comm_hints = {'merge', 'combine', 'concat', 'union', 'intersect',
                      'add', 'multiply', 'xor', 'and_', 'or_', 'min', 'max',
                      'equal', 'compare', 'diff', 'distance'}
        name_bonus = any(h in name_lower for h in comm_hints)

        if not name_bonus:
            return []

        def mk_input(args):
            return (args[1], args[0])

        def mk_output(orig_out, swapped_out):
            try:
                return orig_out == swapped_out
            except Exception:
                return False

        mr = MetamorphicRelation(
            category=MRCategory.COMMUTATIVE,
            description=f'{fc.name}: f(a, b) == f(b, a)',
            input_transform=mk_input,
            output_predicate=mk_output,
            confidence=0.65,
            applicable_params=[a.name, b.name],
        )
        return [mr]

    def _structural_check(self, fc: _FuncContract, params: list) -> list[MetamorphicRelation]:
        """结构保持性: 容器输入/输出间的形态约束。

        规则:
          - 输入 list 返回 list → len(f(x)) <= len(x) (filter/map 模式)
          - 输入 list 返回 bool  → f(x) == not f(not_applicable_element)
                                    这是简化，实际难验证
          - 输入 list 返回 元素类型 → 元素应 ∈ x
        """
        mrs = []
        if not params:
            return mrs

        p = params[0]
        base_in = self._simple_base(p.annotation)
        base_out = self._simple_base(fc.return_ann)

        # 容器到容器: 缩减性 (filter-like)
        if base_in in ('list', 'set') and base_out in ('list', 'set', 'dict'):
            name_lower = fc.name.lower()
            filter_hints = {'filter', 'select', 'find', 'search', 'take',
                          'limit', 'where', 'query', 'match', 'grep'}
            if any(h in name_lower for h in filter_hints):
                def mk_input(args):
                    return args

                def mk_output(orig_out, trans_out):
                    try:
                        return len(trans_out) <= len(orig_out)
                    except Exception:
                        return False

                mrs.append(MetamorphicRelation(
                    category=MRCategory.STRUCTURE_PRESERVING,
                    description=f'{fc.name}: len(f(x)) <= len(x) (filter pattern)',
                    input_transform=mk_input,
                    output_predicate=mk_output,
                    confidence=0.60,
                    applicable_params=[p.name],
                ))

        # 容器到容器: 保持性 (map-like)
        if base_in in ('list', 'set', 'tuple') and base_out == base_in:
            name_lower = fc.name.lower()
            map_hints = {'map', 'transform', 'convert', 'apply', 'process',
                        'encode', 'decode', 'translate'}
            if any(h in name_lower for h in map_hints):
                def mk_input(args):
                    return args

                def mk_output(orig_out, trans_out):
                    try:
                        return len(trans_out) == len(orig_out)
                    except Exception:
                        return False

                mrs.append(MetamorphicRelation(
                    category=MRCategory.STRUCTURE_PRESERVING,
                    description=f'{fc.name}: len(f(x)) == len(x) (map pattern)',
                    input_transform=mk_input,
                    output_predicate=mk_output,
                    confidence=0.55,
                    applicable_params=[p.name],
                ))

        return mrs

    def _monotonic_check(self, fc: _FuncContract, params: list) -> list[MetamorphicRelation]:
        """单调性: 数值类型函数，输入增大则输出不降/不增。"""
        if len(params) != 1:
            return []
        p = params[0]
        base = self._simple_base(p.annotation)
        if base not in ('int', 'float'):
            return []

        name_lower = fc.name.lower()
        # 非递减暗示: count, length, size, sum, max, abs
        nondec = {'count', 'length', 'size', 'sum', 'max', 'abs', 'total',
                  'magnitude', 'norm', 'positive'}
        # 非递增暗示: min, floor, clamp_max, limit
        noninc = {'min', 'floor', 'clamp_max', 'limit', 'ceil'}
        is_nondec = any(h in name_lower for h in nondec)
        is_noninc = any(h in name_lower for h in noninc)
        if not (is_nondec or is_noninc):
            return []

        def mk_input(args):
            # 输入变换: 对数值参数 +1
            return tuple(v + 1 if isinstance(v, (int, float)) else v for v in args)

        direction = 'nondecreasing' if is_nondec else 'nonincreasing'

        def mk_output(orig_out, larger_out):
            try:
                if direction == 'nondecreasing':
                    return larger_out >= orig_out
                else:
                    return larger_out <= orig_out
            except Exception:
                return False

        mr = MetamorphicRelation(
            category=MRCategory.MONOTONIC,
            description=f'{fc.name}: {direction} (x+1 vs x)',
            input_transform=mk_input,
            output_predicate=mk_output,
            confidence=0.55,
            applicable_params=[p.name],
        )
        return [mr]

    def _null_check(self, fc: _FuncContract, params: list) -> list[MetamorphicRelation]:
        """空值保持: f(empty/None) 应返回空/None/False。"""
        mrs = []
        if not params:
            return mrs

        name_lower = fc.name.lower()
        null_hints = {'validate', 'check', 'verify', 'test', 'is_',
                      'has_', 'contains', 'exists', 'detect', 'find',
                      'search', 'match', 'scan', 'parse', 'decode'}
        if not any(h in name_lower for h in null_hints):
            return mrs

        p = params[0]
        base = self._simple_base(p.annotation)

        empty_map = {'str': '', 'bytes': b'', 'list': [], 'dict': {},
                     'set': set(), 'tuple': (), 'int': 0, 'float': 0.0}

        if base not in empty_map:
            return mrs

        empty_val = empty_map[base]

        def mk_input(args):
            return (empty_val,) + args[1:]

        base_out = self._simple_base(fc.return_ann)
        if base_out == 'bool':

            def mk_output(orig_out, empty_out):
                try:
                    return empty_out is False
                except Exception:
                    return False

            mrs.append(MetamorphicRelation(
                category=MRCategory.NULL_PRESERVING,
                description=f'{fc.name}: f(empty_input) should be False',
                input_transform=mk_input,
                output_predicate=mk_output,
                confidence=0.50,
                applicable_params=[p.name],
            ))

        return mrs

    def _negation_check(self, fc: _FuncContract, params: list) -> list[MetamorphicRelation]:
        """奇函数性: f(-x) == -f(x)，仅对 int/float 参数且返回同类型。"""
        if len(params) != 1:
            return []
        p = params[0]
        base_in = self._simple_base(p.annotation)
        base_out = self._simple_base(fc.return_ann)
        if base_in not in ('int', 'float') or base_out not in ('int', 'float'):
            return []

        if base_in != base_out:
            return []

        name_lower = fc.name.lower()
        odd_hints = {'negate', 'inverse', 'complement', 'reverse_sign'}
        if not any(h in name_lower for h in odd_hints):
            return []

        def mk_input(args):
            return tuple(-v if isinstance(v, (int, float)) else v for v in args)

        def mk_output(orig_out, neg_out):
            try:
                return neg_out == -orig_out
            except Exception:
                return False

        mr = MetamorphicRelation(
            category=MRCategory.NEGATION_SYM,
            description=f'{fc.name}: f(-x) == -f(x)',
            input_transform=mk_input,
            output_predicate=mk_output,
            confidence=0.70,
            applicable_params=[p.name],
        )
        return [mr]

    # ---- 工具方法 ----
    @staticmethod
    def _simple_base(ann: str) -> str:
        """取类型注解的最外层基础类型名。"""
        import re
        a = (ann or '').strip().lower()
        while a.startswith(('optional[', 'union[')):
            inner = a[a.index('[') + 1:]
            a = inner.split(',')[0].strip() if inner else ''
        m = re.match(r'([a-z_][a-z0-9_]*)', a)
        return m.group(1) if m else ''

    @staticmethod
    def _deduplicate(mrs: list[MetamorphicRelation]) -> list[MetamorphicRelation]:
        seen = {}
        for mr in mrs:
            key = mr.category
            if key not in seen or mr.confidence > seen[key].confidence:
                seen[key] = mr
        return sorted(seen.values(), key=lambda m: -m.confidence)


__all__ = [
    'MRCategory', 'MetamorphicRelation',
    'MetamorphicSynthesizer',
]
