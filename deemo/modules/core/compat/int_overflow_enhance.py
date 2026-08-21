# coding: utf-8
"""
整数溢出 L4-L6 增强管线 — 同余感知回绕 + 混合符号 + 分配影响链追踪.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# 复用已有模块
from .int_overflow import (
    IntWidth, OverflowType, IntOperation, OverflowResult,
    IntRangeAnalyzer, detect_int_overflow)


class SignFlow(Enum):
    """符号传播方向."""
    SIGNED_TO_SIGNED = auto()     # 有符号→有符号 (安全)
    UNSIGNED_TO_UNSIGNED = auto() # 无符号→无符号 (安全)
    SIGNED_TO_UNSIGNED = auto()   # 有符号→无符号 (危险: 负值变大正)
    UNSIGNED_TO_SIGNED = auto()   # 无符号→有符号 (危险: 大正变负)
    UNKNOWN = auto()


@dataclass
class CongruenceWrapResult:
    """同余精化后的回绕分析结果."""
    raw_range: Tuple[int, int]       # 未精化的结果区间
    congruence_modulus: int           # 模数 (通常是 2^w)
    refined_range: Tuple[int, int]   # 精化后的区间
    narrowing_achieved: bool          # 是否成功精化
    narrowed_by: str                  # 精化方法描述


class CongruenceWrapAnalyzer:
    """L4: 同余感知回绕分析 — 利用模数约束精化 wrap 后区间.

    x*65536 mod 2^32 → result ≡ 0 (mod 65536), 65537 个可能值而非 2^32.
    """

    def __init__(self, width: IntWidth = IntWidth.I32):
        self.modulus = width.value[3] + 1  # 2^w

    def compute_known_divisor(self, op: IntOperation) -> int:
        """计算结果必然可被整除的因子 (常量乘数乘积)."""
        d = 1
        for operand in (op.left, op.right):
            try:
                val = int(operand)
                if val > 1:
                    d *= val
            except (ValueError, TypeError):
                pass
        return d

    def narrow_wrap_range(
        self, op: IntOperation,
        left_range: Tuple[int, int],
        right_range: Tuple[int, int],
        raw_result_lo: int, raw_result_hi: int,
    ) -> CongruenceWrapResult:
        """同余约束精化回绕区间. 未退化则直接返回, 退化了则用 divisor 收缩."""
        modulus = self.modulus
        if raw_result_hi - raw_result_lo + 1 < modulus:
            return CongruenceWrapResult(
                raw_range=(raw_result_lo, raw_result_hi),
                congruence_modulus=1,
                refined_range=(raw_result_lo % modulus, raw_result_hi % modulus),
                narrowing_achieved=False,
                narrowed_by='no congruence constraint available')

        divisor = self.compute_known_divisor(op)
        if divisor <= 1:
            return CongruenceWrapResult(
                raw_range=(raw_result_lo, raw_result_hi),
                congruence_modulus=1,
                refined_range=(raw_result_lo % modulus, raw_result_hi % modulus),
                narrowing_achieved=False,
                narrowed_by='no congruence constraint available')

        refined_lo, refined_hi = 0, modulus - divisor
        refined_count = modulus // divisor
        if op.op == 'mul':
            max_distinct = min(refined_count,
                               (left_range[1] - left_range[0] + 1) * (right_range[1] - right_range[0] + 1))
            if max_distinct < refined_count:
                refined_hi = min(refined_hi, refined_lo + max_distinct * divisor - divisor)

        return CongruenceWrapResult(
            raw_range=(raw_result_lo, raw_result_hi),
            congruence_modulus=divisor,
            refined_range=(refined_lo, refined_hi),
            narrowing_achieved=True,
            narrowed_by=f'result ≡ 0 (mod {divisor}), step={divisor}')


class MixedSignAnalyzer:
    """L5: 混合符号路径分析 — 有符号→无符号/无符号→有符号 风险追踪."""

    _DANGER = {
        SignFlow.SIGNED_TO_UNSIGNED: '负值→大正 (alloc 绕过)',
        SignFlow.UNSIGNED_TO_SIGNED: '大正→负值 (边界检查绕过)',
    }

    def __init__(self):
        self._var_signs: Dict[str, bool] = {}

    def declare(self, var: str, signed: bool):
        self._var_signs[var] = signed

    def analyze_flow(self, src_var: str, dst_var: str,
                     src_width: IntWidth, dst_width: IntWidth) -> Tuple[SignFlow, str]:
        """分析变量间符号传播, 返回 (flow, danger_description)."""
        src_s = self._var_signs.get(src_var, True)
        dst_s = self._var_signs.get(dst_var, False)
        if src_s == dst_s:
            flow = SignFlow.SIGNED_TO_SIGNED if src_s else SignFlow.UNSIGNED_TO_UNSIGNED
        elif src_s:
            flow = SignFlow.SIGNED_TO_UNSIGNED
        else:
            flow = SignFlow.UNSIGNED_TO_SIGNED
        danger = self._DANGER.get(flow, '')
        if dst_width.value[0] < src_width.value[0]:
            danger += f' + 宽度缩小 ({src_width.value[0]}→{dst_width.value[0]}bits)'
        return flow, danger

    def batch_analyze(self, def_use_chains: Dict[str, List[str]]) -> List[Dict]:
        """批量分析符号流."""
        return [{
            'src': src, 'dst': dst,
            'flow': (r := self.analyze_flow(src, dst, IntWidth.I32, IntWidth.I32))[0].name,
            'danger': r[1],
            'is_risky': r[0] in (SignFlow.SIGNED_TO_UNSIGNED, SignFlow.UNSIGNED_TO_SIGNED),
        } for dst, srcs in def_use_chains.items()
          for src in srcs if src in self._var_signs and dst in self._var_signs]


@dataclass
class AllocImpactTrace:
    """溢出→分配影响的追踪结果."""
    overflow_op: IntOperation
    overflow_result: OverflowResult
    reaches_alloc: bool
    alloc_var: str
    alloc_size_range: Tuple[int, int]
    is_exploitable: bool
    trace_path: List[str]   # 从溢出处到分配的变量链


class AllocImpactTracer:
    """L6: 分配器影响链 — BFS 追踪溢出变量 → malloc(N)/alloca(N) 的 def-use 路径."""

    def __init__(self):
        self._alloc_sites: Dict[str, Tuple[int, int]] = {}
        self._write_sites: Dict[str, Tuple[int, int]] = {}
        self._def_use: Dict[str, List[str]] = {}

    def add_alloc(self, size_var: str, lo: int, hi: int):
        self._alloc_sites[size_var] = (lo, hi)

    def add_write(self, size_var: str, lo: int, hi: int):
        self._write_sites[size_var] = (lo, hi)

    def add_def_use(self, def_var: str, use_vars: List[str]):
        self._def_use[def_var] = use_vars

    def trace_to_alloc(self, overflow_var: str, max_depth: int = 4) -> Optional[AllocImpactTrace]:
        """BFS 正向追踪溢出→分配路径. 深度 ≤ max_depth."""
        visited = set()
        queue = [(overflow_var, 0, [overflow_var])]
        while queue:
            var, depth, path = queue.pop(0)
            if var in visited or depth > max_depth:
                continue
            visited.add(var)
            if var in self._alloc_sites:
                alo, ahi = self._alloc_sites[var]
                # 查找关联写入: write_{var} 或 alloc_→write_ 替换
                wlo, whi = 0, 0
                for wv, wr in self._write_sites.items():
                    if wv in (f'write_{var}', var.replace('alloc_', 'write_')):
                        wlo, whi = wr
                        break
                return AllocImpactTrace(
                    overflow_op=IntOperation('?', overflow_var, '?', IntWidth.I32),
                    overflow_result=OverflowResult(
                        IntOperation('?', overflow_var, '?', IntWidth.I32),
                        OverflowType.WRAP_UNSIGNED, (0, 2**32 - 1), (0, 0), True),
                    reaches_alloc=True, alloc_var=var,
                    alloc_size_range=(alo, ahi),
                    is_exploitable=(whi > ahi) if whi > 0 else False,
                    trace_path=path)
            for u in self._def_use.get(var, []):
                if u not in visited:
                    queue.append((u, depth + 1, path + [u]))
        return None


def _parse_op(op_str: str, width: IntWidth, signed: bool) -> Optional[IntOperation]:
    """从字符串解析 IntOperation."""
    parts = op_str.split()
    if len(parts) >= 3:
        return IntOperation(op=parts[1], left=parts[0], right=parts[2], width=width, signed=signed)
    return None


def enhanced_detect_int_overflow(
    operations: List[IntOperation],
    known_ranges: Dict[str, Tuple[int, int]],
    alloc_sites: Dict[str, Tuple[int, int]] = None,
    write_sites: Dict[str, Tuple[int, int]] = None,
    def_use_chains: Dict[str, List[str]] = None,
) -> Tuple[List[Dict], Dict]:
    """增强整数溢出检测 — L1→L6 全管线."""
    alloc_sites = alloc_sites or {}
    write_sites = write_sites or {}
    def_use_chains = def_use_chains or {}
    width = IntWidth.I32
    cwa = CongruenceWrapAnalyzer(width=width)
    msa = MixedSignAnalyzer()
    ait = AllocImpactTracer()
    stats = {'L1_input': len(operations), 'L4_congruence': 0, 'L5_sign': 0, 'L6_alloc_chain': 0, 'final': 0}

    # L0-L2: 基本范围分析
    basic = detect_int_overflow(operations, known_ranges, {k: v[0] for k, v in alloc_sites.items()})

    # L4: 同余感知回绕精化
    enhanced = []
    for c in basic:
        io_op = _parse_op(c['operation'], width, c['signed'])
        if io_op and c['overflow_type'] in ('WRAP_UNSIGNED', 'WRAP_SIGNED'):
            cr = cwa.narrow_wrap_range(
                io_op, known_ranges.get(io_op.left, (0, 2**16)),
                known_ranges.get(io_op.right, (0, 2**16)),
                c['result_range'][0], c['result_range'][1])
            c['congruence'] = {'refined_range': cr.refined_range, 'narrowed': cr.narrowing_achieved, 'method': cr.narrowed_by}
            if cr.narrowing_achieved:
                c['result_range'] = cr.refined_range
                stats['L4_congruence'] += 1
        enhanced.append(c)

    # L5: 混合符号分析
    for c in enhanced:
        if parts := c['operation'].split():
            msa.declare(parts[0], c['signed'])
    risky_vars = {sr['src'] for sr in msa.batch_analyze(def_use_chains) if sr['is_risky']}
    for c in enhanced:
        if (parts := c['operation'].split()) and parts[0] in risky_vars:
            c['sign_mismatch'] = True
            stats['L5_sign'] += 1

    # L6: 分配器影响链
    for var, rng in alloc_sites.items():
        ait.add_alloc(var, rng[0], rng[1])
    for var, rng in write_sites.items():
        ait.add_write(var, rng[0], rng[1])
    for var, uses in def_use_chains.items():
        ait.add_def_use(var, uses)

    filtered = []
    for c in enhanced:
        parts = c['operation'].split()
        if parts and (trace := ait.trace_to_alloc(parts[0])) and trace.reaches_alloc:
            c['alloc_trace'] = {'reaches_alloc': True, 'alloc_var': trace.alloc_var,
                                'alloc_size_range': trace.alloc_size_range,
                                'is_exploitable': trace.is_exploitable, 'trace_path': trace.trace_path}
            if trace.is_exploitable:
                stats['L6_alloc_chain'] += 1
        if c.get('is_dangerous', False):
            filtered.append(c)

    stats['final'] = len(filtered)
    return filtered, stats
