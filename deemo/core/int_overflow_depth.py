"""
整数溢出深度分析器 — 用三维度取代窄正则匹配, 检测通向堆溢出的整数溢出 (CWE-190/191/680/681)。
维度: 类型流转(signed→unsigned)、循环累加、守卫距离, 覆盖纯正则检测的召回盲区。
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# patterns ───────────────────────────────────────────────────────────

_ALLOC = re.compile(
    r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*'
    r'(\w*(?:malloc|calloc|realloc|alloc\w*)\w*)\s*'
    r'\(\s*(.+?)\s*\)')
_ADD_ASSIGN = re.compile(r'(\w[\w.]*)\s*\+=\s*(.+?)\s*;')
_LOOP_HEAD = re.compile(r'\b(?:for|while)\s*\(')
_SIGNED_VAR = re.compile(r'\bint\s+(\w[\w.]*)\b')
_CAST_SIZET = re.compile(r'\(\s*(?:size_t|unsigned(?:\s+long)?)\s*\)\s*'
                         r'(\w[\w.]*)')
_MUL_EXPR = re.compile(r'(\w[\w.]*)\s*\*\s*(?:sizeof\s*\([^)]+\)|\d+|\w[\w.]*)')
_SAFE_GUARD = re.compile(
    r'if\s*\(\s*(\w[\w.]*)\s*(?:>|>=)\s*'
    r'(?:SIZE_MAX|UINT_MAX|INT_MAX|MAX|0x[0-9a-fA-F]+)\s*/\s*'
    r'(?:\([^)]*\)\s*)?(?:sizeof|size|\w[\w.(]*)\s*'
    r'\)\s*(?:return|goto)')


@dataclass
class IoDepthResult:
    """整数溢出深度检测结果。"""
    line: int; alloc_var: str = ''; size_expr: str = ''
    is_signed_source: bool = False   # signed int → unsigned narrowing
    is_loop_accum: bool = False      # += in loop before alloc
    has_nearby_guard: bool = False   # overflow guard within 10 lines
    is_constant_expr: bool = False   # all-constant size expression
    guard_distance: int = -1
    confidence: float = 0.50
    verdict: str = 'REVIEW'
    detail: str = ''


class IntOverflowDepthAnalyzer:
    """三维度整数溢出深度分析器。"""

    def __init__(self):
        self.stats: Dict[str, int] = {}

    def analyze(self, ir_lines: List[str]) -> List[IoDepthResult]:
        """对 IR 行执行完整三维分析。"""
        results = []
        allocs = self._find_allocs(ir_lines)

        for al in allocs:
            result = IoDepthResult(
                line=al[0], alloc_var=al[1], size_expr=al[2])

            # 维度0: 常量表达式检测
            result.is_constant_expr = self._check_constant(al[2])

            # 维度1: signed→unsigned 类型流转
            result.is_signed_source = self._check_signed_source(
                ir_lines, al[2], al[0])

            # 维度2: 循环累加
            result.is_loop_accum = self._check_loop_accum(
                ir_lines, al[1], al[0])

            # 维度3: 守卫距离
            result.has_nearby_guard, result.guard_distance = \
                self._check_guard(ir_lines, al[2], al[0])

            # 评分并裁决
            result.confidence, result.verdict, result.detail = \
                self._score(result)
            results.append(result)

        self.stats = {
            'total_allocs': len(allocs),
            'signed_sources': sum(1 for r in results if r.is_signed_source),
            'loop_accums': sum(1 for r in results if r.is_loop_accum),
            'no_guard': sum(1 for r in results if not r.has_nearby_guard),
            'confirmed': sum(1 for r in results if r.verdict == 'CONFIRMED'),
            'filtered': sum(1 for r in results
                           if r.verdict == 'FILTERED'),
        }
        return results

    @staticmethod
    def _find_allocs(ir_lines: List[str]) -> List[Tuple[int, str, str]]:
        """查找全部堆分配点并提取大小表达式。"""
        allocs = []
        for i, line in enumerate(ir_lines):
            m = _ALLOC.search(line)
            if m:
                allocs.append((i, m.group(1), m.group(3).strip()))
        return allocs

    # 维度1: signed 来源检测 ────────────────────────

    def _check_signed_source(self, ir_lines: List[str],
                             size_expr: str, line: int) -> bool:
        """检测参与分配大小的 signed 整型变量。"""

        # 直接: 大小表达式中含 int 变量
        vars_in_expr = re.findall(r'\b(\w[\w.]*)\b', size_expr)
        # 过滤数字常量与 sizeof
        numeric_vars = {v for v in vars_in_expr
                        if not v.isdigit() and v not in ('sizeof',
                        'NULL', 'SIZE_MAX')}

        # 检查变量是否声明为 signed int
        for vi in numeric_vars:
            for i in range(0, line):
                if re.search(rf'\bint\s+{re.escape(vi)}\b', ir_lines[i]):
                    return True
                # 另查: vi 是否为 atoi/atol 的结果
                if f'{vi} = atoi(' in ir_lines[i] or \
                   f'{vi} = atol(' in ir_lines[i]:
                    return True

        # 间接: 检查大小表达式含 * 且无守卫
        mul_m = _MUL_EXPR.search(size_expr)
        if mul_m:
            # 纯常量操作数安全 (编译期折叠)
            operand = mul_m.group(1)
            if operand.isdigit():
                return False  # 例: malloc(256 * sizeof(int)) 安全
            for i in range(max(0, line - 15), line):
                if _SAFE_GUARD.search(ir_lines[i]):
                    return False  # 有守卫, 无实际危险
            return True  # 无守卫乘法 = 溢出风险

        return False

    # 维度2: 循环累加 ────────────────────────────────

    @staticmethod
    def _check_loop_accum(ir_lines: List[str],
                          alloc_var: str, line: int) -> bool:
        """检测分配大小变量是否在循环中被累加。"""
        # 查找 malloc 使用的大小变量
        # 回溯: 哪个变量喂给分配大小?
        size_var = alloc_var

        # 简单情形: malloc(total), total 在循环中 +=
        for i in range(0, line):
            if _ADD_ASSIGN.search(ir_lines[i]):
                m = _ADD_ASSIGN.search(ir_lines[i])
                acc_var = m.group(1) if m else ''
                # 检查该累加器是否用作大小
                for j in range(i + 1, min(len(ir_lines), line + 1)):
                    al = _ALLOC.search(ir_lines[j])
                    if al and acc_var in al.group(2):
                        # 检查 += 是否在循环内
                        for k in range(max(0, i - 5), i):
                            if _LOOP_HEAD.search(ir_lines[k]):
                                return True
        return False

    # 维度3: 守卫距离 ─────────────────────────────────

    @staticmethod
    def _check_guard(ir_lines: List[str],
                     size_expr: str, line: int) -> Tuple[bool, int]:
        """检查分配附近是否存在溢出守卫。"""
        # 向前扫描守卫
        for dist in range(1, min(20, line + 1)):
            prev = line - dist
            if prev < 0:
                break
            pline = ir_lines[prev]
            if 'if' in pline and 'return' in pline:
                # 提取守卫涉及的变量
                vars_in_guard = set(re.findall(r'\b(\w\w+)\b', pline))
                vars_in_size = set(re.findall(r'\b(\w\w+)\b', size_expr))
                if vars_in_guard & vars_in_size:
                    return True, dist
            sm = _SAFE_GUARD.search(pline)
            if sm:
                return True, dist
        return False, -1

    # 维度0: 常量检测 ───────────────────────────

    @staticmethod
    def _check_constant(size_expr: str) -> bool:
        """检查大小表达式是否全为常量 (编译期可折叠), 如 256*sizeof(int)、1000。"""
        # 去除括号与类型转换前缀
        cleaned = re.sub(r'\([^)]*\)\s*', '', size_expr).strip()
        # 模式: 纯常量与 sizeof
        parts = re.split(r'\s*\*\s*', cleaned)
        for p in parts:
            p = p.strip()
            if p.isdigit():
                continue
            if p.startswith('sizeof'):
                continue
            if p == '':
                continue
            return False  # 含变量
        return True if len(parts) > 0 else False

    # 评分 ──────────────────────────────────────────────────────

    @staticmethod
    def _score(r: IoDepthResult) -> Tuple[float, str, str]:
        """评分: signed(0.35) + loop(0.25) + no_guard(0.40)。常量表达式得 0 分 (构造成安全)。"""
        if r.is_constant_expr:
            return 0.0, 'FILTERED', 'constant_expr'

        score = 0.0; details = []

        if r.is_signed_source:
            score += 0.35; details.append('signed_source')
        if r.is_loop_accum:
            score += 0.25; details.append('loop_accum')
        if not r.has_nearby_guard:
            score += 0.40; details.append('no_guard')
        else:
            details.append(f'guard_at_dist={r.guard_distance}')

        if score >= 0.60:
            verdict = 'CONFIRMED'
        elif score >= 0.35:
            verdict = 'REVIEW'
        else:
            verdict = 'FILTERED'

        return round(score, 2), verdict, ', '.join(details)


def analyze_int_overflow(ir_lines: List[str]) -> Tuple[
    List[IoDepthResult], Dict[str, int]]:
    """便捷接口: 执行深度分析, 返回结果与统计。"""
    analyzer = IntOverflowDepthAnalyzer()
    results = analyzer.analyze(ir_lines)
    return results, analyzer.stats


__all__ = ['IoDepthResult', 'IntOverflowDepthAnalyzer',
           'analyze_int_overflow']
