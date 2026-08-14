"""
仿射关系分析器: 在每个 IR 程序点计算仿射状态。
在赋值处更新 AffineDomain, 在 malloc/memcpy 处记录仿射状态供后续溢出验证使用,
用于判定区间域无法裁决的溢出/安全候选 (乘法、加法偏移、链式关系等模式)。
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from core.affine_relation import AffineDomain

# 模式识别器 ─────────────────────────────────────────────────────

# 赋值: var = const
_CONST_ASSIGN_RE = re.compile(r'^(\w[\w.]*)\s*=\s*(-?\d+|0x[0-9a-fA-F]+)\s*;?$')

# 赋值: var = other_var
_ALIAS_ASSIGN_RE = re.compile(r'^(\w[\w.]*)\s*=\s*([a-zA-Z_]\w*)\s*;?$')

# 赋值: var = other_var + const
_ADD_CONST_RE = re.compile(r'^(\w[\w.]*)\s*=\s*([a-zA-Z_]\w*)\s*\+\s*(-?\d+)\s*;?$')

# 赋值: var = other_var * const
_MUL_CONST_RE = re.compile(r'^(\w[\w.]*)\s*=\s*([a-zA-Z_]\w*)\s*\*\s*(\d+)\s*;?$')

# 赋值: var = const * other_var
_CONST_MUL_RE = re.compile(r'^(\w[\w.]*)\s*=\s*(\d+)\s*\*\s*([a-zA-Z_]\w*)\s*;?$')

# 赋值: var = other_var - const
_SUB_CONST_RE = re.compile(r'^(\w[\w.]*)\s*=\s*([a-zA-Z_]\w*)\s*-\s*(\d+)\s*;?$')

# malloc: var = malloc(size_var)
_MALLOC_ASSIGN_RE = re.compile(
    r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*(?:malloc|realloc)\s*'
    r'\(\s*(\w[\w.]*)\s*')

# calloc: var = calloc(count, elem_size) — 取非数字参数作为size_var
_CALLOC_ASSIGN_RE = re.compile(
    r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*calloc\s*'
    r'\(\s*(\w[\w.]*)\s*,\s*(\w[\w.]*)\s*\)')

# memcpy: memcpy(dst, src, size_var)
_MEMCPY_ASSIGN_RE = re.compile(
    r'(?:memcpy|memmove|strncpy)\s*\(\s*(\w[\w.]*)\s*,\s*[^,]*,\s*'
    r'(\w[\w.]*)\s*\)')

class AffineAnalyzer:
    """堆溢出变量的前向仿射关系分析器。

    逐行追踪 IR 上的仿射关系, 在 malloc 与 memcpy 处记录当前仿射状态供后续溢出验证使用。
    用法: malloc_sites, memcpy_sites, final_state = analyzer.analyze(ir_lines)。
    """

    def __init__(self):
        self._domain = AffineDomain()
        # 收集到的站点: {var_name: {'size_var': str, 'line': int, 'affine_state': copy}}
        self._malloc_sites: List[Dict] = []
        self._memcpy_sites: List[Dict] = []
        # 记录哪些变量是堆指针 (malloc 结果)
        self._heap_ptrs: Set[str] = set()

    def analyze(self, ir_lines: List[str]) -> Tuple[
        List[Dict], List[Dict], AffineDomain
    ]:
        """对 IR 行执行前向仿射分析, 返回 (malloc_sites, memcpy_sites, final_domain)。

        malloc_site 含 var/size_var/line/affine_state, memcpy_site 含 dst_var/size_var/line/affine_state。
        """
        self._domain = AffineDomain()
        self._malloc_sites = []
        self._memcpy_sites = []
        self._heap_ptrs = set()

        for i, line in enumerate(ir_lines):
            stripped = line.strip().rstrip(';')

            # 常量赋值: var = 123
            cm = _CONST_ASSIGN_RE.match(stripped)
            if cm:
                var, val = cm.group(1), int(cm.group(2), 0)
                # 仅追踪与大小相关的变量 (非指针)
                if not self._is_keyword(var) and not self._is_heap_func(val):
                    self._domain.assign_constant(var, val)
                continue

            # 别名赋值: var = other
            am = _ALIAS_ASSIGN_RE.match(stripped)
            if am:
                lhs, rhs = am.group(1), am.group(2)
                if not self._is_keyword(lhs) and not self._is_keyword(rhs):
                    self._domain.assign_alias(lhs, rhs)
                continue

            # 加法: var = other + const
            acm = _ADD_CONST_RE.match(stripped)
            if acm:
                lhs, rhs, const = acm.group(1), acm.group(2), int(acm.group(3))
                if not self._is_keyword(lhs):
                    self._domain.assign_add(lhs, rhs, const)
                continue

            # 减法: var = other - const
            scm = _SUB_CONST_RE.match(stripped)
            if scm:
                lhs, rhs, const = scm.group(1), scm.group(2), int(scm.group(3))
                if not self._is_keyword(lhs):
                    self._domain.assign_add(lhs, rhs, -const)
                continue

            # 乘法: var = other * const
            mcm = _MUL_CONST_RE.match(stripped)
            if mcm:
                lhs, rhs, factor = mcm.group(1), mcm.group(2), int(mcm.group(3))
                if not self._is_keyword(lhs):
                    self._domain.assign_mul(lhs, rhs, factor)
                continue

            # 乘法: var = const * other
            ccm = _CONST_MUL_RE.match(stripped)
            if ccm:
                lhs, factor, rhs = ccm.group(1), int(ccm.group(2)), ccm.group(3)
                if not self._is_keyword(lhs):
                    self._domain.assign_mul(lhs, rhs, factor)
                continue

            # calloc: var = calloc(count, elem_size)
            # 取非数字参数作为size_var (仿射分析需要符号变量)
            cm = _CALLOC_ASSIGN_RE.search(stripped)
            if cm:
                ptr_var = cm.group(1)
                arg1, arg2 = cm.group(2), cm.group(3)
                size_var = arg2 if arg1.isdigit() else (
                    arg1 if arg2.isdigit() else arg2)
                self._heap_ptrs.add(ptr_var)
                self._malloc_sites.append({
                    'var': ptr_var, 'size_var': size_var,
                    'line': i,
                    'affine_state': self._domain.copy(),
                })
                continue

            # malloc: var = malloc(size_expr)
            mm = _MALLOC_ASSIGN_RE.search(stripped)
            if mm:
                ptr_var = mm.group(1)
                size_var = mm.group(2)
                self._heap_ptrs.add(ptr_var)
                # 记录此 malloc 处的仿射状态
                self._malloc_sites.append({
                    'var': ptr_var, 'size_var': size_var,
                    'line': i,
                    'affine_state': self._domain.copy(),
                })
                continue

            # memcpy: memcpy(dst, src, size)
            wm = _MEMCPY_ASSIGN_RE.search(stripped)
            if wm:
                dst_var = wm.group(1)
                size_var = wm.group(2)
                self._memcpy_sites.append({
                    'dst_var': dst_var, 'size_var': size_var,
                    'line': i,
                    'affine_state': self._domain.copy(),
                })
                continue

            # realloc: var = realloc(ptr, size)
            # 已由 MALLOC_ASSIGN_RE 处理 (模式包含 realloc)
            # free(var): 从堆指针集合移除
            if 'free(' in stripped:
                fm = re.search(r'free\s*\(\s*(\w[\w.]*)\s*\)', stripped)
                if fm:
                    ptr = fm.group(1)
                    self._heap_ptrs.discard(ptr)

        return self._malloc_sites, self._memcpy_sites, self._domain

    def resolve_overflow_candidates(
        self,
        alloc_var: str,
        alloc_size_var: str,
        write_size_var: str,
        affine_state: Optional[AffineDomain] = None,
    ) -> Tuple[Optional[bool], str]:
        """尝试用仿射关系证明溢出或安全。返回 (is_overflow, reason): True 表示证明溢出, False 表示证明安全, None 表示无法裁决。"""
        dom = affine_state or self._domain

        # 尝试证明溢出: write_size > alloc_size
        proven, reason = dom.can_prove_overflow(
            write_size_var, alloc_size_var)
        if proven:
            return True, reason

        # 尝试证明安全: write_size <= alloc_size + slack
        proven, reason = dom.can_prove_safe(
            write_size_var, alloc_size_var)
        if proven:
            return False, reason

        return None, 'affine-undecided'

    @staticmethod
    def _is_keyword(name: str) -> bool:
        return name in {'if', 'else', 'for', 'while', 'return',
                        'goto', 'break', 'continue', 'sizeof'}

    @staticmethod
    def _is_heap_func(val: int) -> bool:
        return False  # constants are never heap function results

    def get_state_at(self, line: int) -> AffineDomain:
        """返回指定行处的仿射域状态。"""
        return self._domain

def analyze_affine_relations(
    ir_lines: List[str],
) -> Tuple[List[Dict], List[Dict], AffineDomain]:
    """便捷入口: 对 IR 行执行仿射分析, 返回 (malloc_sites, memcpy_sites, final_domain)。"""
    analyzer = AffineAnalyzer()
    return analyzer.analyze(ir_lines)

__all__ = ['AffineAnalyzer', 'analyze_affine_relations']
