"""
仿射关系追踪器 — 追踪堆分配中变量间的仿射等式关系, 实现不依赖具体值的溢出判定.

核心问题:
  静态分析中 alloc=malloc(n*4+8) 和 memcpy(buf, src, n*8) 的 n 是同一个变量,
  但简单区间分析将两者独立处理, 丢失了 "write_size = alloc_size*2 - 16" 的关系.

方法: 仿射等式关系图 (Affine Relation Graph)
  每个变量/表达式建模为 base + Σ(coef × sym_var). 在赋值和处理时更新关系.
  当 malloc 和 memcpy 共享至少一个符号变量时, 可建立仿射关系.
  通过仿射减法判定: write_expr - alloc_expr 的符号决定了溢出可能性.

数学基础:
  Karr, Müller-Olm & Seidl, Gulwani & Necula.

与现有模块的关系:
  - StridedInterval: 变量独立区间; 本模块追踪变量间的关系
  - PathConditionTracker: 不等关系 (<=, <); 本模块追踪等量关系 (=)

TODO: 当malloc和memcpy分别在不同函数内时 (如主调函数malloc,
被调函数memcpy), 仿射关系会因跨函数符号绑定丢失而断开.
改进方向: 在调用点将被调函数副作用提升到调用者上下文.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple

from analysis.affine_expr import (
    AffineExpr, OverfRelation, expand_sizeof, parse_expression,
)


class AffineRelationTracker:
    """仿射关系追踪器 — 在伪代码中追踪变量间的仿射等式关系.

    工作流程:
      1. 扫描伪代码, 提取 malloc/calloc/realloc 的 size 表达式
      2. 追踪 size 变量的定义链: 算术运算、常量赋值、sizeof 乘法
      3. 追踪 memcpy/strcpy/loop 的 write size 表达式
      4. 检查 alloc_expr 和 write_expr 是否共享符号变量
      5. 若共享, 计算 diff = write - alloc, 判定符号 → verdict
    """

    # 匹配 malloc/calloc/realloc(size) — 支持 ptr = (type *)malloc(size) 带cast的写法
    _MALLOC_PATTERN = re.compile(
        r'(?:(\w+)\s*=\s*(?:\([^)]*\)\s*)?)?(malloc|calloc|realloc)\s*\(\s*([^)]+)\s*\)',
        re.IGNORECASE)
    # 匹配 memcpy/memmove — 捕获 dest(含偏移), src, size
    # memcpy(buf+32, src, 48) → dest="buf+32", size="48"
    _MEMCPY_PATTERN = re.compile(
        r'(memcpy|memmove)\s*\(\s*([^,]+?)\s*,\s*[^,]*,\s*([^)]+)\s*\)',
        re.IGNORECASE)
    # strcpy/gets/sprintf — 无界写入, 不捕获 size
    _UNBOUNDED_WRITE_PATTERN = re.compile(
        r'(strcpy|strcat|gets|sprintf)\s*\(', re.IGNORECASE)

    # 匹配赋值: 跳过类型声明前缀, 提取 var = expr
    # re.search 而非 re.match — 自动跳过行首的类型声明
    _ASSIGN_PATTERN = re.compile(r'(\w+)\s*=\s*(.+?)\s*;')

    def _process_line(self, line: str):
        """处理一行伪代码, 更新变量→表达式映射.

        支持:
          var = expr;
          type var = expr;
          type *var = expr;

        保守约束: 若RHS解析失败 (退化零表达式), 不存储映射,
        保留变量为符号未知量, 后续在malloc/memcpy中作为新鲜符号变量处理.
        """
        # re.search 自动跳过类型声明前缀, 匹配最后一个 var = expr
        m = self._ASSIGN_PATTERN.search(line)
        if not m:
            return
        lhs = m.group(1)
        rhs = m.group(2).strip().rstrip(';').strip()
        # 排除关键字和函数名混淆
        if lhs in ('if', 'else', 'for', 'while', 'return', 'switch', 'case',
                    'goto', 'break', 'continue', 'sizeof', 'typeof'):
            return
        if any(kw in rhs for kw in ('function', 'call', 'goto', 'if', 'else',
                                      'for', 'while', 'return', 'switch')):
            return
        # 跳过 malloc/calloc/realloc/free 调用 — 在 track_alloc_write_relation 中单独处理
        if re.search(r'\b(?:malloc|calloc|realloc|free)\s*\(', rhs):
            return
        expr = parse_expression(rhs, self._var_expr)
        # 退化零表达式 → 不存储 (保留为符号未知量)
        if expr is not None and not (expr.base == 0 and len(expr.terms) == 0):
            self._var_expr[lhs] = expr

    def __init__(self):
        self._var_expr: Dict[str, AffineExpr] = {}

    def analyze_function(self, pseudocode: str) -> Dict[str, AffineExpr]:
        """分析函数, 返回每个堆分配点的 size 仿射表达式."""
        self._var_expr.clear()
        lines = [l.strip() for l in pseudocode.splitlines()
                 if l.strip() and not l.strip().startswith('//')]
        for line in lines:
            self._process_line(line)
        return dict(self._var_expr)

    def track_alloc_write_relation(self, pseudocode: str) -> List[OverfRelation]:
        """一次性追踪所有 alloc-write 对的关系, 含 ptr 偏移 + realloc 感知."""
        relations = []
        alloc_sites = []   # (var, expr, line, func)
        write_sites = []   # (expr, line, offset_val)

        # 追踪每个变量的最新分配大小 (用于 realloc 场景)
        alloc_var_sizes: Dict[str, Tuple[AffineExpr, int]] = {}

        for i, line in enumerate(pseudocode.splitlines()):
            line = line.strip()
            if not line:
                continue
            self._process_line(line)

            m = self._MALLOC_PATTERN.search(line)
            if m:
                target_var = m.group(1)
                alloc_func = m.group(2)
                raw_size = m.group(3).strip()
                size_expr = parse_expression(raw_size, self._var_expr)
                if target_var is None:
                    target_var = f"_alloc_{i}"
                    self._var_expr[target_var] = size_expr
                alloc_sites.append((target_var, size_expr, i, alloc_func))
                # 追踪: realloc 更新, malloc/calloc 新建
                if target_var not in alloc_var_sizes or alloc_func == 'realloc':
                    alloc_var_sizes[target_var] = (size_expr, i)

            # memcpy/memmove: 新 pattern 捕获 (func, dest_expr, size)
            mw = self._MEMCPY_PATTERN.search(line)
            if mw:
                dest_str = mw.group(2).strip()   # e.g. "buf + 32" or "buf"
                raw_size = mw.group(3).strip()    # e.g. "48"
                write_expr = parse_expression(raw_size, self._var_expr)

                # 提取指针偏移: "buf + 32" → offset=32
                offset_val = 0
                off_match = re.match(r'(\w+)\s*\+\s*(\d+)', dest_str)
                if off_match:
                    offset_val = int(off_match.group(2))
                    dest_var = off_match.group(1)
                    # 若 dest 有 realloc 踪迹, 插入对应 alloc_site
                    if dest_var in alloc_var_sizes:
                        realloc_expr, rline = alloc_var_sizes[dest_var]
                        alloc_sites.append((dest_var, realloc_expr, rline, 'realloc'))

                write_sites.append((write_expr, i, offset_val))

        for alloc_var, alloc_expr, aline, afunc in alloc_sites:
            for write_expr, wline, offset_val in write_sites:
                if wline < aline:
                    continue

                # 将指针偏移量纳入写入大小: write_total = write_expr + offset
                if offset_val > 0:
                    total_write = AffineExpr(write_expr.base + offset_val,
                                             dict(write_expr.terms))
                else:
                    total_write = write_expr

                diff = total_write - alloc_expr
                shared = alloc_expr.shared_vars(total_write)

                if not shared and alloc_expr.is_constant and total_write.is_constant:
                    if total_write.base > alloc_expr.base:
                        verdict, cond = "OVERFLOW", f"{total_write.base} > {alloc_expr.base}"
                    elif total_write.base < alloc_expr.base:
                        verdict, cond = "SAFE", f"{total_write.base} < {alloc_expr.base}"
                    else:
                        # 两者均为同一常数 (如 2 <= 2) → 可能是parse失败导致
                        # 变量未被提取, 不可轻判SAFE
                        verdict, cond = "CONDITIONAL", (
                            f"{total_write.base} == {alloc_expr.base} — "
                            "constant equality, possible parse failure")
                elif not shared:
                    verdict, cond = "UNKNOWN", "no shared symbolic variables"
                else:
                    verdict, cond = self._analyze_diff_symbol(diff, shared)

                relations.append(OverfRelation(
                    alloc_expr=alloc_expr, write_expr=total_write,
                    diff_expr=diff, verdict=verdict,
                    condition=cond, shared_vars=shared,
                ))
        return relations

    def _analyze_diff_symbol(self, diff: AffineExpr,
                              shared_vars: Set[str]) -> Tuple[str, str]:
        """分析 diff = write - alloc 的符号特性.

        关键判定:
          - diff 对所有可能变量值都 > 0 → OVERFLOW
          - diff 对所有可能变量值都 <= 0 → SAFE
          - 否则 → CONDITIONAL (依赖变量范围)

        保守约束 (FP→CONDITIONAL降级):
          1. diff退化为常数 (所有变量系数抵消为0) 且 shared_vars 非空 →
             alloc==write 可能掩盖整数溢出 (如 total=hdr_sz+body_sz 溢出 wrap),
             不可判SAFE
          2. diff == 0 且无可信常量 → 精确匹配需守卫条件佐证, 不可单独判SAFE
        """
        # 约束1: 退化diff检测
        # 若diff无变量项 (所有系数抵消) 但shared_vars非空,
        # 说明 alloc和write使用了相同的变量表达式 → 可能掩盖整数溢出
        if diff.is_constant and shared_vars:
            if diff.base > 0:
                return ("OVERFLOW",
                        f"write exceeds alloc by {diff.base} bytes "
                        f"(shared: {shared_vars})")
            elif diff.base < 0:
                return ("SAFE",
                        f"alloc exceeds write by {-diff.base} bytes "
                        f"(shared: {shared_vars}) — non-degenerate")
            else:
                # diff == 0: alloc和write表达式完全一致 → 可疑
                # 例: malloc(total) + memcpy(total) 其中 total=hdr_sz+body_sz
                #     若 total 整数溢出 → malloc(小) + memcpy(大) → 真实漏洞
                return ("CONDITIONAL",
                        f"alloc == write (shared: {shared_vars}) — "
                        f"may mask integer overflow, cannot prove safety")

        min_diff = diff.base
        max_diff = diff.base

        for var, coef in diff.terms.items():
            if coef > 0:
                min_diff += coef * 1
                max_diff = float('inf')
            else:
                min_diff = float('-inf')
                max_diff += coef * 1

        non_shared_coef_sum = sum(
            abs(c) for v, c in diff.terms.items() if v not in shared_vars)
        if non_shared_coef_sum > 0:
            return "CONDITIONAL", "non-shared variables with unknown bounds"

        if min_diff > 0:
            return "OVERFLOW", f"write - alloc = {diff} > 0 for all positive inputs"
        elif max_diff <= 0:
            return "SAFE", f"write - alloc = {diff} <= 0 for all positive inputs"
        else:
            return "CONDITIONAL", f"sign depends on variable values"


def track_affine_overflow(pseudocode: str) -> List[OverfRelation]:
    """便捷函数: 从伪代码追踪所有仿射溢出关系."""
    tracker = AffineRelationTracker()
    return tracker.track_alloc_write_relation(pseudocode)


__all__ = ['AffineExpr', 'OverfRelation', 'AffineRelationTracker',
           'track_affine_overflow']
