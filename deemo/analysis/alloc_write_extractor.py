"""
分配-写入关系提取器 — 从伪代码中提取 alloc-write 对, 扩展 memcpy 以外的写入模式.

与 AffineRelationTracker 配合使用: 前者处理 memcpy/strcpy 等批量写入 (已知写入大小),
本模块处理 buf[idx] = x 等单元素写入 (未知写入大小, 但偏移与分配大小存在关系).

解决的问题:
  - AffineRelationTracker 仅匹配 memcpy(_, _, size) 模式
  - 大量 CVE 样本使用 buf[idx] = value 的数组写入模式
  - 需要提取这类写入的偏移变量和分配大小, 供 GuardAnalysis 判定

扩展的写入模式:
  1. buf[expr] = value          → 单元素写入, offset = expr
  2. buf + offset = value       → 指针运算写入
  3. buf->field = value         → 结构体字段写入 (已知偏移)
  4. loop: for(i=0; i<N; i++) buf[i] = ... → 循环写入, size = N
  5. strcpy(buf, src)           → 无界写入 (危险)

输出: List[AllocWritePair], 每个包含分配信息、写入信息、偏移变量.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class AllocSite:
    """堆分配点."""
    line: int
    func: str            # malloc / calloc / realloc
    var: str             # 分配到的变量名
    size_expr: str       # 分配大小表达式
    size_constant: Optional[int] = None  # 若为常量, 记录值


@dataclass
class WriteSite:
    """堆写入点."""
    line: int
    mode: str            # 'array_index' / 'ptr_offset' / 'struct_field' / 'loop' / 'strcpy'
    target_var: str      # 缓冲区变量名
    offset_var: str      # 偏移变量 (单元素写入)
    offset_expr: str     # 偏移表达式
    size_hint: Optional[int] = None  # 若已知 (来自循环边界)


@dataclass
class AllocWritePair:
    """分配-写入对."""
    alloc: AllocSite
    write: WriteSite
    shared_vars: Set[str] = field(default_factory=set)
    verdict_hint: str = "UNCERTAIN"  # 初步判定


class AllocWriteExtractor:
    """从伪代码中提取分配点和写入点, 并配对.

    工作流程:
      1. 扫描所有的 malloc/calloc/realloc 调用
      2. 扫描所有的数组写入/指针写入/strcpy
      3. 按变量名配对: 写入目标 = 分配给变量
      4. 识别共享符号变量 (例如: malloc(n*4), buf[n] = x → n 为共享)
    """

    _ARRAY_WRITE = re.compile(
        r'(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*', re.IGNORECASE)
    _PTR_DEREF_WRITE = re.compile(
        r'\*\s*\(\s*(\w+)\s*\+\s*(\w+)\s*\)\s*=\s*', re.IGNORECASE)
    _STRUCT_FIELD = re.compile(
        r'(\w+)\s*->\s*(\w+)\s*=\s*', re.IGNORECASE)
    _LOOP_PATTERN = re.compile(
        r'for\s*\(\s*\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\s*;', re.IGNORECASE)

    def __init__(self):
        self._allocs: List[AllocSite] = []
        self._writes: List[WriteSite] = []

    def extract(self, pseudocode: str) -> List[AllocWritePair]:
        """从伪代码提取所有 alloc-write 对."""
        self._allocs.clear()
        self._writes.clear()

        lines = pseudocode.splitlines()
        for i, line in enumerate(lines):
            line_s = line.strip()
            if not line_s or line_s.startswith('//'):
                continue
            self._scan_line(line_s, i + 1)

        return self._pair_allocs_writes()

    def _scan_line(self, line: str, lineno: int):
        """扫描一行, 提取分配或写入."""
        # malloc/calloc/realloc
        m = re.search(
            r'(\w+)\s*=\s*\(\s*\w+\s*\*\s*\)\s*(?:malloc|calloc)\s*\(\s*([^)]+)\s*\)',
            line, re.IGNORECASE)
        if m:
            var = m.group(1)
            size_expr = m.group(2).strip()
            size_const = None
            try:
                size_const = int(size_expr)
            except ValueError:
                pass
            self._allocs.append(AllocSite(
                line=lineno, func='malloc', var=var,
                size_expr=size_expr, size_constant=size_const,
            ))
            return

        # realloc
        m = re.search(
            r'(\w+)\s*=\s*\(\s*\w+\s*\*\s*\)\s*realloc\s*\(\s*\w+\s*,\s*([^)]+)\s*\)',
            line, re.IGNORECASE)
        if m:
            var = m.group(1)
            size_expr = m.group(2).strip()
            self._allocs.append(AllocSite(
                line=lineno, func='realloc', var=var, size_expr=size_expr,
            ))
            return

        # buf[idx] = value
        m = self._ARRAY_WRITE.search(line)
        if m:
            buf = m.group(1)
            idx_var = m.group(2)
            self._writes.append(WriteSite(
                line=lineno, mode='array_index',
                target_var=buf, offset_var=idx_var,
                offset_expr=idx_var,
            ))
            return

# (buf + offset) = value
        m = self._PTR_DEREF_WRITE.search(line)
        if m:
            buf = m.group(1)
            offset = m.group(2)
            self._writes.append(WriteSite(
                line=lineno, mode='ptr_offset',
                target_var=buf, offset_var=offset,
                offset_expr=offset,
            ))
            return

        # strcpy / gets / sprintf (无界写入)
        for func in ('strcpy', 'strcat', 'gets', 'sprintf'):
            m = re.search(
                rf'{func}\s*\(\s*(\w+)\s*,', line, re.IGNORECASE)
            if m:
                self._writes.append(WriteSite(
                    line=lineno, mode=func,
                    target_var=m.group(1), offset_var='_',
                    offset_expr='unbounded',
                ))
                return

    def _pair_allocs_writes(self) -> List[AllocWritePair]:
        """将分配点和写入点配对."""
        pairs = []
        for alloc in self._allocs:
            for write in self._writes:
                # 直接变量匹配: buf = malloc(64); buf[idx] = x
                if write.target_var == alloc.var:
                    shared = self._find_shared_vars(alloc, write)
                    verdict = self._quick_verdict(alloc, write, shared)
                    pairs.append(AllocWritePair(
                        alloc=alloc, write=write,
                        shared_vars=shared,
                        verdict_hint=verdict,
                    ))
                # 指针传递: ptr = buf; ptr[idx] = x (TODO: alias tracking)
        return pairs

    def _find_shared_vars(self, alloc: AllocSite,
                          write: WriteSite) -> Set[str]:
        """找到分配和写入共用的符号变量."""
        shared = set()
        alloc_vars = set(re.findall(r'\b[a-zA-Z_]\w*\b', alloc.size_expr))
        write_vars = set(re.findall(r'\b[a-zA-Z_]\w*\b', write.offset_expr))
        # 排除关键字和常量
        keywords = {'malloc', 'calloc', 'realloc', 'sizeof', 'void',
                    'char', 'int', 'long', 'unsigned', 'size_t', 'if',
                    'else', 'for', 'while', 'return'}
        alloc_vars -= keywords
        write_vars -= keywords
        return alloc_vars & write_vars

    def _quick_verdict(self, alloc: AllocSite, write: WriteSite,
                       shared: Set[str]) -> str:
        """快速判定: 常量大小 → 立即判定, 共享变量 → 需仿射分析."""
        if write.offset_expr == 'unbounded':
            return "DANGEROUS"  # strcpy/gets 无界

        if alloc.size_constant is not None:
            # 常量分配 + 变量偏移 → 需要守卫分析
            if write.mode == 'array_index':
                return "NEEDS_GUARD"

        if shared:
            return "AFFINE_CANDIDATE"  # 共享变量 → 适用仿射分析

        return "UNCERTAIN"


def extract_alloc_write_pairs(pseudocode: str) -> List[AllocWritePair]:
    """便捷函数: 提取所有 alloc-write 对."""
    extractor = AllocWriteExtractor()
    return extractor.extract(pseudocode)


__all__ = [
    'AllocSite', 'WriteSite', 'AllocWritePair',
    'AllocWriteExtractor', 'extract_alloc_write_pairs',
]
