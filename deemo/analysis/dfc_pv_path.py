"""DFC-PV 路径分析器 — 控制流路径上的 free 配对可行性分析.

两条 free 是否可能在同一路径执行: 条件分支互斥性 + goto 环绕 + 循环.
realloc/NULL 赋值必须覆盖所有从 first_free 到 second_free 的路径才安全.
"""
from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple, Optional

from analysis.dfc_pv_types import FreeSite, NullAssign, ReallocSite


class PathBlock:
    """控制流基本块: 起止行号 + 是否条件分支."""
    def __init__(self, start: int, end: int, depth: int,
                 is_branch: bool = False):
        self.start = start
        self.end = end
        self.depth = depth
        self.is_branch = is_branch

    def __repr__(self):
        return f'PathBlock({self.start}-{self.end} d={self.depth})'


class PathAnalyzer:
    """控制流路径分析."""

    def __init__(self, lines: List[str]):
        self.lines = lines
        self.depths: List[int] = []
        self._compute_depths()

    def _compute_depths(self):
        """计算每行的大括号深度."""
        depth = 0
        for line in self.lines:
            self.depths.append(depth)
            depth += line.count('{') - line.count('}')

    def bracedepth(self, line: int) -> int:
        if 1 <= line <= len(self.lines):
            return self.depths[line - 1]
        return 0

    def find_branch_ranges(self) -> List[Tuple[int, int, int, int]]:
        """返回 (if_line, then_start, then_end, else_start) 列表."""
        result = []
        for i, line in enumerate(self.lines, start=1):
            text = line.strip()
            m = re.match(r'\bif\s*\(', text)
            if not m:
                continue
            then_start = i
            for j in range(i, min(i + 50, len(self.lines) + 1)):
                t = self.lines[j-1].strip()
                if '{' in self.lines[i-1]:
                    depth = 0
                    for k in range(i, min(j + 200, len(self.lines) + 1)):
                        depth += self.lines[k-1].count('{') - self.lines[k-1].count('}')
                        if depth <= 0 and k > i:
                            then_end = k
                            break
                    else:
                        then_end = j
                    # 检查 else
                    else_line = then_end + 1
                    if else_line <= len(self.lines):
                        else_text = self.lines[else_line-1].strip()
                        if else_text.startswith('else'):
                            result.append((i, i + 1, then_end, else_line))
                            continue
                    result.append((i, i + 1, then_end, 0))
                    break
        return result

    def is_mutually_exclusive(self, la: int, lb: int) -> bool:
        """两次 free 是否在互斥的 if/else 分支中."""
        branches = self.find_branch_ranges()
        for if_line, then_s, then_e, else_s in branches:
            in_then = then_s <= la <= then_e
            in_else = else_s > 0 and else_s <= lb
            has_else_block = False
            if else_s > 0 and else_s <= len(self.lines):
                depth = 0
                for k in range(else_s, min(else_s + 200, len(self.lines) + 1)):
                    depth += self.lines[k-1].count('{') - self.lines[k-1].count('}')
                    if depth <= 0 and k > else_s:
                        if else_s <= lb <= k:
                            has_else_block = True
                        break
            if in_then and has_else_block:
                return True
            in_then_b = then_s <= lb <= then_e
            in_else_a = else_s > 0 and else_s <= la
            if in_then_b and has_else_block and else_s <= la:
                if else_s <= la <= else_s + 200:
                    depth = 0
                    for k in range(else_s, min(else_s + 200, len(self.lines) + 1)):
                        depth += self.lines[k-1].count('{') - self.lines[k-1].count('}')
                        if depth <= 0 and k > else_s:
                            if else_s <= la <= k:
                                return True
                            break
        # else 分隔: 寻找 } else { 模式
        for i in range(min(la, lb), max(la, lb)):
            if i - 1 < len(self.lines):
                t = self.lines[i - 1].strip()
                if re.match(r'\}\s*else\s*\{?', t):
                    return True
        return False

    def has_guard_between(self, line_a: int, line_b: int,
                           guard_var: str) -> bool:
        """line_a ~ line_b 之间是否有对 guard_var 的条件守卫 (if (guard_var != NULL))."""
        guard_pattern = re.compile(
            rf'\bif\s*\(\s*!?{re.escape(guard_var)}'
            rf'(?:\s*[=!]=\s*(?:NULL|nullptr|0))?\s*\)',
            re.IGNORECASE)
        neg_guard = re.compile(
            rf'\bif\s*\(\s*!{re.escape(guard_var)}\s*\)')
        for i in range(min(line_a, line_b) + 1, max(line_a, line_b)):
            if i - 1 < len(self.lines):
                text = self.lines[i - 1].strip()
                if guard_pattern.search(text) or neg_guard.search(text):
                    return True
        return False

    def has_freed_flag_between(self, line_a: int, line_b: int,
                                freed_flags: Set[str]) -> bool:
        """line_a ~ line_b 之间是否有 freed flag 守卫 (if (!freed))."""
        if not freed_flags:
            return False
        for i in range(line_a + 1, line_b):
            if i - 1 < len(self.lines):
                text = self.lines[i - 1].strip()
                for flag in freed_flags:
                    if re.search(rf'\bif\s*\(\s*!?{re.escape(flag)}\b', text):
                        return True
        return False

    def find_freed_flags(self, source: str) -> Set[str]:
        """识别 'int freed = 0;' 格式的释放状态标志."""
        flags: Set[str] = set()
        for m in re.finditer(
            r'(?:int|bool)\s+(\w+)\s*=\s*0\s*;', source):
            var = m.group(1)
            if 'free' in var.lower() or 'release' in var.lower() or \
               'done' in var.lower():
                flags.add(var)
        return flags

    def in_loop_body(self, line: int) -> bool:
        """line 是否在循环体内. 排除 do { ... } while(0) 宏模式."""
        text = self.lines[line - 1].strip()
        # 检查是否在 do { ... } while(0) 宏模式中 (不是真循环)
        if 'while(0)' in text.replace(' ', '') or \
           'while (0)' in text:
            return False
        loop_m = re.search(r'\b(?:for|while)\s*\(', text)
        if loop_m and 'free' in text.lower():
            # 排除 while(0) 宏模式
            after = text[loop_m.end():]
            if re.match(r'\s*0\s*\)', after):
                return False
            return True
        for i in range(line - 2, -1, -1):
            t = self.lines[i].strip()
            if t.startswith('//'):
                continue
            if re.search(r'\b(?:for|while)\s*\(', t):
                after_match = re.search(r'\b(?:for|while)\s*\(([^)]*)\)', t)
                if after_match and after_match.group(1).strip() in ('0', '0 '):
                    continue
                if self.bracedepth(line) > self.bracedepth(i + 1):
                    return True
                break
        return False
