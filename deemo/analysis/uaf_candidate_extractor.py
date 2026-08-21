"""
从伪代码行中识别 alloc → free → use 模式, 生成 UafCandidate 列表。
包含间接 free 检测 (wrapper函数) 和 double-free 检测。
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from analysis.uaf_cascade_shared import (
    UafCandidate, UafVerdict,
    _FREE_SET, _ALLOC_SET, _USE_SET,
)


def _strip_array_index(var: str) -> str:
    """去除数组下标: items[i] → items, arr[0] → arr."""
    m = re.match(r'(\w[\w]*)\s*\[', var)
    return m.group(1) if m else var


def _find_var_free_sites(lines: List[str]) -> Dict[str, List[int]]:
    """在代码行中定位所有 free(var) 调用. 返回 {var: [行号列表]}."""
    free_map: Dict[str, List[int]] = {}
    for i, line in enumerate(lines, start=1):
        for ff in _FREE_SET:
            escaped_ff = re.escape(ff)
            m = re.search(
                rf'{escaped_ff}\s*\(\s*\*?\s*(\w[\w]*(?:->\w+)?(?:\[[^\]]+\])?)\s*\)',
                line)
            if m:
                var = _strip_array_index(m.group(1))
                free_map.setdefault(var, []).append(i)
    return free_map


def _extract_paren_args(text: str, start_pos: int) -> str:
    """括号深度计数提取参数 — 处理嵌套括号 (如 sizeof(int))."""
    if start_pos >= len(text) or text[start_pos] != '(':
        return ""
    depth = 0
    for i in range(start_pos, len(text)):
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return text[start_pos + 1:i]
    return ""


def _find_var_alloc_sites(lines: List[str]) -> Dict[str, Tuple[int, str, int]]:
    """定位所有 var = alloc(size) 调用. 返回 {var: (行号, 分配函数, size值)}."""
    alloc_map: Dict[str, Tuple[int, str, int]] = {}
    for i, line in enumerate(lines, start=1):
        for af in _ALLOC_SET:
            escaped_af = re.escape(af)
            m = re.search(
                rf'(\w[\w]*(?:\[[^\]]+\])?)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?{escaped_af}\s*\(',
                line)
            if m:
                var = _strip_array_index(m.group(1))
                paren_pos = m.end() - 1
                size_str = _extract_paren_args(line, paren_pos)
                size = 0
                try:
                    num_m = re.search(r'\d+', size_str)
                    if num_m:
                        size = int(num_m.group(0))
                    sizeof_m = re.search(r'sizeof\s*\(\s*(\w+)\s*\)', size_str)
                    if sizeof_m:
                        _SIZEOF_TABLE = {
                            'int': 4, 'char': 1, 'short': 2, 'long': 8,
                            'float': 4, 'double': 8, 'size_t': 8, 'void': 1,
                            'Person': 16, 'Request': 16,
                        }
                        size = _SIZEOF_TABLE.get(sizeof_m.group(1), 4)
                    if af == 'calloc':
                        m2 = re.search(r'(\d+)\s*,\s*(\d+)', size_str)
                        if m2:
                            size = int(m2.group(1)) * int(m2.group(2))
                except (ValueError, AttributeError):
                    size = 0
                alloc_map[var] = (i, af, size)
    return alloc_map


def _find_var_use_sites(lines: List[str], ptr_var: str) -> List[Tuple[int, str]]:
    """定位所有使用 ptr_var 的行. 返回 [(行号, 使用文本)].

    排除: free/delete 调用本身; 声明语句 (char *ptr, int *ptr 等).
    """
    uses = []
    base = _strip_array_index(ptr_var)
    _TYPE_PREFIX = (
        r'(?:char|int|short|long|float|double|void|size_t|unsigned|'
        r'struct|typedef|auto|static|extern|const)\s+')
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        # 排除 free/delete/realloc 调用本身
        if re.search(
                rf'(?:free|kfree|delete|realloc)\s*\(\s*\*?\s*{re.escape(base)}\s*[\),]',
                stripped):
            continue
        # 排除声明: char *ptr, int *ptr 等
        if re.search(rf'{_TYPE_PREFIX}\*{re.escape(base)}\b', stripped):
            continue
        if re.search(rf'{_TYPE_PREFIX}\*\s*{re.escape(base)}\b', stripped):
            continue
        # 解引用: *ptr, ptr->, ptr[
        if re.search(rf'\*{re.escape(base)}\b|{re.escape(base)}\s*->|{re.escape(base)}\s*\[', stripped):
            uses.append((i, stripped[:120]))
            continue
        # 函数参数中作为指针传递
        if re.search(rf'[,\(]\s*{re.escape(base)}\s*[,\)]', stripped):
            uses.append((i, stripped[:120]))
            continue
        for uf in _USE_SET:
            if re.search(rf'{re.escape(uf)}\s*\([^)]*\b{re.escape(base)}\b', stripped):
                uses.append((i, stripped[:120]))
                break
    return uses


def _build_simple_alias_map(lines: List[str]) -> Dict[str, str]:
    """构建简单的别名映射: rhs → lhs.

    匹配: alias = expr; 和 type *alias = expr; (C声明+赋值).
    排除: NULL/nullptr/0/None/数字.
    """
    alias_map: Dict[str, str] = {}
    for line in lines:
        m = re.search(r'\b(\w[\w]*)\s*=\s*(\w[\w]*)\s*;', line)
        if m:
            lhs, rhs = m.group(1), m.group(2)
            if rhs not in ('NULL', 'nullptr', '0', 'None') and not rhs.isdigit():
                alias_map[lhs] = rhs
                continue
        m = re.search(
            r'(?:char|int|short|long|float|double|void|size_t|unsigned|struct\s+\w+|'
            r'\w+)\s*\*+\s*(\w[\w]*)\s*=\s*(\w[\w]*)\s*;', line)
        if m:
            lhs, rhs = m.group(1), m.group(2)
            if rhs not in ('NULL', 'nullptr', '0', 'None') and not rhs.isdigit():
                alias_map[lhs] = rhs
    return alias_map


def extract_uaf_candidates(lines: List[str],
                            func_name: str = "") -> List[UafCandidate]:
    """从代码行提取 UAF 候选 (alloc → free → use 模式).

    扩展提取逻辑:
      1. free(var) 后 use(var) → 候选
      2. free(alias) 后 use(original) → 候选 (通过简单别名映射)
      3. free(var) 两次 → double-free 候选
      4. free(arr[i]) → 视为 free(arr)
      5. wrapper_func(var) 内部含 free → 视为间接 free
    """
    candidates: List[UafCandidate] = []
    alloc_sites = _find_var_alloc_sites(lines)
    free_sites = _find_var_free_sites(lines)
    alias_map = _build_simple_alias_map(lines)

    # 间接 free 检测: 找 wrapper 函数 → 映射调用点
    indirect_free_callers: Dict[str, List[Tuple[int, str]]] = {}
    func_free_map: Dict[str, str] = {}
    for i, line in enumerate(lines):
        fm = re.match(
            r'\s*(?:void|int|char|static|inline)\s+(\w+)\s*\(\s*\w+\s*\*?\s*(\w+)\s*\)',
            line)
        if fm:
            fname, param = fm.group(1), fm.group(2)
            depth = 0
            for j in range(i + 1, min(i + 30, len(lines))):
                l2 = lines[j]
                if '{' in l2:
                    depth += l2.count('{')
                if '}' in l2:
                    depth -= l2.count('}')
                if depth == 0 and '}' in l2:
                    break
                if depth > 0:
                    for ff in _FREE_SET:
                        if re.search(
                                rf'{re.escape(ff)}\s*\(\s*\*?\s*{re.escape(param)}\b',
                                l2):
                            func_free_map[fname] = param
                            break
                    if fname in func_free_map:
                        break

    for i, line in enumerate(lines, start=1):
        for fname, param in func_free_map.items():
            m = re.search(rf'\b{re.escape(fname)}\s*\(\s*(\w[\w]*)\s*\)', line)
            if m:
                arg = m.group(1)
                indirect_free_callers.setdefault(arg, []).append((i, fname))

    for arg, calls in indirect_free_callers.items():
        for cline, _ in calls:
            free_sites.setdefault(arg, []).append(cline)
        free_sites[arg] = sorted(set(free_sites[arg]))

    for var, flines in free_sites.items():
        # double-free 检测 — 两次 free 之间无安全操作才报告
        if len(flines) >= 2:
            for i in range(1, len(flines)):
                prev_free = flines[i - 1]
                curr_free = flines[i]
                has_safe_between = False
                for mid_ln in range(prev_free + 1, curr_free):
                    if mid_ln - 1 < len(lines):
                        ml = lines[mid_ln - 1]
                        for af in _ALLOC_SET:
                            if re.search(
                                    rf'\b{re.escape(var)}\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?{re.escape(af)}\s*\(',
                                    ml):
                                has_safe_between = True
                                break
                        if re.search(rf'\b{re.escape(var)}\s*=\s*(?:NULL|nullptr|0)\s*;', ml):
                            has_safe_between = True
                        if re.search(rf'\b{re.escape(var)}\s*=\s*\w+\s*\(', ml):
                            has_safe_between = True
                        if re.search(rf'\b{re.escape(var)}\s*=\s*&', ml):
                            has_safe_between = True
                        if re.search(r'\}\s*else\s*\{', ml):
                            has_safe_between = True
                if has_safe_between:
                    continue
                candidates.append(UafCandidate(
                    ptr_name=var, func_name=func_name,
                    alloc_lineno=alloc_sites.get(var, (0, '', 0))[0],
                    free_lineno=curr_free, use_lineno=curr_free,
                    alloc_func=alloc_sites.get(var, ('', 'malloc', 0))[1],
                    use_text=f'double-free of {var}',
                    confidence=0.85,
                ))

        check_vars = {var}
        for alias, orig in alias_map.items():
            if orig == var:
                check_vars.add(alias)
            if alias == var:
                check_vars.add(orig)

        for fline in flines:
            for cv in check_vars:
                all_uses = _find_var_use_sites(lines, cv)
                uses_after = [(ln, txt) for ln, txt in all_uses if ln >= fline]
                if not uses_after:
                    for i in range(fline, len(lines)):
                        l = lines[i]
                        if re.search(rf'\b{re.escape(cv)}\b', l) and not re.search(
                                rf'(?:free|kfree|delete)\s*\(\s*\*?\s*{re.escape(cv)}\s*[\),]',
                                l):
                            uses_after.append((i + 1, l.strip()[:120]))
                            break
                for use_ln, use_txt in uses_after:
                    alloc_ln0, alloc_func0, alloc_size0 = alloc_sites.get(
                        cv, (0, 'malloc', 0))
                    if alloc_ln0 == 0 and cv != var:
                        alloc_ln0, alloc_func0, alloc_size0 = alloc_sites.get(
                            var, (0, 'malloc', 0))
                    candidates.append(UafCandidate(
                        ptr_name=var, func_name=func_name,
                        alloc_lineno=alloc_ln0,
                        free_lineno=fline, use_lineno=use_ln,
                        alloc_func=alloc_func0, use_text=use_txt,
                        confidence=0.50,
                    ))
                    if cv != var:
                        candidates[-1].aliases.add(cv)

    # 按 free_lineno 排序, 去重
    seen: Set[Tuple[str, int, int]] = set()
    unique: List[UafCandidate] = []
    for c in sorted(candidates, key=lambda x: (x.free_lineno, x.use_lineno)):
        key = (c.ptr_name, c.free_lineno, c.use_lineno)
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


__all__ = [
    'extract_uaf_candidates',
    '_strip_array_index', '_find_var_free_sites',
    '_extract_paren_args', '_find_var_alloc_sites',
    '_find_var_use_sites', '_build_simple_alias_map',
]
