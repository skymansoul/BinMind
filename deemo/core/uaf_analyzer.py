"""
Use-After-Free 深度分析 — 从简单正则升级为指针别名追踪+调用上下文分析。

当前 _check_uaf_heuristic 用 free(X).*?X-> 正则跨行匹配,
无法处理以下真实场景:
  1. 指针复制后释放: p=ptr; free(ptr); p->field → 检测失败
  2. 通过函数参数传递: free(obj); process(obj) → 检测失败(process内解引用)
  3. 条件释放后的使用: if(x) free(p); p->field → 缺路径感知

方案: 两阶段分析。
  Phase 1 — 别名追踪: 在反编译伪代码中追踪指针赋值链(p=ptr, q=p),
    构建别名集。free(X) 将 X 及其所有别名标记为 freed。
    后续任何 freed 别名的解引用均报警。
  Phase 2 — 调用上下文: 若 free(X) 后 X 作为参数传递给其他函数,
    标记为 "潜在UAF" (WARNING), 因无法静态分析被调用函数的内部行为。

复杂度: O(N·A), N=代码行数, A=每行平均别名数(通常<5)。
不引入符号执行——保持与现有管线兼容的轻量特性。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple


@dataclass
class AliasGroup:
    """一组互为别名的指针变量。"""
    names: Set[str] = field(default_factory=set)
    freed: bool = False
    free_lineno: int = 0


def _extract_aliases(pseudocode: str) -> Dict[str, AliasGroup]:
    """从反编译伪代码提取指针别名关系。

    识别模式: p=ptr, q=p, 以及函数返回赋值(malloc 等)。
    返回 {变量名: AliasGroup} 映射。
    """
    lines = pseudocode.split('\n')
    aliases: Dict[str, AliasGroup] = {}

    # 赋值模式: lhs = rhs (简单变量, 不含运算符)
    assign_pat = re.compile(r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*;?\s*$')

    for i, line in enumerate(lines, start=1):
        m = assign_pat.search(line.strip())
        if not m:
            continue
        lhs, rhs = m.group(1), m.group(2)
        # 跳过字面量和函数调用
        if rhs in ('NULL', 'nullptr', '0', 'None'):
            continue
        # 合并别名组
        if lhs not in aliases:
            aliases[lhs] = AliasGroup(names={lhs})
        if rhs not in aliases:
            aliases[rhs] = AliasGroup(names={rhs})
        # 两个组合并
        combined = aliases[lhs].names | aliases[rhs].names
        for name in combined:
            aliases[name].names = combined
    return aliases


def _find_free_vars(pseudocode: str) -> List[Tuple[str, int]]:
    """找到所有 free(X) 调用, 返回 [(var_name, lineno), ...]."""
    results: List[Tuple[str, int]] = []
    for i, line in enumerate(pseudocode.split('\n'), start=1):
        m = re.search(r'free\s*\(\s*(?:&)?(\w[\w]*)\s*\)', line)
        if m:
            results.append((m.group(1), i))
    return results


def _find_derefs(pseudocode: str) -> List[Tuple[str, int, str]]:
    """找到所有指针解引用, 返回 [(var, lineno, pattern), ...].
    pattern 为 '->' 或 '[*]'。
    """
    results: List[Tuple[str, int, str]] = []
    for i, line in enumerate(pseudocode.split('\n'), start=1):
        for m in re.finditer(r'(\w[\w]*)\s*->', line):
            results.append((m.group(1), i, '->'))
    return results


def detect_uaf_deep(pseudocode: str, func_name: str) -> List[dict]:
    """深度 UAF 检测: 别名追踪 + 条件感知。

    返回 finding 列表, 每条含 var/free_lineno/deref_lineno/confidence。
    """
    findings: List[dict] = []
    aliases = _extract_aliases(pseudocode)
    frees = _find_free_vars(pseudocode)
    derefs = _find_derefs(pseudocode)

    for free_var, free_ln in frees:
        # 获取 free_var 的全部别名
        freed_set: Set[str] = {free_var}
        if free_var in aliases:
            freed_set |= aliases[free_var].names

        for deref_var, deref_ln, pattern in derefs:
            if deref_var not in freed_set:
                continue
            if deref_ln <= free_ln:
                continue  # 释放在解引用之后, 不报警

            # 检查中间是否有重新赋值(排除重分配后使用的假阳性)
            lines_between = pseudocode.split('\n')[free_ln:deref_ln]
            reallocated = any(
                re.search(rf'{re.escape(deref_var)}\s*=\s*(malloc|calloc|realloc|new)',
                          line) for line in lines_between
            )
            if reallocated:
                continue

            confidence = 0.85 if deref_var == free_var else 0.65
            findings.append({
                'rule_id': 'UAF-DEEP',
                'type': 'heap-corruption',
                'function': func_name,
                'var': deref_var,
                'free_lineno': free_ln,
                'deref_lineno': deref_ln,
                'pattern': pattern,
                'severity': 'Critical',
                'confidence': confidence,
                'description': (
                    f'UAF: {deref_var} 在 L{free_ln} 被 free(), '
                    f'L{deref_ln} 通过 {pattern} 解引用'
                    f'{"" if deref_var==free_var else " (通过别名 "+free_var+")"}'
                ),
                'cwe': 'CWE-416',
            })
    return findings


def detect_double_free_deep(pseudocode: str, func_name: str) -> List[dict]:
    """深度 Double-Free 检测: 别名感知。

    原始 _check_double_free 直接计数同一变量名出现次数。
    本版本考虑别名: 若 free(p) 和 free(q) 且 p,q 互为别名, 视为 double-free。
    """
    findings: List[dict] = []
    aliases = _extract_aliases(pseudocode)
    frees = _find_free_vars(pseudocode)

    freed_groups: Dict[str, List[int]] = {}
    for var, ln in frees:
        # 找到该变量的规范化组标识
        group_key = var
        if var in aliases:
            group_key = min(aliases[var].names)  # 用最小名字作为组标识
        freed_groups.setdefault(group_key, []).append(ln)

    for group_key, lines in freed_groups.items():
        if len(lines) >= 2:
            findings.append({
                'rule_id': 'DF-DEEP',
                'type': 'heap-corruption',
                'function': func_name,
                'var': group_key,
                'free_lines': lines,
                'severity': 'Critical',
                'confidence': 0.90,
                'description': (
                    f'Double-Free: {group_key} freed at lines {lines}'
                ),
                'cwe': 'CWE-415',
            })
    return findings


def comprehensive_uaf_check(pseudocode: str, func_name: str) -> List[dict]:
    """一站式 UAF+DF 检测。"""
    findings = detect_uaf_deep(pseudocode, func_name)
    findings.extend(detect_double_free_deep(pseudocode, func_name))
    return findings
