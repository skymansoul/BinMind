"""
UAF别名分析辅助函数。
"""

import re
from collections import defaultdict
from typing import Dict, List, Set, Tuple


def extract_aliases(code: str) -> Dict[str, List[Tuple[str, str]]]:
    """提取指针别名关系: {var: [(alias, kind), ...]}.
    kind: 'direct' | 'struct_field' | 'array_element'
    """
    aliases: Dict[str, List[Tuple[str, str]]] = defaultdict(list)

    for m in re.finditer(
        r'(?:\w+\s*\*?\s*)(\w+)\s*=\s*(\w+)\s*;',
        code,
    ):
        alias = m.group(1)
        target = m.group(2)
        if alias != target:
            aliases[target].append((alias, 'direct'))

    for m in re.finditer(
        r'(\w+)\s*=\s*(\w+)\s*->\s*(\w+)\s*;',
        code,
    ):
        alias = m.group(1)
        obj = m.group(2)
        field = m.group(3)
        if alias != obj:
            aliases[obj].append((alias, 'struct_field'))
            aliases[f'{obj}->{field}'].append((alias, 'field_ref'))

    for m in re.finditer(
        r'(\w+)\s*=\s*(\w+)\s*\[\s*\w+\s*\]\s*;',
        code,
    ):
        alias = m.group(1)
        array = m.group(2)
        if alias != array:
            aliases[array].append((alias, 'array_element'))

    return dict(aliases)


def extract_struct_aliases_from_field(code: str) -> Dict[str, Set[str]]:
    """提取struct字段的间接别名: 若 ref = obj->data, 则 obj的释放影响ref."""
    field_aliases: Dict[str, Set[str]] = defaultdict(set)

    for m in re.finditer(
        r'(\w+)\s*=\s*(\w+)\s*->\s*(\w+)\s*;',
        code,
    ):
        alias = m.group(1)
        obj = m.group(2)
        field_aliases[obj].add(alias)

    return dict(field_aliases)


def expand_freed_vars(freed_var: str,
                      aliases: Dict[str, List[Tuple[str, str]]],
                      field_aliases: Dict[str, Set[str]]) -> Set[str]:
    """展开被释放变量及其所有别名, 得到应检查使用的完整集合."""
    expanded = {freed_var}

    if freed_var in aliases:
        for alias, _ in aliases[freed_var]:
            expanded.add(alias)

    for obj, field_set in field_aliases.items():
        if obj == freed_var:
            expanded.update(field_set)

    for target, alias_list in aliases.items():
        for alias, _ in alias_list:
            if alias == freed_var:
                expanded.add(target)

    return expanded


def extract_global_allocations(code: str) -> Dict[str, List[int]]:
    """提取全局/静态变量的分配点: {var: [line_numbers]}."""
    globals_map: Dict[str, List[int]] = defaultdict(list)
    lines = code.split('\n')

    for i, line in enumerate(lines):
        m = re.search(
            r'\b(g_\w+|\w+_g|global_\w+|[a-z]\w*)\s*='
            r'\s*(?:malloc|calloc|strdup)\s*\(', line)
        if m:
            var = m.group(1)
            globals_map[var].append(i)

    return dict(globals_map)


def is_pointer_use(line: str, var: str) -> bool:
    """检查一行代码是否包含对变量的指针使用.

    模式: *var, var->field, var[index], func(..., var, ...)
    """
    if re.search(rf'\*{re.escape(var)}\b|{re.escape(var)}\s*->|{re.escape(var)}\s*\[', line):
        return True
    if re.search(rf'{re.escape(var)}\s*->\s*\w+\s*=|{re.escape(var)}\s*\[[^\]]*\]\s*=', line):
        return True
    if re.search(rf'\w+\s*\([^)]*{re.escape(var)}[^)]*\)', line):
        return True
    return False
