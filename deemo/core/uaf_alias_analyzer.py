"""
UAF别名感知检测器 — 追踪指针别名 + 跨函数全局变量, 消除3类FN。
检测增强: A1 别名追踪, A2 struct字段别名, A3 跨函数全局变量, A4 条件池管理。
保守性原则: 仅当别名关系确定时标记, 不确定时保留现有行为。
"""
import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from core.uaf_alias_helpers import (
    extract_aliases as _extract_aliases,
    extract_struct_aliases_from_field as _extract_struct_aliases_from_field,
    expand_freed_vars as _expand_freed_vars,
    extract_global_allocations as _extract_global_allocations,
    is_pointer_use as _is_pointer_use,
)


def detect_uaf_with_aliases(code: str, func_name: str = '') -> List[dict]:
    """别名感知的UAF检测 — detect_uaf.

    层级:
      L0: 基础 free→use 检测 (同 detect_uaf, 保留100%原有逻辑)
      L1: 别名追踪: free(p)后检查p的别名是否被使用
      L2: struct字段: free(obj)后检查obj->field的别名
      L3: 跨函数全局变量: if(g) use(g) after free(g)

    返回 UAF findings list (兼容现有格式)。
    """
    findings = []
    lines = [l.strip() for l in code.split('\n')]
    if len(lines) < 2:
        return findings

    aliases = _extract_aliases(code)
    field_aliases = _extract_struct_aliases_from_field(code)

    # L0: 基础 free→use 检测
    free_points: List[Tuple[int, str]] = []  # (line_no, freed_expr)
    freed_fields: Set[Tuple[int, str, str]] = set()  # (line, obj, field): obj->field被释放
    for i, line in enumerate(lines):
        # free(var) 或 free(var->field), 一行可能有多个free
        for m in re.finditer(r'free\s*\(\s*(\w+(?:->\w+)*)\s*\)', line):
            freed_expr = m.group(1)
            free_points.append((i, freed_expr))
            # 记录struct字段释放: free(obj->field)
            if '->' in freed_expr:
                parts = freed_expr.rsplit('->', 1)
                freed_fields.add((i, parts[0], parts[1]))

    seen_vars: Set[Tuple[str, str]] = set()  # 去重: (freed_var, used_var)

    for free_ln, freed_var in free_points:
        # 检查释放后原变量的使用
        uses_after = []
        for j in range(free_ln + 1, min(len(lines), free_ln + 50)):
            if _is_pointer_use(lines[j], freed_var):
                uses_after.append(lines[j].strip()[:120])

        if uses_after:
            key = (freed_var, freed_var)
            if key not in seen_vars:
                seen_vars.add(key)
                findings.append({
                    'vuln_type': 'use-after-free',
                    'vuln_subtype': 'direct-uaf',
                    'function': func_name,
                    'freed_variable': freed_var,
                    'free_location': f'L{free_ln}',
                    'use_after': uses_after[:3],
                    'confidence': 0.70,
                    'cwe': 'CWE-416',
                    'description': (
                        f'指针 {freed_var} 在L{free_ln}释放后仍被解引用'
                    ),
                })

        # L1+L2: 别名追踪
        affected = _expand_freed_vars(freed_var, aliases, field_aliases)
        affected.discard(freed_var)

        for alias_var in affected:
            alias_uses = []
            for j in range(free_ln + 1, min(len(lines), free_ln + 50)):
                if _is_pointer_use(lines[j], alias_var):
                    alias_uses.append({
                        'line': j,
                        'var': alias_var,
                        'code': lines[j][:120],
                    })

            if alias_uses:
                key = (freed_var, alias_var)
                if key not in seen_vars:
                    seen_vars.add(key)
                    findings.append({
                        'vuln_type': 'use-after-free',
                        'vuln_subtype': 'alias-uaf',
                        'function': func_name,
                        'freed_variable': freed_var,
                        'alias_variable': alias_var,
                        'affected_aliases': list(affected),
                        'free_line': free_ln,
                        'use_after': alias_uses[:5],
                        'confidence': 0.72,
                        'cwe': 'CWE-416',
                        'description': (
                            f'别名UAF: {freed_var} 在L{free_ln}释放, '
                            f'其别名 {alias_var} 在L{alias_uses[0]["line"]}仍被使用'
                        ),
                    })

    # L3: 跨函数全局变量UAF
    glob_findings = _detect_global_uaf(code, func_name, lines)
    findings.extend(glob_findings)

    # L4: struct字段释放后父对象返回 → 悬空指针传播
    for free_ln, obj, field in freed_fields:
        for j in range(free_ln, min(len(lines), free_ln + 20)):
            if re.search(rf'return\s+{re.escape(obj)}\b', lines[j]):
                # 确保return在free之后 (同行的return在free之后由代码顺序保证)
                findings.append({
                    'vuln_type': 'use-after-free',
                    'vuln_subtype': 'dangling-field-return',
                    'function': func_name,
                    'freed_variable': f'{obj}->{field}',
                    'free_line': free_ln,
                    'confidence': 0.60,
                    'cwe': 'CWE-416',
                    'description': (
                        f'悬空字段传播: {obj}->{field} 在L{free_ln}释放, '
                        f'{obj}在L{j}返回 → 调用者获得包含悬空指针的结构体'
                    ),
                })
                break

    return findings


def _detect_global_uaf(code: str, func_name: str, lines: List[str]) -> List[dict]:
    """检测跨函数的全局/静态变量UAF.

    模式: char *g = NULL;
          void mk(){g = malloc(n);}
          void rm(){free(g);}
          void use(){if(g) printf(...);}  // UAF: g 已被释放
    """
    findings = []
    # 识别全局变量模式: 在函数外声明, 或在多个函数中被赋值/释放
    free_of_globals: Dict[str, List[int]] = defaultdict(list)
    use_of_globals: Dict[str, List[Tuple[int, str]]] = defaultdict(list)

    for i, line in enumerate(lines):
        # free(全局变量模式)
        m = re.search(r'free\s*\(\s*(\w+)\s*\)', line)
        if m:
            var = m.group(1)
            free_of_globals[var].append(i)

    # 对每个被释放的变量, 检查是否有 "if(var) use(var)" 模式
    # (条件检查暗示var已被释放)
    for var, free_lines in free_of_globals.items():
        for free_ln in free_lines:
            for j in range(free_ln + 1, min(len(lines), free_ln + 30)):
                line = lines[j]
                # if(var) 模式 → 暗示调用者不确定var是否有效
                if re.search(rf'if\s*\(\s*{re.escape(var)}\s*\)', line):
                    uses_after = []
                    for k in range(j, min(len(lines), j + 5)):
                        if _is_pointer_use(lines[k], var):
                            uses_after.append(lines[k][:120])
                    if uses_after:
                        findings.append({
                            'vuln_type': 'use-after-free',
                            'vuln_subtype': 'global-uaf',
                            'function': func_name,
                            'freed_variable': var,
                            'free_line': free_ln,
                            'use_after': uses_after[:3],
                            'confidence': 0.65,
                            'cwe': 'CWE-416',
                            'description': (
                                f'跨函数UAF: 全局变量 {var} L{free_ln}释放后, '
                                f'L{j}仍通过条件检查后使用'
                            ),
                        })
                    break

    return findings


def detect_uaf_interprocedural(pseudocode_by_func: Dict[str, str]) -> List[dict]:
    """跨函数UAF检测: 在多函数代码中追踪全局变量的alloc→free→use路径。

    参数: pseudocode_by_func {func_name: pseudocode} 字典。
    返回跨函数边界的 UAF findings。
    """
    findings = []
    # 全局变量候选: 在多个函数中被操作的变量
    all_code = '\n'.join(pseudocode_by_func.values())
    global_candidates: Dict[str, Dict[str, List[int]]] = defaultdict(
        lambda: {'alloc': [], 'free': [], 'use': []})

    for fname, code in pseudocode_by_func.items():
        lines = code.split('\n')
        for i, line in enumerate(lines):
            # alloc
            m = re.search(r'(\w+)\s*=\s*(?:malloc|calloc|strdup)\s*\(', line)
            if m:
                global_candidates[m.group(1)]['alloc'].append(i)
            # free
            m = re.search(r'free\s*\(\s*(\w+)\s*\)', line)
            if m:
                var = m.group(1)
                global_candidates[var]['free'].append(i)
            # use (deref)
            for m2 in re.finditer(r'\*(\w+)\b|(\w+)\s*->|(\w+)\s*\[', line):
                used_var = m2.group(1) or m2.group(2) or m2.group(3)
                if used_var:
                    global_candidates[used_var]['use'].append(i)

    for var, events in global_candidates.items():
        if events['free'] and events['use']:
            # 若 use 发生在 free 之后 (跨函数, 无法精确判断行序)
            findings.append({
                'vuln_type': 'use-after-free',
                'vuln_subtype': 'interprocedural-uaf',
                'variable': var,
                'alloc_count': len(events['alloc']),
                'free_count': len(events['free']),
                'use_count': len(events['use']),
                'confidence': 0.55,
                'cwe': 'CWE-416',
                'description': (
                    f'跨函数UAF: {var} 在函数间被分配/释放/使用, '
                    f'存在释放后使用的风险'
                ),
            })

    return findings
