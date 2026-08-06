"""
UAF函数参数匹配增强 — 检测free(p)后p出现在函数调用参数中的模式。

问题: heap_lifecycle_fsm.py 的 detect_uaf_static 仅检测赋值RHS中的
变量使用(var = expr中的expr), 漏检以下模式:
  printf("%s", p)    ← p 是函数参数, 非赋值RHS
  memcpy(dst, p, n)  ← p 是函数参数
  return p           ← p 是返回值
  p[0] = 'x'         ← p 是数组基址

本模块不替换heap_lifecycle_fsm——作为补充层, 在FSM结果之上追加检测。
"""

import re
from typing import Dict, List

_HEAP_ALLOC = {'malloc', 'calloc', 'realloc', 'new', 'mmap',
                'HeapAlloc', 'kalloc', 'kmalloc', '_malloc_r'}
_HEAP_FREE = {'free', 'kfree', 'delete', 'munmap', 'HeapFree'}

_ALLOC_PAT = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*\w+\s*\*\s*\))?\s*(' +
    '|'.join(_HEAP_ALLOC) + r')\s*\(', re.IGNORECASE)
_FREE_PAT = re.compile(
    r'(' + '|'.join(_HEAP_FREE) + r')\s*\(\s*(\w+)\s*\)', re.IGNORECASE)


def detect_uaf_args(code: str, func_name: str = "") -> List[Dict]:
    """检测free(p)后p出现在函数参数/返回值/数组索引中的UAF模式。

    补充 heap_lifecycle_fsm.detect_uaf_static 的盲区。
    返回格式与FSM兼容, 可直接合并到 vuln_analyzer 的finding列表中。
    """
    lines = [l.strip() for l in code.split('\n')
             if l.strip() and not l.strip().startswith('//')]
    findings = []

    # Phase 1: 收集alloc/free站点
    alloc_vars: Dict[str, int] = {}   # var -> alloc_line
    free_vars: Dict[str, int] = {}    # var -> free_line

    for i, line in enumerate(lines):
        m = _ALLOC_PAT.search(line)
        if m:
            alloc_vars[m.group(1)] = i
        m = _FREE_PAT.search(line)
        if m:
            free_vars[m.group(2)] = i

    # Phase 2: 对每个free的变量, 检查free之后是否有使用
    for var, free_ln in free_vars.items():
        if var not in alloc_vars:
            continue
        for i in range(free_ln + 1, len(lines)):
            line = lines[i]
            # 排除新的alloc赋值: var = malloc(...)
            if re.search(rf'\b{re.escape(var)}\s*=.*(?:malloc|calloc)', line):
                break  # 新分配→不再是同一对象
            # 排除free调用自身
            if re.search(rf'(?:free|kfree|delete)\s*\(\s*{re.escape(var)}\s*\)', line):
                continue
            # 检查变量使用: 函数参数(var前有逗号/左括号) 或 数组索引(var后跟[) 或 返回值
            if _is_var_used(line, var):
                findings.append({
                    'rule_id': f'UAF-ARG-{var}',
                    'type': 'heap-corruption',
                    'function': func_name,
                    'severity': 'Critical',
                    'description': (
                        f'{var}: alloc@L{alloc_vars[var]} free@L{free_ln} '
                        f'use@L{i} (function arg/return pattern)'),
                    'cwe': 'CWE-416',
                    'confidence': 0.72,
                    'vuln_subtype': 'uaf',
                    'alloc_line': alloc_vars[var],
                    'free_line': free_ln,
                    'use_line': i,
                })
                break  # 每个变量只报告第一个use

    return findings


def _is_var_used(line: str, var: str) -> bool:
    """检查变量是否在函数参数上下文或数组索引中被使用。

    匹配模式:
      func(..., var, ...)  — 函数参数
      func(var)            — 单参数函数
      return var           — 返回值
      var[0]               — 数组索引
      ... = var            — 赋值(已被FSM覆盖, 这里也检测)
    """
    # 排除自身赋值: var = ...
    if re.match(rf'{re.escape(var)}\s*=', line):
        return False
    # var出现在行中即可(已排除free和malloc)
    return bool(re.search(rf'\b{re.escape(var)}\b', line))
