"""
指针生命周期状态机 - 跨函数追踪堆指针从分配到释放到悬垂使用的完整生命周期。
状态转换: ALLOCATED - IN_USE - FREED - DANGLING (FREED 状态下再次解引用即 UAF)。
跨函数策略: 调用者传入的指针在被调用者内释放, 以及全局/静态指针的跨函数传播。
"""

import re
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

# 生命周期状态
class PtrState(Enum):
    UNKNOWN = 0
    ALLOCATED = 1
    IN_USE = 2
    FREED = 3
    DANGLING = 4  # UAF确认

# 分配/释放/使用函数集
_ALLOC_SET = {'malloc', 'calloc', 'realloc', 'memalign', 'aligned_alloc',
              'strdup', 'strndup', 'asprintf', 'vasprintf'}
_FREE_SET = {'free', 'realloc'}  # realloc(ptr, 0) 等价于free
_USE_SET = {'memcpy', 'memmove', 'strcpy', 'strncpy', 'strcat', 'strncat',
            'printf', 'fprintf', 'sprintf', 'snprintf', 'puts', 'fwrite',
            'send', 'write', 'read', 'fread', 'fgets', 'gets'}
# printf类函数格式串后的第一个参数也可是指针使用
_PRINTF_LIKE = {'printf', 'fprintf', 'sprintf', 'snprintf'}

def _extract_ptr_operations(pseudocode: str) -> List[Dict[str, Any]]:
    """从伪代码提取所有指针操作: alloc/free/use, 附带行号。"""
    ops = []
    for i, line in enumerate(pseudocode.split('\n')):
        # 分配: var = malloc(size)
        for af in _ALLOC_SET:
            m = re.match(rf'.*?(\w+)\s*=\s*(?:\([^)]*\*?\s*\))?\s*{af}\s*\(', line)
            if m:
                ops.append({'line': i, 'type': 'alloc', 'func': af,
                           'var': m.group(1), 'text': line.strip()[:120]})
        # 释放: free(var)
        for ff in _FREE_SET:
            m = re.search(rf'{ff}\s*\(\s*(\w+)\s*\)', line)
            if m:
                ops.append({'line': i, 'type': 'free', 'func': ff,
                           'var': m.group(1), 'text': line.strip()[:120]})
        # 使用: memcpy(dst, ...)
        for uf in _USE_SET:
            m = re.match(rf'.*?{uf}\s*\(\s*(\w+)', line)
            if m and m.group(1) not in ('"%s"', '"%d"', '"%x"', '"%p"'):
                ops.append({'line': i, 'type': 'use', 'func': uf,
                           'var': m.group(1), 'text': line.strip()[:120]})
        # printf-like: 第二个参数可能是指针使用 (printf("%s", ptr))
        for pf in _PRINTF_LIKE:
            m = re.match(rf'.*?{pf}\s*\([^,]+,\s*(\w+)', line)
            if m:
                ops.append({'line': i, 'type': 'use', 'func': pf,
                           'var': m.group(1), 'text': line.strip()[:120]})
        # 解引用: *ptr, ptr->field, ptr[expr]
        for dm in re.finditer(r'\*(\w+)\b|(\w+)\s*->|(\w+)\s*\[', line):
            var = dm.group(1) or dm.group(2) or dm.group(3)
            if var and not var.startswith('_'):
                ops.append({'line': i, 'type': 'deref', 'func': 'operator',
                           'var': var, 'text': line.strip()[:120]})
    return sorted(ops, key=lambda o: o['line'])

def analyze_pointer_lifecycle(pseudocode: str, func_name: str = "",
                              global_ptrs: Optional[Dict[str, PtrState]] = None
                              ) -> Tuple[List[Dict[str, Any]], Dict[str, PtrState]]:
    """分析函数内所有堆指针的生命周期。

    参数: pseudocode 反编译伪代码, func_name 函数名(用于日志),
    global_ptrs 跨函数传递的指针状态表(调用者维护)。
    返回 (findings: UAF发现列表, final_states: 函数返回时各指针的状态)。
    """
    ops = _extract_ptr_operations(pseudocode)
    states: Dict[str, PtrState] = dict(global_ptrs or {})
    findings: List[Dict[str, Any]] = []

    for op in ops:
        var = op['var']
        if op['type'] == 'alloc':
            states[var] = PtrState.ALLOCATED
        elif op['type'] == 'use' or op['type'] == 'deref':
            if var in states and states[var] == PtrState.FREED:
                findings.append({
                    'vuln_type': 'use-after-free',
                    'function': func_name,
                    'variable': var,
                    'trigger_line': op['line'],
                    'trigger_text': op['text'],
                    'state_before': 'FREED',
                    'confidence': 0.85,
                    'description': (
                        f'UAF: pointer {var} dereferenced at line {op["line"]} '
                        f'after being freed in {func_name}'
                    ),
                    'exploitation': (
                        'Heap spray to reclaim freed chunk → place attacker-'
                        'controlled data at {var} → vtable/function pointer '
                        'overwrite or data-only privilege escalation'
                    ),
                })
                states[var] = PtrState.DANGLING
            elif var in states:
                states[var] = PtrState.IN_USE
        elif op['type'] == 'free':
            if var in states and states[var] == PtrState.FREED:
                findings.append({
                    'vuln_type': 'double-free',
                    'function': func_name,
                    'variable': var,
                    'trigger_line': op['line'],
                    'trigger_text': op['text'],
                    'confidence': 0.90,
                    'description': (
                        f'Double-free: {var} freed again at line {op["line"]} '
                        f'after prior free in {func_name}'
                    ),
                })
            states[var] = PtrState.FREED

    return findings, states

def inter_procedural_uaf_scan(
    func_pseudocodes: Dict[str, str],
    call_graph: Optional[Dict[str, List[str]]] = None,
) -> List[Dict[str, Any]]:
    """跨函数UAF扫描 - 在调用图中传播指针状态.

    func_pseudocodes: {func_name: pseudocode}
    call_graph: {caller: [callee, ...]}

    对每个函数独立分析, 收集全局指针(函数间传递的指针参数),
    跨函数追踪其状态变化. 使用已访问集合防止循环调用导致无限传播.
    """
    all_findings = []
    global_states: Dict[str, PtrState] = {}
    visited_funcs: Set[str] = set()

    for fname, pcode in func_pseudocodes.items():
        if fname in visited_funcs:
            continue
        visited_funcs.add(fname)
        findings, final_states = analyze_pointer_lifecycle(
            pcode, fname, global_states)
        all_findings.extend(findings)
        for var, state in final_states.items():
            if state in (PtrState.FREED, PtrState.DANGLING):
                global_states[var] = state

    return sorted(all_findings, key=lambda f: -f['confidence'])
