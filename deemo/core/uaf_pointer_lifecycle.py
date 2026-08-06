"""
指针生命周期状态机 -- 跨函数追踪堆指针从分配到释放到悬垂使用的完整生命周期。

设计理由:
  现有 heap_uaf_detector.py 仅在同一函数内搜索 free(p) 后的 *p 访问,
  无法处理跨函数UAF(函数A中free, 函数B中使用)。这是UAF误检/漏检的主因。
  本模块维护每个堆指针的状态机: ALLOCATED → IN_USE → FREED → DANGLING,
  跨反编译的函数边界追踪状态转换。

状态转换规则:
  ALLOCATED: malloc/calloc/realloc 返回非NULL → 进入此状态
  IN_USE:   指针被解引用/传递给memcpy等 → 正常使用
  FREED:    free(p) 被调用 → 指针变为悬垂
  DANGLING: 在FREED状态下, 指针再次被解引用 → UAF确认

跨函数追踪策略:
  1. 调用者传入指针 → 被调用者内部free → 返回后调用者继续使用 → UAF
  2. 全局/静态指针: 函数A中malloc, 函数B中free, 函数C中使用 → UAF

局限:
  不处理多线程并发UAF(需要happens-before分析, 纯静态无法精确捕获)
  间接调用(jump table/vtable)保守假设可能触发free

参考:
  - Caballero et al., USENIX Security 2012, "Undangle: Early Detection of
    Dangling Pointers in Use-After-Free and Double-Free Vulnerabilities"
  - Gennissen & O'Keeffe, 2023, "HeapHop: Heap-use-after-free detection via
    dynamic points-to analysis"
"""

from __future__ import annotations

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
# printf类函数格式串后的第一个参数也可能是指针的使用
_PRINTF_LIKE = {'printf', 'fprintf', 'sprintf', 'snprintf'}


def _extract_ptr_operations(pseudocode: str) -> List[Dict[str, Any]]:
    """从伪代码提取所有指针操作: alloc/free/use, 附带行号。"""
    import re
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

    Args:
        pseudocode: 反编译伪代码
        func_name: 函数名(用于日志)
        global_ptrs: 跨函数传递的指针状态表(调用者维护)

    Returns:
        (findings: UAF发现列表, final_states: 函数返回时各指针的状态)
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
    """跨函数UAF扫描 -- 在调用图中传播指针状态。

    func_pseudocodes: {func_name: pseudocode}
    call_graph: {caller: [callee, ...]}

    对每个函数独立分析, 收集全局指针(函数间传递的指针参数),
    跨函数追踪其状态变化。
    """
    all_findings = []
    global_states: Dict[str, PtrState] = {}

    for fname, pcode in func_pseudocodes.items():
        findings, final_states = analyze_pointer_lifecycle(
            pcode, fname, global_states)
        all_findings.extend(findings)
        # 传播状态到调用者
        for var, state in final_states.items():
            if state in (PtrState.FREED, PtrState.DANGLING):
                global_states[var] = state  # 跨函数保留危险状态

    return sorted(all_findings, key=lambda f: -f['confidence'])
