"""
整数溢出下游影响分类 — 溢出值流向追踪→利用等级。

问题定义:
  整数溢出被分析工具报告为统一类别，但下游影响差异极大:
    - 溢出后值未使用 → 死溢出 (0 利用价值)
    - 溢出后仅用于算术 → 错误计算结果 (低危)
    - 溢出后作为 malloc 参数 → 分配不足→堆溢出 (高危)
    - 溢出后作为 memcpy 长度 → 直接缓冲区溢出 (极危)
    - 溢出后绕过边界检查 → 内存破坏 (极危)

  本模块建立溢出值→下游操作的因果链，按影响等级分类。

  五级影响分类:
    L0 (dead):        溢出值未被任何后续操作使用
    L1 (arithmetic):  仅用于计算/比较，不涉及内存
    L2 (allocation):  影响 malloc/calloc/realloc 大小
    L3 (bounds):      影响数组索引或边界检查
    L4 (memory_copy): 影响 memcpy/strcpy/snprintf 的长度参数
    L5 (control_flow): 影响分支条件或间接跳转目标

  CWE-190: Integer Overflow or Wraparound
  CWE-680: Integer Overflow to Buffer Overflow
  无现有分类工具 — 现有扫描器仅报告溢出存在性.

修改记录:
  2026-08-01 10:27 - 初始版本，五级下游影响分类
"""

from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Set

class OverflowLevel(IntEnum):
    DEAD = 0            # 溢出值未使用
    ARITHMETIC = 1      # 仅影响计算/比较
    ALLOCATION = 2      # 影响分配大小
    BOUNDS = 3          # 影响数组索引/边界检查
    MEMORY_COPY = 4     # 影响内存拷贝长度
    CONTROL_FLOW = 5    # 影响分支/间接跳转

# 下游函数 → 影响等级映射
_DOWNSTREAM_IMPACT: Dict[str, OverflowLevel] = {
    'malloc': OverflowLevel.ALLOCATION, 'calloc': OverflowLevel.ALLOCATION,
    'realloc': OverflowLevel.ALLOCATION, 'alloca': OverflowLevel.ALLOCATION,
    'new': OverflowLevel.ALLOCATION, 'new[]': OverflowLevel.ALLOCATION,
    'operator new': OverflowLevel.ALLOCATION,
    'memcpy': OverflowLevel.MEMORY_COPY, 'memmove': OverflowLevel.MEMORY_COPY,
    'memset': OverflowLevel.MEMORY_COPY, 'bcopy': OverflowLevel.MEMORY_COPY,
    'strcpy': OverflowLevel.MEMORY_COPY, 'strncpy': OverflowLevel.MEMORY_COPY,
    'strcat': OverflowLevel.MEMORY_COPY, 'strncat': OverflowLevel.MEMORY_COPY,
    'sprintf': OverflowLevel.MEMORY_COPY, 'snprintf': OverflowLevel.MEMORY_COPY,
    'read': OverflowLevel.MEMORY_COPY, 'fread': OverflowLevel.MEMORY_COPY,
    'recv': OverflowLevel.MEMORY_COPY, 'recvfrom': OverflowLevel.MEMORY_COPY,
    'fgets': OverflowLevel.MEMORY_COPY, 'gets': OverflowLevel.MEMORY_COPY,
    'array_index': OverflowLevel.BOUNDS, 'ptr_arithmetic': OverflowLevel.BOUNDS,
}

# 每级 exploitability 映射
_LEVEL_EXPLOIT: Dict[OverflowLevel, float] = {
    OverflowLevel.DEAD: 0.0,
    OverflowLevel.ARITHMETIC: 0.5,
    OverflowLevel.ALLOCATION: 5.0,
    OverflowLevel.BOUNDS: 6.5,
    OverflowLevel.MEMORY_COPY: 8.5,
    OverflowLevel.CONTROL_FLOW: 9.5,
}

@dataclass
class OverflowTriage:
    """整数溢出下游影响分类。"""
    overflow_location: str
    overflow_type: str              # signed/unsigned/wraparound/truncation
    downstream_level: OverflowLevel
    downstream_functions: List[str]
    exploitability: float           # 0-10
    escalation_path: str = ''
    cwe_mapping: List[str] = field(default_factory=list)

def _trace_downstream(
    overflowed_variable: str,
    available_callees: List[str],
    pseudocode_hints: str = '',
) -> Tuple[OverflowLevel, List[str]]:
    """
    从溢出变量名和可用调用追踪下游影响。

    pseudocode_hints: Ghidra/IDA 反编译片段，用于匹配变量→函数。
    """
    max_level = OverflowLevel.DEAD
    matched_funcs: List[str] = []

    # 在伪代码中搜索 "overflowed_var → function" 模式
    search_text = pseudocode_hints.lower() if pseudocode_hints else ''
    var_lower = overflowed_variable.lower()

    for func, level in _DOWNSTREAM_IMPACT.items():
        func_lower = func.lower()
        for callee in available_callees:
            if func_lower in callee.lower():
                # 在伪代码中检查此变量是否与调用关联
                # 简单启发式: 变量名和函数名在同一行或在相邻行
                lines = search_text.split('\n')
                for i, line in enumerate(lines):
                    if var_lower in line and func_lower in line:
                        matched_funcs.append(func)
                        max_level = max(max_level, level)
                        break
                    # 检查相邻行
                    if i > 0 and var_lower in lines[i-1] and func_lower in line:
                        matched_funcs.append(func)
                        max_level = max(max_level, level)
                        break
                    if i < len(lines)-1 and var_lower in lines[i+1] and func_lower in line:
                        matched_funcs.append(func)
                        max_level = max(max_level, level)
                        break

    # 回退: 无伪代码时，基于 callee 名称做保守推断
    if not matched_funcs:
        for callee in available_callees:
            for func, level in _DOWNSTREAM_IMPACT.items():
                if func.lower() in callee.lower():
                    max_level = max(max_level, level)

    return max_level, matched_funcs

def _cwe_for_level(level: OverflowLevel) -> List[str]:
    return {
        OverflowLevel.DEAD: ['CWE-190'],
        OverflowLevel.ARITHMETIC: ['CWE-190', 'CWE-682'],
        OverflowLevel.ALLOCATION: ['CWE-190', 'CWE-680', 'CWE-789'],
        OverflowLevel.BOUNDS: ['CWE-190', 'CWE-680', 'CWE-129', 'CWE-823'],
        OverflowLevel.MEMORY_COPY: ['CWE-190', 'CWE-680', 'CWE-122', 'CWE-787'],
        OverflowLevel.CONTROL_FLOW: ['CWE-190', 'CWE-680', 'CWE-193', 'CWE-822'],
    }.get(level, ['CWE-190'])

def triage_overflow(
    overflow_location: str = '',
    overflow_type: str = 'unsigned_wraparound',
    overflowed_variable: str = '',
    available_callees: Optional[List[str]] = None,
    pseudocode_hints: str = '',
) -> OverflowTriage:
    """
    分类整数溢出的下游影响。

    overflow_type: signed/unsigned_wraparound/truncation/width_extension
    """
    level, funcs = _trace_downstream(
        overflowed_variable, available_callees or [], pseudocode_hints
    )

    exploit = _LEVEL_EXPLOIT[level]

    # 溢出类型修正
    if overflow_type == 'signed' and level >= OverflowLevel.BOUNDS:
        exploit += 0.5  # signed overflow is UB → 编译器可能消除检查

    exploit = round(min(exploit, 10.0), 1)

    escalation = {
        OverflowLevel.DEAD: '无利用价值 — 溢出值未被下游使用',
        OverflowLevel.ARITHMETIC: '低危 — 仅影响计算结果。可能的 DoS',
        OverflowLevel.ALLOCATION: '高危 — 影响分配大小→堆溢出利用链',
        OverflowLevel.BOUNDS: '高危 — 绕过边界检查→越界读写',
        OverflowLevel.MEMORY_COPY: '极危 — 直接控制 memcpy 长度→任意写入',
        OverflowLevel.CONTROL_FLOW: '极危 — 影响控制流→代码执行',
    }.get(level, '未知')

    return OverflowTriage(
        overflow_location=overflow_location or 'unknown',
        overflow_type=overflow_type,
        downstream_level=level,
        downstream_functions=funcs,
        exploitability=exploit,
        escalation_path=escalation,
        cwe_mapping=_cwe_for_level(level),
    )
