"""
堆溢出专项检测 — malloc/free配对 + size参数流分析。

检测逻辑:
  1. 定位malloc/calloc/realloc调用点, 提取size参数
  2. 定位后续memcpy/strcpy/read等写入操作, 提取写入长度
  3. 若size参数 < 写入长度 → 堆溢出告警

与path_taint_simplified.py的关系:
  path_taint_simplified检测"外部输入→危险函数"的污点路径。
  本模块检测"分配大小≠写入大小"的算术不一致。

修改记录:
  创建 2025-02-06
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class HeapOverflowFinding:
    location: str
    alloc_func: str
    alloc_size_value: int
    write_func: str
    write_size_value: int
    overflow_bytes: int
    confidence: str


_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', '_Znwm', 'HeapAlloc', 'VirtualAlloc'}
_WRITE_FUNCS = {'memcpy', 'memmove', 'memset', 'strcpy', 'strncpy', 'strcat',
                'sprintf', 'snprintf', 'read', 'fread', 'recv', 'recvfrom', 'gets'}


def _extract_size_src(func_name: str) -> str:
    if func_name in ('malloc', 'operator new'): return 'rdi'
    if func_name == 'calloc': return 'rdi*rsi'
    if func_name in ('memcpy', 'memmove', 'strncpy', 'read', 'recv'): return 'rdx'
    if func_name in ('strcpy', 'strcat', 'gets', 'sprintf'): return 'unbounded'
    return 'unknown'


def detect_heap_overflow(
    instructions: List[str],
    known_constants: Optional[Dict[str, int]] = None,
) -> List[HeapOverflowFinding]:
    findings: List[HeapOverflowFinding] = []
    constants = known_constants or {}
    last_alloc: Optional[Tuple[str, int, str]] = None

    for i, insn in enumerate(instructions):
        insn_lower = insn.lower().strip()
        if not ('call' in insn_lower or 'bl' in insn_lower): continue
        parts = insn_lower.split()
        if len(parts) < 2: continue
        callee = parts[-1].lstrip('*').strip('<>').split('@')[0]

        if callee in _ALLOC_FUNCS:
            src = _extract_size_src(callee)
            val = constants.get(src, 0)
            last_alloc = (callee, val, src)
        elif callee in _WRITE_FUNCS and last_alloc is not None:
            wsrc = _extract_size_src(callee)
            wval = constants.get(wsrc, 0)
            afunc, aval, _ = last_alloc
            if wsrc == 'unbounded':
                findings.append(HeapOverflowFinding(
                    location=f'{callee}@{i}', alloc_func=afunc,
                    alloc_size_value=aval, write_func=callee,
                    write_size_value=0, overflow_bytes=-1, confidence='likely'))
            elif aval > 0 and wval > 0 and wval > aval:
                findings.append(HeapOverflowFinding(
                    location=f'{callee}@{i}', alloc_func=afunc,
                    alloc_size_value=aval, write_func=callee,
                    write_size_value=wval, overflow_bytes=wval-aval,
                    confidence='confirmed'))
    return findings
