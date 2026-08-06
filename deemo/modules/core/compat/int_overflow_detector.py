# -*- coding: utf-8 -*-
"""整数溢出检测 — 识别算术运算中的上溢/下溢, 判定是否被用于内存分配.

CWE-190 (Integer Overflow/Wraparound) 在二进制层面的检测:
  1. 识别 mul/imul/add/sub 等算术指令
  2. 检查结果是否被传递到 malloc/calloc/realloc 等分配函数
  3. 若溢出后的值用作分配大小 → 分配缓冲区过小 → 后续写入堆溢出

与编译器的 -ftrapv 差异: 编译器插桩需源码重编译. 本模块在反汇编层检测,
适用于 stripped binary, 无需源码或重编译.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 可能导致溢出的算术操作 (x86-64 助记符)
_OVERFLOW_PRONE_OPS = frozenset({
    'imul', 'mul', 'add', 'sub', 'shl', 'sal',
    'madd', 'msub',  # ARM
})

# 内存分配相关的函数/指令模式
_ALLOC_SINK_PATTERNS = [
    re.compile(r'(?:call|bl|jal).*?(?:malloc|calloc|realloc|alloc|new)', re.I),
    re.compile(r'(?:call|bl).*?(?:kmalloc|kzalloc|kmem_cache_alloc)', re.I),
]


@dataclass
class IntOverflowCandidate:
    """一个整数溢出候选."""
    overflow_site: int        # 算术指令地址
    op_type: str              # 'mul'|'imul'|'add'|'shl'|'sub'
    operand_width: int        # 8|16|32|64 (位宽)
    lhs_range: str            # 左操作数的值区间描述
    rhs_range: str            # 右操作数的值区间描述
    reaches_alloc: bool       # 溢出结果是否流向分配函数
    alloc_site: int = 0       # 分配函数调用地址
    confidence: float = 0.0
    exploitable: bool = False
    detail: str = ''


def detect_overflow_ops(
    instructions: List[Dict],
    def_use_chains: Optional[Dict[int, List[int]]] = None,
) -> List[IntOverflowCandidate]:
    """在指令序列中检测可能导致溢出的算术操作.

    instructions: [{addr, mnemonic, operands}, ...]
    def_use_chains: 地址 → [源操作数地址] 的 def-use 映射

    返回检测到的溢出候选列表, 按可信度降序排列.
    """
    candidates = []
    du = def_use_chains or {}

    for insn in instructions:
        mnemonic = insn.get('mnemonic', '').lower()
        if mnemonic not in _OVERFLOW_PRONE_OPS:
            continue

        addr = insn.get('addr', 0)
        operands = insn.get('operands', '')
        width = _infer_width(insn)

        # 检查: 结果是否被后续的分配函数使用
        reaches_alloc = False
        alloc_site = 0
        if du:
            sinks = _find_sinks(addr, du, max_depth=5)
            for sink in sinks:
                if _is_alloc_call(sink, instructions):
                    reaches_alloc = True
                    alloc_site = sink
                    break

        # 操作数区间 (简化: 从立即数和寄存器推断)
        lhs_range = _extract_range(operands, 0)
        rhs_range = _extract_range(operands, 1)

        conf = 0.35
        if reaches_alloc:
            conf += 0.35  # 流向分配函数 → 高概率可用
        if mnemonic in ('imul', 'mul'):
            conf += 0.15  # 乘法最易溢出

        exploitable = reaches_alloc and conf >= 0.50

        detail = (f'{mnemonic} @ 0x{addr:x}: {lhs_range} × {rhs_range} '
                 f'(width={width}bit)')
        if reaches_alloc:
            detail += f' → reaches alloc @ 0x{alloc_site:x}'

        candidates.append(IntOverflowCandidate(
            overflow_site=addr, op_type=mnemonic,
            operand_width=width, lhs_range=lhs_range, rhs_range=rhs_range,
            reaches_alloc=reaches_alloc, alloc_site=alloc_site,
            confidence=min(1.0, conf), exploitable=exploitable,
            detail=detail,
        ))

    candidates.sort(key=lambda c: -c.confidence)
    return candidates


def _infer_width(insn: Dict) -> int:
    """从指令助记符后缀推断操作数位宽 (x86: l=32, q=64, w=16, b=8)."""
    m = insn.get('mnemonic', '')
    operands = insn.get('operands', '')
    if 'qword' in operands or m.endswith('q') or 'rax' in operands or 'r' in operands[:8]:
        return 64
    if 'dword' in operands or m.endswith('l') or 'eax' in operands:
        return 32
    if 'word' in operands or m.endswith('w') or 'ax' in operands:
        return 16
    return 32


def _extract_range(ops: str, index: int) -> str:
    """从操作数字符串中提取指定索引操作数的值区间描述."""
    parts = [p.strip() for p in ops.split(',')]
    if index >= len(parts):
        return '?'
    part = parts[index]
    if part.startswith('0x'):
        return f'const({int(part,16)})'
    if part.isdigit() or (part.startswith('-') and part[1:].isdigit()):
        return f'const({part})'
    return f'reg({part})'


def _find_sinks(addr: int, du: Dict[int, List[int]], max_depth: int) -> List[int]:
    """BFS: du 为 def→[use] 映射, 从 addr 出发沿正向找到所有使用点."""
    from collections import deque
    sinks = []
    visited = {addr}
    q = deque([(addr, 0)])
    while q:
        cur, depth = q.popleft()
        if depth >= max_depth:
            continue
        for use_site in du.get(cur, []):
            if use_site not in visited:
                visited.add(use_site)
                sinks.append(use_site)
                q.append((use_site, depth + 1))
    return sinks


def _is_alloc_call(addr: int, instructions: List[Dict]) -> bool:
    """检查指定地址的指令是否为分配函数调用."""
    for insn in instructions:
        if insn.get('addr') == addr:
            op_str = (insn.get('mnemonic', '') + ' ' + insn.get('callee', '') +
                      ' ' + insn.get('operands', ''))
            return any(p.search(op_str) for p in _ALLOC_SINK_PATTERNS)
    return False


def int_overflow_summary(candidates: List[IntOverflowCandidate]) -> Dict[str, Any]:
    exploitable = [c for c in candidates if c.exploitable]
    reaches_alloc = [c for c in candidates if c.reaches_alloc]
    return {
        'total': len(candidates),
        'exploitable': len(exploitable),
        'reaches_alloc': len(reaches_alloc),
        'by_op': {op: sum(1 for c in candidates if c.op_type == op)
                  for op in set(c.op_type for c in candidates)},
        'avg_confidence': round(
            sum(c.confidence for c in candidates) / max(1, len(candidates)), 2),
    }
