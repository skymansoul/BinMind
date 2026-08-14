"""
汇编级整数溢出检测 — 追踪 mul/imul/add 结果流入 malloc/memcpy 的路径。
补充伪代码检测的盲区, 适用于反编译器失效的 stripped/O3 二进制。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class AsmOverflowSite:
    address: int
    overflow_op: str       # "mul"/"imul"/"add"/"shl"
    operand_regs: List[str]
    downstream_op: str     # "malloc"/"memcpy"/"array_access"
    downstream_addr: int
    confidence: float
    evidence: str = ""


# 溢出操作→后续安全操作的最大指令距离
_MAX_DISTANCE = 25

# 溢出操作模式
_OVERFLOW_OPS = [
    (r'\b(?:mul|imul)\s+(\w+)', 'mul'),
    (r'\badd\s+(\w+),\s*(0x[0-9a-fA-F]+|\d+)', 'add'),
    (r'\bshl\s+(\w+),\s*(0x[0-9a-fA-F]+|\d+)', 'shl'),
]

# 下游安全操作
_DOWNSTREAM = [
    (r'call.*<(?:malloc|calloc|realloc)', 'malloc'),
    (r'call.*<(?:memcpy|memmove)', 'memcpy'),
    (r'mov\s+\[(\w+)\+(\w+)\*', 'array_access'),
]


def detect_int_overflow_asm(
    disasm_lines: List[str],
    func_name: str = "",
) -> List[AsmOverflowSite]:
    """从反汇编检测整数溢出→安全操作的模式。

    对每条mul/imul/add/shl指令, 向前搜索其操作数的定义(常量值),
    向后搜索其结果的使用(malloc/memcpy/数组索引)。
    若操作数已知且乘积超过INT32_MAX→高置信度溢出。
    """
    candidates: List[AsmOverflowSite] = []

    for i, line in enumerate(disasm_lines):
        stripped = line.strip().lower()
        if not stripped or stripped.startswith(';'):
            continue

        # 匹配溢出操作
        op_type = ""
        op_regs: List[str] = []
        for pattern, otype in _OVERFLOW_OPS:
            m = re.search(pattern, stripped)
            if m:
                op_type = otype
                op_regs = [m.group(1)]
                # mul可能有两个操作数
                m2 = re.search(pattern.replace('+','').replace('\\s+','\\s+\\w+,\\s*'), stripped)
                if m2:
                    try:
                        op_regs.append(m2.group(2))
                    except (IndexError, AttributeError):
                        pass
                break
        if not op_type:
            continue

        # 提取操作数的已知常量值
        known_vals = {}
        for reg in op_regs:
            val = _backtrack_const(disasm_lines, i, reg)
            if val is not None:
                known_vals[reg] = val

        # 若所有操作数已知→判断溢出
        overflow_detected = False
        if len(known_vals) >= 1 and op_type in ('mul', 'imul'):
            if len(known_vals) == 2:
                a, b = list(known_vals.values())[:2]
                if abs(a * b) > 0x7FFFFFFF:
                    overflow_detected = True

        # 搜索下游安全操作
        downstream = ""
        downstream_addr = 0
        for j in range(i + 1, min(len(disasm_lines), i + _MAX_DISTANCE)):
            dl = disasm_lines[j].strip().lower()
            for pattern, dtype in _DOWNSTREAM:
                if re.search(pattern, dl):
                    downstream = dtype
                    downstream_addr = j
                    break
            if downstream:
                break

        if downstream:
            base_conf = 0.55 if overflow_detected else 0.35
            if len(known_vals) >= 1:
                base_conf += 0.15
            candidates.append(AsmOverflowSite(
                address=i, overflow_op=op_type,
                operand_regs=op_regs,
                downstream_op=downstream,
                downstream_addr=downstream_addr,
                confidence=round(min(0.95, base_conf), 3),
                evidence=f"{op_type}@{hex(i)}→{downstream}@{hex(downstream_addr)}",
            ))

    candidates.sort(key=lambda c: -c.confidence)
    return candidates[:20]


def _backtrack_const(lines: List[str], from_idx: int,
                      reg: str, max_back: int = 10) -> Optional[int]:
    """反向追踪寄存器的常量值。"""
    for i in range(from_idx - 1, max(-1, from_idx - max_back), -1):
        l = lines[i].strip().lower()
        m = re.search(rf'mov\s+{reg},\s*(0x[0-9a-fA-F]+|\d+)', l)
        if m:
            try:
                return int(m.group(1), 0)
            except ValueError:
                pass
    return None


__all__ = ["AsmOverflowSite", "detect_int_overflow_asm"]
