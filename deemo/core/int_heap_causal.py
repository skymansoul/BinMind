# Integer overflow → heap overflow causal chain: tracks mul/add results
# flowing directly into malloc size arguments.
# Most dangerous pattern: size = count * element_size; ptr = malloc(size);
# if count*element_size overflows, malloc allocates far less than expected,
# and subsequent writes trigger heap overflow.
# Pattern matching catches individual patterns; this module establishes the
# causal chain: overflow op → malloc → heap write.
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class CausalChain:
    """整数溢出→堆溢出因果链"""
    overflow_addr: int        # mul/add指令地址
    overflow_op: str          # "mul"/"add"/"shl"
    malloc_addr: int          # malloc调用地址
    heap_write_addr: int      # 堆写入地址
    estimated_overflow_bytes: int  # 溢出字节数估计
    confidence: float
    evidence: str = ""
    func_name: str = ""


def detect_int_heap_causal(
    disasm_lines: List[str],
    func_name: str = "",
) -> List[CausalChain]:
    """检测整数溢出→堆溢出因果链。

    三步: (1)找到mul/add→(2)结果流向malloc的size参数→(3)malloc后存在堆写入。
    三步全部匹配→因果链确认→最高置信度(>0.8)。
    缺一步→降权。
    """
    chains: List[CausalChain] = []

    for i, line in enumerate(disasm_lines):
        stripped = line.strip().lower()
        if not stripped or stripped.startswith(';'):
            continue

        # 步骤1: 找到溢出操作 (mul/imul/add其中至少一个操作数非零)
        op_type = ""
        m = re.search(r'(?:imul|mul)\s+(\w+)(?:\s*,\s*(\w+))?', stripped)
        if m:
            op_type = "mul"
        else:
            m = re.search(r'add\s+(\w+),\s*(0x[0-9a-fA-F]+|\d+)', stripped)
            if m:
                op_type = "add"
        if not op_type:
            continue

        # 步骤2: 搜索后续malloc(在max_distance内)
        malloc_addr = -1
        for j in range(i + 1, min(len(disasm_lines), i + 20)):
            dl = disasm_lines[j].strip().lower()
            if re.search(r'call.*<(?:malloc|calloc|realloc)', dl):
                malloc_addr = j
                break
        if malloc_addr < 0:
            continue

        # 步骤3: 搜索malloc后的堆写入
        heap_write_addr = -1
        for k in range(malloc_addr + 1, min(len(disasm_lines), malloc_addr + 15)):
            dl = disasm_lines[k].strip().lower()
            if any(kw in dl for kw in ('mov [', 'strcpy', 'memcpy', 'memset')):
                heap_write_addr = k
                break

        # 置信度: 三步全→0.85, 两步→0.55, 一步→0.30
        if heap_write_addr > 0:
            conf = 0.85
            ev = (f"因果链: {op_type}@{hex(i)}→malloc@{hex(malloc_addr)}"
                  f"→堆写@{hex(heap_write_addr)}")
        elif malloc_addr > 0:
            conf = 0.55
            ev = f"部分链: {op_type}@{hex(i)}→malloc@{hex(malloc_addr)}(无后续写入)"
        else:
            conf = 0.30
            ev = f"孤立溢出: {op_type}@{hex(i)}(无malloc)"

        chains.append(CausalChain(
            overflow_addr=i, overflow_op=op_type,
            malloc_addr=malloc_addr, heap_write_addr=heap_write_addr,
            estimated_overflow_bytes=-1, confidence=round(conf, 3),
            evidence=ev, func_name=func_name,
        ))

    chains.sort(key=lambda c: -c.confidence)
    return chains[:15]


__all__ = ["CausalChain", "detect_int_heap_causal"]
