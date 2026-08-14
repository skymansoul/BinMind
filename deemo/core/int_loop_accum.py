# int_loop_accum.py - 检测循环累加溢出: 单次 add 不溢出, 但千次迭代会溢出, 是模式匹配的盲区。
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class LoopAccumOverflow:
    """循环累加溢出候选"""
    loop_start: int          # 循环入口地址
    loop_end: int            # 循环出口地址(jmp回跳目标)
    add_instruction: int     # add指令地址
    add_register: str        # 被累加的寄存器
    iterations_estimate: int # 估计迭代次数(-1=未知)
    downstream_use: str      # "malloc"/"memcpy"/"unknown"
    confidence: float
    evidence: str = ""


def detect_loop_accum_overflow(
    disasm_lines: List[str],
    func_name: str = "",
) -> List[LoopAccumOverflow]:
    """检测循环累加溢出: 向后跳转+循环体内add+add结果用于malloc。"""
    results: List[LoopAccumOverflow] = []

    for i, line in enumerate(disasm_lines):
        stripped = line.strip().lower()
        if not stripped or stripped.startswith(';'):
            continue

        # 找向后跳转(jmp或条件跳转, 目标<当前地址)
        m = re.search(r'(?:jmp|j[abglnewzcpso]+)\s+(0x[0-9a-fA-F]+)', stripped)
        if not m:
            continue
        try:
            target = int(m.group(1), 16)
        except ValueError:
            continue
        if target >= i:
            continue  # 向前跳转→不是循环回边

        # 确认: target到i之间形成了循环
        loop_body = disasm_lines[target:i + 1]

        # 在循环体内搜索add指令
        for j, bline in enumerate(loop_body):
            bl = bline.strip().lower()
            m = re.search(r'add\s+(\w+),\s*(0x[0-9a-fA-F]+|\d+)', bl)
            if not m:
                continue
            add_reg = m.group(1)
            try:
                add_val = int(m.group(2), 0)
            except ValueError:
                add_val = 1

            # 搜索add结果的下游使用
            downstream = "unknown"
            for k in range(i + 1, min(len(disasm_lines), i + 20)):
                dl = disasm_lines[k].strip().lower()
                if f'mov rdi, {add_reg}' in dl or f'mov edi, {add_reg}' in dl:
                    if any(c in disasm_lines[min(k+1, len(disasm_lines)-1)].lower()
                           for c in ('malloc', 'calloc')):
                        downstream = "malloc"
                        break
                if 'memcpy' in dl or 'memmove' in dl:
                    downstream = "memcpy"
                    break

            # 估计迭代次数: 搜索cmp reg, N; jcc模式
            iterations = -1
            for bline2 in loop_body:
                m2 = re.search(r'cmp\s+\w+,\s*(0x[0-9a-fA-F]+|\d+)', bline2.strip().lower())
                if m2:
                    try:
                        iterations = int(m2.group(1), 0)
                    except ValueError:
                        pass
                    break

            # 若已知迭代次数和累加值→计算总溢出量
            if iterations > 0 and add_val > 0:
                total = iterations * add_val
                if total > 0x7FFFFFFF:
                    results.append(LoopAccumOverflow(
                        loop_start=target, loop_end=i,
                        add_instruction=target + j, add_register=add_reg,
                        iterations_estimate=iterations,
                        downstream_use=downstream,
                        confidence=0.75,
                        evidence=f"循环{iterations}次×每次+{add_val}={total}→溢出",
                    ))
            else:
                results.append(LoopAccumOverflow(
                    loop_start=target, loop_end=i,
                    add_instruction=target + j, add_register=add_reg,
                    iterations_estimate=iterations,
                    downstream_use=downstream,
                    confidence=0.40,
                    evidence=f"循环累加({add_reg})→{downstream}",
                ))

    results.sort(key=lambda r: -r.confidence)
    return results[:15]


__all__ = ["LoopAccumOverflow", "detect_loop_accum_overflow"]
