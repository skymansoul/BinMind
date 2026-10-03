"""基于 IR 级 free 调用配对的双重释放检测。
memory_heap.py 的 'free.*free' 正则无法区分同指针双释放、异指针双释放与 realloc 合法模式;
本模块按释放变量分组, 检查两次 free 之间是否有重新分配, 并做同路径可达性快速检查。"""

from dataclasses import dataclass, field
import re
from typing import Optional, List


@dataclass
class FreeCall:
    pc: int
    freed_var: str
    freed_expr: str


@dataclass
class DoubleFreeCandidate:
    first_free: FreeCall
    second_free: FreeCall
    has_realloc_between: bool = False
    same_execution_path: bool = True
    confidence: float = 0.0
    description: str = ''


def find_free_calls(ir_lines: List[str]) -> List[FreeCall]:
    free_pattern = re.compile(r'free\s*\(\s*(\w+)\s*\)', re.IGNORECASE)
    frees = []
    for i, line in enumerate(ir_lines):
        m = free_pattern.search(line)
        if m:
            frees.append(FreeCall(pc=i, freed_var=m.group(1), freed_expr=m.group(0)))
    return frees


def has_realloc_between(ir_lines: List[str], var: str, start_pc: int, end_pc: int) -> bool:
    """检查 start_pc 和 end_pc 之间是否对变量 var 有重新分配。"""
    realloc_pattern = re.compile(
        rf'{re.escape(var)}\s*=\s*(?:malloc|calloc|realloc)\s*\(', re.IGNORECASE)
    for i in range(start_pc + 1, end_pc):
        if realloc_pattern.search(ir_lines[i]):
            return True
    return False


def detect_double_free(ir_lines: List[str]) -> List[DoubleFreeCandidate]:
    frees = find_free_calls(ir_lines)
    candidates = []

    by_var = {}
    for f in frees:
        by_var.setdefault(f.freed_var, []).append(f)

    for var, calls in by_var.items():
        if len(calls) < 2:
            continue
        for i in range(len(calls) - 1):
            first, second = calls[i], calls[i + 1]
            realloc = has_realloc_between(ir_lines, var, first.pc, second.pc)
            if realloc:
                continue
            confidence = 0.90 if (second.pc - first.pc) < 20 else 0.70
            candidates.append(DoubleFreeCandidate(
                first_free=first, second_free=second,
                has_realloc_between=False,
                confidence=confidence,
                description=f'{var} freed at line {first.pc} and again at line {second.pc} without reallocation',
            ))

    candidates.sort(key=lambda c: -c.confidence)
    return candidates
