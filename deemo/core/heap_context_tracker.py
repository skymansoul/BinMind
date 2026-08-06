"""
Multi-allocation context tracking for heap operations.

The heap overflow detector analyzes malloc→store pairs but ignores
intermediate realloc/free calls. e.g. p=malloc(64); free(p); p=malloc(256);
store(p+200) is legal because p was reallocated larger after free.

Maintains per-variable allocation history recording every malloc/realloc/free.
When checking a store, uses the *last* allocation size, not the first.

Runs as an independent context layer before the detector, correcting
the allocation size passed in — does not modify the core detector logic.
"""

from dataclasses import dataclass, field
import re
from typing import Optional


@dataclass
class AllocEvent:
    """A single allocation event — malloc/realloc/free call."""
    pc: int
    op_type: str         # 'malloc' | 'calloc' | 'realloc' | 'free'
    var_name: str         # 接收/释放的变量名
    size: int = 0         # 分配大小 (free 时为 0)
    is_dynamic: bool = False


@dataclass
class VariableAllocHistory:
    """Complete allocation history for one variable, time-ordered."""
    var_name: str
    events: list[AllocEvent] = field(default_factory=list)

    def last_alloc_size(self) -> int:
        """Effective size from the most recent allocation; zeroed after free."""
        effective = 0
        for e in self.events:
            if e.op_type in ('malloc', 'calloc'):
                effective = e.size
            elif e.op_type == 'realloc':
                effective = e.size
            elif e.op_type == 'free':
                effective = 0
        return effective

    def is_freed_before_store(self, store_pc: int) -> bool:
        """在 store 之前指针是否已被 free (且未重新分配)。"""
        last_free = -1
        last_alloc = -1
        for e in self.events:
            if e.op_type == 'free':
                last_free = e.pc
            elif e.op_type in ('malloc', 'calloc', 'realloc'):
                last_alloc = e.pc
        return last_free > last_alloc and store_pc > last_free


def extract_alloc_context(ir_lines: list[str]) -> dict[str, VariableAllocHistory]:
    """从 IR 中提取所有堆操作事件的完整上下文。

    Returns {var_name: VariableAllocHistory} for use by the heap overflow detector."""
    histories: dict[str, VariableAllocHistory] = {}
    alloc_pattern = re.compile(
        r'(?:(\w+)\s*=\s*)?(malloc|calloc|realloc)\s*\(\s*(\d+|\w+)(?:,\s*(\d+|\w+))?\s*\)',
        re.IGNORECASE,
    )
    free_pattern = re.compile(r'free\s*\(\s*(\w+)\s*\)', re.IGNORECASE)

    for i, line in enumerate(ir_lines):
        m = alloc_pattern.search(line)
        if m:
            var = m.group(1) or ''
            func = m.group(2).lower()
            size_str = m.group(3)
            try:
                size = int(size_str, 0)
                is_dyn = False
            except (ValueError, TypeError):
                size = 0
                is_dyn = True
            if var:
                hist = histories.setdefault(var, VariableAllocHistory(var_name=var))
                hist.events.append(AllocEvent(pc=i, op_type=func, var_name=var,
                                              size=size, is_dynamic=is_dyn))
            continue

        m = free_pattern.search(line)
        if m:
            var = m.group(1)
            hist = histories.setdefault(var, VariableAllocHistory(var_name=var))
            hist.events.append(AllocEvent(pc=i, op_type='free', var_name=var, size=0))

    return histories


def get_effective_alloc_size(var_name: str, store_pc: int,
                              histories: dict[str, VariableAllocHistory]) -> int:
    """查询变量在 store_pc 处的有效分配大小。

    Returns 0 if freed without reallocation (UAF, not heap overflow; handled by uaf_use_site_detector)."""
    hist = histories.get(var_name)
    if hist is None:
        return 0
    if hist.is_freed_before_store(store_pc):
        return 0
    return hist.last_alloc_size()
