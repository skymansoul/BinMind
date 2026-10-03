"""
多分配上下文追踪 — 记录每个变量的 malloc/realloc/free 历史。
检查 store 时采用最近一次分配的大小而非首次, 修正传入的分配大小;
作为独立上下文层运行, 不修改核心检测器逻辑。
"""

from dataclasses import dataclass, field
import re
from typing import Optional


@dataclass
class AllocEvent:
    """单个分配事件 — malloc/realloc/free 调用。"""
    pc: int
    op_type: str         # 'malloc' | 'calloc' | 'realloc' | 'free'
    var_name: str         # 接收/释放的变量名
    size: int = 0         # 分配大小 (free 时为 0)
    is_dynamic: bool = False


@dataclass
class VariableAllocHistory:
    """单个变量的完整分配历史, 按时间排序。"""
    var_name: str
    events: list[AllocEvent] = field(default_factory=list)

    def last_alloc_size(self) -> int:
        """最近一次分配的有效大小, free 后归零。"""
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
    """从IR中提取所有堆操作事件的完整上下文, 返回 {变量名: 历史} 供溢出检测器使用。"""
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
    """查询变量在 store_pc 处的有效分配大小; 释放后未重分配返回 0 (属UAF, 由 uaf_use_site_detector 处理)。"""
    hist = histories.get(var_name)
    if hist is None:
        return 0
    if hist.is_freed_before_store(store_pc):
        return 0
    return hist.last_alloc_size()
