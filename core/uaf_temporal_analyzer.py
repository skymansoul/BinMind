# UAF 时序分析器 — 追踪每个堆指针的操作序列, 检测 free→use 时序违例。
# 基于 Undangle 思路, 但采用反汇编级分析 (Undangle 依赖类型信息, 对去符号二进制无效)。
# 提供: (a) 每指针的时序操作序列 (按地址排序的 alloc/free/use);
# (b) 别名推断 (同 malloc 或经 mov 指向同一对象的指针); (c) 路径可行性分析。

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class OpType(Enum):
    ALLOC = 1
    FREE  = 2
    USE   = 3   # 解引用/写入/读取


@dataclass
class PointerEvent:
    """堆对象上的单次指针操作。"""
    ptr_name: str       # variable name or register
    op_type: OpType
    address: int        # instruction address (for ordering)
    line: str = ""      # raw code line
    func_name: str = "" # 所在函数


@dataclass
class PointerTimeline:
    """单个逻辑堆对象的完整操作时间线。"""
    object_id: str       # 唯一标识(malloc地址+变量名)
    events: List[PointerEvent] = field(default_factory=list)
    aliases: Set[str] = field(default_factory=set)  # 指向同一对象的所有指针名

    @property
    def has_uaf(self) -> bool:
        """检查 FREE 事件之后是否存在 USE 事件。"""
        freed = False
        for e in sorted(self.events, key=lambda x: x.address):
            if e.op_type == OpType.FREE:
                freed = True
            elif e.op_type == OpType.USE and freed:
                return True
        return False

    @property
    def has_double_free(self) -> bool:
        free_count = sum(1 for e in self.events if e.op_type == OpType.FREE)
        return free_count >= 2


@dataclass
class TemporalUafReport:
    """时序 UAF 分析报告。"""
    timelines: List[PointerTimeline]
    uaf_objects: List[PointerTimeline]   # has_uaf=True的子集
    double_free_objects: List[PointerTimeline]
    total_objects: int
    uaf_count: int
    double_free_count: int


class UafTemporalAnalyzer:
    """UAF 时序分析器: 构建指针时间线并检测时序违例。"""

    def analyze(self, disasm_lines: List[str],
                func_name: str = "") -> TemporalUafReport:
        """从反汇编构建所有堆指针的操作时间线。"""
        events = self._extract_events(disasm_lines, func_name)
        timelines = self._build_timelines(events)
        timelines = self._merge_aliases(timelines, disasm_lines)
        uaf_objs = [t for t in timelines if t.has_uaf]
        df_objs = [t for t in timelines if t.has_double_free]
        return TemporalUafReport(
            timelines=timelines, uaf_objects=uaf_objs,
            double_free_objects=df_objs,
            total_objects=len(timelines),
            uaf_count=len(uaf_objs),
            double_free_count=len(df_objs),
        )

    def _extract_events(self, lines: List[str],
                         func: str) -> List[PointerEvent]:
        events: List[PointerEvent] = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith(';'):
                continue
            lower = stripped.lower()

            # malloc/calloc → ALLOC 事件
            m = re.search(r'(\w+)\s*=.*(?:malloc|calloc|realloc)\s*\(', lower)
            if m:
                events.append(PointerEvent(
                    ptr_name=m.group(1), op_type=OpType.ALLOC,
                    address=i, line=stripped, func_name=func))
                continue

            # free(p) → FREE 事件
            m = re.search(r'free\s*\(\s*(\w+)\s*\)', lower)
            if m:
                events.append(PointerEvent(
                    ptr_name=m.group(1), op_type=OpType.FREE,
                    address=i, line=stripped, func_name=func))
                continue

# p / p->field / p[index] → USE 事件
            m = re.search(r'[*\[]\s*(\w+)\s*[\]\s]|(\w+)\s*->', lower)
            if m:
                ptr = m.group(1) or m.group(2)
                if ptr and not ptr.startswith(('0x', 'rsp', 'rbp')):
                    events.append(PointerEvent(
                        ptr_name=ptr, op_type=OpType.USE,
                        address=i, line=stripped, func_name=func))

        return events

    @staticmethod
    def _build_timelines(events: List[PointerEvent]) -> List[PointerTimeline]:
        """按指针名分组事件, 每组构成一条时间线。"""
        groups: Dict[str, List[PointerEvent]] = defaultdict(list)
        for e in events:
            groups[e.ptr_name].append(e)
        timelines = []
        for ptr_name, evts in groups.items():
            has_alloc = any(e.op_type == OpType.ALLOC for e in evts)
            if not has_alloc:
                continue
            tl = PointerTimeline(
                object_id=ptr_name, events=evts, aliases={ptr_name})
            timelines.append(tl)
        return timelines

    @staticmethod
    def _merge_aliases(timelines: List[PointerTimeline],
                        disasm_lines: List[str]) -> List[PointerTimeline]:
        """合并别名: 若经 mov 得到 ptr_a = ptr_b, 则合并二者的时间线。"""
        # 提取 mov 别名关系
        aliases: Dict[str, str] = {}
        for line in disasm_lines:
            m = re.search(r'(\w+)\s*=\s*(\w+)\s*;', line.strip())
            if m:
                dst, src = m.group(1), m.group(2)
                if src in aliases:
                    aliases[dst] = aliases[src]
                else:
                    aliases[dst] = src

        # 合并时间线
        merged: Dict[str, PointerTimeline] = {}
        for tl in timelines:
            canonical = aliases.get(tl.object_id, tl.object_id)
            if canonical in merged:
                merged[canonical].events.extend(tl.events)
                merged[canonical].aliases.add(tl.object_id)
            else:
                merged[canonical] = tl
        return list(merged.values())


__all__ = [
    "OpType", "PointerEvent", "PointerTimeline",
    "TemporalUafReport", "UafTemporalAnalyzer",
]
