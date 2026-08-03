"""
跨编译单元常量折叠传播符号表。

参考 CRYPTBARA 依赖上下文 + 跨文件追踪:
  硬编码密钥/IV/盐在多个编译单元中重复出现 → 跨单元传播信号，
  单文件扫描无法检测。本表记录常量指纹及其来源，供跨文件查询。

边界:
  - 键=常量字节值(指纹)，值=来源符号列表。
  - LRU 上限防止无界增长；读写加锁，容忍并发。
  - 同源+近似偏移(<64B)视为重复，仅递增计数。
"""

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass
class ConstantSymbol:
    """单次常量出现记录."""
    value: bytes
    category: str          # key / iv / salt
    origin_source: str     # 文件路径或 "memory"
    origin_offset: int
    first_seen: float
    times_seen: int = 1


class ModuleSymbolTable:
    """模块级符号表 — 常量指纹 → 出现记录，跨扫描实例共享."""

    MAX_ENTRIES = 1024          # 指纹上限，超出逐出最旧条目
    OFFSET_MERGE_BAND = 64      # 同源同值偏移差 ≤ 此值 → 合并

    def __init__(self) -> None:
        self._entries: "OrderedDict[bytes, List[ConstantSymbol]]" = OrderedDict()
        self._lock = threading.Lock()
        self._reads = 0
        self._hit_reads = 0

    def record(self, value: bytes, category: str, source: str,
               offset: int) -> List[ConstantSymbol]:
        """记录常量出现，返回该值的全部历史条目。含新条目，调用方可立即判断跨单元。"""
        if not value:
            return []
        with self._lock:
            now = time.time()
            if value in self._entries:
                lst = self._entries[value]
                merged = False
                for sym in lst:
                    if (sym.origin_source == source and
                            abs(sym.origin_offset - offset) < self.OFFSET_MERGE_BAND):
                        sym.times_seen += 1
                        merged = True
                        break
                if not merged:
                    lst.append(ConstantSymbol(value, category, source, offset, now))
                self._entries.move_to_end(value)
            else:
                self._entries[value] = [ConstantSymbol(value, category, source, offset, now)]
                if len(self._entries) > self.MAX_ENTRIES:
                    self._entries.popitem(last=False)
            return list(self._entries[value])

    def lookup(self, value: bytes) -> List[ConstantSymbol]:
        """查询常量的全部历史出现."""
        if not value:
            return []
        with self._lock:
            self._reads += 1
            if value in self._entries:
                self._hit_reads += 1
                return list(self._entries[value])
            return []

    def cross_unit(self, value: bytes, current_source: str) -> Tuple[bool, List[ConstantSymbol]]:
        """检查常量是否在其它编译单元中出现。返回 (跨单元?, 其它来源列表)。"""
        others = [s for s in self.lookup(value) if s.origin_source != current_source]
        return (len(others) > 0, others)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def stats(self) -> dict:
        with self._lock:
            return {
                'entries': len(self._entries),
                'reads': self._reads,
                'hit_reads': self._hit_reads,
                'hit_rate': round(self._hit_reads / self._reads, 3) if self._reads else 0.0,
            }
