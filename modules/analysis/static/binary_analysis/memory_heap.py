from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class Allocation:
    """堆分配记录：地址、大小与分配类型。"""
    address: int
    size: int
    alloc_type: str = "malloc"
    freed: bool = False
    free_site: int = 0


class HeapAnalyzer:
    # 堆分配生命周期分析
    # 按地址登记分配，跟踪释放状态，供 UAF 与 double-free 启发式判定使用

    def __init__(self):
        self._allocations: Dict[int, Allocation] = {}
        self._events: List[Tuple[str, int, int]] = []  # (action, addr, line)

    def track_alloc(self, address: int, size: int, alloc_type: str = "malloc") -> None:
        """登记一次分配。同地址重复分配视为覆盖旧记录。"""
        self._allocations[address] = Allocation(address, size, alloc_type)
        self._events.append(("alloc", address, size))

    def track_free(self, address: int, line: int = 0) -> None:
        """登记一次释放，将对应分配标记为 freed。"""
        alloc = self._allocations.get(address)
        if alloc is not None:
            alloc.freed = True
            alloc.free_site = line
            self._events.append(("free", address, line))

    def get_allocation(self, address: int) -> Optional[Allocation]:
        return self._allocations.get(address)

    def allocations(self) -> List[Allocation]:
        return list(self._allocations.values())

    def freed_allocations(self) -> List[Allocation]:
        return [a for a in self._allocations.values() if a.freed]

    def analyze(self, data: bytes) -> dict:
        """保持旧接口兼容：返回分配统计。"""
        return {
            "allocator": "unknown",
            "chunks": [{"address": a.address, "size": a.size} for a in self._allocations.values()],
        }


def detect_uaf(allocations: List[Allocation],
               use_sites: Optional[Dict[int, List[int]]] = None) -> List[dict]:
    """启发式 UAF 检测：分配已被释放且后续存在使用点。"""
    findings: List[dict] = []
    use_sites = use_sites or {}
    for alloc in allocations:
        if not alloc.freed:
            continue
        sites = use_sites.get(alloc.address, [])
        if sites:
            findings.append({
                "type": "use_after_free",
                "address": alloc.address,
                "size": alloc.size,
                "free_site": alloc.free_site,
                "use_sites": sites,
                "severity": "Critical",
            })
    return findings


def detect_double_free(allocations: List[Allocation],
                       free_sites: Optional[Dict[int, List[int]]] = None) -> List[dict]:
    """启发式 double-free 检测：同一分配被释放两次及以上。"""
    findings: List[dict] = []
    free_sites = free_sites or {}
    for alloc in allocations:
        sites = free_sites.get(alloc.address, [])
        if len(sites) >= 2:
            findings.append({
                "type": "double_free",
                "address": alloc.address,
                "size": alloc.size,
                "free_sites": sites,
                "severity": "Critical",
            })
    return findings
