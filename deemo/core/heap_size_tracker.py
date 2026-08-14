# heap_size_tracker.py - 记录堆分配大小以减少误报, malloc(N) 时登记 {指针变量: 大小表达式}。
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

_ALLOC_FNS = r'(malloc|calloc|realloc|kmalloc|kzalloc|vmalloc|alloc_skb|grub_malloc|ntoh_malloc)'
_ALLOC_PAT = re.compile(r"(\w[\w\d_]*)\s*=\s*(?:" + _ALLOC_FNS + r")\s*\(([^)]+)\)")
_FREE_PAT = re.compile(r"(?:free|kfree)\s*\(([^)]+)\)")

@dataclass
class HeapAllocSite:
    pointer_var: str
    alloc_func: str
    size_expr: str
    line_no: int
    size_value: Optional[int] = None
    is_constant: bool = False

class HeapSizeTracker:
    def __init__(self):
        self._allocations: Dict[str, HeapAllocSite] = {}
        self._freed: set = set()
    def track(self, pseudocode: str) -> List[HeapAllocSite]:
        lines = pseudocode.splitlines()
        active = []
        for line_no, raw in enumerate(lines):
            line = raw.strip()
            alloc_m = _ALLOC_PAT.search(line)
            if alloc_m:
                var, func, size_str = alloc_m.group(1), alloc_m.group(2), alloc_m.group(3).strip()
                site = HeapAllocSite(pointer_var=var, alloc_func=func, size_expr=size_str, line_no=line_no)
                try:
                    site.size_value = int(size_str)
                    site.is_constant = True
                except ValueError:
                    pass
                self._allocations[var] = site
                active.append(site)
            free_m = _FREE_PAT.search(line)
            if free_m:
                freed_var = free_m.group(1).strip().split(",")[0].strip()
                self._freed.add(freed_var)
        return active
    def get_allocation(self, var_name: str) -> Optional[HeapAllocSite]:
        return self._allocations.get(var_name)
    def is_freed(self, var_name: str) -> bool:
        return var_name in self._freed