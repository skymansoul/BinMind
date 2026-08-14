# heap_fp_filter.py - 基于边界检查的堆溢出误报过滤器。
from typing import Dict
from core.heap_bounds_checker import HeapBoundsChecker

class HeapFPFilter:
    def __init__(self):
        self.checker = HeapBoundsChecker()
    def filter(self, pseudocode: str) -> Dict:
        checks = self.checker.check(pseudocode)
        # 按 (pointer_var, write_size_expr) 去重 — 阶段2可能对同一写入产生更高置信度的条目
        seen = {}
        for c in checks:
            key = (c.pointer_var, c.write_size_expr)
            if key not in seen:
                seen[key] = c
            elif c.is_overflow and not seen[key].is_overflow:
                seen[key] = c  # 优先保留阶段2启发式给出的溢出条目
        deduped = list(seen.values())
        overflows = [c for c in deduped if c.is_overflow]
        safe = [c for c in deduped if not c.is_overflow and c.alloc_size is not None]
        total = max(len(deduped), 1)
        return {
            "total_heap_writes": len(deduped),
            "true_overflows": len(overflows),
            "filtered_false_positives": len(safe),
            "fp_reduction_rate": round(len(safe)/total, 3),
            "overflows": [{"var":c.pointer_var, "alloc":c.alloc_size,
                "write_size":c.write_size_expr} for c in overflows],
            "filtered": [{"var":c.pointer_var, "alloc":c.alloc_size,
                "reason":"write_size <= alloc_size"} for c in safe],
        }
