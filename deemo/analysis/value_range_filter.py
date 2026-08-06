# [DEPRECATED] — 功能已迁移至 modules/info/analysis/value_range_filter.py 或 src/value_range_filter.py
# 若确认无外部引用, 可安全删除
"""值范围约束过滤 — 从 core/value_range.py 重新导出。"""
from core.value_range import (
    analyze_heap_bounds, extract_alloc_sites, extract_heap_writes,
    check_bounds, Interval, AllocSite, HeapWrite, BoundsViolation,
)
