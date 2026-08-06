# [DEPRECATED] — 功能已迁移至 modules/info/analysis/__init__.py 或 src/__init__.py
# 若确认无外部引用, 可安全删除
"""分析增强模块 — 从 core/ 重新导出堆溢出误报削减的三大组件。"""
from core.value_range import (
    analyze_heap_bounds, extract_alloc_sites, extract_heap_writes,
    check_bounds, Interval, AllocSite, HeapWrite, BoundsViolation,
)
from core.vsa_lite import analyze_vsa, StrideInterval, HeapObj, MemWrite
from core.interval_filter import classify, apply_filter, filter_stats, Tier, FilterResult
from core.cfg_normalizer import extract_cfg_features, CFGFeatures
