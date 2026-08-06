# [DEPRECATED] — 功能已迁移至 modules/info/analysis/uaf_deep_analyzer.py 或 src/uaf_deep_analyzer.py
# 若确认无外部引用, 可安全删除
"""UAF深度分析包装器 → core/uaf_analyzer.py"""
from core.uaf_analyzer import (
    detect_uaf_deep, detect_double_free_deep, comprehensive_uaf_check,
)
