# 崩溃原语指纹入口 — 从crash_primitive_fingerprint_types/analyzers/api拆分.
# 原实现已按职责分散到子模块, 此文件仅做re-export以保持API兼容.
# 创建: 2026-05-10 (拆分)

from .crash_primitive_fingerprint_types import (
    RegisterControl, PrimitiveType,
    RegisterAnalysis, HeapOperationSequence, CrashFingerprint,
)
from .crash_primitive_fingerprint_analyzers import (
    _analyze_register, _extract_heap_ops_from_text,
    _compute_exploitability_scores, _recommend_strategy,
)
from .crash_primitive_fingerprint_api import fingerprint_crash, infer_heap_layout

__all__ = [
    "RegisterControl", "PrimitiveType",
    "RegisterAnalysis", "HeapOperationSequence", "CrashFingerprint",
    "fingerprint_crash", "infer_heap_layout",
    "_analyze_register", "_extract_heap_ops_from_text",
    "_compute_exploitability_scores", "_recommend_strategy",
]
