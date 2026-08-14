# 崩溃原语指纹入口 — 原实现已按职责拆分到 types/analyzers/api 子模块,
# 此文件仅做 re-export 以保持 API 兼容。

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
