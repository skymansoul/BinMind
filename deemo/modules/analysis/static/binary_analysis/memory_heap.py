from __future__ import annotations

class HeapAnalyzer:
    """堆分配器状态分析"""
    def __init__(self): pass
    def analyze(self, data: bytes) -> dict:
        return {"allocator": "unknown", "chunks": []}
