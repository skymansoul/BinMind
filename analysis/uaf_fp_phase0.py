"""
UAF 误报过滤 Phase 0: 模式安全检测 — 委托到 uaf_fp_cascade.py.

O(n) 文本扫描, 识别 free 后置 NULL / free 后重新分配等可证明安全的模式.
实际逻辑在 uaf_fp_cascade.phase0_pattern_safety, 本模块重导出保持路径有效.
"""

from analysis.uaf_fp_cascade import phase0_pattern_safety

__all__ = ['phase0_pattern_safety']
