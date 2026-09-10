"""
UAF 误报过滤 Phase 3: 逃逸分析 — 委托到 uaf_fp_cascade.py.

按存储位置分级: STACK/HEAP/GLOBAL/VTABLE, 判定对象是否可能跨函数逃逸.
实际逻辑在 uaf_fp_cascade.phase3_escape_analysis, 本模块重导出保持路径有效.
"""

from analysis.uaf_fp_cascade import phase3_escape_analysis

__all__ = ['phase3_escape_analysis']
