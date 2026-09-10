"""
UAF 误报过滤 Phase 1: 别名感知生命周期 — 委托到 uaf_fp_cascade.py.

Union-Find 别名集 + 区间分析, 判定 free→use 路径是否在同一别名集内可达.
实际逻辑在 uaf_fp_cascade.phase1_alias_lifetime, 本模块重导出保持路径有效.
"""

from analysis.uaf_fp_cascade import phase1_alias_lifetime

__all__ = ['phase1_alias_lifetime']
