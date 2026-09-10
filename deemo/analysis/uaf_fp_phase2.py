"""
UAF 误报过滤 Phase 2: 路径敏感支配 — 委托到 uaf_fp_cascade.py.

简化 CFG + BFS 可达性, 判定 free 点是否支配 use 点.
实际逻辑在 uaf_fp_cascade.phase2_path_dominance, 本模块重导出保持路径有效.
"""

from analysis.uaf_fp_cascade import phase2_path_dominance

__all__ = ['phase2_path_dominance']
