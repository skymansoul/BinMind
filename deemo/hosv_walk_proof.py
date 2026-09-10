"""
指针游走写安全证明 — 根目录入口, 委托到 analysis/hosv_walk_write.py.

文档中引用此路径, 实际逻辑在 analysis/hosv_walk_write.py.
本模块重导出核心检测函数保持路径有效.
"""

from analysis.hosv_walk_write import (
    collect_walk_writes, _estimate_iter_bound,
)

__all__ = ['collect_walk_writes', '_estimate_iter_bound']
