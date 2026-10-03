"""
指针游走写安全证明 — 根目录入口, 委托到 analysis/heap_write_walk_wr.py.

文档中引用此路径, 实际逻辑在 analysis/heap_write_walk_wr.py.
本模块重导出核心检测函数保持路径有效.
"""

from analysis.heap_write_walk_wr import (
    collect_walk_writes, _estimate_iter_bound,
)

__all__ = ['collect_walk_writes', '_estimate_iter_bound']
