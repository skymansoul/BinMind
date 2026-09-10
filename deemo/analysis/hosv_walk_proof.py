"""
指针游走写安全证明 — 委托到 hosv_walk_write.py.

从指针游走写入模式中提取循环上界与增长系数, 做可证明安全的过滤.
实际逻辑在 hosv_walk_write.py, 本模块重导出核心检测函数保持路径有效.
"""

from analysis.hosv_walk_write import (
    collect_walk_writes, _estimate_iter_bound,
)

__all__ = ['collect_walk_writes', '_estimate_iter_bound']
