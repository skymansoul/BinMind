"""
UAF 对象代际调用传播 (src/uaf/og 路径) — 委托到 modules/vuln/src/uaf/og/gen_flow.py.

此路径在文档创新点 #4 中引用, 实际代码在 modules/vuln/src/uaf/og/gen_flow.py.
本模块重导出核心 API 保持路径有效.
"""

from modules.vuln.src.uaf.og.gen_flow import (
    GenEvent, GenFlowTracker,
)

__all__ = ['GenEvent', 'GenFlowTracker']
