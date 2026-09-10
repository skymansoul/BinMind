"""
UAF 对象代际调用传播 — 委托到 modules/vuln/src/uaf/og/gen_flow.py.

跨函数调用时的代际状态传播: 实参寄存器代际快照 → 被调用函数形参绑定.
实际逻辑在 gen_flow.py 的 GenFlow + call 事件处理中, 本模块重导出保持路径有效.
"""

from modules.vuln.src.uaf.og.gen_flow import (
    GenEvent, GenFlowTracker,
)

__all__ = ['GenEvent', 'GenFlowTracker']
