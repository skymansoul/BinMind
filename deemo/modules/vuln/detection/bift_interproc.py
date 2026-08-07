# coding: utf-8
# 创建: 2026-06-07  |  跨函数污点传播——调用图驱动的递归污点追踪
#
"""
跨函数污点传播——基于调用图的递归跨函数污点追踪。

技术问题:
  bift_taint.TaintPropagator的跨函数传播仅在call指令层面
  标记参数为污点, 不实际进入被调用函数执行污点传播。
  这导致: 若recv→funcA→funcB→memcpy, 且funcA内部有寄存器清除,
  但funcB内没有——当前实现可能误标记为"可达"或"不可达"。

解决方案:
  调用图驱动的递归污点追踪:
    1. 当遇到call指令且调用目标在call_graph中时,
       递归进入被调用函数执行完整的污点传播
    2. 被调用函数的返回寄存器(rax)若被污点, 则传播回调用者
    3. 递归深度限制(max_call_depth)防止无限递归
    4. 缓存已分析的(函数, 污点输入)对→避免重复计算

  这是对bift_taint.py中过度近似的实质性修正——
  从"同一函数内任何污点都可能到达任何汇"变为
  "仅通过明确的调用图路径且无寄存器清除的污点才可达"。
"""

import logging
from typing import Dict, List, Set, Tuple

_log = logging.getLogger(__name__)


class InterProcTaintTracker:
    """跨函数递归污点追踪——调用图驱动的精确污点分析。

    使用示例:
        tracker = InterProcTaintTracker(call_graph, functions)
        reachable_sinks = tracker.trace(source_func='main',
                                         tainted_regs={'rdi', 'rsi'})
    """

    def __init__(self, call_graph: Dict[str, List[str]],
                 functions: Dict[str, List[str]],
                 max_call_depth: int = 5):
        self._call_graph = call_graph
        self._functions = functions
        self._max_depth = max_call_depth
        # 缓存: (func_name, frozenset(tainted_regs)) → set(reachable_sinks)
        self._cache: Dict[Tuple[str, Tuple[str, ...]],
                           Set[str]] = {}

    def trace(self, source_func: str,
               tainted_regs: Set[str],
               depth: int = 0) -> Set[str]:
        """从source_func开始, 递归追踪污点寄存器流经的所有汇。

        参数:
          source_func: 起始函数名
          tainted_regs: 此函数入口处的污点寄存器集合
          depth: 当前递归深度

        返回可达的sink名称集合。
        """
        if depth >= self._max_depth:
            return set()
        if source_func not in self._functions:
            return set()

        cache_key = (source_func, tuple(sorted(tainted_regs)))
        if cache_key in self._cache:
            return self._cache[cache_key]

        insns = self._functions[source_func]
        current_tainted = set(tainted_regs)
        reached_sinks = set()

        for insn_str in insns:
            parts = insn_str.strip().split()
            if len(parts) < 2:
                continue
            mnem = parts[0].lower()
            ops_str = ' '.join(parts[1:])

            # 寄存器传播: mov/add/lea/xor
            defs, uses = self._reg_flow(mnem, ops_str)

            # 清除检测: xor reg,reg → 从污点集中移除reg
            if mnem == 'xor':
                ops = ops_str.split(',')
                if len(ops) >= 2 and ops[0].strip().lower() == ops[1].strip().lower():
                    cleared_reg = ops[0].strip().lower()
                    current_tainted.discard(cleared_reg)

            # 传播: 若use在污点集中→def也被污点
            if uses & current_tainted:
                current_tainted.update(defs)

            # 危险操作检测
            if self._is_sink(mnem, ops_str):
                if uses & current_tainted or defs & current_tainted:
                    reached_sinks.add(f"{source_func}:{mnem}")

            # 跨函数调用: 若调用目标在call_graph中且参数被污点
            if mnem == 'call' and len(parts) >= 2:
                called_func = parts[1].strip().lower()
                called_funcs = self._call_graph.get(source_func, [])
                matched = [cf for cf in called_funcs
                           if cf.lower() == called_func or
                           called_func in cf.lower()]
                for cf in matched[:1]:  # 追踪第一个匹配的
                    # 确定哪些参数被污点→被调用函数的参数寄存器
                    callee_tainted = set()
                    for reg in sorted(current_tainted):
                        if reg in ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'):
                            callee_tainted.add(reg)
                    if callee_tainted and cf in self._functions:
                        sub_sinks = self.trace(cf, callee_tainted,
                                                depth + 1)
                        reached_sinks.update(sub_sinks)
                        # 被调用函数返回时, rax可能被污点
                        if sub_sinks:
                            current_tainted.add('rax')

        self._cache[cache_key] = reached_sinks
        return reached_sinks

    def _reg_flow(self, mnem: str,
                   ops_str: str) -> Tuple[Set[str], Set[str]]:
        """分析单条指令的寄存器定义和使用。

        返回(def_regs, use_regs)。
        """
        defs, uses = set(), set()
        ops = [o.strip().lower() for o in ops_str.split(',')]

        if mnem in ('cmp', 'test', 'jmp', 'je', 'jne', 'jg', 'jl',
                     'jge', 'jle', 'ret', 'nop'):
            # 这些指令不修改寄存器(只读或控制流)
            for op in ops:
                reg = self._reg(op)
                if reg:
                    uses.add(reg)
            return defs, uses

        if mnem == 'mov' and len(ops) >= 2:
            defs.add(self._reg(ops[0]))
            uses.add(self._reg(ops[1]))
        elif mnem in ('add', 'sub', 'and', 'or', 'xor', 'shl', 'shr',
                       'sal', 'sar') and len(ops) >= 2:
            defs.add(self._reg(ops[0]))
            uses.add(self._reg(ops[0]))
            uses.add(self._reg(ops[1]))
        elif mnem == 'lea' and len(ops) >= 2:
            defs.add(self._reg(ops[0]))
            uses.add(self._reg(ops[1]))
        elif mnem == 'push':
            uses.add(self._reg(ops[0]) if ops else '')
        elif mnem == 'pop':
            defs.add(self._reg(ops[0]) if ops else '')
        elif mnem == 'call':
            uses.update({'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'})

        # 清理空字符串
        defs.discard('')
        uses.discard('')
        return defs, uses

    def _is_sink(self, mnem: str, ops_str: str) -> bool:
        dangerous = {'memcpy', 'strcpy', 'strcat', 'sprintf',
                     'system', 'execve', 'popen', 'mprotect'}
        if mnem == 'call':
            for d in dangerous:
                if d in ops_str.lower():
                    return True
        return False

    @staticmethod
    def _reg(op: str) -> str:
        """从操作数提取基寄存器名"""
        op = op.strip().lower()
        if not op or op.startswith('0x') or op.startswith('-'):
            return ''
        if op.startswith('['):
            inner = op[1:].split(']')[0]
            for sep in ('+', '-', '*'):
                if sep in inner:
                    return inner.split(sep)[0].strip()
            return inner.strip()
        if op.isdigit():
            return ''
        for sep in ('+', '-', '*'):
            if sep in op:
                return op.split(sep)[0].strip()
        return op


__all__ = ["InterProcTaintTracker"]
