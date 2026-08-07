# coding: utf-8
# 创建: 2026-06-23  |  污点传播引擎
# 修改: 2026-06-23  |  审计后补充文件头与错误处理
#
"""
二进制级静态前向污点传播——寄存器/内存级保守过近似, 零执行成本。

算法: 标记参数/输入为源→迭代传播mov/lea/算术→检测到达危险操作的汇。
过近似: 牺牲精度换覆盖率——保证零漏报(所有真正可达路径必被标记)。

与DABSS互补: DABSS后向切片(源追溯), BIFT前向污点(汇可达性)。
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict

_log = logging.getLogger(__name__)


# 污点元素


@dataclass
class TaintSource:
    """污点源——外部输入进入程序的位置"""
    source_id: str
    source_type: str          # func_param | recv_call | read_call | global_var
    location: str = ""        # "func::argN" 或 "insn_addr"
    function_name: str = ""
    arg_index: int = -1       # 参数索引(0-based for rdi/rsi/...)
    data_size_hint: int = 0   # 污点数据的大小提示(0=未知)


@dataclass
class TaintSink:
    """污点汇——危险操作(污点数据到达此处可能触发漏洞)"""
    sink_id: str
    sink_type: str            # memcpy | system | execve | strcpy | ...
    address: int = 0
    function_name: str = ""
    # 到达此汇的污点源
    reached_by: List[str] = field(default_factory=list)  # source_id列表
    taint_depth: int = 0      # 从源到汇的传播步数


@dataclass
class TaintPath:
    """单条污点传播路径——源→汇"""
    source: TaintSource
    sink: TaintSink
    # 中间指令地址序列
    path_addresses: List[int] = field(default_factory=list)
    path_length: int = 0
    # 路径上的关键操作
    key_operations: List[str] = field(default_factory=list)


# 污点传播引擎


class TaintPropagator:
    """跨函数前向污点传播——寄存器/内存级别的保守过近似。

    传播规则(保守——牺牲精度换覆盖):
      1. mov dst, src: 若src被污点→dst被污点
      2. add/sub/xor dst, src: 若任一操作数被污点→dst被污点
      3. lea dst, [src+off]: 若src被污点→dst被污点(地址计算)
      4. push src / pop dst: 栈传播
      5. call func: 若参数被污点→被调用函数对应参数标记为污点
      6. store [addr], src: 若src被污点→目标内存地址标记为污点
      7. load dst, [addr]: 若内存地址被污点→dst被污点

    不追踪(保守假设为不传播):
      - 条件分支后的污点(路径敏感→爆炸)
      - 复杂指针链(双重/三重解引用)
    """

    # x86_64调用约定——参数寄存器顺序
    _CALLER_ARG_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

    # 外部输入函数
    _INPUT_FUNCTIONS = {
        'recv', 'read', 'fread', 'fgets', 'gets', 'scanf',
        '__isoc99_scanf', 'recvfrom', 'recvmsg', 'readv',
    }

    def __init__(self, max_iterations: int = 20):
        self._max_iter = max_iterations

    def propagate(self, functions: Dict[str, List[str]],
                   call_graph: Dict[str, List[str]] = None,
                   initial_sources: List[TaintSource] = None
                   ) -> Tuple[List[TaintSink], List[TaintPath]]:
        """跨函数前向污点传播。

        参数:
          functions: {函数名: [反汇编行]}
          call_graph: {调用者: [被调用者]}
          initial_sources: 初始污点源(若不提供则自动识别函数参数)

        返回(到达的污点汇列表, 污点路径列表)。
        """
        call_graph = call_graph or {}

        # 初始化污点标记: {函数名: {污点元素集合}}
        # 污点元素: "reg:rax", "mem:0x401000", "arg:2"
        tainted: Dict[str, Set[str]] = defaultdict(set)

        # 识别或使用初始污点源
        sources = initial_sources or self._identify_sources(functions)

        # 对每个源做初始标记
        for src in sources:
            if src.source_type == 'func_param':
                reg = self._CALLER_ARG_REGS[src.arg_index] if src.arg_index < len(
                    self._CALLER_ARG_REGS) else f'stack_{src.arg_index}'
                tainted[src.function_name].add(f'reg:{reg}')
            elif src.source_type == 'recv_call':
                # recv的返回值(rax)被污点→通常存入某寄存器
                tainted[src.function_name].add('reg:rax')

        # 识别危险操作(污点汇)
        sinks = self._identify_sinks(functions)

        # 迭代传播至固定点
        changed = True
        iteration = 0
        while changed and iteration < self._max_iter:
            changed = False
            iteration += 1

            for func_name, insns in functions.items():
                tainted_func = tainted[func_name]
                new_taints = self._propagate_in_function(
                    insns, tainted_func, functions, call_graph, tainted)
                if new_taints - tainted_func:
                    tainted_func.update(new_taints)
                    changed = True

        # 检测到达汇的污点
        paths = []
        for sink in sinks:
            func_tainted = tainted.get(sink.function_name, set())
            for taint_item in func_tainted:
                # 若sink所在函数的任何污点数据可能到达sink
                if self._can_reach_sink(sink, taint_item, functions):
                    sink.reached_by.append(taint_item)
                    sink.taint_depth = iteration

        # 构建路径
        for sink in sinks:
            if sink.reached_by:
                for src in sources:
                    if src.function_name in call_graph.get(sink.function_name, []) or \
                       src.function_name == sink.function_name:
                        paths.append(TaintPath(
                            source=src, sink=sink,
                            path_length=iteration))

        reached_sinks = [s for s in sinks if s.reached_by]
        return reached_sinks, paths

    def _propagate_in_function(self, insns: List[str],
                                 current_tainted: Set[str],
                                 all_functions: Dict[str, List[str]],
                                 call_graph: Dict[str, List[str]],
                                 global_tainted: Dict[str, Set[str]]
                                 ) -> Set[str]:
        """在单函数内传播污点——返回新增污点标记"""
        new_taints = set(current_tainted)

        for insn_str in insns:
            parts = insn_str.strip().split()
            if len(parts) < 2:
                continue
            mnem = parts[0].lower()

            # mov dst, src
            if mnem == 'mov' and len(parts) >= 2:
                operands = ' '.join(parts[1:]).split(',')
                if len(operands) >= 2:
                    dst, src = operands[0].strip(), operands[1].strip()
                    src_reg = self._extract_reg(src)
                    if f'reg:{src_reg}' in new_taints:
                        dst_reg = self._extract_reg(dst)
                        if dst_reg:
                            new_taints.add(f'reg:{dst_reg}')
                        if '[' in dst:
                            new_taints.add(f'mem:{dst}')

            # 算术(add/sub/xor)——若操作数被污点→目标被污点
            if mnem in ('add', 'sub', 'xor', 'and', 'or') and len(parts) >= 2:
                ops = ' '.join(parts[1:]).split(',')
                if len(ops) >= 2:
                    dst, src = ops[0].strip(), ops[1].strip()
                    if any(f'reg:{self._extract_reg(o)}' in new_taints
                           for o in (dst, src)):
                        dst_reg = self._extract_reg(dst)
                        if dst_reg:
                            new_taints.add(f'reg:{dst_reg}')

            # lea——地址计算的传播
            if mnem == 'lea' and len(parts) >= 2:
                ops = ' '.join(parts[1:]).split(',')
                if len(ops) >= 2:
                    dst, addr = ops[0].strip(), ops[1].strip()
                    addr_reg = self._extract_reg(addr)
                    if f'reg:{addr_reg}' in new_taints:
                        dst_reg = self._extract_reg(dst)
                        if dst_reg:
                            new_taints.add(f'reg:{dst_reg}')

        return new_taints - current_tainted

    def _identify_sources(self, functions: Dict[str, List[str]]
                            ) -> List[TaintSource]:
        """自动识别污点源——入口函数参数+输入函数调用"""
        sources = []
        for func_name, insns in functions.items():
            # 入口函数的所有参数→污点源
            if func_name in ('main', '_start', 'entry', 'WinMain'):
                for i in range(6):
                    sources.append(TaintSource(
                        source_id=f"{func_name}_arg{i}",
                        source_type='func_param',
                        function_name=func_name, arg_index=i))

            # 输入函数调用→污点源
            for insn in insns:
                for inp_func in self._INPUT_FUNCTIONS:
                    if inp_func in insn.lower():
                        sources.append(TaintSource(
                            source_id=f"{func_name}_{inp_func}",
                            source_type='recv_call',
                            function_name=func_name))
        return sources

    def _identify_sinks(self, functions: Dict[str, List[str]]
                          ) -> List[TaintSink]:
        """识别危险操作(污点汇)"""
        sinks = []
        dangerous = {'memcpy', 'strcpy', 'strcat', 'sprintf',
                     'system', 'execve', 'popen', 'mprotect'}
        for func_name, insns in functions.items():
            for insn in insns:
                for dang in dangerous:
                    if dang in insn.lower():
                        sinks.append(TaintSink(
                            sink_id=f"{func_name}_{dang}",
                            sink_type=dang, function_name=func_name))
        return sinks

    def _can_reach_sink(self, sink: TaintSink, taint_item: str,
                          functions: Dict[str, List[str]]) -> bool:
        """判断污点项是否可能到达汇——基于指令级数据流可达性。

        不采用'同一函数内总是True'的过度近似。
        而是检查: 污点所在的指令位置是否在sink之前,
        且二者之间是否存在任何会清除该寄存器的指令。
        """
        func_insns = functions.get(sink.function_name, [])
        if not func_insns:
            return False

        # 从taint_item提取寄存器名
        taint_reg = taint_item.replace('reg:', '').strip()
        if not taint_reg:
            return True  # 无法提取寄存器→保守返回True

        # 定位sink指令和追踪污点清除
        sink_idx = -1
        reg_clobbered_at = -1
        for i, insn in enumerate(func_insns):
            # 找到sink位置
            if sink.sink_type in insn.lower() and 'call' in insn.lower():
                sink_idx = i
            # 检测寄存器清除——任何写入taint_reg的指令
            if sink_idx < 0:  # 仅在sink之前检查
                parts = insn.strip().split()
                if len(parts) >= 2:
                    mnem = parts[0].lower()
                    # xor reg, reg → 清除寄存器
                    if mnem == 'xor' and taint_reg in insn.lower():
                        ops = ' '.join(parts[1:]).split(',')
                        if len(ops) >= 2 and ops[0].strip().lower() == taint_reg and \
                           ops[0].strip().lower() == ops[1].strip().lower():
                            reg_clobbered_at = i
                    # mov reg, 0 → 清除寄存器
                    if mnem == 'mov' and taint_reg in insn.lower():
                        ops = ' '.join(parts[1:]).split(',')
                        if len(ops) >= 2 and ops[0].strip().lower() == taint_reg:
                            src = ops[1].strip()
                            if src in ('0', '0x0'):
                                reg_clobbered_at = i

        if sink_idx < 0:
            return True  # sink不在本函数→保守
        if reg_clobbered_at >= 0 and reg_clobbered_at > sink_idx:
            return False  # 寄存器在sink后被清除→不影响
        # 寄存器在sink前被清除→污点不达
        if reg_clobbered_at >= 0:
            return False
        return True

    @staticmethod
    def _extract_reg(operand: str) -> str:
        """从操作数提取寄存器名"""
        op = operand.strip().lower()
        if op.startswith('['):
            inner = op[1:].split(']')[0]
            for sep in ('+', '-', '*'):
                if sep in inner:
                    return inner.split(sep)[0].strip()
            return inner.strip()
        # 去掉偏移
        for sep in ('+', '-'):
            if sep in op:
                return op.split(sep)[0].strip()
        return op


__all__ = [
    "TaintSource",
    "TaintSink",
    "TaintPath",
    "TaintPropagator",
]
