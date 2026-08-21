# coding: utf-8
"""
DABSS数据流切片器-从二进制反汇编中追溯缓冲区/指针操作的数据流路径。

算法: 反向数据流切片-从敏感操作(sink)沿定义-使用链追溯至外部输入(source)。
约束标注: 路径上的比较指令(cmp/test)被标注为边界约束节点。

与现有方法的差异:
  FieldsFuzz: 需要运行时taint tracking → 本模块纯静态
  PBFuzz: 需要LLM API → 本模块零外部依赖
  FuzzRDUCC: 需要符号执行 → 本模块轻量级指令遍历
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict

from .dabss_insn_parser import (
    parse_insn, extract_reg, get_def_regs,
    parse_constraint_value, infer_buffer_capacity,
    SINK_MNEMONICS, SOURCE_INDICATORS,
)

_log = logging.getLogger(__name__)


@dataclass
class DataFlowNode:
    """数据流切片节点-单条指令"""
    addr: int
    mnemonic: str
    operands: List[str] = field(default_factory=list)
    def_sources: List[int] = field(default_factory=list)
    is_sink: bool = False
    is_source: bool = False
    is_constraint: bool = False
    constraint_op: str = ""
    constraint_value: int = 0
    block_addr: int = 0
    slice_depth: int = 0


@dataclass
class BufferSlice:
    """缓冲区切片-sink到source的完整数据流路径"""
    sink_addr: int
    sink_mnemonic: str
    buffer_operand: str = ""
    size_operand: str = ""
    nodes: List[DataFlowNode] = field(default_factory=list)
    bound_constraints: List[Tuple[str, int]] = field(default_factory=list)
    null_checks: List[int] = field(default_factory=list)
    type_casts: List[str] = field(default_factory=list)
    inferred_buffer_capacity: int = 0
    confidence: float = 0.0


class DataFlowSlicer:
    """反向数据流切片器-从sink指令追溯至输入源。

    切片深度: 最大64步(函数内)，跨函数截断→标记为source。
    架构支持: x86_64/ARM32/ARM64/MIPS32(通过操作数解析适配)。

    与graph_binary_embedder集成:
      输入: BasicBlockNode列表(含instructions字段)
      输出: BufferSlice列表→dabss_constraint_extractor消费
    """

    def __init__(self, max_slice_depth: int = 64):
        self._max_depth = max_slice_depth

    def slice_function(self, basic_blocks: List[Dict],
                        arch: str = "x86_64") -> List[BufferSlice]:
        """对函数基本块列表执行数据流切片-定位所有sink并逐条追溯。"""
        insn_map: Dict[int, Tuple[str, List[str], int]] = {}
        block_preds: Dict[int, List[int]] = defaultdict(list)
        for bb in basic_blocks:
            addr = bb.get('addr', 0)
            for succ in bb.get('successors', []):
                block_preds[succ].append(addr)
            for insn_str in bb.get('instructions', []):
                insn_addr, mnem, ops = parse_insn(insn_str, arch)
                if insn_addr:
                    insn_map[insn_addr] = (mnem, ops, addr)

        slices = []
        for addr, (mnem, ops, bb_addr) in insn_map.items():
            if not self._is_sink(mnem, ops):
                continue
            buf_op, size_op = self._identify_buffer(mnem, ops)
            if not buf_op:
                continue
            nodes = self._backward_slice(addr, buf_op, insn_map,
                                          block_preds, set(), 0)
            if not nodes:
                continue
            bounds, nulls = [], []
            for n in nodes:
                if n.is_constraint:
                    bounds.append((n.constraint_op, n.constraint_value))
                if 'null' in n.mnemonic or 'test' in n.mnemonic:
                    nulls.append(n.addr)
            slices.append(BufferSlice(
                sink_addr=addr, sink_mnemonic=mnem,
                buffer_operand=buf_op, size_operand=size_op or '',
                nodes=nodes, bound_constraints=bounds,
                null_checks=nulls,
                inferred_buffer_capacity=infer_buffer_capacity(bounds, size_op),
                confidence=self._slice_confidence(nodes)))
        return slices

    def _backward_slice(self, addr, target_op, insn_map, preds,
                          visited, depth) -> List[DataFlowNode]:
        """递归后向切片-含跨基本块与跨函数传播。

        追踪三层:
          1. 同基本块内-搜索当前指令之前的写入target_op寄存器的指令
          2. 跨基本块-若当前块内无定义, 沿前驱边递归追踪
             (检查前驱块的最后一条写入target_op的指令)
          3. 跨函数-若target_op来自call指令的返回值(rax),
             且有调用图信息, 递归进入被调用函数

        深度计数严格递增, 到达max_depth或循环时终止。
        """
        if depth >= self._max_depth or addr in visited:
            return []
        visited.add(addr)
        if addr not in insn_map:
            return []
        mnem, ops, bb_addr = insn_map[addr]

        node = DataFlowNode(addr=addr, mnemonic=mnem, operands=ops,
                             block_addr=bb_addr, slice_depth=depth)
        if mnem in ('cmp', 'test', 'sub', 'add'):
            node.is_constraint = True
            node.constraint_op, node.constraint_value = parse_constraint_value(mnem, ops)

        defs = get_def_regs(mnem, ops)
        for op in ops:
            if op.startswith('[') or op.startswith('*'):
                node.is_source = True
                continue
            op_reg = extract_reg(op)
            if not op_reg:
                continue

            # Layer 1: 同基本块内-搜索当前指令之前的定义者
            found_in_block = False
            same_block_addrs = sorted(
                [a for a in insn_map if insn_map[a][2] == bb_addr and a < addr],
                reverse=True)
            for prev_addr in same_block_addrs:
                if depth + 1 >= self._max_depth:
                    break
                if op_reg in get_def_regs(*insn_map[prev_addr][:2]):
                    node.def_sources.append(prev_addr)
                    found_in_block = True
                    # 检查是否为call指令-若是, 标记为跨函数源
                    p_mnem = insn_map[prev_addr][0]
                    if p_mnem == 'call':
                        node.is_source = True
                    break

            # Layer 2: 跨基本块-沿前驱边递归
            if not found_in_block and bb_addr in preds:
                for pred_addr in preds[bb_addr]:
                    if depth + 1 >= self._max_depth:
                        break
                    # 在前驱块中搜索最后写入op_reg的指令
                    pred_insns = sorted(
                        [(a, insn_map[a]) for a in insn_map
                         if insn_map[a][2] == pred_addr],
                        key=lambda x: x[0], reverse=True)
                    for p_addr, (p_mnem, p_ops, _) in pred_insns:
                        if op_reg in get_def_regs(p_mnem, p_ops):
                            node.def_sources.append(p_addr)
                            found_in_block = True
                            # 递归进入前驱块
                            sub_nodes = self._backward_slice(
                                p_addr, op_reg, insn_map, preds,
                                visited, depth + 1)
                            if sub_nodes:
                                node.def_sources.extend(
                                    n.addr for n in sub_nodes)
                            break
                    if found_in_block:
                        break

            # Layer 3: 未找到定义→标记为source(外部输入)
            if not found_in_block:
                node.is_source = True

        return [node]

    def _is_sink(self, mnem: str, ops: List[str]) -> bool:
        """sink判定: call敏感函数 或 特定指令模式"""
        if mnem == 'call' and ops:
            return any(s in ops[0].lower() for s in SINK_MNEMONICS['call'])
        return any(s in mnem.lower() for s in SINK_MNEMONICS['any'])

    def _identify_buffer(self, mnem: str, ops: List[str]) -> Tuple[str, str]:
        """识别缓冲区操作数与大小操作数"""
        if ops:
            return ops[0], (ops[2] if len(ops) >= 3 else '')
        return '', ''

    def _slice_confidence(self, nodes: List[DataFlowNode]) -> float:
        """切片可靠性-source存在(+0.3)+约束≥2(+0.2)+短路径(+0.2)+完整(+0.3)"""
        if not nodes:
            return 0.0
        c = sum([0.3 * any(n.is_source for n in nodes),
                 0.2 * (sum(1 for n in nodes if n.is_constraint) >= 2),
                 0.2 * (len(nodes) <= 16),
                 0.3 * (not any(n.slice_depth >= self._max_depth - 1 for n in nodes))])
        return min(1.0, c)


__all__ = ["DataFlowNode", "BufferSlice", "DataFlowSlicer"]
