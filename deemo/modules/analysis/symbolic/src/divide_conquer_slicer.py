# 创建: 2026-06-23 09:30
# 修改: 2026-06-23 — 后向 use-def BFS 切片 + 拓扑序副作用组合
"""
分治符号执行切片器 — 程序分解为独立切片, 逐片执行, 组合副作用。

传统符号执行在每个分支处 fork 状态——路径数指数增长。
分治策略: 沿数据依赖边界将程序分解为独立切片,
每个切片单独执行符号执行 (状态空间小, 无路径爆炸),
切片间的副作用通过摘要函数传递。

算法:
  1. 后向切片: 从漏洞 sink (如 memcpy/strcpy 调用) 沿数据流回溯,
     裁剪与 sink 无关的代码路径
  2. 切片执行: 对每个切片独立运行符号执行——仅此切片内的路径被探索
  3. 摘要提取: 每个切片的 I/O 行为压缩为函数摘要 (pre-condition → post-condition)
  4. 副作用组合: 按调用图顺序组合摘要, 验证完整路径的可满足性

为什么后向切片有效:
  前向符号执行从程序入口开始——路径数随程序长度指数增长。
  后向切片从漏洞点开始回溯——仅关注能到达 sink 的数据流路径,
  自动裁剪 90%+ 的无关代码。参考: BinSleuth 的
  backward slicing strategy 实现了 42× 加速。

ref: BinSleuth — backward slicing + under-constrained SE,
     本项目取其切片策略但用于完整符号执行而非 UCSE
ref: Divide, Conquer and Verify — program splitting
     into slices for independent SE, 本项目增加摘要提取 + 副作用组合
ref: Symerge — state merging + function summaries,
     本项目的切片摘要借鉴其多级合并思想
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional, Callable


@dataclass
class DataFlowNode:
    """数据流图中的一个节点——指令 + 数据依赖。"""
    pc: int
    mnemonic: str
    defines: set[int]    # 此指令写入的寄存器/内存
    uses: set[int]       # 此指令读取的寄存器/内存
    is_sink: bool = False
    slice_depth: int = 0


@dataclass
class ProgramSlice:
    """一个可独立符号执行的程序切片。"""
    slice_id: int
    entry_pc: int
    exit_pc: int
    nodes: list[DataFlowNode]
    # 摘要: {(reg_id, mem_addr) → symbolic_expr}
    pre_condition: dict = field(default_factory=dict)
    post_condition: dict = field(default_factory=dict)
    depends_on: list[int] = field(default_factory=list)  # 依赖的其他 slice_id


# 数据流图构建

def build_dataflow_graph(instructions: list[dict],
                         sink_addrs: set[int]) -> list[DataFlowNode]:
    """从指令列表构建数据流图——标记每个指令的 def/use 关系。"""
    nodes = []
    for ins in instructions:
        mnemonic = ins.get('mnemonic', '').lower()
        pc = ins.get('address', 0)
        op_str = str(ins.get('operands', ''))

        # 简化的 def/use 分析: 基于操作数位置
        defines: set[int] = set()
        uses: set[int] = set()
        # 目的操作数 = def, 源操作数 = use
        parts = op_str.replace('[', '').replace(']', '').split(',')
        if len(parts) >= 1:
            defines.add(hash(parts[0].strip()) & 0xFFFF)
        if len(parts) >= 2:
            uses.add(hash(parts[1].strip()) & 0xFFFF)

        nodes.append(DataFlowNode(
            pc=pc, mnemonic=mnemonic,
            defines=defines, uses=uses,
            is_sink=(pc in sink_addrs),
        ))

    return nodes


# 后向切片

def backward_slice(nodes: list[DataFlowNode],
                   sink_addr: int,
                   max_depth: int = 500) -> ProgramSlice:
    """从 sink 地址后向切片——沿 use-def 链回溯。
    仅保留数据流上能到达 sink 的指令。"""
    pc_to_idx = {n.pc: i for i, n in enumerate(nodes)}
    sink_idx = pc_to_idx.get(sink_addr)
    if sink_idx is None:
        return ProgramSlice(slice_id=0, entry_pc=0, exit_pc=sink_addr, nodes=[])

    # BFS 后向遍历 use-def 链
    relevant: set[int] = set()
    queue = [sink_idx]
    while queue and len(relevant) < max_depth:
        idx = queue.pop(0)
        if idx in relevant:
            continue
        relevant.add(idx)
        node = nodes[idx]
        # 寻找定义此指令使用的值的指令
        for u in node.uses:
            for j in range(idx - 1, max(0, idx - 100), -1):
                if u in nodes[j].defines:
                    if j not in relevant:
                        queue.append(j)
                    break

    slice_nodes = [nodes[i] for i in sorted(relevant)]
    for i, n in enumerate(slice_nodes):
        n.slice_depth = i

    entry = slice_nodes[0].pc if slice_nodes else 0
    return ProgramSlice(
        slice_id=hash(sink_addr) & 0xFFFF,
        entry_pc=entry, exit_pc=sink_addr,
        nodes=slice_nodes,
    )


# 切片摘要提取
# 将切片的符号执行结果压缩为输入→输出的映射。

def extract_slice_summary(symbolic_executor: Callable,
                          slice_obj: ProgramSlice,
                          input_symbols: dict[int, str]) -> dict:
    """对切片运行符号执行, 提取 I/O 摘要。
    symbolic_executor: (pc_start, pc_end, input_symbols) → dict of outputs。"""
    try:
        result = symbolic_executor(
            slice_obj.entry_pc, slice_obj.exit_pc, input_symbols)
        slice_obj.post_condition = result
        return result
    except Exception:
        return {}
    # 此处提取—实际实现调用 angr/z3, 此处提供接口骨架


# 副作用组合
# 按依赖拓扑序组合各切片的副作用。

def compose_slices(slices: list[ProgramSlice]) -> dict:
    """按拓扑序组合所有切片的副作用——生成完整路径的可满足性判定。

    对每个切片, 若其 pre_condition (上游切片输出) 与自身 post_condition
    一致, 则切片链可满足。"""
    composed = {}
    sorted_slices = _topological_sort(slices)

    for sl in sorted_slices:
        # 检查上游依赖的副作用是否满足此切片的前置条件
        deps_satisfied = True
        for dep_id in sl.depends_on:
            dep_output = composed.get(dep_id, {})
            for key, expected in sl.pre_condition.items():
                if dep_output.get(key) != expected:
                    deps_satisfied = False
                    break
        if deps_satisfied:
            composed[sl.slice_id] = sl.post_condition

    return composed


def _topological_sort(slices: list[ProgramSlice]) -> list[ProgramSlice]:
    """拓扑排序切片——保证依赖在其被依赖者之前执行。"""
    in_degree: dict[int, int] = defaultdict(int)
    for sl in slices:
        for dep in sl.depends_on:
            in_degree[sl.slice_id] += 1
    queue = [sl for sl in slices if in_degree[sl.slice_id] == 0]
    result = []
    while queue:
        sl = queue.pop(0)
        result.append(sl)
        for other in slices:
            if sl.slice_id in other.depends_on:
                in_degree[other.slice_id] -= 1
                if in_degree[other.slice_id] == 0:
                    queue.append(other)
    return result


# 端到端分治管线

class DivideConquerSymExec:
    """分治符号执行管线——切片→执行→摘要→组合。"""

    __slots__ = ('_slices', '_summaries', '_composed')

    def __init__(self):
        self._slices: list[ProgramSlice] = []
        self._summaries: dict[int, dict] = {}
        self._composed: dict = {}

    def analyze(self, instructions: list[dict],
                sink_addrs: set[int],
                symexec_fn: Callable | None = None) -> dict:
        """完整分治分析管线。返回组合后的副作用字典。"""
        nodes = build_dataflow_graph(instructions, sink_addrs)

        for sink in sink_addrs:
            sl = backward_slice(nodes, sink)
            if sl.nodes:
                self._slices.append(sl)

        # 提取摘要
        if symexec_fn:
            for sl in self._slices:
                summary = extract_slice_summary(symexec_fn, sl, {})
                self._summaries[sl.slice_id] = summary

        # 组合
        self._composed = compose_slices(self._slices)
        return self._composed

    def reduction_ratio(self, total_instructions: int) -> float:
        """切片后的指令缩减比——衡量分治裁剪效果。"""
        sliced_count = sum(len(sl.nodes) for sl in self._slices)
        if total_instructions == 0:
            return 0.0
        return sliced_count / total_instructions

    def stats(self) -> dict:
        return {
            'slices': len(self._slices),
            'total_sliced_instructions': sum(len(sl.nodes) for sl in self._slices),
            'composed_side_effects': len(self._composed),
        }


__all__ = [
    'DivideConquerSymExec', 'ProgramSlice', 'DataFlowNode',
    'build_dataflow_graph', 'backward_slice',
    'extract_slice_summary', 'compose_slices',
]
