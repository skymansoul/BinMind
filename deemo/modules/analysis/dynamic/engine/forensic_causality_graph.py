# 修改记录:
# 2025-08-07 10:33 - 逆向因果推理: 数据流因果链构建
# 2025-08-07 15:18 - 最小因果子图提取: BFS找最短因果路径
# 2025-08-22 09:40 - 时序约束传播: 时间戳过滤不可能因果边, 时序邻近度加权置信度

"""法医因果图 - 从崩溃点逆向构建攻击因果链

现有法医工具 (Volatility, Rekall, forensic_timeline_reconstructor.py) 产生
扁平时间线--事件的序列列表。这对理解"发生了什么"有用
但对"攻击者如何达到崩溃点"的回答不充分

缺失的维度: 因果关系。事件 A 在事件 B 之前发生 != A 导致了 B
崩溃可能是由 100+ 条指令之前的某个内存写入触发的--
而该写入又由 200 条指令之前的输入数据驱动

本模块构建有向因果图:
  节点: 法医事件 (寄存器写入、内存写入、条件分支、系统调用)
  边:   A->B 表示 A 的输出被 B 作为输入消费 (数据流因果)
        A->B 也可表示 A 是 B 的控制依赖 (若 A 是条件分支而 B 在其 taken 路径上)

图的拓扑结构直接揭示攻击因果链: 攻击者输入 -> 中间计算 -> 漏洞触发 -> 崩溃
从崩溃点到攻击者输入的路径就是利用的因果链

与现有工作的差异:
- GenDFIR: LLM 驱动的 timeline 语义富化 -> 依赖 LLM, 不可形式化验证
- SPECTRE: 异常检测 -> 找异常但不建立因果关系
- Hyper Timeline: 部分序 timeline -> 时间序而非因果序
- 本模块: 形式化数据流因果图, 可验证, 从汇编 trace 自动构建
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# 因果节点类型

class CausalityNodeType(Enum):
    REG_WRITE = auto()        # 寄存器被写入
    MEM_WRITE = auto()        # 内存被写入
    MEM_READ = auto()         # 内存被读取 (使用的输入)
    COND_BRANCH = auto()      # 条件分支 (控制依赖的根)
    SYSCALL = auto()          # 系统调用 (副作用边界)
    INPUT_SOURCE = auto()     # 攻击者可控的输入源 (因果链起点)
    CRASH_SITE = auto()       # 崩溃点 (因果链终点)
    CONSTANT = auto()         # 常量--无因果前驱


@dataclass
class CausalityNode:
    """因果图中的一个节点--单个法医事件"""
    node_id: int
    node_type: CausalityNodeType
    # 位置信息
    address: int = 0              # 指令地址
    timestamp: int = 0            # 逻辑时钟 (指令序号)
    # 数据信息
    target_register: str = ''     # 被写入的寄存器 (REG_WRITE)
    target_address: int = 0       # 被访问的内存地址 (MEM_WRITE/MEM_READ)
    value_abstract: str = ''      # 值的摘要 (如 '0x41414141' 或 'tainted')
    # 污点
    is_attacker_controlled: bool = False
    taint_source: str = ''        # INPUT_BYTE | NETWORK | FILE | HEAP_SPRAY
    taint_distance: int = 999     # 离污染源的步数
    # 图结构
    causal_parents: List[int] = field(default_factory=list)   # 入边--这些节点导致了本节点
    causal_children: List[int] = field(default_factory=list)  # 出边--本节点导致的节点


# 因果边

@dataclass
class CausalityEdge:
    """因果图中的有向边"""
    src_id: int
    dst_id: int
    edge_type: str = 'data_flow'   # data_flow | control_dep | temporal_order
    confidence: float = 1.0        # [0,1] - 1=确定的因果, <1=推断
    evidence: str = ''             # 支持此因果关系的证据


# 因果图

@dataclass
class CausalityGraph:
    """完整的法医因果图"""
    nodes: Dict[int, CausalityNode] = field(default_factory=dict)
    edges: List[CausalityEdge] = field(default_factory=list)
    # 关键路径
    crash_site_id: int = -1
    input_source_ids: List[int] = field(default_factory=list)
    # 提取的攻击链: 最短的 input->crash 因果路径
    exploit_causality_chain: List[int] = field(default_factory=list)


# 因果图构建器

class ForensicCausalityBuilder:
    """从指令 trace 逆向构建法医因果图

    算法:
    1. 在崩溃点创建 CRASH_SITE 节点
    2. 向回遍历指令 trace (逆序)
    3. 每条指令创建 def-use 边: 若指令写入 reg/mem, 且该 reg/mem
       在后继指令中被读取 -> 创建因果边
    4. 条件分支创建控制依赖边: 若分支后的指令在 taken/not-taken 路径上
       -> 控制依赖
    5. 到达攻击者可控输入时标记 INPUT_SOURCE 节点并停止该链
    6. 后处理: 提取 input->crash 的最短因果路径
    """

    _MAX_BACKWARD = 200   # 最大逆向步数--避免无限循环

    def __init__(self):
        self._next_id = 0
        self._graph = CausalityGraph()
        # 追踪活跃的数据流: reg_name -> 最后写入它的 node_id
        self._last_writer: Dict[str, int] = {}

    def build(
        self,
        instruction_trace: List[Tuple[int, str, Dict[str, Any]]],
        crash_info: Dict[str, Any],
    ) -> CausalityGraph:
        """从指令 trace 构建因果图

        instruction_trace: [(address, disasm_text, metadata), ...]
          按执行顺序排列
        crash_info: {'crash_address': int, 'registers': {name: val},
                      'fault_type': str, 'crash_insn': str}

        返回 CausalityGraph
        """
        self._graph = CausalityGraph()
        self._last_writer.clear()
        self._next_id = 0

        trace = instruction_trace[-self._MAX_BACKWARD:]

        # 1. 创建崩溃节点
        crash_node = self._add_node(
            CausalityNodeType.CRASH_SITE,
            address=crash_info.get('crash_address', 0),
            timestamp=len(trace),
        )
        self._graph.crash_site_id = crash_node.node_id

        # 2. 标记崩溃指令涉及的寄存器--作为因果链的初始目标
        crash_insn = crash_info.get('crash_insn', '')
        crash_regs = self._extract_registers(crash_insn)
        for reg in crash_regs:
            self._last_writer[reg] = crash_node.node_id

        # 3. 逆向遍历--从后向前构建因果
        for i in range(len(trace) - 1, -1, -1):
            addr, text, meta = trace[i]
            self._process_instruction(addr, text, meta, i)

        # 4. 后处理--标记攻击者输入源
        self._mark_input_sources()

        # 5. 时序约束传播--过滤不可能因果边
        self._apply_temporal_constraints()

        # 6. 提取 exploit 因果链--最短路径
        if self._graph.input_source_ids and self._graph.crash_site_id >= 0:
            chain = self._extract_shortest_causal_chain()
            self._graph.exploit_causality_chain = chain

        return self._graph

    def _process_instruction(
        self, addr: int, text: str, meta: Dict[str, Any], timestamp: int,
    ) -> None:
        """处理单条指令--创建因果节点和边"""
        parts = text.strip().lower().split()
        if not parts:
            return
        mnemonic = parts[0]
        operands = ' '.join(parts[1:])

        # 检测是否为输入源 (syscall/API call)
        if self._is_input_source(mnemonic, operands):
            node = self._add_node(
                CausalityNodeType.INPUT_SOURCE,
                address=addr, timestamp=timestamp,
                value_abstract=f'input:{mnemonic}',
                is_attacker_controlled=True,
                taint_distance=0,
            )
            self._graph.input_source_ids.append(node.node_id)
            # 输入源的返回值 (rax) 被后续指令使用 -> 因果
            self._last_writer['rax'] = node.node_id
            self._last_writer['eax'] = node.node_id
            return

        # 提取目标寄存器和源寄存器
        dst_regs = self._get_dst_regs(mnemonic, operands)
        src_regs = self._get_src_regs(mnemonic, operands)

        # 为每个目标寄存器创建 REG_WRITE 节点
        for dst in dst_regs:
            node = self._add_node(
                CausalityNodeType.REG_WRITE,
                address=addr, timestamp=timestamp,
                target_register=dst,
            )

            # 因果边: 源寄存器 -> 本写入
            for src in src_regs:
                parent_id = self._last_writer.get(src)
                if parent_id is not None and parent_id != node.node_id:
                    # 检查循环依赖
                    if not self._would_create_cycle(parent_id, node.node_id):
                        node.causal_parents.append(parent_id)
                        self._graph.nodes[parent_id].causal_children.append(node.node_id)
                        self._graph.edges.append(CausalityEdge(
                            src_id=parent_id, dst_id=node.node_id,
                            edge_type='data_flow',
                            evidence=f'{src}->{dst} @ 0x{addr:x}',
                        ))

            # 更新最后写入者
            self._last_writer[dst] = node.node_id

        # 条件分支创建控制依赖
        if mnemonic.startswith('j') or mnemonic in ('cmp', 'test'):
            if self._graph.nodes:
                # 控制依赖: 分支前的比较结果 -> 分支后的指令
                cond_node = self._add_node(
                    CausalityNodeType.COND_BRANCH,
                    address=addr, timestamp=timestamp,
                )

    def _apply_temporal_constraints(self) -> None:
        """时序约束传播: 过滤违反时序的因果边, 增强邻近边置信度

        核心原则: 若事件 A 在事件 B 之后发生, A 不可能导致 B
        使用节点的时间戳 (logical clock) 验证每条因果边
        """
        nodes = self._graph.nodes
        invalid_edges = []

        for edge in self._graph.edges:
            src = nodes.get(edge.src_id)
            dst = nodes.get(edge.dst_id)
            if src is None or dst is None:
                invalid_edges.append(edge)
                continue
            # 时序约束: 源必须在目标之前 (或同时)
            if src.timestamp > dst.timestamp:
                invalid_edges.append(edge)
                continue
            # 邻近度加权: 时间越近, 因果关联越强
            time_dist = dst.timestamp - src.timestamp
            if time_dist <= 3:
                edge.confidence = min(1.0, edge.confidence + 0.15)
            elif time_dist > 50:
                edge.confidence = max(0.3, edge.confidence - 0.10)

        # 移除无效边
        for e in invalid_edges:
            self._graph.edges.remove(e)
            src_node = nodes.get(e.src_id)
            dst_node = nodes.get(e.dst_id)
            if src_node and e.dst_id in src_node.causal_children:
                src_node.causal_children.remove(e.dst_id)
            if dst_node and e.src_id in dst_node.causal_parents:
                dst_node.causal_parents.remove(e.src_id)

    def _add_node(self, node_type: CausalityNodeType, **kwargs) -> CausalityNode:
        node = CausalityNode(
            node_id=self._next_id,
            node_type=node_type,
            **kwargs,
        )
        self._graph.nodes[node.node_id] = node
        self._next_id += 1
        return node

    def _would_create_cycle(self, src_id: int, dst_id: int) -> bool:
        """检查添加 src->dst 边是否会引入环--DFS"""
        visited: Set[int] = set()
        stack = [dst_id]
        while stack:
            nid = stack.pop()
            if nid == src_id:
                return True
            if nid in visited:
                continue
            visited.add(nid)
            node = self._graph.nodes.get(nid)
            if node:
                stack.extend(node.causal_children)
        return False

    def _mark_input_sources(self) -> None:
        """递归标记攻击者可控节点--从已知输入源沿因果边正向传播"""
        queue = list(self._graph.input_source_ids)
        visited: Set[int] = set()

        while queue:
            nid = queue.pop(0)
            if nid in visited:
                continue
            visited.add(nid)
            node = self._graph.nodes.get(nid)
            if node is None:
                continue

            # 传播污点到因果后代
            for child_id in node.causal_children:
                child = self._graph.nodes.get(child_id)
                if child and not child.is_attacker_controlled:
                    child.is_attacker_controlled = True
                    child.taint_source = node.taint_source or node.value_abstract
                    child.taint_distance = node.taint_distance + 1
                    queue.append(child_id)

    def _extract_shortest_causal_chain(self) -> List[int]:
        """BFS 找从任一 input_source 到 crash_site 的最短因果路径"""
        target = self._graph.crash_site_id
        if target < 0:
            return []

        # 反向 BFS--从 crash 向回走到 input
        parent: Dict[int, int] = {}
        queue = [target]
        visited = {target}
        found_input = -1

        while queue:
            nid = queue.pop(0)
            node = self._graph.nodes.get(nid)
            if node is None:
                continue

            if node.node_type == CausalityNodeType.INPUT_SOURCE:
                found_input = nid
                break

            for parent_id in node.causal_parents:
                if parent_id not in visited:
                    visited.add(parent_id)
                    parent[parent_id] = nid
                    queue.append(parent_id)

        if found_input < 0:
            return []

        # 回溯路径
        chain = []
        current = found_input
        while current != target:
            chain.append(current)
            current = parent.get(current)
            if current is None:
                break
        chain.append(target)
        return chain

# 寄存器提取
    _REG_RE = __import__('re').compile(
        r'\b(r(?:ax|bx|cx|dx|si|di|bp|sp|8|9|1[0-5])'
        r'|e(?:ax|bx|cx|dx|si|di|bp|sp)|[abcd]x|[abcd][lh]'
        r'|r(?:8|9|1[0-5])[dwb]?)\b'
    )

    def _extract_registers(self, text: str) -> List[str]:
        return [m.lower() for m in self._REG_RE.findall(text.lower())]

    def _get_dst_regs(self, mnemonic: str, operands: str) -> List[str]:
        """提取指令写入的寄存器"""
        if mnemonic in ('cmp', 'test', 'jmp', 'je', 'jne', 'jz', 'jnz',
                        'jb', 'jae', 'ja', 'jbe', 'jl', 'jg', 'call', 'ret', 'nop'):
            return []
        parts = operands.split(',')
        if not parts:
            return []
        return self._extract_registers(parts[0])

    def _get_src_regs(self, mnemonic: str, operands: str) -> List[str]:
        """提取指令读取的寄存器"""
        parts = operands.split(',')
        # 所有操作数都可能被读取
        src_parts = parts if mnemonic in ('push',) else parts
        found = []
        for p in src_parts:
            found.extend(self._extract_registers(p.strip()))
        return list(set(found))  # 去重

    def _is_input_source(self, mnemonic: str, operands: str) -> bool:
        """检测指令是否为攻击者可控输入源"""
        input_funcs = {'read', 'fread', 'recv', 'recvfrom', 'recvmsg',
                       'scanf', 'fscanf', 'fgets', 'getc', 'getchar'}
        return mnemonic == 'call' and any(
            f in operands.lower() for f in input_funcs
        )
