"""稀疏需求驱动污点传播引擎 — 从用户输入源到堆操作操作数的数据流追踪.

创建: 2026-05-04
用途: 替代 controllability_filter 中基于正则模式匹配的"可控性"判定,
      用真实的数据流分析追踪用户输入如何通过寄存器/内存传播到
      heap access 的偏移/大小操作数。

方法论核心:
  - Mango 做全程序污点分析, 对所有变量维护污点标签 → O(N²) 内存。
  - 本引擎采用需求驱动 (demand-driven): 仅在发现潜在 heap overflow 时,
    从该点向后切片追踪数据依赖, 直到确认或否定用户可控性。
  - 为什么这样做: 全程序污点分析对 strip 过的二进制代码会产生大量
    假污点 (寄存器重用/栈槽复用), 反而是噪音。需求驱动避免了这些假污点,
    因为只追踪与特定 heap access 相关的数据流。
  - 保守性: 若无法确定来源 → 标记为"可能可控" (宁可误报, 不漏报)。

  - Mango: 值组合追踪, 证明污点可从用户输入传播到危险函数
  - FIE on Firmware: 固件二进制上的轻量级污点分析
  - Kim et al.: "Filtering false alarms of buffer overflow analysis
    using SMT solvers" — 使用约束求解过滤误报的先驱工作
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, FrozenSet
from enum import Enum, auto

class TaintSourceType(Enum):
    """污点源类型——决定污点的初始置信度."""
    USER_INPUT = auto()       # scanf/gets/read/recv — 完全用户可控
    FILE_INPUT = auto()       # fread/fgets — 文件输入, 半可控
    NETWORK = auto()          # recvfrom/recvmsg — 网络输入
    ARGUMENT = auto()         # 函数参数 — 不直接可控但外部传入
    MEMORY = auto()           # 从全局内存加载 — 可能是持久化的攻击面

class TaintStatus(Enum):
    """污点状态三值逻辑 (Belap 的 FOUR valued 简化版)."""
    TAINTED = "tainted"       # 确定来自用户输入
    UNTAINTED = "untainted"   # 确定非用户输入 (编译期常数/局部变量)
    UNKNOWN = "unknown"       # 无法确定 (保守视作 tainted)

@dataclass
class TaintSource:
    """污点源描述."""
    insn_addr: int
    source_type: TaintSourceType
    base_confidence: float      # 该源类型的基准置信度
    description: str = ""

@dataclass
class TaintLabel:
    """一个数据位置的污点标签."""
    status: TaintStatus
    sources: FrozenSet[int] = field(default_factory=frozenset)
    confidence: float = 0.0
    propagation_path: List[int] = field(default_factory=list)

    @property
    def is_tainted(self) -> bool:
        return self.status == TaintStatus.TAINTED

# 用户输入函数名 → (源类型, 置信度, 哪个参数接收数据)
_INPUT_FUNCTIONS: Dict[str, Tuple[TaintSourceType, float, int]] = {
    'scanf': (TaintSourceType.USER_INPUT, 0.95, 1),
    '__isoc99_scanf': (TaintSourceType.USER_INPUT, 0.95, 1),
    'gets': (TaintSourceType.USER_INPUT, 0.98, 0),
    'fgets': (TaintSourceType.FILE_INPUT, 0.75, 1),
    'read': (TaintSourceType.USER_INPUT, 0.85, 1),
    'recv': (TaintSourceType.NETWORK, 0.90, 2),
    'recvfrom': (TaintSourceType.NETWORK, 0.90, 2),
    'recvmsg': (TaintSourceType.NETWORK, 0.90, 2),
    'fread': (TaintSourceType.FILE_INPUT, 0.70, 1),
    'strcpy': (TaintSourceType.USER_INPUT, 0.80, 1),
    'memcpy': (TaintSourceType.USER_INPUT, 0.60, 0),
}

# x86-64 调用约定: 函数参数 → 寄存器映射
_X86_64_ARG_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

class SparseTaintEngine:
    """稀疏需求驱动污点传播引擎.

    核心数据结构:
      - _taint_sources: 污点源 (输入函数调用点) 集合
      - _dataflow_graph: 指令级数据依赖图 (def-use chains)
      - _label_cache: 已计算的位置 → TaintLabel (缓存避免重复传播)

    使用方式:
      engine = SparseTaintEngine()
      engine.register_source(0x401050, 'scanf', TaintSourceType.USER_INPUT, 0.95)
      engine.add_dataflow_edge('rsi@0x401050', 'rax@0x401060', 'mov')
      label = engine.query_taint('rax@0x401080')
      if label.is_tainted:
          print(f'Tainted via path: {label.propagation_path}')
    """

    def __init__(self):
        self._taint_sources: List[TaintSource] = []
        self._source_locations: Set[str] = set()     # "reg@addr" 格式

        # 数据流图: src_loc → [(dst_loc, op_type), ...]
        self._dataflow_graph: Dict[str, List[Tuple[str, str]]] = {}

        # 查询缓存: location → TaintLabel
        self._label_cache: Dict[str, TaintLabel] = {}

        # 寄存器清空点 (如 xor eax,eax → 结束污点)
        self._clear_points: Set[str] = set()

# 注册

    def register_source(self, insn_addr: int, func_name: str,
                        source_type: TaintSourceType,
                        confidence: float,
                        arg_index: int = 0) -> str:
        """注册一个输入函数调用为污点源. 返回源位置的键."""
        loc_key = f"mem@{insn_addr:x}"  # 输入数据写入的内存位置
        source = TaintSource(
            insn_addr=insn_addr, source_type=source_type,
            base_confidence=confidence,
            description=f'{func_name}() at {insn_addr:#x}')
        self._taint_sources.append(source)
        self._source_locations.add(loc_key)

        # 初始标签
        self._label_cache[loc_key] = TaintLabel(
            status=TaintStatus.TAINTED,
            sources=frozenset([insn_addr]),
            confidence=confidence,
            propagation_path=[insn_addr])
        return loc_key

    def register_arg_as_source(self, insn_addr: int, arg_reg: str,
                                source_type: TaintSourceType,
                                confidence: float) -> str:
        """将函数参数寄存器标记为污点源 (用于入口函数参数)."""
        loc_key = f"{arg_reg}@{insn_addr:x}"
        source = TaintSource(
            insn_addr=insn_addr, source_type=source_type,
            base_confidence=confidence,
            description=f'{arg_reg} (arg) at {insn_addr:#x}')
        self._taint_sources.append(source)
        self._source_locations.add(loc_key)
        self._label_cache[loc_key] = TaintLabel(
            status=TaintStatus.TAINTED,
            sources=frozenset([insn_addr]),
            confidence=confidence,
            propagation_path=[insn_addr])
        return loc_key

    def add_dataflow_edge(self, src_loc: str, dst_loc: str,
                          op_type: str = 'mov') -> None:
        """添加一条数据流边: src_loc → dst_loc."""
        self._dataflow_graph.setdefault(src_loc, []).append(
            (dst_loc, op_type))

    def mark_cleared(self, loc_key: str) -> None:
        """标记某位置的数据被清零 (如 xor eax,eax), 终止污点."""
        self._clear_points.add(loc_key)
        self._label_cache[loc_key] = TaintLabel(
            status=TaintStatus.UNTAINTED,
            confidence=0.99)

# 核心查询

    def query_taint(self, loc_key: str, max_depth: int = 10) -> TaintLabel:
        """需求驱动查询: loc_key 是否携带污点.

        max_depth 限制向后追踪深度, 避免在深度递归中耗尽资源.
        """
        if loc_key in self._label_cache:
            return self._label_cache[loc_key]

        if loc_key in self._clear_points:
            return TaintLabel(status=TaintStatus.UNTAINTED, confidence=0.99)

        # 向后遍历数据流图
        tainted, sources, paths = self._propagate_backward(
            loc_key, depth=0, max_depth=max_depth)

        if tainted:
            label = TaintLabel(
                status=TaintStatus.TAINTED,
                sources=frozenset(sources),
                confidence=min(0.98, 0.40 + 0.05 * len(sources)),
                propagation_path=list(reversed(paths)))
        else:
            label = TaintLabel(
                status=TaintStatus.UNKNOWN if depth_insufficient(
                    tainted, paths) else TaintStatus.UNTAINTED,
                confidence=(0.30 if label_would_be_unknown(
                    tainted, paths) else 0.80))

        self._label_cache[loc_key] = label
        return label

    def _propagate_backward(self, loc: str, depth: int,
                            max_depth: int
                            ) -> Tuple[bool, Set[int], List[int]]:
        """反向传播污点查询."""
        if depth >= max_depth:
            return False, set(), []

        # 直接污点源
        if loc in self._source_locations:
            for src in self._taint_sources:
                src_key = f"mem@{src.insn_addr:x}"
                if src_key == loc:
                    return True, {src.insn_addr}, [src.insn_addr]

        # 遍历前驱
        all_sources: Set[int] = set()
        all_paths: List[int] = []
        any_tainted = False

        predecessors = self._get_predecessors(loc)
        for pred_loc in predecessors:
            if pred_loc in self._label_cache:
                cached = self._label_cache[pred_loc]
                if cached.status == TaintStatus.TAINTED:
                    any_tainted = True
                    all_sources.update(cached.sources)
                    all_paths.extend(cached.propagation_path)
                continue

            sub_tainted, sub_sources, sub_paths = \
                self._propagate_backward(pred_loc, depth + 1, max_depth)
            if sub_tainted:
                any_tainted = True
                all_sources.update(sub_sources)
                all_paths.extend(sub_paths)

        return any_tainted, all_sources, all_paths

    def _get_predecessors(self, loc: str) -> List[str]:
        """获取数据流图中的前驱节点."""
        preds = []
        for src, edges in self._dataflow_graph.items():
            for dst, _ in edges:
                if dst == loc:
                    preds.append(src)
        return preds

# 便捷方法

    def is_operand_tainted(self, insn_addr: int, operand: str,
                           max_depth: int = 8) -> TaintLabel:
        """便捷查询: 给定指令地址和操作数, 返回污点标签."""
        loc_key = f"{operand}@{insn_addr:x}"
        return self.query_taint(loc_key, max_depth)

    def stats(self) -> dict:
        return {
            'n_sources': len(self._taint_sources),
            'n_dataflow_edges': sum(len(v) for v in self._dataflow_graph.values()),
            'n_cache_entries': len(self._label_cache),
            'n_clear_points': len(self._clear_points),
        }

    def clear(self) -> None:
        self._taint_sources.clear()
        self._source_locations.clear()
        self._dataflow_graph.clear()
        self._label_cache.clear()
        self._clear_points.clear()

# 辅助

def label_would_be_unknown(tainted: bool, paths: List[int]) -> bool:
    return not tainted and len(paths) == 0

def depth_insufficient(tainted: bool, paths: List[int]) -> bool:
    return not tainted and len(paths) > 0
