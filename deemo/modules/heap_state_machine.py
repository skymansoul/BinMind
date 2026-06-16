"""
堆交互图预测模块

给定堆操作序列，预测ptmalloc/tcmalloc等分配器的块状态转移，
输出可达的堆布局状态图，用于证明利用确定性。

Author: BinaryAnalysisPlatform
Version: 1.0.0
"""

import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple
from collections import defaultdict

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from modules.heap_feng_shui import AllocatorType, HeapChunk

logger = logging.getLogger(__name__)


class ChunkState(Enum):
    """堆块状态枚举"""
    ALLOCATED = "allocated"
    FREED = "freed"
    IN_TCACHE = "in_tcache"
    IN_FASTBIN = "in_fastbin"
    IN_UNSORTED_BIN = "in_unsorted_bin"
    IN_SMALL_BIN = "in_small_bin"
    IN_LARGE_BIN = "in_large_bin"
    CONSOLIDATED = "consolidated"


class HeapOperation(Enum):
    """堆操作类型枚举"""
    MALLOC = "malloc"
    FREE = "free"
    REALLOC = "realloc"
    CALLOC = "calloc"


@dataclass
class HeapEvent:
    """堆操作事件"""
    operation: HeapOperation
    size: Optional[int] = None
    chunk_address: Optional[int] = None
    timestamp: int = 0


@dataclass
class HeapState:
    """堆状态"""
    chunks: Dict[int, HeapChunk] = field(default_factory=dict)
    tcache: Dict[int, List[int]] = field(default_factory=lambda: defaultdict(list))
    fastbins: Dict[int, List[int]] = field(default_factory=lambda: defaultdict(list))
    unsorted_bin: List[int] = field(default_factory=list)
    small_bins: Dict[int, List[int]] = field(default_factory=lambda: defaultdict(list))
    large_bins: Dict[int, List[int]] = field(default_factory=lambda: defaultdict(list))
    top_chunk: int = 0
    arena_base: int = 0x555555554000
    state_id: str = ""
    
    def get_chunk_state(self, addr: int) -> ChunkState:
        """获取chunk的状态"""
        if addr in self.chunks:
            chunk = self.chunks[addr]
            if chunk.in_use:
                return ChunkState.ALLOCATED
            
            # 检查是否在tcache
            for size, entries in self.tcache.items():
                if addr in entries:
                    return ChunkState.IN_TCACHE
            
            # 检查是否在fastbin
            for size, entries in self.fastbins.items():
                if addr in entries:
                    return ChunkState.IN_FASTBIN
            
            # 检查是否在unsorted bin
            if addr in self.unsorted_bin:
                return ChunkState.IN_UNSORTED_BIN
            
            # 检查是否在small bin
            for size, entries in self.small_bins.items():
                if addr in entries:
                    return ChunkState.IN_SMALL_BIN
            
            # 检查是否在large bin
            for size, entries in self.large_bins.items():
                if addr in entries:
                    return ChunkState.IN_LARGE_BIN
        
        return ChunkState.FREED


@dataclass
class StateTransition:
    """状态转移"""
    from_state: str
    to_state: str
    event: HeapEvent
    probability: float = 1.0
    description: str = ""


@dataclass
class StateGraph:
    """状态图"""
    states: Dict[str, HeapState] = field(default_factory=dict)
    transitions: List[StateTransition] = field(default_factory=list)
    initial_state: str = ""
    goal_states: List[str] = field(default_factory=list)


class HeapStateMachine(BaseAnalyzer):
    """
    堆状态机分析器
    
    核心功能：
    1. 模拟堆操作序列的状态转移
    2. 预测ptmalloc/tcmalloc分配器的块状态
    3. 生成可达的堆布局状态图
    4. 证明利用的确定性
    """
    
    def __init__(self):
        self.allocator_type = AllocatorType.PTMALLOC
        self.state_graph = StateGraph()
        self.current_state = HeapState()
        self.state_counter = 0
        self.operation_log: List[HeapEvent] = []
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行堆状态机分析
        
        Args:
            **kwargs: 分析参数
                - operations: List[Dict] - 堆操作序列
                - allocator: str - 分配器类型 'ptmalloc', 'tcmalloc', 'jemalloc'
                - initial_layout: Dict - 初始堆布局
                - target_pattern: Dict - 目标布局模式
        
        Returns:
            分析结果字典
        """
        operations = kwargs.get('operations', [])
        allocator = kwargs.get('allocator', 'ptmalloc')
        initial_layout = kwargs.get('initial_layout', {})
        target_pattern = kwargs.get('target_pattern', {})
        
        self.allocator_type = AllocatorType(allocator)
        
        # 初始化状态
        self._initialize_state(initial_layout)
        
        # 执行状态转移
        result = self._execute_operations(operations, target_pattern)
        
        return {
            'success': True,
            'state_graph': self._format_state_graph(),
            'reachable_states': result['reachable_states'],
            'goal_reachable': result['goal_reachable'],
            'state_transitions': result['transitions'],
            'final_state': self._format_heap_state(self.current_state),
            'analysis_summary': result['summary']
        }
    
    def _initialize_state(self, initial_layout: Dict[str, Any]) -> None:
        """
        初始化堆状态
        
        Args:
            initial_layout: 初始布局配置
        """
        state = HeapState()
        state.state_id = self._generate_state_id()
        state.arena_base = initial_layout.get('arena_base', 0x555555554000)
        state.top_chunk = initial_layout.get('top_chunk', state.arena_base + 0x2000)
        
        # 初始化已分配的chunk
        for chunk_data in initial_layout.get('chunks', []):
            addr = chunk_data.get('address', state.arena_base)
            size = chunk_data.get('size', 0x80)
            in_use = chunk_data.get('in_use', True)
            
            chunk = HeapChunk(
                size=size,
                address=addr,
                in_use=in_use
            )
            state.chunks[addr] = chunk
            
            if in_use:
                state.top_chunk = addr + size + 0x10  # chunk header
        
        self.current_state = state
        self.state_graph.states[state.state_id] = state
        self.state_graph.initial_state = state.state_id
        
        logger.info(f"初始化堆状态: {state.state_id}")
    
    def _execute_operations(
        self,
        operations: List[Dict[str, Any]],
        target_pattern: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        执行堆操作序列
        
        Args:
            operations: 堆操作序列
            target_pattern: 目标模式
        
        Returns:
            执行结果
        """
        transitions = []
        reachable_states = []
        goal_reachable = False
        operations_executed = 0
        operations_failed = 0
        
        for idx, op_data in enumerate(operations):
            try:
                operation = HeapOperation(op_data['operation'])
                size = op_data.get('size')
                addr = op_data.get('address')
                
                event = HeapEvent(
                    operation=operation,
                    size=size,
                    chunk_address=addr,
                    timestamp=idx
                )
                
                self.operation_log.append(event)
                
                # 执行操作并获取新状态
                new_state = self._apply_operation(event)
                
                if new_state:
                    transition = StateTransition(
                        from_state=self.current_state.state_id,
                        to_state=new_state.state_id,
                        event=event,
                        probability=self._calculate_transition_probability(event)
                    )
                    transitions.append(transition)
                    self.state_graph.transitions.append(transition)
                    
                    # 检查是否达到目标状态
                    if self._matches_pattern(new_state, target_pattern):
                        goal_reachable = True
                        self.state_graph.goal_states.append(new_state.state_id)
                    
                    reachable_states.append(new_state.state_id)
                    self.current_state = new_state
                    operations_executed += 1
                else:
                    operations_failed += 1
                    logger.warning(f"操作执行失败: {operation.value}")
                    
            except Exception as e:
                operations_failed += 1
                logger.error(f"执行操作时出错: {e}")
        
        return {
            'transitions': transitions,
            'reachable_states': reachable_states,
            'goal_reachable': goal_reachable,
            'summary': {
                'total_operations': len(operations),
                'executed_operations': operations_executed,
                'failed_operations': operations_failed,
                'reachable_states_count': len(reachable_states),
                'goal_reachable': goal_reachable,
                'allocator': self.allocator_type.value
            }
        }
    
    def _apply_operation(self, event: HeapEvent) -> Optional[HeapState]:
        """
        应用堆操作，返回新状态
        
        Args:
            event: 堆操作事件
        
        Returns:
            新的堆状态或None
        """
        new_state = self._clone_state(self.current_state)
        
        if event.operation == HeapOperation.MALLOC:
            return self._apply_malloc(new_state, event.size)
        elif event.operation == HeapOperation.FREE:
            return self._apply_free(new_state, event.chunk_address)
        elif event.operation == HeapOperation.REALLOC:
            return self._apply_realloc(new_state, event.chunk_address, event.size)
        elif event.operation == HeapOperation.CALLOC:
            return self._apply_calloc(new_state, event.size)
        
        return None
    
    def _apply_malloc(self, state: HeapState, size: Optional[int]) -> Optional[HeapState]:
        """
        应用malloc操作
        
        Args:
            state: 当前状态
            size: 分配大小
        
        Returns:
            新状态
        """
        if size is None or size <= 0:
            return None
        
        # 对齐到chunk大小
        aligned_size = ((size + 0xf) & ~0xf)
        
        # 检查tcache（ptmalloc特有）
        if self.allocator_type == AllocatorType.PTMALLOC and aligned_size in state.tcache:
            if state.tcache[aligned_size]:
                addr = state.tcache[aligned_size].pop()
                chunk = state.chunks.get(addr)
                if chunk:
                    chunk.in_use = True
                state.state_id = self._generate_state_id()
                self.state_graph.states[state.state_id] = state
                return state
        
        # 检查fastbin
        if aligned_size <= 0x80 and aligned_size in state.fastbins:
            if state.fastbins[aligned_size]:
                addr = state.fastbins[aligned_size].pop()
                chunk = state.chunks.get(addr)
                if chunk:
                    chunk.in_use = True
                state.state_id = self._generate_state_id()
                self.state_graph.states[state.state_id] = state
                return state
        
        # 检查unsorted bin
        if state.unsorted_bin:
            addr = state.unsorted_bin.pop()
            chunk = state.chunks.get(addr)
            if chunk:
                chunk.in_use = True
            state.state_id = self._generate_state_id()
            self.state_graph.states[state.state_id] = state
            return state
        
        # 检查small bins
        for bin_size in sorted(state.small_bins.keys()):
            if bin_size >= aligned_size and state.small_bins[bin_size]:
                addr = state.small_bins[bin_size].pop()
                chunk = state.chunks.get(addr)
                if chunk:
                    chunk.in_use = True
                state.state_id = self._generate_state_id()
                self.state_graph.states[state.state_id] = state
                return state
        
        # 检查large bins
        for bin_size in sorted(state.large_bins.keys()):
            if bin_size >= aligned_size and state.large_bins[bin_size]:
                addr = state.large_bins[bin_size].pop()
                chunk = state.chunks.get(addr)
                if chunk:
                    chunk.in_use = True
                state.state_id = self._generate_state_id()
                self.state_graph.states[state.state_id] = state
                return state
        
        # 从top chunk分配
        addr = state.top_chunk
        chunk = HeapChunk(
            size=aligned_size,
            address=addr,
            in_use=True
        )
        state.chunks[addr] = chunk
        state.top_chunk = addr + aligned_size + 0x10
        
        state.state_id = self._generate_state_id()
        self.state_graph.states[state.state_id] = state
        
        return state
    
    def _apply_free(self, state: HeapState, addr: Optional[int]) -> Optional[HeapState]:
        """
        应用free操作
        
        Args:
            state: 当前状态
            addr: 释放的地址
        
        Returns:
            新状态
        """
        if addr is None or addr not in state.chunks:
            return None
        
        chunk = state.chunks[addr]
        if not chunk.in_use:
            return None
        
        chunk.in_use = False
        
        size = chunk.size
        
        # ptmalloc的tcache优先
        if self.allocator_type == AllocatorType.PTMALLOC:
            # 检查是否适合tcache（< 0x410，且tcache未满）
            if size < 0x410 and len(state.tcache[size]) < 7:
                state.tcache[size].append(addr)
                state.state_id = self._generate_state_id()
                self.state_graph.states[state.state_id] = state
                return state
        
        # 检查是否适合fastbin
        if size <= 0x80:
            state.fastbins[size].append(addr)
            state.state_id = self._generate_state_id()
            self.state_graph.states[state.state_id] = state
            return state
        
        # 放入unsorted bin
        state.unsorted_bin.append(addr)
        state.state_id = self._generate_state_id()
        self.state_graph.states[state.state_id] = state
        
        return state
    
    def _apply_realloc(self, state: HeapState, addr: Optional[int], size: Optional[int]) -> Optional[HeapState]:
        """
        应用realloc操作
        
        Args:
            state: 当前状态
            addr: 原地址
            size: 新大小
        
        Returns:
            新状态
        """
        if addr is None or size is None or addr not in state.chunks:
            return None
        
        # 先free原chunk
        free_result = self._apply_free(state, addr)
        if not free_result:
            return None
        
        # 再malloc新chunk
        return self._apply_malloc(free_result, size)
    
    def _apply_calloc(self, state: HeapState, size: Optional[int]) -> Optional[HeapState]:
        """
        应用calloc操作（malloc + 清零）
        
        Args:
            state: 当前状态
            size: 分配大小
        
        Returns:
            新状态
        """
        return self._apply_malloc(state, size)
    
    def _clone_state(self, state: HeapState) -> HeapState:
        """
        克隆堆状态
        
        Args:
            state: 原状态
        
        Returns:
            克隆后的状态
        """
        new_state = HeapState()
        new_state.chunks = {k: HeapChunk(**vars(v)) for k, v in state.chunks.items()}
        new_state.tcache = {k: list(v) for k, v in state.tcache.items()}
        new_state.fastbins = {k: list(v) for k, v in state.fastbins.items()}
        new_state.unsorted_bin = list(state.unsorted_bin)
        new_state.small_bins = {k: list(v) for k, v in state.small_bins.items()}
        new_state.large_bins = {k: list(v) for k, v in state.large_bins.items()}
        new_state.top_chunk = state.top_chunk
        new_state.arena_base = state.arena_base
        
        return new_state
    
    def _generate_state_id(self) -> str:
        """生成唯一状态ID"""
        self.state_counter += 1
        return f"state_{self.state_counter:04d}"
    
    def _calculate_transition_probability(self, event: HeapEvent) -> float:
        """
        计算状态转移概率
        
        Args:
            event: 堆操作事件
        
        Returns:
            概率值（0-1）
        """
        # 确定性操作的概率为1.0
        if event.operation in [HeapOperation.MALLOC, HeapOperation.FREE]:
            return 1.0
        return 0.95
    
    def _matches_pattern(self, state: HeapState, pattern: Dict[str, Any]) -> bool:
        """
        检查状态是否匹配目标模式
        
        Args:
            state: 当前状态
            pattern: 目标模式
        
        Returns:
            是否匹配
        """
        if not pattern:
            return False
        
        # 检查特定chunk状态
        if 'chunk_state' in pattern:
            target_addr = pattern['chunk_state'].get('address')
            target_state = pattern['chunk_state'].get('state')
            
            if target_addr and target_state:
                actual_state = state.get_chunk_state(target_addr)
                if actual_state.value != target_state:
                    return False
        
        # 检查tcache条件
        if 'tcache_count' in pattern:
            for size, count in pattern['tcache_count'].items():
                if len(state.tcache.get(size, [])) != count:
                    return False
        
        # 检查fastbin条件
        if 'fastbin_count' in pattern:
            for size, count in pattern['fastbin_count'].items():
                if len(state.fastbins.get(size, [])) != count:
                    return False
        
        return True
    
    def _format_state_graph(self) -> Dict[str, Any]:
        """格式化状态图"""
        return {
            'states': {
                state_id: self._format_heap_state(state)
                for state_id, state in self.state_graph.states.items()
            },
            'transitions': [
                {
                    'from': t.from_state,
                    'to': t.to_state,
                    'operation': t.event.operation.value,
                    'size': t.event.size,
                    'address': t.event.chunk_address,
                    'probability': t.probability,
                    'description': t.description
                }
                for t in self.state_graph.transitions
            ],
            'initial_state': self.state_graph.initial_state,
            'goal_states': self.state_graph.goal_states
        }
    
    def _format_heap_state(self, state: HeapState) -> Dict[str, Any]:
        """格式化堆状态"""
        return {
            'state_id': state.state_id,
            'arena_base': state.arena_base,
            'top_chunk': state.top_chunk,
            'chunks': [
                {
                    'address': addr,
                    'size': chunk.size,
                    'in_use': chunk.in_use,
                    'state': state.get_chunk_state(addr).value
                }
                for addr, chunk in state.chunks.items()
            ],
            'tcache': {size: len(entries) for size, entries in state.tcache.items()},
            'fastbins': {size: len(entries) for size, entries in state.fastbins.items()},
            'unsorted_bin_size': len(state.unsorted_bin),
            'small_bins': {size: len(entries) for size, entries in state.small_bins.items()},
            'large_bins': {size: len(entries) for size, entries in state.large_bins.items()}
        }
    
    def generate_state_transition_graph(self) -> str:
        """
        生成状态转移图的DOT格式
        
        Returns:
            DOT格式的状态转移图
        """
        lines = []
        lines.append("digraph HeapStateMachine {")
        lines.append("    rankdir=LR;")
        lines.append("    node [shape=box, style=filled, color=lightblue];")
        lines.append("")
        
        # 添加初始状态标记
        lines.append(f"    {self.state_graph.initial_state} [color=green];")
        
        # 添加目标状态标记
        for goal_state in self.state_graph.goal_states:
            lines.append(f"    {goal_state} [color=red];")
        
        # 添加转移边
        for transition in self.state_graph.transitions:
            op = transition.event.operation.value
            label = op
            if transition.event.size:
                label += f"({transition.event.size})"
            elif transition.event.chunk_address:
                label += f"(0x{transition.event.chunk_address:x})"
            
            lines.append(f"    {transition.from_state} -> {transition.to_state} "
                        f'[label="{label}", prob={transition.probability}];')
        
        lines.append("}")
        
        return "\n".join(lines)
    
    def generate_analysis_report(self) -> str:
        """
        生成分析报告
        
        Returns:
            报告字符串
        """
        lines = []
        lines.append("=" * 70)
        lines.append("堆状态机分析报告")
        lines.append("=" * 70)
        lines.append("")
        
        lines.append(f"【分配器类型】{self.allocator_type.value}")
        lines.append(f"【状态总数】{len(self.state_graph.states)}")
        lines.append(f"【转移总数】{len(self.state_graph.transitions)}")
        lines.append(f"【初始状态】{self.state_graph.initial_state}")
        lines.append(f"【目标状态数】{len(self.state_graph.goal_states)}")
        lines.append("")
        
        if self.operation_log:
            lines.append("【操作日志】")
            for event in self.operation_log:
                op_str = f"[{event.timestamp}] {event.operation.value}"
                if event.size:
                    op_str += f" size={event.size}"
                if event.chunk_address:
                    op_str += f" addr=0x{event.chunk_address:x}"
                lines.append(f"  {op_str}")
        
        lines.append("")
        lines.append("【状态转移概率】")
        probs = [t.probability for t in self.state_graph.transitions]
        if probs:
            avg_prob = sum(probs) / len(probs)
            lines.append(f"  平均转移概率: {avg_prob:.2%}")
            lines.append(f"  最小转移概率: {min(probs):.2%}")
            lines.append(f"  最大转移概率: {max(probs):.2%}")
        
        lines.append("")
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def verify_exploit_determinism(self, target_pattern: Dict[str, Any]) -> bool:
        """
        验证漏洞利用的确定性
        
        Args:
            target_pattern: 目标模式
        
        Returns:
            是否确定可达
        """
        # 检查是否存在到达目标状态的路径
        if self.state_graph.goal_states:
            # 检查所有到达目标状态的路径概率
            success_prob = 1.0
            for goal_state in self.state_graph.goal_states:
                # 找到到达目标状态的转移
                for transition in self.state_graph.transitions:
                    if transition.to_state == goal_state:
                        success_prob *= transition.probability
            
            return success_prob >= 0.9
        
        return False
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="HeapStateMachine",
            type=AnalyzerType.VULNERABILITY_DETECTOR,
            version="1.0.0",
            description="堆交互图预测模块，预测ptmalloc/tcmalloc分配器的块状态转移，输出可达的堆布局状态图",
            author="BinaryAnalysisPlatform",
            dependencies=["collections"],
            supported_platforms=["x86", "x86_64"]
        )


def analyze_heap_state_machine(operations: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
    """便捷函数：执行堆状态机分析"""
    analyzer = HeapStateMachine()
    return analyzer.analyze(operations=operations, **kwargs)