"""
堆交互图预测模块测试
"""

import pytest
from modules.heap_state_machine import HeapStateMachine, HeapState, ChunkState, HeapOperation


class TestHeapStateMachine:
    """堆状态机测试类"""
    
    def test_analyze_basic(self):
        """测试基本分析功能"""
        machine = HeapStateMachine()
        
        operations = [
            {'operation': 'malloc', 'size': 0x80},
            {'operation': 'malloc', 'size': 0x80},
            {'operation': 'free', 'address': 0x555555554000},
            {'operation': 'malloc', 'size': 0x80}
        ]
        
        result = machine.analyze(
            operations=operations,
            allocator='ptmalloc',
            initial_layout={'arena_base': 0x555555554000}
        )
        
        assert result['success'] is True
        assert 'state_graph' in result
        assert 'reachable_states' in result
    
    def test_apply_malloc(self):
        """测试malloc操作"""
        machine = HeapStateMachine()
        machine.current_state = HeapState()
        machine.current_state.arena_base = 0x555555554000
        machine.current_state.top_chunk = 0x555555554000
        
        event = machine._create_event(HeapOperation.MALLOC, size=0x80)
        new_state = machine._apply_malloc(machine.current_state, 0x80)
        
        assert new_state is not None
        assert len(new_state.chunks) == 1
    
    def test_apply_free(self):
        """测试free操作"""
        machine = HeapStateMachine()
        machine.current_state = HeapState()
        machine.current_state.arena_base = 0x555555554000
        machine.current_state.top_chunk = 0x555555554100
        
        # 添加一个已分配的chunk
        from modules.heap_feng_shui import HeapChunk
        addr = 0x555555554000
        machine.current_state.chunks[addr] = HeapChunk(
            size=0x80,
            address=addr,
            in_use=True
        )
        
        new_state = machine._apply_free(machine.current_state, addr)
        
        assert new_state is not None
        assert not new_state.chunks[addr].in_use
    
    def test_clone_state(self):
        """测试状态克隆"""
        machine = HeapStateMachine()
        original = HeapState()
        original.arena_base = 0x555555554000
        original.top_chunk = 0x555555556000
        
        cloned = machine._clone_state(original)
        
        assert cloned.arena_base == original.arena_base
        assert cloned.top_chunk == original.top_chunk
        assert cloned is not original
    
    def test_get_chunk_state(self):
        """测试获取chunk状态"""
        state = HeapState()
        addr = 0x555555554000
        
        # 未分配的chunk
        result = state.get_chunk_state(addr)
        assert result == ChunkState.FREED
        
        # 已分配的chunk
        from modules.heap_feng_shui import HeapChunk
        state.chunks[addr] = HeapChunk(size=0x80, address=addr, in_use=True)
        result = state.get_chunk_state(addr)
        assert result == ChunkState.ALLOCATED
    
    def test_metadata(self):
        """测试元数据获取"""
        metadata = HeapStateMachine.get_metadata()
        
        assert metadata.name == "HeapStateMachine"
        assert metadata.type.value == "vulnerability_detector"
    
    def _create_event(self, operation, **kwargs):
        """辅助方法：创建事件"""
        from modules.heap_state_machine import HeapEvent
        return HeapEvent(operation=operation, **kwargs)


class TestHeapState:
    """堆状态测试类"""
    
    def test_state_initialization(self):
        """测试状态初始化"""
        state = HeapState()
        
        assert state.arena_base == 0x555555554000
        assert state.top_chunk == 0
        assert len(state.chunks) == 0
    
    def test_state_id_generation(self):
        """测试状态ID生成"""
        machine = HeapStateMachine()
        id1 = machine._generate_state_id()
        id2 = machine._generate_state_id()
        
        assert id1 != id2
        assert id1.startswith('state_')
        assert id2.startswith('state_')