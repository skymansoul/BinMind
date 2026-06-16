"""
分布式符号执行引擎测试
"""

import pytest
import time
from modules.distributed_symbex import (
    DistributedSymExecEngine, 
    StandaloneSymExecEngine,
    SymbolicState,
    ExecutionResult,
    ExecutionStatus,
    StateShardManager,
    ClusterConfig,
    create_engine,
    RAY_AVAILABLE
)


class TestSymbolicState:
    """符号状态测试"""
    
    def test_state_creation(self):
        """测试状态创建"""
        state = SymbolicState(
            state_id="test_1",
            pc=0x1000,
            depth=0
        )
        
        assert state.state_id == "test_1"
        assert state.pc == 0x1000
        assert state.depth == 0
    
    def test_state_serialization(self):
        """测试状态序列化"""
        state = SymbolicState(
            state_id="test_2",
            pc=0x2000,
            constraints=[],
            depth=5
        )
        
        data = state.serialize()
        restored = SymbolicState.deserialize(data)
        
        assert restored.state_id == state.state_id
        assert restored.pc == state.pc
        assert restored.depth == state.depth
    
    def test_state_hash(self):
        """测试状态哈希"""
        state1 = SymbolicState(state_id="s1", pc=0x1000, depth=1)
        state2 = SymbolicState(state_id="s2", pc=0x1000, depth=1)
        state3 = SymbolicState(state_id="s3", pc=0x2000, depth=1)
        
        assert state1.get_hash() == state2.get_hash()
        assert state1.get_hash() != state3.get_hash()


class TestStateShardManager:
    """状态分片管理器测试"""
    
    def test_shard_creation(self):
        """测试分片创建"""
        manager = StateShardManager(num_shards=8)
        
        assert manager.num_shards == 8
        assert manager.total_states == 0
    
    def test_add_state(self):
        """测试添加状态"""
        manager = StateShardManager()
        
        state = SymbolicState(state_id="s1", pc=0x1000)
        shard_id = manager.add_state(state)
        
        assert shard_id in range(manager.num_shards)
        assert manager.total_states == 1
    
    def test_remove_state(self):
        """测试移除状态"""
        manager = StateShardManager()
        
        state = SymbolicState(state_id="s1", pc=0x1000)
        shard_id = manager.add_state(state)
        
        success = manager.remove_state(shard_id, "s1")
        
        assert success is True
        assert manager.total_states == 0


class TestStandaloneEngine:
    """独立模式引擎测试"""
    
    def test_engine_creation(self):
        """测试引擎创建"""
        engine = StandaloneSymExecEngine(max_workers=2)
        
        assert engine.max_workers == 2
        assert engine.is_running is False
    
    def test_execute(self):
        """测试执行"""
        engine = StandaloneSymExecEngine()
        
        result = engine.execute(
            binary_path="/test/binary",
            max_states=10,
            max_depth=5
        )
        
        assert result['success'] is True
        assert 'execution_id' in result
        assert result['completed_states'] > 0
    
    def test_get_stats(self):
        """测试获取统计"""
        engine = StandaloneSymExecEngine()
        
        stats = engine.get_stats()
        
        assert 'mode' in stats
        assert stats['mode'] == 'standalone'


class TestDistributedEngine:
    """分布式引擎测试"""
    
    def test_engine_creation(self):
        """测试引擎创建"""
        config = ClusterConfig(num_workers=2)
        engine = DistributedSymExecEngine(config)
        
        assert engine.config.num_workers == 2
        assert engine.is_initialized is False
    
    @pytest.mark.skipif(not RAY_AVAILABLE, reason="Ray not installed")
    def test_initialize(self):
        """测试初始化"""
        engine = DistributedSymExecEngine(
            config=ClusterConfig(num_workers=1)
        )
        
        success = engine.initialize()
        
        # 如果 Ray 可用则测试
        if RAY_AVAILABLE:
            assert success is True
            assert engine.is_initialized is True
        
        engine.shutdown()


class TestFactory:
    """工厂函数测试"""
    
    def test_create_standalone_engine(self):
        """测试创建独立引擎"""
        engine = create_engine(distributed=False)
        
        assert isinstance(engine, StandaloneSymExecEngine)
    
    def test_create_distributed_engine_without_ray(self):
        """测试无 Ray 时创建分布式引擎"""
        engine = create_engine(distributed=True)
        
        # 应该回退到独立模式
        assert isinstance(engine, StandaloneSymExecEngine)
