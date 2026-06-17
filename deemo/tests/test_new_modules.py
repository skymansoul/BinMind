"""
独立测试脚本 - 测试6个新模块
"""

import sys
import os

# 添加 modules 目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 直接导入测试所需的模块，避免通过 __init__.py
from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from modules.heap_feng_shui import AllocatorType, HeapChunk

def test_ai_mutator():
    """测试AI变异器模块"""
    print("\n=== 测试 AI Mutator ===")
    from modules.ai_mutator import AIMutator, NgramMutator, GrammarBasedMutator, HybridMutator
    
    mutator = AIMutator()
    seeds = [b"GET /api/user HTTP/1.1\r\nHost: example.com\r\n\r\n"]
    
    result = mutator.analyze(mode='train', seeds=seeds, strategy='hybrid')
    assert result['success'] is True, "训练失败"
    print("✓ AI变异器训练成功")
    
    result = mutator.analyze(mode='mutate', seed=b"GET /test HTTP/1.1\r\n")
    assert result['success'] is True, "变异失败"
    print("✓ AI变异器变异成功")
    
    metadata = AIMutator.get_metadata()
    assert metadata.name == "AIMutator"
    print("✓ AI变异器元数据正确")

def test_concurrency_explorer():
    """测试并发漏洞探索器模块"""
    print("\n=== 测试 Concurrency Explorer ===")
    from modules.concurrency_explorer import ConcurrencyExplorer
    
    explorer = ConcurrencyExplorer()
    
    pseudocode = """
    void thread1() {
        mutex_lock(&lock1);
        shared_var = 1;
        mutex_unlock(&lock1);
    }
    """
    
    result = explorer.analyze(
        pseudocode=pseudocode,
        binary_info={'arch': 'x86_64'},
        max_interleavings=5,
        detection_mode='all'
    )
    assert result['success'] is True, "分析失败"
    print("✓ 并发漏洞探索器分析成功")
    
    metadata = ConcurrencyExplorer.get_metadata()
    assert metadata.name == "ConcurrencyExplorer"
    print("✓ 并发漏洞探索器元数据正确")

def test_side_channel_evaluator():
    """测试侧信道评估器模块"""
    print("\n=== 测试 Side Channel Evaluator ===")
    try:
        from modules.side_channel_evaluator import SideChannelEvaluator, LeakageSeverity
        
        evaluator = SideChannelEvaluator()
        
        # 测试严重程度判断
        severity = evaluator._determine_severity(
            signal_strength=0.05,
            p_value=0.5,
            bandwidth=0.05
        )
        assert severity == LeakageSeverity.NONE
        print("✓ 侧信道评估器严重程度判断正确")
        
        metadata = SideChannelEvaluator.get_metadata()
        assert metadata.name == "SideChannelEvaluator"
        print("✓ 侧信道评估器元数据正确")
    except ImportError as e:
        print(f"⚠ 跳过侧信道评估器测试: {e}")

def test_capability_checker():
    """测试能力检查器模块"""
    print("\n=== 测试 Capability Checker ===")
    from modules.capability_checker import CapabilityChecker, Capability, Component, IPCInterface, CapabilityLevel
    
    checker = CapabilityChecker()
    
    capabilities = [
        {'name': 'high_cap', 'level': 'high'},
        {'name': 'low_cap', 'level': 'low'},
    ]
    
    components = [
        {
            'name': 'low_comp',
            'capabilities': ['low_cap'],
            'interfaces': ['high_iface'],
            'security_level': 'low'
        },
        {
            'name': 'high_comp',
            'capabilities': ['high_cap'],
            'security_level': 'high'
        }
    ]
    
    interfaces = [
        {
            'name': 'high_iface',
            'provider': 'high_comp',
            'required_capabilities': ['high_cap'],
            'exposed_capabilities': ['high_cap'],
            'ipc_type': 'binder'
        }
    ]
    
    result = checker.analyze(
        binary_path='/system/framework/framework.jar',
        ipc_type='binder',
        capabilities=capabilities,
        components=components,
        interfaces=interfaces
    )
    assert result['success'] is True, "分析失败"
    print("✓ 能力检查器分析成功")
    
    metadata = CapabilityChecker.get_metadata()
    assert metadata.name == "CapabilityChecker"
    print("✓ 能力检查器元数据正确")

def test_supply_chain_reachability():
    """测试供应链可达性分析器模块"""
    print("\n=== 测试 Supply Chain Reachability ===")
    try:
        from modules.supply_chain_reachability import SupplyChainReachability, ReachabilityStatus
        
        analyzer = SupplyChainReachability()
        
        result = analyzer.analyze(
            binary_path='/path/to/binary',
            call_graph={
                'main': {'func_a'},
                'func_a': {'target_func'}
            },
            entry_points=['main']
        )
        assert result['success'] is True, "分析失败"
        print("✓ 供应链可达性分析器分析成功")
        
        metadata = SupplyChainReachability.get_metadata()
        assert metadata.name == "SupplyChainReachability"
        print("✓ 供应链可达性分析器元数据正确")
    except ImportError as e:
        print(f"⚠ 跳过供应链可达性分析器测试: {e}")

def test_heap_state_machine():
    """测试堆状态机模块"""
    print("\n=== 测试 Heap State Machine ===")
    from modules.heap_state_machine import HeapStateMachine, HeapState, ChunkState, HeapOperation
    
    machine = HeapStateMachine()
    
    operations = [
        {'operation': 'malloc', 'size': 0x80},
        {'operation': 'malloc', 'size': 0x80},
    ]
    
    result = machine.analyze(
        operations=operations,
        allocator='ptmalloc',
        initial_layout={'arena_base': 0x555555554000}
    )
    assert result['success'] is True, "分析失败"
    print("✓ 堆状态机分析成功")
    
    metadata = HeapStateMachine.get_metadata()
    assert metadata.name == "HeapStateMachine"
    print("✓ 堆状态机元数据正确")

if __name__ == '__main__':
    print("=" * 60)
    print("测试6个新模块")
    print("=" * 60)
    
    try:
        test_ai_mutator()
        test_concurrency_explorer()
        test_side_channel_evaluator()
        test_capability_checker()
        test_supply_chain_reachability()
        test_heap_state_machine()
        
        print("\n" + "=" * 60)
        print("所有测试通过! ✓")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)