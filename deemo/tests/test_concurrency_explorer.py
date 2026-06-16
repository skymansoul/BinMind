"""
并发漏洞系统化检测模块测试
"""

import pytest
from modules.concurrency_explorer import ConcurrencyExplorer, ThreadInfo, MemoryAccess


class TestConcurrencyExplorer:
    """并发漏洞探索器测试类"""
    
    def test_analyze_basic(self):
        """测试基本分析功能"""
        explorer = ConcurrencyExplorer()
        
        pseudocode = """
        void thread1() {
            mutex_lock(&lock1);
            shared_var = 1;
            mutex_lock(&lock2);
            shared_var = 2;
            mutex_unlock(&lock2);
            mutex_unlock(&lock1);
        }
        
        void thread2() {
            mutex_lock(&lock2);
            shared_var = 3;
            mutex_lock(&lock1);
            shared_var = 4;
            mutex_unlock(&lock1);
            mutex_unlock(&lock2);
        }
        """
        
        result = explorer.analyze(
            pseudocode=pseudocode,
            binary_info={'arch': 'x86_64'},
            max_interleavings=10,
            detection_mode='all'
        )
        
        assert result['success'] is True
        assert 'static_analysis' in result
        assert 'exploration' in result
    
    def test_detect_data_races(self):
        """测试数据竞争检测"""
        explorer = ConcurrencyExplorer()
        
        memory_accesses = [
            {'thread_id': 0, 'variable': 'shared_var', 'access_type': 'write', 'step': 0, 'held_locks': set()},
            {'thread_id': 1, 'variable': 'shared_var', 'access_type': 'write', 'step': 1, 'held_locks': set()},
            {'thread_id': 0, 'variable': 'shared_var', 'access_type': 'read', 'step': 2, 'held_locks': {'lock1'}},
            {'thread_id': 1, 'variable': 'shared_var', 'access_type': 'read', 'step': 3, 'held_locks': {'lock2'}},
        ]
        
        races = explorer._detect_data_races(memory_accesses)
        
        assert isinstance(races, list)
    
    def test_check_deadlock(self):
        """测试死锁检测"""
        explorer = ConcurrencyExplorer()
        
        thread_locks = {
            0: {'lock1'},
            1: {'lock2'}
        }
        lock_states = {
            'lock1': 0,
            'lock2': 1
        }
        
        result = explorer._check_deadlock(0, thread_locks, lock_states)
        
        assert isinstance(result, bool)
    
    def test_generate_interleavings(self):
        """测试生成线程交错序列"""
        explorer = ConcurrencyExplorer()
        
        interleavings = explorer._generate_interleavings(2, 5)
        
        assert isinstance(interleavings, list)
        assert len(interleavings) <= 5
    
    def test_metadata(self):
        """测试元数据获取"""
        metadata = ConcurrencyExplorer.get_metadata()
        
        assert metadata.name == "ConcurrencyExplorer"
        assert metadata.type.value == "vulnerability_detector"


class TestThreadInfo:
    """线程信息测试类"""
    
    def test_thread_info_creation(self):
        """测试线程信息创建"""
        thread = ThreadInfo(tid=1, name="thread1")
        
        assert thread.tid == 1
        assert thread.name == "thread1"
        assert thread.state.value == "running"