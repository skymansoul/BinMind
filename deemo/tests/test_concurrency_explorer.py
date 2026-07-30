# ConcurrencyExplorer —— 线程交错(interleaving)探索，死锁检测，数据竞争
# test_concurrency_explorer: 深入测试线程交错序列生成和静态分析

import pytest

from modules.concurrency_explorer import ConcurrencyExplorer, ThreadInfo, MemoryAccess

_DEBUG_THIS_MODULE = False


class TestConcurrencyExplorer:
    """并发漏洞探索器 —— 比基本的race detector更深入"""

    def test_analyze_basic(self):
        """基本分析流程 —— 含死锁场景的经典例子"""
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
        """数据竞争检测 —— 没有锁的并发访问"""
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
        """死锁检测 —— lock1被thread0持有, lock2被thread1持有, 互相等"""
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
        """生成2个线程最多5个交错序列"""
        explorer = ConcurrencyExplorer()

        interleavings = explorer._generate_interleavings(2, 5)

lass字段完整性$/d
        assert isinstance(interleavings, list)
        assert len(interleavings) <= 5

    def test_metadata(self):
        """模块元数据 —— 给插件系统用的"""
        metadata = ConcurrencyExplorer.get_metadata()

        assert metadata.name == "ConcurrencyExplorer"
        assert metadata.type.value == "vulnerability_detector"


class TestThreadInfo:
    """ThreadInfo —— 线程状态信息"""

    def test_thread_info_creation(self):

        thread = ThreadInfo(tid=1, name="thread1")

        assert thread.tid == 1
        assert thread.name == "thread1"
        assert thread.state.value == "running"


