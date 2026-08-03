#
# 静态并发缺陷检测模块的单元测试

import sys
import os

_pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

import pytest
from analysis.static.concurrency_analysis.src.sync_primitive import (
    SyncPrimitive, SyncType, SyncSite,
    extract_sync_primitives, build_lock_pairs,
)
from analysis.static.concurrency_analysis.src.lock_graph import (
    LockGraph, LockNode, LockOrderEdge,
    build_lock_graph, detect_deadlock_cycles,
)
from analysis.static.concurrency_analysis.src.race_detector import (
    SharedAccess, AccessType,
    collect_thread_entries, find_shared_accesses,
    detect_potential_races, RaceReport,
)
from analysis.static.concurrency_analysis.src.concurrency_pipeline import (
    analyze_binary_concurrency, ConcurrencyReport,
)


class TestSyncPrimitiveExtraction:
    """同步原语提取测试"""

    def test_extract_pthread_mutex(self):
        """pthread_mutex_lock 的识别"""
        imports = ['libpthread.so.0.pthread_mutex_lock',
                    'libpthread.so.0.pthread_mutex_unlock']
        found = extract_sync_primitives(imports)
        assert len(found) == 2
        assert any(p.sync_type == SyncType.MUTEX_LOCK for p in found.values())
        assert any(p.sync_type == SyncType.MUTEX_UNLOCK for p in found.values())

    def test_extract_windows_critical_section(self):
        """Windows CriticalSec 的识别"""
        imports = ['KERNEL32.EnterCriticalSection',
                    'KERNEL32.LeaveCriticalSection']
        found = extract_sync_primitives(imports)
        assert len(found) == 2

    def test_unknown_symbol_ignored(self):
        """未知导入符号应被忽略"""
        imports = ['libc.so.6.printf', 'libm.so.6.sqrt']
        found = extract_sync_primitives(imports)
        assert found == {}

    def test_extract_spinlock(self):
        """pthread_spin_lock → SyncType.SPIN_LOCK"""
        imports = ['libpthread.so.0.pthread_spin_lock']
        found = extract_sync_primitives(imports)
        assert len(found) == 1
        prim = list(found.values())[0]
        assert prim.sync_type == SyncType.SPIN_LOCK


class TestLockPairing:
    """锁配对测试"""

    def test_simple_lock_unlock_pair(self):
        """简单的 lock → unlock 配对"""
        sites = [
            SyncSite(0x1000, 'worker', 0, SyncType.MUTEX_LOCK, 'mtx_a', 'pthread_mutex_lock'),
            SyncSite(0x1000, 'worker', 3, SyncType.MUTEX_UNLOCK, 'mtx_a', 'pthread_mutex_unlock'),
        ]
        pairs = build_lock_pairs(sites)
        assert len(pairs) == 1

    def test_unlock_without_lock(self):
        """unlock 先于 lock → 无配对但不应崩溃"""
        sites = [
            SyncSite(0x1000, 'worker', 0, SyncType.MUTEX_UNLOCK, 'mtx_a', 'pthread_mutex_unlock'),
        ]
        pairs = build_lock_pairs(sites)
        assert pairs == []


class TestLockGraph:
    """锁图构建与死锁检测测试"""

    def test_build_simple_lock_graph(self):
        """单函数中 A → B 的锁序"""
        sites = [
            SyncSite(0x1000, 'transfer', 0, SyncType.MUTEX_LOCK, 'A', 'lock'),
            SyncSite(0x1000, 'transfer', 1, SyncType.MUTEX_LOCK, 'B', 'lock'),
            SyncSite(0x1000, 'transfer', 2, SyncType.MUTEX_UNLOCK, 'B', 'unlock'),
            SyncSite(0x1000, 'transfer', 3, SyncType.MUTEX_UNLOCK, 'A', 'unlock'),
        ]
        graph = build_lock_graph(sites)
        assert len(graph.nodes) >= 2
        assert len(graph.edges) >= 1
        # 应有 A → B 的边
        edges_ab = [e for e in graph.edges if e.src_lock == 'A' and e.dst_lock == 'B']
        assert len(edges_ab) == 1

    def test_no_deadlock_acyclic(self):
        """无环锁图 → 无死锁"""
        sites = [
            # 函数 1: → B
            SyncSite(0x1000, 'f1', 0, SyncType.MUTEX_LOCK, 'A', 'lock'),
            SyncSite(0x1000, 'f1', 1, SyncType.MUTEX_LOCK, 'B', 'lock'),
            SyncSite(0x1000, 'f1', 2, SyncType.MUTEX_UNLOCK, 'B', 'unlock'),
            SyncSite(0x1000, 'f1', 3, SyncType.MUTEX_UNLOCK, 'A', 'unlock'),
        ]
        graph = build_lock_graph(sites)
        cycles = detect_deadlock_cycles(graph)
        assert cycles == []

    def test_deadlock_detected(self):
        """AB-BA 锁序 → 死锁环"""
        sites = [
            # 函数 1: → B
            SyncSite(0x1000, 'f1', 0, SyncType.MUTEX_LOCK, 'A', 'lock'),
            SyncSite(0x1000, 'f1', 1, SyncType.MUTEX_LOCK, 'B', 'lock'),
            SyncSite(0x1000, 'f1', 2, SyncType.MUTEX_UNLOCK, 'B', 'unlock'),
            SyncSite(0x1000, 'f1', 3, SyncType.MUTEX_UNLOCK, 'A', 'unlock'),
            # 函数 2: B → A（反向序）
            SyncSite(0x2000, 'f2', 0, SyncType.MUTEX_LOCK, 'B', 'lock'),
            SyncSite(0x2000, 'f2', 1, SyncType.MUTEX_LOCK, 'A', 'lock'),
            SyncSite(0x2000, 'f2', 2, SyncType.MUTEX_UNLOCK, 'A', 'unlock'),
            SyncSite(0x2000, 'f2', 3, SyncType.MUTEX_UNLOCK, 'B', 'unlock'),
        ]
        graph = build_lock_graph(sites)
        cycles = detect_deadlock_cycles(graph)
        assert len(cycles) >= 1


class TestRaceDetection:
    """数据竞争检测测试"""

    def test_shared_access_detection(self):
        """全局变量的读写检测"""
        global_vars = {'g_counter': 0x600000}
        insns = [
            ('mov', ['rax', 'g_counter']),   # 读取
            ('inc', ['g_counter']),            # 读取-写入
        ]
        accesses = find_shared_accesses('inc_counter', 0x1000, insns, global_vars)
        assert len(accesses) == 1
        assert accesses[0].data_label == 'g_counter'

    def test_potential_race_detected(self):
        """两个函数无锁访问同一变量 + 至少一个写 → 竞争"""
        thread_entries = {'worker_a': {'main'}, 'worker_b': {'main'}}
        shared = {
            'worker_a': [SharedAccess('worker_a', 0x1000, 'g_data', 0x600000, AccessType.WRITE)],
            'worker_b': [SharedAccess('worker_b', 0x2000, 'g_data', 0x600000, AccessType.READ)],
        }
        func_locks = {'worker_a': set(), 'worker_b': set()}  # 无锁保护
        races = detect_potential_races(thread_entries, shared, func_locks)
        assert len(races) >= 1
        assert races[0].severity == 'HIGH'


class TestConcurrencyPipeline:
    """并发分析管线集成测试"""

    def test_empty_binary_no_concurrency(self):
        """无同步原语的二进制 → 干净报告"""
        imports = ['libc.so.6.printf']
        func_insns = {
            'main': (0x1000, [('mov', ['rax', '0']), ('ret', [])]),
        }
        report = analyze_binary_concurrency('/tmp/test', imports, func_insns)
        assert report.total_sync_sites == 0
        assert not report.has_critical_issues

    def test_simple_mutex_no_deadlock(self):
        """单锁使用 → 无死锁"""
        imports = ['libpthread.so.0.pthread_mutex_lock',
                    'libpthread.so.0.pthread_mutex_unlock']
        func_insns = {
            'worker': (0x2000, [
                ('call', ['pthread_mutex_lock', 'mtx']),
                ('call', ['pthread_mutex_unlock', 'mtx']),
            ]),
        }
        report = analyze_binary_concurrency('/tmp/test', imports, func_insns)
        assert not report.has_critical_issues


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
