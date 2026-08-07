# 并发模糊测试引擎 — 多线程程序的竞态条件/死锁/原子性违反测试
# 核心思路: 对每个fuzz输入生成N种线程调度变体，通过控制锁获取顺序、
# 线程创建/销毁时序、共享变量访问交错来暴露并发漏洞。
# 文献:
#   DDRace: Finding Concurrency UAF in Linux Drivers
#   Razzer: Finding Kernel Race Bugs through Fuzzing
#   ConcurrencyFuzzer
#   SKI: Systematic Interleaving Enumeration
import random
import time
from typing import List, Dict, Set, Tuple, Optional, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum


class ConcurrencyBugType(str, Enum):
    DATA_RACE = "data_race"              # 同地址非同步读-写或写-写
    DEADLOCK = "deadlock"                 # 环形锁依赖
    ATOMICITY_VIOLATION = "atomicity"     # 原子操作序列被另一线程中断
    ORDER_VIOLATION = "order_violation"   # 预期happens-before关系未满足
    THREAD_LEAK = "thread_leak"           # 线程未正确回收
    LOCK_INVERSION = "lock_inversion"     # AB-BA锁获取顺序


@dataclass
class ThreadSchedule:
    """一次线程调度编排 — N个线程的执行交叠序列。"""
    thread_count: int
    operations: List[Tuple[int, str, Any]]  # (thread_id, op_type, detail)
    # op_type: 'acquire' | 'release' | 'read' | 'write' | 'create' | 'join'
    lock_order: List[Tuple[int, int]]       # [(lock_id, thread_id), ...]
    seed_id: str = ""


@dataclass
class ConcurrencyFinding:
    """一次并发漏洞发现。"""
    bug_type: ConcurrencyBugType
    description: str
    schedule: Optional[ThreadSchedule] = None
    threads_involved: List[int] = field(default_factory=list)
    locks_involved: List[int] = field(default_factory=list)
    confidence: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)


class ConcurrencyFuzzer:
    """并发模糊测试主引擎。

    设计: 不实际操控线程（需要内核级支持），而是在测试用例层面生成多种
    线程调度方案。每个方案定义:
    - 线程数 (2-16)
    - 锁获取顺序
    - 共享内存访问时间线

    每个调度方案编码为调度描述，输入给被测程序的scheduler harness
    （harness按描述创建线程、获取锁、访问共享变量），
    执行期间由ASan/TSan捕获实际数据竞争。
    """

    def __init__(self, max_threads: int = 8):
        self._max_threads = max_threads
        self._lock_graph: Dict[int, Set[int]] = defaultdict(set)
        self._shared_vars: Dict[int, int] = {}  # var_addr -> size
        self._schedules: List[ThreadSchedule] = []
        self._findings: List[ConcurrencyFinding] = []
        self._rng = random.Random()

    # 锁图构建
    def register_lock(self, lock_id: int) -> None:
        self._lock_graph.setdefault(lock_id, set())

    def register_lock_order(self, lock_a: int, lock_b: int) -> None:
        """记录某次执行中lock_a->lock_b的获取顺序。

        若某调度中存在lock_b->lock_a，则为锁逆序。
        """
        self._lock_graph[lock_a].add(lock_b)

    def register_shared_var(self, var_addr: int, size: int = 4) -> None:
        self._shared_vars[var_addr] = size

    # 调度生成
    def generate_schedules(self, count: int = 32,
                           base_seed_id: str = "") -> List[ThreadSchedule]:
        """生成count个随机线程调度方案。"""
        self._schedules = []
        for i in range(count):
            n_threads = self._rng.randint(2, self._max_threads)
            n_locks = min(len(self._lock_graph), self._rng.randint(1, 6))
            lock_ids = self._rng.sample(
                list(self._lock_graph.keys()),
                min(n_locks, len(self._lock_graph))) if self._lock_graph else []

            ops: List[Tuple[int, str, Any]] = []
            lock_order: List[Tuple[int, int]] = []

            # 为每个线程生成操作序列
            for tid in range(n_threads):
                # 每个线程: 获取1-3个锁 -> 读写0-2个共享变量 -> 释放
                thread_locks = self._rng.sample(
                    lock_ids, min(self._rng.randint(1, 3), len(lock_ids))
                ) if lock_ids else []
                for lid in thread_locks:
                    ops.append((tid, 'acquire', lid))
                    lock_order.append((lid, tid))

                # 访问共享变量
                vars_to_access = self._rng.sample(
                    list(self._shared_vars.keys()),
                    min(self._rng.randint(0, 2), len(self._shared_vars))
                ) if self._shared_vars else []
                for va in vars_to_access:
                    access_type = self._rng.choice(['read', 'write'])
                    ops.append((tid, access_type, va))

                for lid in reversed(thread_locks):  # 先获取的后释放
                    ops.append((tid, 'release', lid))

            # 随机打乱操作顺序以模拟不同线程交叠
            self._rng.shuffle(ops)

            schedule = ThreadSchedule(
                thread_count=n_threads,
                operations=ops,
                lock_order=lock_order,
                seed_id=f"{base_seed_id}_sched_{i:03d}")
            self._schedules.append(schedule)

        return self._schedules

    # 静态检测（无需实际执行）
    def detect_deadlock_cycles(self) -> List[ConcurrencyFinding]:
        """Floyd-Warshall传递闭包检测环形锁依赖。"""
        findings = []
        locks = list(self._lock_graph.keys())
        n = len(locks)
        lock_idx = {lk: i for i, lk in enumerate(locks)}
        reachable = [[False] * n for _ in range(n)]
        for lk_from, lk_tos in self._lock_graph.items():
            for lk_to in lk_tos:
                if lk_from in lock_idx and lk_to in lock_idx:
                    reachable[lock_idx[lk_from]][lock_idx[lk_to]] = True
        for k in range(n):
            for i in range(n):
                for j in range(n):
                    reachable[i][j] = reachable[i][j] or (
                        reachable[i][k] and reachable[k][j])
        for i in range(n):
            for j in range(i + 1, n):
                if reachable[i][j] and reachable[j][i]:
                    findings.append(ConcurrencyFinding(
                        bug_type=ConcurrencyBugType.DEADLOCK,
                        description=f'环形锁依赖: lock#{locks[i]} <-> lock#{locks[j]}',
                        locks_involved=[locks[i], locks[j]],
                        confidence=0.85))
        return findings

    def detect_lock_inversion(self) -> List[ConcurrencyFinding]:
        """检测已记录执行顺序中的锁逆序模式。

        若调度A中lock_i->lock_j，调度B中lock_j->lock_i，则标记为锁逆序。
        """
        findings = []
        lock_pairs = defaultdict(list)  # (i,j) -> [schedule_ids]
        for sched in self._schedules:
            for i in range(len(sched.lock_order) - 1):
                la = sched.lock_order[i][0]
                lb = sched.lock_order[i + 1][0]
                if la != lb:
                    lock_pairs[(la, lb)].append(sched.seed_id)

        for (la, lb), sids in lock_pairs.items():
            reverse_key = (lb, la)
            if reverse_key in lock_pairs:
                findings.append(ConcurrencyFinding(
                    bug_type=ConcurrencyBugType.LOCK_INVERSION,
                    description=f'锁逆序: lock#{la}->lock#{lb} vs lock#{lb}->lock#{la}',
                    locks_involved=[la, lb],
                    confidence=0.70,
                    evidence={
                        'forward_schedules': sids[:5],
                        'reverse_schedules': lock_pairs[reverse_key][:5],
                    }))
        return findings

    def detect_potential_race(self) -> List[ConcurrencyFinding]:
        """同调度内检测对同一共享变量的无锁保护并发访问。"""
        findings = []
        for sched in self._schedules:
            # 按变量分组访问
            var_access: Dict[int, List[Tuple[int, str]]] = defaultdict(list)
            for (tid, op_type, detail) in sched.operations:
                if op_type in ('read', 'write'):
                    var_access[detail].append((tid, op_type))

            for var_addr, accesses in var_access.items():
                if len(accesses) < 2:
                    continue
                for i in range(len(accesses)):
                    for j in range(i + 1, len(accesses)):
                        ta, oa = accesses[i]
                        tb, ob = accesses[j]
                        if ta != tb and ('write' in (oa, ob)):
                            findings.append(ConcurrencyFinding(
                                bug_type=ConcurrencyBugType.DATA_RACE,
                                description=f'潜在数据竞争: 变量 0x{var_addr:x} '
                                f'在线程#{ta}({oa})和#{tb}({ob})间',
                                schedule=sched,
                                threads_involved=[ta, tb],
                                confidence=0.50,
                                evidence={'var_addr': var_addr,
                                          'access_a': oa, 'access_b': ob}))

        return findings

    # 测试输入生成
    def generate_harness_input(self, schedule: ThreadSchedule) -> bytes:
        """将调度方案编码为二进制格式供harness解析。

        格式: [n_threads(1B)] [n_ops(2B)] [op_tuple...]
        op_tuple: [thread_id(1B)] [op_type(1B)] [detail(4B LE)]
        """
        buf = bytearray()
        buf.append(schedule.thread_count & 0xFF)
        n_ops = min(len(schedule.operations), 65535)
        buf.extend(n_ops.to_bytes(2, 'little'))
        op_codes = {'acquire': 1, 'release': 2, 'read': 3,
                    'write': 4, 'create': 5, 'join': 6}
        for tid, op_type, detail in schedule.operations:
            buf.append(tid & 0xFF)
            buf.append(op_codes.get(op_type, 0))
            if isinstance(detail, int):
                buf.extend((detail & 0xFFFFFFFF).to_bytes(4, 'little'))
            else:
                buf.extend(b'\x00\x00\x00\x00')
        return bytes(buf)

    # 报告
    def all_findings(self) -> List[ConcurrencyFinding]:
        return (self.detect_deadlock_cycles()
                + self.detect_lock_inversion()
                + self.detect_potential_race())

    def stats(self) -> Dict[str, Any]:
        findings = self.all_findings()
        return {
            'schedules_generated': len(self._schedules),
            'locks_registered': len(self._lock_graph),
            'shared_vars': len(self._shared_vars),
            'findings_total': len(findings),
            'by_type': {
                bt.value: len([f for f in findings if f.bug_type == bt])
                for bt in ConcurrencyBugType
            },
        }
