# 原子指令模式锁识别 + lockset must-race 分类
# 二进制级锁图数据竞争检测 - 无需符号/调试信息的锁函数识别 + 线程模块化分析.
# 三阶段: 锁函数识别(原子指令模式) → 锁图构建(lockset分析) → must-race分类.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from typing import Optional
import re


class RaceSeverity(Enum):
    MUST_RACE = 'must_race'
    MAY_RACE = 'may_race'
    NO_RACE = 'no_race'


@dataclass
class LockFunction:
    """识别出的锁函数-无符号表中恢复。"""
    addr: int
    lock_type: str = ''       # 'spinlock' | 'mutex' | 'semaphore' | 'rcu'
    pair_addr: int = 0        # 对应的 unlock 函数地址
    is_recursive: bool = False
    confidence: float = 0.0   # 识别置信度 [0,1]


@dataclass
class SharedAccess:
    """一次共享内存访问-被锁保护的读/写。"""
    addr: int
    size: int
    is_write: bool
    held_locks: set[int]      # 访问时持有的锁地址集合
    pc: int                   # 程序计数器
    thread_id: int = 0


@dataclass
class RaceReport:
    """must-race 检测报告。"""
    memory_addr: int
    access1_pc: int
    access2_pc: int
    locks1: set[int]
    locks2: set[int]
    common_locks: set[int]
    severity: RaceSeverity
    description: str = ''


# 锁函数识别
# 二进制中的原子指令模式-x86/ARM 统一处理。

def identify_lock_functions(instructions: list[dict]) -> list[LockFunction]:
    """在二进制指令中识别锁函数-无符号表。

    x86 模式: lock cmpxchg + 循环 (自旋锁)
    ARM 模式: ldrex + strex + 循环 (exclusive load/store)
    交叉引用: lock 和 unlock 通常成对调用-同一 caller 中调用两者的比例>50%"""
    funcs = _group_into_functions(instructions)
    locks: list[LockFunction] = []

    for func_addr, func_ins in funcs.items():
        # 检测原子指令 + 循环模式
        has_atomic = False
        has_loop = False
        for ins in func_ins:
            mnemonic = ins.get('mnemonic', '').lower()
            if mnemonic in ('cmpxchg', 'lock', 'xchg',
                           'ldrex', 'strex', 'ldaxr', 'stlxr'):
                has_atomic = True
            if mnemonic in ('jmp', 'jne', 'je', 'jz', 'jnz', 'bne', 'beq', 'b'):
                has_loop = True

        if has_atomic and has_loop:
            lock_type = 'spinlock'
            if any('mutex' in str(ins).lower() for ins in func_ins):
                lock_type = 'mutex'
            locks.append(LockFunction(
                addr=func_addr, lock_type=lock_type,
                confidence=0.8 if has_loop else 0.5,
            ))

    # 交叉引用配对: lock/unlock 在相同 caller 中共现
    _pair_lock_unlock(locks, funcs, instructions)
    return locks


def _pair_lock_unlock(locks: list[LockFunction],
                      funcs: dict[int, list[dict]],
                      instructions: list[dict]) -> None:
    """通过交叉引用分析配对 lock 和 unlock。"""
    call_graph = defaultdict(set)
    for ins in instructions:
        mnemonic = ins.get('mnemonic', '').lower()
        if mnemonic != 'call':
            continue
        target = _extract_call_target(ins)
        if target:
            caller = _find_enclosing_function(ins.get('address', 0), funcs)
            if caller:
                call_graph[caller].add(target)

    for lock in locks:
        for other in locks:
            if other is lock:
                continue
            # 统计共现: 同一 caller 中同时调用两者的比例
            co_count = sum(1 for callees in call_graph.values()
                          if lock.addr in callees and other.addr in callees)
            lock_only = sum(1 for callees in call_graph.values()
                           if lock.addr in callees and other.addr not in callees)
            if co_count >= 2 and co_count > lock_only:
                lock.pair_addr = other.addr
                lock.confidence = min(1.0, lock.confidence + 0.2)
                break


# 锁图构建 + Lockset 分析

class LockGraphRaceDetector:
    """二进制级锁图 + lockset must-race 检测器。"""

    __slots__ = ('_locks', '_accesses', '_reports')

    def __init__(self):
        self._locks: dict[int, LockFunction] = {}
        self._accesses: list[SharedAccess] = []
        self._reports: list[RaceReport] = []

    def register_lock(self, lock: LockFunction) -> None:
        self._locks[lock.addr] = lock

    def record_access(self, mem_addr: int, size: int, is_write: bool,
                      held_locks: set[int], pc: int, thread_id: int = 0) -> None:
        self._accesses.append(SharedAccess(
            addr=mem_addr, size=size, is_write=is_write,
            held_locks=held_locks, pc=pc, thread_id=thread_id,
        ))

    def detect_races(self) -> list[RaceReport]:
        """lockset 分析: 对每对访问同一内存地址的线程,
        若无共同锁 → race。进一步分类 must-race vs may-race。"""
        self._reports = []
        n = len(self._accesses)

        for i in range(n):
            for j in range(i + 1, n):
                a1, a2 = self._accesses[i], self._accesses[j]
                # 同一线程 → 无 race
                if a1.thread_id == a2.thread_id:
                    continue
                # 地址不重叠 → 无 race
                if not _addresses_overlap(a1.addr, a1.size, a2.addr, a2.size):
                    continue
                # 至少一个是写 → 潜在 race
                if not (a1.is_write or a2.is_write):
                    continue

                common = a1.held_locks & a2.held_locks
                if common:
                    continue  # 有共同锁保护 → 无 race

                # 分类 severity
                severity = self._classify_severity(a1, a2)

                self._reports.append(RaceReport(
                    memory_addr=a1.addr,
                    access1_pc=a1.pc, access2_pc=a2.pc,
                    locks1=a1.held_locks, locks2=a2.held_locks,
                    common_locks=common,
                    severity=severity,
                    description=f'{"W" if a1.is_write else "R"} vs {"W" if a2.is_write else "R"} @0x{a1.addr:x}',
                ))

        return self._reports

    def _classify_severity(self, a1: SharedAccess,
                           a2: SharedAccess) -> RaceSeverity:
        """分类 must-race vs may-race。

        must-race 条件:
          1. 两个访问都没有持有任何锁 → 裸访问, 无保护
          2. 两个访问在不同的线程中, 且线程必然并发 (非 join/before)
          3. 地址范围精确重叠 (非部分重叠)

        may-race 条件:
          满足 lockset 不交但缺少以上任一条件。
        """
        # 条件1: 双方都无锁 → must
        both_unprotected = not a1.held_locks and not a2.held_locks
        # 条件3: 精确重叠 (同地址同大小)
        exact_overlap = (a1.addr == a2.addr and a1.size == a2.size)
        # 条件2 简化: 不同 thread_id → 假设可能并发 (二进制层无法精确判断)

        if both_unprotected and exact_overlap:
            return RaceSeverity.MUST_RACE
        if both_unprotected:
            return RaceSeverity.MUST_RACE  # 即使部分重叠, 裸访问也标记为 must
        return RaceSeverity.MAY_RACE

    def must_race_count(self) -> int:
        return sum(1 for r in self._reports
                   if r.severity == RaceSeverity.MUST_RACE)

    def stats(self) -> dict:
        return {
            'total_accesses': len(self._accesses),
            'locks_identified': len(self._locks),
            'races_detected': len(self._reports),
            'must_races': self.must_race_count(),
            'may_races': sum(1 for r in self._reports
                            if r.severity == RaceSeverity.MAY_RACE),
        }


# 助手

def _addresses_overlap(a1: int, s1: int, a2: int, s2: int) -> bool:
    return a1 < a2 + s2 and a2 < a1 + s1


def _group_into_functions(ins: list[dict]) -> dict[int, list[dict]]:
    funcs: dict[int, list[dict]] = {}
    current = 0
    for i in ins:
        addr = i.get('address', 0)
        if i.get('function_start') or current == 0:
            current = addr
        funcs.setdefault(current, []).append(i)
    return funcs


def _find_enclosing_function(addr: int,
                             funcs: dict[int, list[dict]]) -> int:
    for faddr, fins in funcs.items():
        if any(i.get('address') == addr for i in fins):
            return faddr
    return 0


def _extract_call_target(ins: dict) -> int | None:
    ops = str(ins.get('operands', ''))
    m = re.search(r'(?:0x)?([0-9a-fA-F]{4,})', ops)
    return int(m.group(1), 16) if m else None


__all__ = [
    'LockFunction', 'SharedAccess', 'RaceReport', 'RaceSeverity',
    'LockGraphRaceDetector', 'identify_lock_functions',
]
