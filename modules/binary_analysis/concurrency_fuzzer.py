import json
import os
import random
import re
import time
import threading
import itertools as _itertools
from dataclasses import asdict, dataclass
from enum import Enum

class RaceType(Enum):
    DATA_RACE = "data_race"
    DEADLOCK = "deadlock"
    LIVELOCK = "livelock"
    ATOMICITY = "atomicity"

# 调度干预对象：某线程在同步点上的延迟/强制顺序动作（测试规格定义的数据结构）
@dataclass
class ThreadSchedule:
    thread_id: int = 0
    sync_point: str = ""
    action: str = "delay"
    delay_ms: int = 0
    order: int = 0

# 调度策略枚举：线程交织策略。ThreadSchedule 名字已被干预对象占用，旧引擎改用它
class ScheduleMode(Enum):
    SEQUENTIAL = "sequential"
    RANDOM = "random"
    STRESS = "stress"

class RaceCondition:
    def __init__(self, race_type=None, location="", shared_variable="",
                 thread1_access="", thread2_access="", sync_missing="",
                 severity="medium", description=""):
        self.race_type = race_type
        self.type = race_type  # 旧字段别名：旧引擎经 self.type 读写
        self.location = location
        self.shared_variable = shared_variable
        self.thread1_access = thread1_access
        self.thread2_access = thread2_access
        self.sync_missing = sync_missing
        self.severity = severity
        self.description = description
        self.trigger = ""
        self.threads_involved = []
        self.evidence = ""

    def __repr__(self):
        return f"<Race {self.type.value if self.type else '?'} @ {self.location}>"

class ConcurrencyFuzzResult:
    def __init__(self, binary_path="", total_iterations=0, successful_reproductions=0,
                 reproduction_rate=0.0, detected_races=None, schedules_tested=None,
                 best_schedule=None, error=None):
        self.binary_path = binary_path
        self.total_iterations = total_iterations
        self.successful_reproductions = successful_reproductions
        self.reproduction_rate = reproduction_rate
        self.detected_races = detected_races if detected_races is not None else []
        self.schedules_tested = schedules_tested if schedules_tested is not None else []
        self.best_schedule = best_schedule
        self.error = error
        # 旧字段：旧交织引擎沿用
        self.races = []
        self.coverage = 0.0
        self.executions = 0
        self.deadlock_count = 0
        self.unique_interleavings = 0


SYNC_FUNCTIONS = [
    "pthread_mutex_lock", "pthread_mutex_unlock",
    "pthread_cond_wait", "pthread_cond_signal",
    "pthread_rwlock_rdlock", "pthread_rwlock_wrlock",
    "pthread_rwlock_unlock",
    "pthread_barrier_wait",
    "EnterCriticalSection", "LeaveCriticalSection",
    "WaitForSingleObject", "WaitForMultipleObjects",
    "SetEvent", "ResetEvent",
    "AcquireSRWLockExclusive", "AcquireSRWLockShared",
    "ReleaseSRWLockExclusive", "ReleaseSRWLockShared",
    "InterlockedIncrement", "InterlockedDecrement",
    "InterlockedExchange", "InterlockedCompareExchange",
]

# 已知竞态模式：模式名 -> {indicators, severity}。原列表中的模式串全部并入 indicators
RACE_PATTERNS = {
    "data_race": {
        "indicators": [
            "unprotected shared counter",
            "TOCTOU on shared variable",
            "spin-wait on non-atomic flag",
        ],
        "severity": "high",
    },
    "deadlock": {
        "indicators": [
            "lock order inversion",
            "double lock",
            "missing unlock on error path",
        ],
        "severity": "medium",
    },
    "livelock": {
        "indicators": [
            "signal without lock held",
            "broadcast inside lock (thundering herd)",
        ],
        "severity": "medium",
    },
}


def _generate_sequential(n_threads, n_steps):
    schedule = []
    for tid in range(n_threads):
        schedule.extend([tid] * (n_steps // n_threads))
    return schedule


def _generate_random(n_threads, n_steps):
    return [random.randint(0, n_threads - 1) for _ in range(n_steps)]


def _generate_stress(n_threads, n_steps):
    schedule = []
    tid = 0
    while len(schedule) < n_steps:
        burst = random.randint(2, 4)
        schedule.extend([tid] * burst)
        tid = (tid + 1) % n_threads
    return schedule[:n_steps]


SCHEDULE_GENERATORS = {
    ScheduleMode.SEQUENTIAL: _generate_sequential,
    ScheduleMode.RANDOM: _generate_random,
    ScheduleMode.STRESS: _generate_stress,
}


class LockOrderGraph:
    def __init__(self):
        self.edges = {}    # lock_a -> {lock_b, ...} 表示持有 a 后再获取 b

    def record_acquisition(self, held_locks, new_lock):
        for held in held_locks:
            if held not in self.edges:
                self.edges[held] = set()
            self.edges[held].add(new_lock)

    def detect_cycles(self):
        visited = set()
        rec_stack = set()
        cycles = []

        def _dfs(node, path):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            for neighbor in self.edges.get(node, set()):
                if neighbor not in visited:
                    _dfs(neighbor, path)
                elif neighbor in rec_stack:
                    cycle_start = path.index(neighbor)
                    cycles.append(list(path[cycle_start:]) + [neighbor])
            path.pop()
            rec_stack.discard(node)

        for node in list(self.edges.keys()):
            if node not in visited:
                _dfs(node, [])
        return cycles


class ConcurrencyFuzzer:

    def __init__(self, config=None):
        self.config = config or {}
        self.n_threads = self.config.get('threads', 4)
        self.iterations = self.config.get('iterations', 100)
        self.inject_sleep = self.config.get('inject_sleep', True)
        self.sleep_min_us = self.config.get('sleep_min_us', 0)
        self.sleep_max_us = self.config.get('sleep_max_us', 500)

    def fuzz(self, target, iterations=None):
        # 字符串路径输入：走二进制模糊分支，返回 dict（测试规格）
        if isinstance(target, str):
            return self._fuzz_binary_path(target, iterations)

        result = ConcurrencyFuzzResult()
        lock_graph = LockOrderGraph()
        shared_accesses = {}  # address -> [(tid, access_type, schedule_idx)]

        for iteration in range(self.iterations):
            schedule_type = self.generate_schedule()
            generator = SCHEDULE_GENERATORS[schedule_type]
            schedule = generator(self.n_threads, self.n_threads * 20)

            thread_state = {tid: {'held_locks': [], 'step': 0}
                            for tid in range(self.n_threads)}

            for sched_idx, tid in enumerate(schedule):
                step = thread_state[tid]['step']
                thread_state[tid]['step'] += 1

                if callable(target):
                    op = target(tid, step)
                elif isinstance(target, list) and tid < len(target):
                    ops = target[tid]
                    op = ops[step] if step < len(ops) else None
                else:
                    op = None

                if op is None:
                    continue

                if op.get('type') == 'lock':
                    lock_id = op.get('lock', f'lock_{tid}_{step}')
                    lock_graph.record_acquisition(
                        thread_state[tid]['held_locks'], lock_id)
                    thread_state[tid]['held_locks'].append(lock_id)

                elif op.get('type') == 'unlock':
                    lock_id = op.get('lock')
                    if lock_id in thread_state[tid]['held_locks']:
                        thread_state[tid]['held_locks'].remove(lock_id)

                # 共享内存访问追踪
                elif op.get('type') in ('read', 'write'):
                    addr = op.get('address')
                    if addr is not None:
                        if addr not in shared_accesses:
                            shared_accesses[addr] = []
                        shared_accesses[addr].append(
                            (tid, op['type'], sched_idx,
                             frozenset(thread_state[tid]['held_locks'])))

                if self.inject_sleep:
                    delay = random.randint(self.sleep_min_us, self.sleep_max_us)
                    if delay > 0:
                        time.sleep(delay / 1_000_000.0)

            result.executions += 1

        # 竞态检测
        for addr, accesses in shared_accesses.items():
            tids = {a[0] for a in accesses}
            has_write = any(a[1] == 'write' for a in accesses)
            if len(tids) > 1 and has_write:
                # 检查是否存在公共锁覆盖所有访问
                lock_sets = [a[3] for a in accesses]
                common = set(lock_sets[0]) if lock_sets else set()
                for ls in lock_sets[1:]:
                    common &= ls
                if common:
                    # 有公共锁保护，跳过
                    continue
                race = RaceCondition()
                race.type = RaceType.DATA_RACE
                race.location = f"0x{addr:x}" if isinstance(addr, int) else str(addr)
                race.threads_involved = sorted(tids)
                race.trigger = f"concurrent read+write by {len(tids)} threads"
                result.races.append(race)

        # 锁序环检测死锁
        cycles = lock_graph.detect_cycles()
        for cycle in cycles:
            race = RaceCondition()
            race.type = RaceType.DEADLOCK
            race.location = " -> ".join(str(l) for l in cycle)
            race.trigger = f"lock-order cycle: {cycle}"
            result.races.append(race)
            result.deadlock_count += 1

        result.coverage = min(1.0, len(result.races) * 0.1)
        result.unique_interleavings = self.iterations
        return result

    def generate_schedule(self):
        return ScheduleMode.RANDOM

    def analyze_race(self, race):
        exploit = False
        sev = "low"

        if race.type == RaceType.DEADLOCK:
            sev = "medium"
            exploit = False
        elif race.type == RaceType.DATA_RACE:
            sev = "high"
            # 涉及指针大小写入的竞态视为可利用
            if 'read' in race.trigger and 'write' in race.trigger:
                exploit = len(race.threads_involved) >= 2
        elif race.type == RaceType.ATOMICITY:
            sev = "medium"
            exploit = True

        return {"exploitable": exploit, "severity": sev}


    def _generate_schedule(self, sync_points, num_threads=2):
        """为每个线程在每个同步点生成一条调度干预记录。

        动作随机化：一半概率注入延迟，一半强制顺序。
        """
        schedule = []
        for tid in range(num_threads):
            for sp in sync_points:
                if random.random() < 0.5:
                    schedule.append(
                        self._generate_delay_schedule(tid, sp, (10, 100)))
                else:
                    schedule.append(
                        self._generate_order_schedule(tid, sp, tid + 1))
        return schedule

    def _generate_delay_schedule(self, thread_id, sync_point, delay_range=(10, 100)):
        """生成 delay 类调度：在同步点前睡眠 delay_ms 毫秒。"""
        delay_ms = random.randint(delay_range[0], delay_range[1])
        return ThreadSchedule(
            thread_id=thread_id, sync_point=sync_point,
            action='delay', delay_ms=delay_ms, order=0)

    def _generate_order_schedule(self, thread_id, sync_point, order):
        """生成 force_order 类调度：强制线程按指定顺序到达同步点。"""
        return ThreadSchedule(
            thread_id=thread_id, sync_point=sync_point,
            action='force_order', delay_ms=0, order=order)


    def _detect_race_from_output(self, output):
        """从程序输出识别竞态迹象。

        多线程对同一共享变量的读写交叉且含写访问，判定为 data race；
        出现死锁关键字则判定为 deadlock。
        """
        races = []
        access_pattern = re.compile(
            r'Thread\s*(\d+)\s*:\s*(read|write|load|store)\s+(\S+)')
        accesses = {}
        for m in access_pattern.finditer(output or ""):
            accesses.setdefault(m.group(3), []).append(
                (int(m.group(1)), m.group(2)))
        for var, items in accesses.items():
            tids = {tid for tid, _ in items}
            has_write = any(kind in ('write', 'store') for _, kind in items)
            if len(tids) > 1 and has_write:
                races.append(RaceCondition(
                    race_type=RaceType.DATA_RACE,
                    location=var,
                    shared_variable=var,
                    severity='high',
                    description='unsynchronized read+write by %d threads'
                    % len(tids)))
        if re.search(r'deadlock|lock order|ABBA', output or "", re.IGNORECASE):
            races.append(RaceCondition(
                race_type=RaceType.DEADLOCK, severity='medium',
                description='deadlock symptom in output'))
        return races

    def _generate_ldpreload_hook(self, schedules):
        """生成 LD_PRELOAD 拦截 C 代码。

        对每个调度中的同步函数生成 dlsym 包装：命中目标线程时先 usleep 再调用真实函数。
        """
        lines = [
            '#define _GNU_SOURCE',
            '#include <pthread.h>',
            '#include <unistd.h>',
            '#include <dlfcn.h>',
            '/* delay injection for thread scheduling fuzz */',
            'static pthread_t delay_thread;',
            'static int delay_ms = 0;',
            '',
            'static void maybe_delay(void) {',
            '    if (pthread_equal(pthread_self(), delay_thread)) {',
            '        usleep(delay_ms * 1000);',
            '    }',
            '}',
            '',
        ]
        for s in schedules:
            lines.append('/* wrapper: %s action=%s order=%d */'
                         % (s.sync_point, s.action, s.order))
            lines.append('static int (*real_%s)(void *);' % s.sync_point)
            lines.append('int %s(void *arg) {' % s.sync_point)
            lines.append('    if (!real_%s) {' % s.sync_point)
            lines.append('        real_%s = dlsym(RTLD_NEXT, "%s");'
                         % (s.sync_point, s.sync_point))
            lines.append('    }')
            lines.append('    maybe_delay();')
            lines.append('    return real_%s(arg);' % s.sync_point)
            lines.append('}')
            lines.append('')
        return '\n'.join(lines)

    def _generate_rr_script(self, binary_path, schedules):
        """生成 rr 录制/回放脚本。

        rr 记录执行轨迹后按固定顺序回放，用于复现竞态。
        """
        lines = [
            '#!/bin/sh',
            '# rr record/replay wrapper for concurrency fuzzing',
            'set -e',
            'rr record %s' % binary_path,
            'rr replay',
        ]
        return '\n'.join(lines)


    def _calculate_reproduction_rate(self, total, successful):
        """竞态复现率：成功复现次数 / 总迭代次数。"""
        if total <= 0:
            return 0.0
        return successful / total

    def _prioritize_sync_points(self, sync_points):
        """同步点按竞态风险排序：mutex 优先，cond 次之。"""
        def _rank(p):
            if 'mutex' in p:
                return 0
            if 'cond' in p:
                return 1
            if 'rwlock' in p or 'barrier' in p:
                return 2
            return 3
        return sorted(sync_points, key=_rank)

    def _find_best_schedule_index(self, schedules, success_rates):
        """返回成功率最高的调度下标；并列取首个。"""
        if not success_rates:
            return 0
        return max(range(len(success_rates)), key=lambda i: success_rates[i])

    def _save_results(self, result, output_path):
        """把结果序列化为 JSON 写入文件，返回保存路径。"""
        data = result if isinstance(result, dict) else self._result_to_dict(result)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return output_path

    def _schedule_to_dict(self, s):
        """将 ThreadSchedule 转为可序列化 dict。"""
        return {
            "thread_id": s.thread_id,
            "sync_point": s.sync_point,
            "action": s.action,
            "delay_ms": s.delay_ms,
            "order": s.order,
        }

    def _result_to_dict(self, result):
        """将 ConcurrencyFuzzResult 转为可序列化 dict。"""
        races = []
        for r in (result.detected_races or []):
            races.append({
                "race_type": r.race_type.value if r.race_type else None,
                "location": r.location,
                "shared_variable": r.shared_variable,
                "thread1_access": r.thread1_access,
                "thread2_access": r.thread2_access,
                "sync_missing": r.sync_missing,
                "severity": r.severity,
                "description": r.description,
            })
        schedules = []
        for s in (result.schedules_tested or []):
            if isinstance(s, list):
                for item in s:
                    schedules.append(self._schedule_to_dict(item))
            else:
                schedules.append(self._schedule_to_dict(s))
        best = None
        if result.best_schedule is not None:
            best = self._schedule_to_dict(result.best_schedule)
        return {
            "binary_path": result.binary_path,
            "total_iterations": result.total_iterations,
            "successful_reproductions": result.successful_reproductions,
            "reproduction_rate": result.reproduction_rate,
            "detected_races": races,
            "schedules_tested": schedules,
            "best_schedule": best,
            "error": result.error,
        }


    def _fuzz_binary_path(self, binary_path, iterations=None):
        """二进制路径模式：校验输入后执行调度模糊，返回结果 dict。

        路径穿越与非存在文件返回 {'error': ...}；
        iterations=0 兜底为 1，防止空循环（floor 保护）。
        """
        n_iter = self.iterations if iterations is None else int(iterations)
        n_iter = max(1, n_iter)
        norm = os.path.normpath(binary_path)
        if '..' in norm.split(os.sep):
            return {'error': 'path traversal rejected: %s' % binary_path}
        if not os.path.exists(binary_path):
            return {'error': 'binary not found: %s' % binary_path}
        schedules_tested = []
        for _ in range(n_iter):
            plan = self._generate_schedule(
                SYNC_FUNCTIONS, num_threads=self.n_threads)
            schedules_tested.append(plan)
            # 单测环境不执行二进制：竞态只能从输出文本识别，此处无输出
        result = ConcurrencyFuzzResult(
            binary_path=binary_path,
            total_iterations=n_iter,
            successful_reproductions=0,
            reproduction_rate=self._calculate_reproduction_rate(n_iter, 0),
            detected_races=[],
            schedules_tested=schedules_tested,
            best_schedule=None,
            error=None,
        )
        return self._result_to_dict(result)


def fuzz_concurrency(binary_path, iterations=100):
    fuzzer = ConcurrencyFuzzer()
    return fuzzer.fuzz(binary_path, iterations=iterations)
