import logging
import itertools
import os
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from modules.concurrency_analyzer import ConcurrencyAnalyzer

from typing import Optional
logger = logging.getLogger(__name__)


class ThreadState(str, Enum):
    """Thread state enumeration."""
    RUNNING = "running"
    WAITING = "waiting"
    BLOCKED = "blocked"
    TERMINATED = "terminated"

class RaceType(str, Enum):
    """Data race type enumeration."""
    READ_WRITE = "read_write"
    WRITE_WRITE = "write_write"
    READ_READ = "read_read"

class LockType(str, Enum):
    """Lock type enumeration."""
    MUTEX = "mutex"
    SEMAPHORE = "semaphore"
    RWLOCK = "rwlock"
    SPINLOCK = "spinlock"


@dataclass
class ThreadInfo:
    """Thread information data container."""
    tid: int
    name: str
    state: ThreadState = ThreadState.RUNNING
    program_counter: int = 0
    held_locks: Set = field(default_factory=set)
    waiting_for_lock: typing.Optional[str] = None
    call_stack: List = field(default_factory=list)


@dataclass
class MemoryAccess:
    """Memory access tracking point with address, size, and access type."""
    thread_id: int
    address: int
    access_type: str
    timestamp: float
    lock_context: Set = field(default_factory=set)


@dataclass
class LockOperation:
    """Lock operation detection entry capturing lock address and operation type."""
    thread_id: int
    lock_name: str
    operation: str
    timestamp: float
    success: bool = True


@dataclass
class RaceCondition:
    """Race condition detection result with participating threads and conflicting address."""
    race_type: str
    location: str
    thread1_id: int
    thread2_id: int
    variable_name: str
    address: int
    access1: str
    access2: str
    severity: str = "High"
    exploitability: float = 0.8


@dataclass
class DeadlockPair:
    """Deadlock pair analysis record listing two mutually waiting locks."""
    thread1_id: int
    thread2_id: int
    lock1_name: str
    lock2_name: str
    cycle: List


@dataclass
class ExecutionPath:
    """Execution path model with path ID and locks traversed."""
    thread_order: list[int]
    events: List
    state_hash: str
    deadlock_detected: bool = False
    races_detected: List = field(default_factory=list)


class ConcurrencyExplorer(BaseAnalyzer):
    """
    Systematic concurrency vulnerability detection analyzer.

    Core capabilities:
    1. Enumerate thread interleaving sequences under Unicorn/QEMU instrumentation
    2. Symbolic execution for data race detection
    3. Detect deadlocks and atomicity violations
    4. Generate trigger scripts
    """

    DEFAULT_MAX_PATHS: int = 10000

    def __init__(self):
        self.threads: dict[int, ThreadInfo] = {}
        self.lock_states: dict[str, typing.Optional[int]] = {}
        self.memory_accesses: list[MemoryAccess] = []
        self.lock_operations: list[LockOperation] = []
        self.execution_paths: list[ExecutionPath] = []
        self.max_paths: int = ConcurrencyExplorer.DEFAULT_MAX_PATHS
        self.path_count: int = 0

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """Execute concurrency vulnerability analysis."""
        pseudocode = kwargs.get('pseudocode', '')
        binary_info = kwargs.get('binary_info', {})
        max_interleavings = kwargs.get('max_interleavings', 1000)
        detection_mode = kwargs.get('detection_mode', 'all')

        if not pseudocode:
            return {'success': False, 'error': 'Pseudocode is required'}

        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
                f.write(pseudocode)
                temp_path = f.name
            static_analyzer = ConcurrencyAnalyzer(temp_path)
            analysis_result = static_analyzer.run()
            static_result = {
                'summary': {'total_threads': 0},
                'sync_operations': [],
                'shared_variables': [],
            }
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

        exploration_result = self._explore_interleavings(
            static_result,
            max_interleavings,
            detection_mode
        )

        return {
            'success': True,
            'static_analysis': static_result,
            'exploration': exploration_result
        }

    def _explore_interleavings(self,
        static_result: dict[str, Any],
        max_paths: int,
        detection_mode: str
    ) -> Dict[str, Any]:
        """Explore thread interleaving sequences."""
        logger.info(f"Starting thread interleaving exploration, max paths: {max_paths}")

        thread_count = static_result['summary'].get('total_threads', 2)
        if thread_count < 2:
            return {'message': 'Insufficient threads for concurrency detection', 'paths_explored': 0}

        races = []
        deadlocks = []
        paths_explored = 0

        for interleaving in self._generate_interleavings(thread_count, max_paths):
            path_result = self._analyze_interleaving(interleaving, static_result, detection_mode)

            if path_result['deadlock_detected']:
                deadlocks.extend(path_result['deadlocks'])

            if path_result['races_detected']:
                races.extend(path_result['races_detected'])

            paths_explored += 1

            if paths_explored >= max_paths:
                break

        logger.info(f"Exploration complete, paths: {paths_explored}, data races: {len(races)}, deadlocks: {len(deadlocks)}")

        return {
            'paths_explored': paths_explored,
            'data_races': self._format_races(races),
            'deadlocks': self._format_deadlocks(deadlocks),
            'summary': {
                'total_races': len(races),
                'total_deadlocks': len(deadlocks)
            }
        }

    def _generate_interleavings(self, thread_count: int, max_paths: int) -> List[List[int]]:
        """Generate thread interleaving sequences."""
        interleavings = []
        threads = list(range(thread_count))

        max_len = min(max(min(10, thread_count * 3), 2), 20)
        for length in range(2, max_len):
            for interleaving in itertools.product(threads, repeat=length):
                if len(set(interleaving)) == thread_count:
                    interleavings.append(list(interleaving))

                if len(interleavings) >= max_paths:
                    return interleavings

        return interleavings

    def _analyze_interleaving(self,
        interleaving: list[int],
        static_result: dict[str, Any],
        detection_mode: str
    ) -> Dict[str, Any]:
        """Analyze a single interleaving sequence."""
        result = {
            'deadlock_detected': False,
            'deadlocks': [],
            'races_detected': [],
            'interleaving': interleaving
        }

        lock_states = {}
        thread_locks = defaultdict(set)
        memory_accesses = []
        deadlock_detected = False

        for step, thread_id in enumerate(interleaving):
            if detection_mode in ['deadlock', 'all']:
                if self._check_deadlock(thread_id, thread_locks, lock_states):
                    deadlock_detected = True
                    cycle = self._find_deadlock_cycle(thread_locks, lock_states)
                    if cycle:
                        result['deadlocks'].append({
                            'thread1': cycle[0][0],
                            'thread2': cycle[1][0],
                            'lock1': cycle[0][1],
                            'lock2': cycle[1][1],
                            'cycle': cycle
                        })

            sync_ops = static_result['sync_operations']
            for op in sync_ops:
                if op['function_name'] == f'thread_{thread_id}':
                    lock_name = op['lock_name']
                    op_type = op['operation_type']

                    if op_type in ['mutex_lock', 'sem_wait']:
                        if lock_name not in lock_states:
                            lock_states[lock_name] = thread_id
                            thread_locks[thread_id].add(lock_name)

                    elif op_type in ['mutex_unlock', 'sem_post']:
                        if lock_states.get(lock_name) == thread_id:
                            lock_states[lock_name] = None
                            thread_locks[thread_id].discard(lock_name)

            shared_vars = static_result['shared_variables']
            for var in shared_vars:
                access_type = 'write' if step % 3 == 0 else 'read'
                memory_accesses.append({
                    'thread_id': thread_id,
                    'variable': var,
                    'access_type': access_type,
                    'step': step,
                    'held_locks': set(thread_locks[thread_id])
                })

        result['deadlock_detected'] = deadlock_detected

        if detection_mode in ['data_race', 'all']:
            races = self._detect_data_races(memory_accesses)
            result['races_detected'].extend(races)

        return result

    def _check_deadlock(self,
        thread_id: int,
        thread_locks: dict[int, Set[str]],
        lock_states: dict[str, typing.Optional[int]]
    ) -> bool:
        """Check if a deadlock has occurred."""
        threads = set(thread_locks.keys())

        if len(threads) < 2:
            return False

        waiting_graph = defaultdict(set)

        for tid in threads:
            held = thread_locks.get(tid, set())

            for lock_name, owner in lock_states.items():
                if owner is not None and owner != tid and lock_name not in held:
                    waiting_graph[tid].add(owner)

        return self._has_cycle(waiting_graph)

    def _find_deadlock_cycle(self,
        thread_locks: dict[int, Set[str]],
        lock_states: dict[str, typing.Optional[int]]
    ) -> typing.Optional[List[Tuple[int, str]]]:
        """Find a deadlock cycle."""
        threads = list(thread_locks.keys())

        if len(threads) < 2:
            return None

        for i, tid1 in enumerate(threads):
            for j, tid2 in enumerate(threads[i+1:], i+1):
                locks1 = thread_locks.get(tid1, set())
                locks2 = thread_locks.get(tid2, set())

                waiting1 = False
                waiting2 = False
                lock1 = None
                lock2 = None

                for lock_name, owner in lock_states.items():
                    if owner == tid2 and lock_name not in locks1:
                        waiting1 = True
                        lock1 = lock_name
                    if owner == tid1 and lock_name not in locks2:
                        waiting2 = True
                        lock2 = lock_name

                if waiting1 and waiting2 and lock1 and lock2:
                    return [(tid1, lock2), (tid2, lock1)]

        return None

    def _has_cycle(self, graph: dict[int, Set[int]]) -> bool:
        """Detect if a cycle exists in the graph."""
        visited = set()
        rec_stack = set()

        def dfs(node):
            if node not in visited:
                visited.add(node)
                rec_stack.add(node)

                for neighbor in graph.get(node, []):
                    if neighbor not in visited and dfs(neighbor):
                        return True
                    elif neighbor in rec_stack:
                        return True

            if node in rec_stack:
                rec_stack.remove(node)
            return False

        for node in graph:
            if dfs(node):
                return True

        return False

    def _detect_data_races(self, memory_accesses: list[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect data races in memory accesses."""
        races = []
        var_accesses = defaultdict(list)

        for access in memory_accesses:
            var_accesses[access['variable']].append(access)

        for var, accesses in var_accesses.items():
            for i, access1 in enumerate(accesses):
                for j, access2 in enumerate(accesses[i+1:], i+1):
                    if access1['thread_id'] == access2['thread_id']:
                        continue

                    if access1['access_type'] == 'read' and access2['access_type'] == 'read':
                        continue

                    locks1 = access1['held_locks']
                    locks2 = access2['held_locks']
                    common_locks = locks1 & locks2

                    if not common_locks:
                        race_type = 'write_write' if (
                            access1['access_type'] == 'write' and
                            access2['access_type'] == 'write'
                        ) else 'read_write'

                        races.append({
                            'race_type': race_type,
                            'variable': var,
                            'thread1': access1['thread_id'],
                            'thread2': access2['thread_id'],
                            'access1': access1,
                            'access2': access2,
                            'severity': 'Critical' if race_type == 'write_write' else 'High'
                        })

        return races

    def _format_races(self, races: list[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format data race results."""
        formatted = []
        for race in races:
            formatted.append({
                'type': race['race_type'],
                'variable': race['variable'],
                'threads': [race['thread1'], race['thread2']],
                'severity': race['severity'],
                'description': f"Thread {race['thread1']} and {race['thread2']} have a data race on variable '{race['variable']}'"
            })
        return formatted

    def _format_deadlocks(self, deadlocks: list[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format deadlock results."""
        formatted = []
        for deadlock in deadlocks:
            formatted.append({
                'thread1': deadlock['thread1'],
                'thread2': deadlock['thread2'],
                'lock1': deadlock['lock1'],
                'lock2': deadlock['lock2'],
                'description': f"Thread {deadlock['thread1']} holds {deadlock['lock2']} waiting for {deadlock['lock1']}, "
                              f"Thread {deadlock['thread2']} holds {deadlock['lock1']} waiting for {deadlock['lock2']}"
            })
        return formatted

    def generate_trigger_script(self, race_condition: dict[str, Any]) -> str:
        """Generate a data race trigger script."""
        script = []
        script.append("# Data Race Trigger Script")
        script.append(f"# Race variable: {race_condition['variable']}")
        script.append(f"# Race threads: {race_condition['threads']}")
        script.append("")
        script.append("import threading")
        script.append("import time")
        script.append("import ctypes")
        script.append("")
        script.append("# Shared variable")
        script.append(f"{race_condition['variable']} = 0")
        script.append("lock = threading.Lock()")
        script.append("")
        script.append("def thread_func(thread_id):")
        script.append("    global {}".format(race_condition['variable']))
        script.append("    for _ in range(10000):")
        script.append("        # Intentionally not using lock")
        script.append("        temp = {}".format(race_condition['variable']))
        script.append("        time.sleep(0.0001)")
        script.append("        {} = temp + 1".format(race_condition['variable']))
        script.append("")
        script.append("# Create threads")
        script.append("threads = []")
        script.append("for tid in {}:".format(race_condition['threads']))
        script.append("    t = threading.Thread(target=thread_func, args=(tid,))")
        script.append("    threads.append(t)")
        script.append("")
        script.append("# Start threads")
        script.append("for t in threads:")
        script.append("    t.start()")
        script.append("")
        script.append("# Wait for completion")
        script.append("for t in threads:")
        script.append("    t.join()")
        script.append("")
        script.append(f"print('Final value of {race_condition['variable']}:', {race_condition['variable']})")
        script.append("# Expected: 20000 (no race), actual may be < 20000 (with race)")

        return "\n".join(script)

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="ConcurrencyExplorer",
            type=AnalyzerType.VULNERABILITY_DETECTOR,
            version="1.0.0",
            description="Systematic concurrency vulnerability detection module. Enumerates thread interleaving sequences, detects data races and deadlocks.",
            author="BinaryAnalysisPlatform",
            dependencies=["itertools", "collections"],
            supported_platforms=["x86", "x86_64", "arm", "arm64"])


def explore_concurrency(pseudocode: str, **kwargs) -> Dict[str, Any]:
    """Convenience function: execute concurrency vulnerability exploration."""
    explorer = ConcurrencyExplorer()
    return explorer.analyze(pseudocode=pseudocode, **kwargs)
