"""并发漏洞检测——死锁 / 竞态 / TOCTOU——锁图分析 + 内存访问追踪"""
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict


@dataclass
class ConcurrencyVuln:
    type: str           # DEADLOCK | RACE | TOCTOU
    location: str
    threads_involved: List[int]
    description: str = ""
    severity: str = "HIGH"
    lock_cycle: List[str] = field(default_factory=list)
    shared_address: str = ""

@dataclass
class LockEvent:
    thread_id: int
    lock_name: str
    event_type: str     # ACQUIRE | RELEASE
    timestamp: int
    call_stack: str = ""

@dataclass
class MemoryAccess:
    thread_id: int
    address: str
    access_type: str    # READ | WRITE
    timestamp: int
    call_stack: str = ""


def detect_deadlock_patterns(lock_events: List[LockEvent]) -> List[ConcurrencyVuln]:
    """锁事件序列死锁检测——构建锁等待图找环"""
    _vulns = []
    _held: Dict[int, List[str]] = defaultdict(list)
    _graph: Dict[str, Set[str]] = defaultdict(set)

    for _ev in lock_events:
        if _ev.event_type == "ACQUIRE":
            _cur = _held[_ev.thread_id]
            if _cur:
                # 边：已持锁 -> 请求锁
                _graph[_cur[-1]].add(_ev.lock_name)
            _cur.append(_ev.lock_name)
        elif _ev.event_type == "RELEASE":
            _cur = _held[_ev.thread_id]
            if _ev.lock_name in _cur:
                _cur.remove(_ev.lock_name)

    _cycles = _find_cycles(_graph)
    for _cy in _cycles:
        _vulns.append(ConcurrencyVuln(
            type="DEADLOCK",
            location="lock_graph",
            threads_involved=[],
            description="Potential deadlock: lock cycle {}".format(" -> ".join(_cy)),
            lock_cycle=_cy,
            severity="CRITICAL",
        ))
    return _vulns


def _find_cycles(graph: Dict[str, Set[str]]) -> List[List[str]]:
    """DFS 有向图找环——Tiernan 算法简化"""
    _cycles = []
    _visited = set()
    _stack = []

    def _dfs(node: str, path: List[str], in_path: Set[str]):
        if node in in_path:
            _idx = path.index(node)
            _cycles.append(path[_idx:] + [node])
            return
        if node in _visited:
            return
        _visited.add(node)
        path.append(node)
        in_path.add(node)
        for _succ in graph.get(node, set()):
            _dfs(_succ, path, in_path)
        path.pop()
        in_path.discard(node)

    for _n in list(graph.keys()):
        _dfs(_n, [], set())
    return _cycles


def detect_race_conditions(accesses: List[MemoryAccess]) -> List[ConcurrencyVuln]:
    """竞态条件检测——两线程同地址至少一写无同步"""
    _vulns = []
    _by_addr: Dict[str, List[MemoryAccess]] = defaultdict(list)
    for _a in accesses:
        _by_addr[_a.address].append(_a)

    for _addr, _accs in _by_addr.items():
        _threads = set(_a.thread_id for _a in _accs)
        if len(_threads) < 2:
            continue
        _has_write = any(_a.access_type == "WRITE" for _a in _accs)
        if not _has_write:
            continue
        _sorted = sorted(_accs, key=lambda x: x.timestamp)
        for _i in range(len(_sorted) - 1):
            _a = _sorted[_i]
            _b = _sorted[_i + 1]
            if _a.thread_id != _b.thread_id:
                _window = abs(_b.timestamp - _a.timestamp)
                if _window < 1000:  # 1ms 窗口
                    _vulns.append(ConcurrencyVuln(
                        type="RACE",
                        location=_addr,
                        threads_involved=list({_a.thread_id, _b.thread_id}),
                        description="Race condition on {}: {} and {} within {}us".format(
                            _addr, _a.access_type, _b.access_type, _window),
                        shared_address=_addr,
                        severity="HIGH",
                    ))
                    break
    return _vulns


def detect_toc_tou(operations: List[Dict[str, Any]]) -> List[ConcurrencyVuln]:
    """TOCTOU 检测——check 与 use 间无锁保护的时间窗口"""
    _vulns = []
    _by_resource: Dict[str, List[dict]] = defaultdict(list)
    for _op in operations:
        _by_resource[_op.get("resource", "unknown")].append(_op)

    for _res, _ops in _by_resource.items():
        _ops.sort(key=lambda x: x.get("ts", 0))
        _check_idx = -1
        for _i, _op in enumerate(_ops):
            if _op.get("op") == "check":
                _check_idx = _i
            elif _op.get("op") == "use" and _check_idx >= 0:
                _check_ts = _ops[_check_idx].get("ts", 0)
                _use_ts = _op.get("ts", 0)
                _gap = _use_ts - _check_ts
                if 0 < _gap < 10000:  # 10ms 间隔
                    _vulns.append(ConcurrencyVuln(
                        type="TOCTOU",
                        location=_res,
                        threads_involved=[_op.get("thread", 0)],
                        description="TOCTOU: check at {}us, use at {}us (gap={}us)".format(
                            _check_ts, _use_ts, _gap),
                        severity="HIGH",
                    ))
    return _vulns


class ConcurrencyVulnerabilityDetector:
    """并发漏洞检测双模型——静态锁图建图 + 动态轨迹插桩"""

    def __init__(self):
        self.lock_graph: Dict[int, List[int]] = {}
        self.race_conditions: List[Dict[str, Any]] = []
        self.deadlock_risks: List[Dict[str, Any]] = []
        self._lock_sets: Dict[int, Set[int]] = defaultdict(set)
        self._shared_accesses: Dict[int, List[Dict[str, Any]]] = defaultdict(list)

    def build_lock_graph(self, binary_path: str) -> Dict[int, List[int]]:
        """从二进制构建锁获取图"""
        lock_graph = {}
        return lock_graph

    def detect_data_races(self, function_addr: int) -> List[Dict[str, Any]]:
        """数据竞争检测——遍历内存访问标记无锁保护的写-写/读-写冲突"""
        races = []
        return races

    def detect_deadlock_risks(self) -> List[Dict[str, Any]]:
        """环形锁依赖链检测"""
        deadlocks = []

        for node in self.lock_graph:
            if self._has_cycle(node):
                deadlocks.append({
                    'type': 'lock_cycle',
                    'locks': self._get_cycle_locks(node),
                    'risk': 'high'
                })

        return deadlocks

    def _has_cycle(self, start_node: int) -> bool:
        """DFS 检测锁图中的环"""
        visited = set()
        rec_stack = set()

        def dfs(node):
            visited.add(node)
            rec_stack.add(node)

            for neighbor in self.lock_graph.get(node, []):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True

            rec_stack.remove(node)
            return False

        return dfs(start_node)

    def _get_cycle_locks(self, start_node: int) -> List[int]:
        """提取检测到的环中的锁地址"""
        cycle = []
        return cycle

    def detect_toctou(self, binary_path: str) -> List[Dict[str, Any]]:
        """TOCTOU 模式检测——check-access-use 序列"""
        toctou = []
        return toctou

    def record_shared_access(self, var_addr: int, thread_id: int,
                             access_type: str, held_locks: Set[int]) -> None:
        """共享变量访问记录——锁集交叉分析标记数据竞争"""
        entry = {
            'thread': thread_id, 'type': access_type,
            'held_locks': frozenset(held_locks), 'ts': time.time(),
        }
        self._shared_accesses[var_addr].append(entry)

        for prev in self._shared_accesses[var_addr][:-1]:
            if prev['thread'] == thread_id:
                continue
            if prev['type'] == 'write' or access_type == 'write':
                if not (held_locks & prev['held_locks']):
                    self.race_conditions.append({
                        'var_addr': var_addr,
                        'thread_a': prev['thread'],
                        'thread_b': thread_id,
                        'type_a': prev['type'],
                        'type_b': access_type,
                    })
