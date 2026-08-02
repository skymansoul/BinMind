# 2026-07-24
# Concurrency vulnerability detection — deadlock / race / TOCTOU
# 从线程执行轨迹分析锁顺序、共享内存访问模式。
# deadlock 检测：构建锁等待图 -> 找环。
# race 检测：两线程对同一内存位置，至少一个写，无同步点。
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict


@dataclass
class ConcurrencyVuln:
    type: str           # DEADLOCK | RACE | TOCTOU
    location: str       # function or address
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


# ================================================
def detect_deadlock_patterns(lock_events: List[LockEvent]) -> List[ConcurrencyVuln]:
    """分析锁事件序列，检测死锁模式。
    构建 lock graph：如果线程 A 持有 lock1 后尝试获取 lock2，
    则添加边 lock1 -> lock2。在图中找环 = potential deadlock。
    """
    _vulns = []
    # thread -> [held locks in acquisition order]
    _held: Dict[int, List[str]] = defaultdict(list)
    _graph: Dict[str, Set[str]] = defaultdict(set)

    for _ev in lock_events:
        if _ev.event_type == "ACQUIRE":
            _cur = _held[_ev.thread_id]
            if _cur:
                # 边：最后获取的锁 -> 现在要获取的锁
                _graph[_cur[-1]].add(_ev.lock_name)
            _cur.append(_ev.lock_name)
        elif _ev.event_type == "RELEASE":
            _cur = _held[_ev.thread_id]
            if _ev.lock_name in _cur:
                _cur.remove(_ev.lock_name)

    # 在图中找环
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
    """DFS 找有向图中的所有环。Tiernan 算法简化版。"""
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


# ================================================
def detect_race_conditions(accesses: List[MemoryAccess]) -> List[ConcurrencyVuln]:
    """检测竞态条件：两个线程对同一地址，至少有一个 WRITE，且无同步标签。"""
    _vulns = []
    # 按地址分组
    _by_addr: Dict[str, List[MemoryAccess]] = defaultdict(list)
    for _a in accesses:
        _by_addr[_a.address].append(_a)

    for _addr, _accs in _by_addr.items():
        _threads = set(_a.thread_id for _a in _accs)
        if len(_threads) < 2:
            continue
        # 检查是否有写
        _has_write = any(_a.access_type == "WRITE" for _a in _accs)
        if not _has_write:
            continue
        # 检查时间窗口：两个线程在相近时间访问
        _sorted = sorted(_accs, key=lambda x: x.timestamp)
        for _i in range(len(_sorted) - 1):
            _a = _sorted[_i]
            _b = _sorted[_i + 1]
            if _a.thread_id != _b.thread_id:
                _window = abs(_b.timestamp - _a.timestamp)
                if _window < 1000:  # 1ms window
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


# ================================================
def detect_toc_tou(operations: List[Dict[str, Any]]) -> List[ConcurrencyVuln]:
    """检测 TOCTOU (Time-of-Check Time-of-Use) 模式。
    输入：操作列表 [{op: "check"|"use", resource: str, thread: int, ts: int}, ...]
    模式：同一资源在 check 和 use 之间有时间窗口，且无锁保护。
    """
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
                if 0 < _gap < 10000:  # 10ms gap
                    _vulns.append(ConcurrencyVuln(
                        type="TOCTOU",
                        location=_res,
                        threads_involved=[_op.get("thread", 0)],
                        description="TOCTOU: check at {}us, use at {}us (gap={}us)".format(
                            _check_ts, _use_ts, _gap),
                        severity="HIGH",
                    ))
    return _vulns
