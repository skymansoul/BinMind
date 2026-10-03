import logging
import re
from collections import defaultdict
from enum import Enum
from dataclasses import dataclass, field


logger = logging.getLogger(__name__)

_HAS_NX = False
try:
    import networkx as nx
    _HAS_NX = True
except ImportError:
    logger.warning('networkx unavailable, using built-in DFS')


class LockType(str, Enum):
    MUTEX = 'mutex'
    SEM = 'semaphore'
    RW = 'rw_lock'
    SPIN = 'spin_lock'


class LockOperation(str, Enum):
    ACQ = 'acquire'
    REL = 'release'
    ACQUIRE = 'acquire'   # 规范名别名，与 ACQ 同值
    RELEASE = 'release'   # 规范名别名，与 REL 同值


@dataclass
class LockDependency:
    from_lock: str = ''
    to_lock: str = ''
    func: str = ''

    def __post_init__(self):
        if self.from_lock is not None:
            self.from_lock = str(self.from_lock)
        if self.to_lock is not None:
            self.to_lock = str(self.to_lock)
        if self.func is not None:
            self.func = str(self.func)

    def to_dict(self):
        return {'from_lock': self.from_lock, 'to_lock': self.to_lock, 'function': self.func}


@dataclass
class DeadlockPath:
    cycle: list[str] = field(default_factory=list)
    funcs: list[str] = field(default_factory=list)
    desc: str = ''

    def __post_init__(self):
        self.cycle = list(self.cycle) if self.cycle else []
        self.funcs = list(self.funcs) if self.funcs else []
        self.desc = str(self.desc) if self.desc else ''

    def to_dict(self):
        return {'cycle': self.cycle, 'functions': self.funcs, 'description': self.desc}


@dataclass
class DeadlockAnalysisResult:
    deadlocks: list[DeadlockPath] = field(default_factory=list)
    lock_deps: list[LockDependency] = field(default_factory=list)
    total_locks: int = 0
    total_functions: int = 0
    potential_deadlocks: int = 0

    def __post_init__(self):
        self.deadlocks = list(self.deadlocks) if self.deadlocks else []
        self.lock_deps = list(self.lock_deps) if self.lock_deps else []
        self.total_locks = int(self.total_locks) if self.total_locks is not None else 0
        self.total_functions = int(self.total_functions) if self.total_functions is not None else 0
        self.potential_deadlocks = int(self.potential_deadlocks) if self.potential_deadlocks is not None else 0

    def to_dict(self):
        return {
            'deadlocks': [d.to_dict() for d in self.deadlocks],
            'lock_dependencies': [ld.to_dict() for ld in self.lock_deps],
            'total_locks': self.total_locks, 'total_functions': self.total_functions,
            'potential_deadlocks': self.potential_deadlocks,
        }


class DeadlockDetector:

    LOCK_PATS = (
        (r'\b(pthread_mutex_lock)\s*\(\s*[&]?(\w+)',   LockType.MUTEX, LockOperation.ACQ),
        (r'\b(pthread_mutex_unlock)\s*\(\s*[&]?(\w+)', LockType.MUTEX, LockOperation.REL),
        (r'\b(pthread_mutex_init)\s*\(\s*[&]?(\w+)',   LockType.MUTEX, None),
        (r'\b(pthread_rwlock_rdlock)\s*\(\s*[&]?(\w+)', LockType.RW, LockOperation.ACQ),
        (r'\b(pthread_rwlock_wrlock)\s*\(\s*[&]?(\w+)', LockType.RW, LockOperation.ACQ),
        (r'\b(pthread_rwlock_unlock)\s*\(\s*[&]?(\w+)', LockType.RW, LockOperation.REL),
        (r'\b(sem_wait)\s*\(\s*[&]?(\w+)',   LockType.SEM, LockOperation.ACQ),
        (r'\b(sem_post)\s*\(\s*[&]?(\w+)',   LockType.SEM, LockOperation.REL),
        (r'\b(Lock|lock)\s*\(\s*[&]?(\w+)',   LockType.MUTEX, LockOperation.ACQ),
        (r'\b(Unlock|unlock)\s*\(\s*[&]?(\w+)', LockType.MUTEX, LockOperation.REL),
        (r'\b(mutex_lock)\s*\(\s*[&]?(\w+)',   LockType.MUTEX, LockOperation.ACQ),
        (r'\b(mutex_unlock)\s*\(\s*[&]?(\w+)', LockType.MUTEX, LockOperation.REL),
    )

    def __init__(self):
        self._ops = []
        self._locks = set()
        self._funcs = set()
        self._deps = []

    def add_op(self, func_name, lock, operation, lock_type=None, line=None):
        if lock_type is None:
            lock_type = LockType.MUTEX
        self._ops.append({
            'function': func_name, 'lock': lock, 'operation': operation,
            'lock_type': lock_type, 'line': line,
        })
        self._locks.add(lock)
        self._funcs.add(func_name)

    def add_from_decomp(self, results):
        if results is None:
            return
        for r in results:
            fn = r.get('function_name', 'unknown')
            ps = r.get('pseudocode', '')
            for pat, ltype, op in self.LOCK_PATS:
                for m in re.finditer(pat, ps):
                    lock_name = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(1)
                    if op:
                        self.add_op(fn, lock_name, op, ltype)

    def _build_graph(self):
        g = defaultdict(set)
        stacks = {}
        sorted_ops = sorted(self._ops, key=lambda x: (x.get('line') is None, x.get('line', 0)))
        for op in sorted_ops:
            fn = op['function']
            lk = op['lock']
            opr = op['operation']
            if fn not in stacks:
                stacks[fn] = []
            if opr == LockOperation.ACQ:
                for held in stacks[fn]:
                    if held != lk:
                        g[held].add(lk)
                        self._deps.append(LockDependency(from_lock=held, to_lock=lk, func=fn))
                stacks[fn].append(lk)
            elif opr == LockOperation.REL:
                if lk in stacks[fn]:
                    stacks[fn].remove(lk)
        return g

    def _dfs_cycles(self, graph):
        cycles = []
        visited = set()
        rec = set()

        def _dfs(node, path):
            if node in rec:
                idx = path.index(node)
                cyc = path[idx:]
                if cyc not in cycles:
                    cycles.append(cyc)
                return
            if node in visited:
                return
            visited.add(node)
            rec.add(node)
            for nb in graph.get(node, []):
                _dfs(nb, path + [node])
            rec.remove(node)

        for node in graph:
            if node not in visited:
                _dfs(node, [])
        return cycles

    def _nx_cycles(self, graph):
        if not _HAS_NX:
            return []
        G = nx.DiGraph()
        for node, nbs in graph.items():
            for nb in nbs:
                G.add_edge(node, nb)
        out = []
        try:
            for cyc in nx.simple_cycles(G):
                if len(cyc) >= 2:
                    out.append(cyc)
        except Exception as e:
            logger.error('nx cycle detection failed: %s', e)
        return out

    def _funcs_in_cycle(self, cycle):
        funcs = set()
        n = len(cycle)
        for i in range(n):
            frm = cycle[i]
            to = cycle[(i + 1) % n]
            for d in self._deps:
                if d.from_lock == frm and d.to_lock == to:
                    funcs.add(d.func)
        return list(funcs)

    def _desc(self, cycle, funcs):
        order = ' -> '.join(cycle + [cycle[0]])
        flist = ', '.join(funcs)
        return 'deadlock cycle: [%s], functions: %s' % (order, flist)

    def detect(self):
        logger.info('deadlock detection start')
        if not self._ops:
            logger.warning('no lock ops, skipping')
            return DeadlockAnalysisResult()

        g = self._build_graph()
        cycles = self._nx_cycles(g) if _HAS_NX else self._dfs_cycles(g)

        paths = []
        for cyc in cycles:
            funcs = self._funcs_in_cycle(cyc)
            paths.append(DeadlockPath(
                cycle=cyc, funcs=funcs,
                desc=self._desc(cyc, funcs)))

        result = DeadlockAnalysisResult(
            deadlocks=paths, lock_deps=self._deps, total_locks=len(self._locks),
            total_functions=len(self._funcs), potential_deadlocks=len(paths))
        logger.info('detection done: %d potential deadlocks', len(paths))
        return result

    def export_dot(self, output_path):
        g = self._build_graph()
        lines = ['digraph LockDependencies {']
        for lk in self._locks:
            lines.append('    "%s" [shape=circle];' % lk)
        for frm, tos in g.items():
            for to in tos:
                lines.append('    "%s" -> "%s";' % (frm, to))
        lines.append('}')
        with open(output_path, 'w', encoding='utf-8') as fh:
            fh.write('\n'.join(lines))
        logger.info('graph exported: %s', output_path)

    def analyze_from_info(self, info):
        if info is None:
            return DeadlockAnalysisResult()
        decomp = info.get('decompilation_results', [])
        if decomp:
            self.add_from_decomp(decomp)
        strs = info.get('key_strings', []) + info.get('strings', [])
        for s in strs:
            if isinstance(s, str) and ('mutex' in s.lower() or 'lock' in s.lower()):
                self._funcs.add('string_ref:%s' % s[:20])
        return self.detect()

# 兼容别名：规范方法名映射到现有实现（历史测试按规范名调用）

def _add_lock_operation(self, func_name, lock, operation, lock_type=None,
                        line_number=None, **kw):
    # 位置参数兼容：第 4 位为 lock_type、第 5 位为行号（历史调用形式）
    return self.add_op(func_name, lock, operation,
                       lock_type=lock_type, line=line_number)


DeadlockDetector.add_lock_operation = _add_lock_operation
DeadlockDetector.add_operations_from_decompilation = DeadlockDetector.add_from_decomp
DeadlockDetector.detect_deadlocks = DeadlockDetector.detect
DeadlockDetector.export_graph_to_dot = DeadlockDetector.export_dot
DeadlockDetector.analyze_from_binary_info = DeadlockDetector.analyze_from_info
DeadlockDetector.locks = property(lambda s: s._locks)
DeadlockDetector.functions_with_locks = property(lambda s: s._funcs)
DeadlockDetector.operations = property(lambda s: s._ops)
