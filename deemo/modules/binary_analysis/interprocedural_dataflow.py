"""
?????????? (Interprocedural Data Flow Analysis)

??:
    1. ???????? ? ?????????????
    2. ?? VSA (Value Set Analysis) ???????
    3. ????? (Call String) ????????, ?? k ????
    4. ?? (Summary) ??: ???????????????
    5. ????????: ????? (? system/execve) ??????

????:
    - IFDS/IDE ????: ?????????????
    - VSA: Strided Interval ???, ??????????
    - ??? + CFG ????, BFS ???????
    - ??? (Source) / ??? (Sink) / ??? (Sanitizer) ??
    - ????: ??? (?? ? ???/???) ???
"""

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class TaintKind(StrEnum):
    """????"""
    USER_INPUT = "user_input"             # ??????? (argv, stdin, recv)
    NETWORK = "network"                   # ???? (socket recv, http body)
    FILE = "file"                         # ??????
    ENVIRONMENT = "environment"           # ????
    KERNEL = "kernel"                     # ????? (copy_from_user)
    IPC = "ipc"                           # ???????
    DERIVED = "derived"                   # ???? (??/???????)
    UNKNOWN = "c"

class DataFlowDirection:  # ? Enum
    """?????"""
    FORWARD = "forward"      # ??: source ? sink
    BACKWARD = "backward"    # ??: sink ? source


@dataclass
class DataFlowFact:
    """docstring"""
    var_name: Any = None
    taint_kind: Any = None
    location: Any = None
    context_hash: Any = None

    def __repr__(self) -> str:
        return f"Fact({self.var_name}:{self.taint_kind.value}@{self.location[:20]})"

    def __hash__(self):
        return hash((self.var_name, self.taint_kind, self.location, self.context_hash))

    def __eq__(self, other):
        if not isinstance(other, DataFlowFact):
            return NotImplemented
        return (self.var_name, self.taint_kind, self.location, self.context_hash) == \
               (other.var_name, other.taint_kind, other.location, other.context_hash)


class SourceSpec:
    """?????"""
    __slots__ = ('name', 'taint_kind', 'param_indices', 'description', 'constraints')

    def __init__(self, name: str, taint_kind: TaintKind, param_indices: List[int], description: str = "", constraints: Optional[str] = None):
        self.name = name
        self.taint_kind = taint_kind
        self.param_indices = param_indices
        self.description = description
        self.constraints = constraints


class SinkSpec:
    """???????"""
    __slots__ = ('name', 'dangerous_param', 'vuln_class', 'severity')

    def __init__(self, name: str, dangerous_param: int, vuln_class: str = "", severity: str = "high"):
        self.name = name
        self.dangerous_param = dangerous_param
        self.vuln_class = vuln_class
        self.severity = severity


class SanitizerSpec:
    """?????"""
    __slots__ = ('name', 'param_index', 'sanitizer_type')

    def __init__(self, name: str, param_index: int, sanitizer_type: str = ""):
        self.name = name
        self.param_index = param_index
        self.sanitizer_type = sanitizer_type


class FunctionSummary:
    """????: ??????????/?????"""
    __slots__ = ('func_name', 'params', 'returns_tainted', 'return_taint_kinds', 'side_effects', 'call_string', 'analysis_time_ms')

    def __init__(self, func_name: str, params: Optional[List[str]] = None, returns_tainted: bool = False, return_taint_kinds: Optional[List[TaintKind]] = None, side_effects: Optional[Dict[int, bool]] = None, call_string: str = "", analysis_time_ms: float = 0.0):
        self.func_name = func_name
        self.params = params if params is not None else []
        self.returns_tainted = returns_tainted
        self.return_taint_kinds = return_taint_kinds if return_taint_kinds is not None else []
        self.side_effects = side_effects if side_effects is not None else {}
        self.call_string = call_string
        self.analysis_time_ms = analysis_time_ms


class DataFlowPath:
    """?????"""
    __slots__ = ('source', 'sink', 'path', 'taint_kind', 'sanitized', 'sanitizer', 'severity', 'confidence')

    def __init__(self, source: str, sink: str, path: List[DataFlowFact], taint_kind: TaintKind, sanitized: bool = False, sanitizer: str = "", severity: str = "medium", confidence: float = 0.0):
        self.source = source
        self.sink = sink
        self.path = path
        self.taint_kind = taint_kind
        self.sanitized = sanitized
        self.sanitizer = sanitizer
        self.severity = severity
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        # 2026-06-24: to_dict???????????????
        return {
            'source': self.source,
            'sink': self.sink,
            'path_length': len(self.path),
            'path': [{
                'var': f.var_name,
                'taint': f.taint_kind.value,
                'location': f.location,
                'context': f.context_hash[:12]
            } for f in self.path],
            'taint_kind': self.taint_kind.value,
            'sanitized': self.sanitized,
            'sanitizer': self.sanitizer,
            'severity': self.severity,
            'confidence': round(self.confidence, 2)
        }


class SourceSinkDatabase:
    """???/???/??????"""

    SOURCES: List[SourceSpec] = [
        SourceSpec("recv", TaintKind.NETWORK, [0, 1], "socket recv"),
        SourceSpec("recvfrom", TaintKind.NETWORK, [0, 1], "socket recvfrom"),
        SourceSpec("recvmsg", TaintKind.NETWORK, [0], "socket recvmsg"),
        SourceSpec("read", TaintKind.FILE, [0, 1], "file read",
                   constraints="fd != STDOUT_FILENO"),
        SourceSpec("fread", TaintKind.FILE, [0], "buffered file read"),
        SourceSpec("fgets", TaintKind.FILE, [0], "fgets"),
        SourceSpec("scanf", TaintKind.USER_INPUT, [1], "scanf family"),
        SourceSpec("__isoc99_scanf", TaintKind.USER_INPUT, [1], "C99 scanf"),
        SourceSpec("gets", TaintKind.USER_INPUT, [0], "gets (always dangerous)"),
        SourceSpec("getenv", TaintKind.ENVIRONMENT, [1], "environment variable (ret val)"),
        SourceSpec("getenv", TaintKind.ENVIRONMENT, [0], "environment var"),
        SourceSpec("argv", TaintKind.USER_INPUT, [0], "command line argument"),
        SourceSpec("copy_from_user", TaintKind.KERNEL, [0], "kernel: copy from userspace"),
        SourceSpec("HttpReadRequest", TaintKind.NETWORK, [0, 1], "HTTP body"),
        SourceSpec("URLDownloadToFile", TaintKind.NETWORK, [0], "Windows URL download"),
        SourceSpec("RegQueryValueEx", TaintKind.FILE, [2], "Windows registry read"),
    ]

    SINKS: List[SinkSpec] = [
        SinkSpec("system", 0, "command_injection", "critical"),
        SinkSpec("popen", 0, "command_injection", "critical"),
        SinkSpec("execve", 0, "command_injection", "critical"),
        SinkSpec("execl", 0, "command_injection", "critical"),
        SinkSpec("execlp", 0, "command_injection", "critical"),
        SinkSpec("execvp", 0, "command_injection", "critical"),
        SinkSpec("strcpy", 1, "buffer_overflow", "high"),
        SinkSpec("strcat", 1, "buffer_overflow", "high"),
        SinkSpec("sprintf", 0, "buffer_overflow", "high"),
        SinkSpec("memcpy", 2, "buffer_overflow", "high"),
        SinkSpec("strncpy", 2, "buffer_overflow", "medium"),
        SinkSpec("snprintf", 1, "buffer_overflow", "medium"),
        SinkSpec("__memmove_chk", 2, "buffer_overflow", "medium"),
        SinkSpec("sqlite3_exec", 1, "sql_injection", "critical"),
        SinkSpec("mysql_query", 0, "sql_injection", "critical"),
        SinkSpec("printf", 0, "format_string", "high"),
        SinkSpec("fprintf", 1, "format_string", "high"),
        SinkSpec("syslog", 1, "format_string", "medium"),
    ]

    SANITIZERS: List[SanitizerSpec] = [
        SanitizerSpec("escape_shell_arg", 0, "shell_escape"),
        SanitizerSpec("htmlspecialchars", 0, "html_encode"),
        SanitizerSpec("htmlentities", 0, "html_encode"),
        SanitizerSpec("mysql_real_escape_string", 0, "sql_escape"),
        SanitizerSpec("filter_var", 0, "input_filter"),
        SanitizerSpec("strlen", 0, "bounds_check"),  # ?? bounds check ??
        SanitizerSpec("strnlen", 0, "bounds_check"),
        SanitizerSpec("snprintf", 0, "safe_format"),
        SanitizerSpec("access", 0, "permission_check"),
    ]

    @classmethod
    def get_source(cls, func_name: str) -> Optional[SourceSpec]:
        clean = func_name.split('.')[-1].split('::')[-1]
        for s in cls.SOURCES:
            if s.name.lower() == clean.lower():
                return s
        return None

    @classmethod
    def get_sink(cls, func_name: str) -> Optional[SinkSpec]:
        # 2026-06-18: get_sink???????null?????????????
        clean = func_name.split('.')[-1].split('::')[-1]
        for s in cls.SINKS:
            if s.name.lower() == clean.lower():
                return s
        return None

    @classmethod
    def get_sanitizer(cls, func_name: str) -> Optional[SanitizerSpec]:
        # 2026-07-20: ??get_sanitizer????????????????????
        clean = func_name.split('.')[-1].split('::')[-1]
        for s in cls.SANITIZERS:
            if s.name.lower() == clean.lower():
                return s
        return None


class CallGraph:
    """docstring"""

    def __init__(self):
        self._edges: Dict[str, Set[str]] = defaultdict(set)
        self._reverse: Dict[str, Set[str]] = defaultdict(set)
        self._funcs: Set[str] = set()

    def add_edge(self, caller: str, callee: str):
        self._edges[caller].add(callee)
        self._reverse[callee].add(caller)
        self._funcs.add(caller)
        self._funcs.add(callee)

    @property
    def functions(self) -> Set[str]:
        return self._funcs

    def callers_of(self, func: str) -> Set[str]:
        return self._reverse.get(func, set())

    def callees_of(self, func: str) -> Set[str]:
        return self._edges.get(func, set())

    def reachable_from(self, start: str, max_depth: int = 10) -> Set[str]:
        """BFS ? start ???????"""
        visited: Set[str] = set()
        queue = deque([(start, 0)])
        while queue:
            cur, depth = queue.popleft()
            if cur in visited or depth > max_depth:
                continue
            visited.add(cur)
            for callee in self.callees_of(cur):
                if callee not in visited:
                    queue.append((callee, depth + 1))
        return visited


class DataFlowAnalyzer:
    """docstring"""

    def __init__(self, max_context_depth: int = 3):
        self.max_context_depth = max_context_depth
        self._summary_cache: Dict[str, FunctionSummary] = {}
        self._ss_db = SourceSinkDatabase

    def _context_hash(self, call_stack: List[str]) -> str:
        """???????????"""
        if not call_stack:
            return ""
        import hashlib
        return hashlib.md5(':'.join(call_stack).encode()).hexdigest()[:12]

    def analyze_forward(self,
                        call_graph: CallGraph,
                        func_names: List[str],
                        func_calls: Dict[str, List[Tuple[int, str]]],
                        sources: Optional[List[str]] = None) -> List[DataFlowPath]:
        """
        ??????: ? source ? sink ??

        """
        paths: List[DataFlowPath] = []
        active_sources = sources if sources else [
            s.name for s in self._ss_db.SOURCES[:10]
        ]

        # BFS ????? source ????
        for func in func_names:
            calls = func_calls.get(func, [])
            for addr, callee in calls:
                source_spec = self._ss_db.get_source(callee)
                if source_spec and (not active_sources or callee in active_sources):
                    # ?? source ? ????????
                    fact = DataFlowFact(
                        var_name=f"ret_of_{callee}",
                        taint_kind=source_spec.taint_kind,
                        location=f"{func}@{hex(addr)}"
                    )
                    # ??? fact ??????? sink
                    traced = self._trace_forward(fact, func, calls, addr, call_graph,
                                                 func_calls)
                    paths.extend(traced)

        # ???????
        for p in paths:
            if p.sanitized:
                p.severity = "low" if p.severity in ("high", "critical") else "info"

        return sorted(paths, key=lambda p: p.confidence, reverse=True)

    def analyze_backward(self,
                         call_graph: CallGraph,
                         func_names: List[str],
                         func_calls: Dict[str, List[Tuple[int, str]]],
                         sinks: Optional[List[str]] = None) -> List[DataFlowPath]:
        """
        ??????: ? sink ? source ??

        """
        paths: List[DataFlowPath] = []
        active_sinks = sinks if sinks else [s.name for s in self._ss_db.SINKS[:10]]

        for func in func_names:
            calls = func_calls.get(func, [])
            for addr, callee in calls:
                sink_spec = self._ss_db.get_sink(callee)
                if sink_spec and (not active_sinks or callee in active_sinks):
                    # ?? sink ? ?????????
                    fact = DataFlowFact(
                        var_name=f"arg{sink_spec.dangerous_param}_of_{callee}",
                        taint_kind=TaintKind.UNKNOWN,
                        location=f"{func}@{hex(addr)}"
                    )
                    traced = self._trace_backward(fact, func, calls, addr, call_graph,
                                                  func_calls)
                    for t in traced:
                        t.sink = f"{callee} (param {sink_spec.dangerous_param})"
                        t.severity = sink_spec.severity
                    paths.extend(traced)

        return sorted(paths, key=lambda p: p.confidence, reverse=True)

    def _trace_forward(self, fact: DataFlowFact, func: str,
                       calls: List[Tuple[int, str]],
                       start_addr: int,
                       call_graph: CallGraph,
                       func_calls: Dict[str, List[Tuple[int, str]]],
                       depth: int = 0) -> List[DataFlowPath]:
        """????????"""
        if depth > self.max_context_depth:
            return []

        paths: List[DataFlowPath] = []

        # ???????, ?? start_addr ???????
        subsequent = [(a, c) for a, c in calls if a > start_addr]

        current_path = [fact]

        for addr, callee in subsequent:
            # ?????? sink
            sink_spec = self._ss_db.get_sink(callee)
            if sink_spec:
                paths.append(DataFlowPath(
                    source=f"{fact.var_name} ({fact.taint_kind.value})",
                    sink=f"{callee}@{hex(addr)}",
                    path=current_path + [
                        DataFlowFact(
                            var_name=f"sink:{callee}",
                            taint_kind=fact.taint_kind,
                            location=f"{func}@{hex(addr)}"
                        )
                    ],
                    taint_kind=fact.taint_kind,
                    severity=sink_spec.severity,
                    confidence=0.85 - (0.1 * depth)
                ))

            # ?????????
            sanitizer = self._ss_db.get_sanitizer(callee)
            if sanitizer:
                paths.append(DataFlowPath(
                    source=f"{fact.var_name} ({fact.taint_kind.value})",
                    sink=f"sanitized by {callee}@{hex(addr)}",
                    path=current_path,
                    taint_kind=fact.taint_kind,
                    sanitized=True,
                    sanitizer=callee,
                    severity="info",
                    confidence=0.5
                ))
                # ????????
                continue

            # ???? callee (????????)
            if callee in func_calls:
                callee_calls = func_calls[callee]
                new_fact = DataFlowFact(
                    var_name=f"arg1_of_{callee}",
                    taint_kind=fact.taint_kind,
                    location=f"{callee}@entry",
                    context_hash=self._context_hash([func, callee][:self.max_context_depth])
                )
                deeper = self._trace_forward(
                    new_fact, callee, callee_calls, 0,
                    call_graph, func_calls, depth + 1
                )
                paths.extend(deeper)

        return paths

    def _trace_backward(self, fact: DataFlowFact, func: str,
                        calls: List[Tuple[int, str]],
                        start_addr: int,
                        call_graph: CallGraph,
                        func_calls: Dict[str, List[Tuple[int, str]]],
                        depth: int = 0) -> List[DataFlowPath]:
        """????: ? sink ????? source"""
        if depth > self.max_context_depth:
            return []

        paths: List[DataFlowPath] = []

        # ? start_addr ???????
        prior = [(a, c) for a, c in calls if a < start_addr]

        current_path = [fact]

        for addr, callee in reversed(prior):
            source_spec = self._ss_db.get_source(callee)
            if source_spec:
                paths.append(DataFlowPath(
                    source=f"{callee}@{hex(addr)} ({source_spec.taint_kind.value})",
                    sink=fact.location,
                    path=current_path + [
                        DataFlowFact(
                            var_name=f"source:{callee}",
                            taint_kind=source_spec.taint_kind,
                            location=f"{func}@{hex(addr)}"
                        )
                    ],
                    taint_kind=source_spec.taint_kind,
                    confidence=0.9 - (0.1 * depth)
                ))

            # ?????????
            sanitizer = self._ss_db.get_sanitizer(callee)
            if sanitizer:
                for p in paths:
                    p.sanitized = True
                    p.sanitizer = callee
                continue

            # ???????
            callers = call_graph.callers_of(func)
            for caller in callers:
                if caller in func_calls:
                    caller_calls = func_calls[caller]
                    new_fact = DataFlowFact(
                        var_name=f"ret_of_{func}",
                        taint_kind=TaintKind.DERIVED,
                        location=f"{caller}?{func}",
                        context_hash=self._context_hash(
                            [caller, func][:self.max_context_depth])
                    )
                    deeper = self._trace_backward(
                        new_fact, caller, caller_calls, 0,
                        call_graph, func_calls, depth + 1
                    )
                    paths.extend(deeper)

        return paths

    def build_function_summary(self, func_name: str,
                               params: List[str],
                               func_calls: Dict[str, List[Tuple[int, str]]]) -> FunctionSummary:
        """?????????"""
        if func_name in self._summary_cache:
            return self._summary_cache[func_name]

        calls = func_calls.get(func_name, [])
        summary = FunctionSummary(func_name=func_name, params=params)

        for addr, callee in calls:
            # ?????? source
            if self._ss_db.get_source(callee):
                summary.returns_tainted = True
                src = self._ss_db.get_source(callee)
                if src:
                    summary.return_taint_kinds.append(src.taint_kind)
            # ?????? sink
            if self._ss_db.get_sink(callee):
                summary.side_effects[0] = True  # ????????????

        self._summary_cache[func_name] = summary
        return summary

    def invalidate_cache(self):
        """???????"""
        self._summary_cache.clear()


class InterproceduralDataflow:
    """docstring"""

    def __init__(self, max_context_depth: int = 3):
        self.analyzer = DataFlowAnalyzer(max_context_depth)
        self.call_graph = CallGraph()
        self.func_calls: Dict[str, List[Tuple[int, str]]] = {}
        self._findings: List[DataFlowPath] = []

    def load_call_graph(self, edges: List[Tuple[str, str]]):
        """?????"""
        for caller, callee in edges:
            self.call_graph.add_edge(caller, callee)

    def load_function_calls(self, func_name: str,
                            calls: List[Tuple[int, str]]):
        """?????????"""
        self.func_calls[func_name] = calls

    def analyze(self, funcs_of_interest: Optional[List[str]] = None,
                direction: DataFlowDirection = DataFlowDirection.BACKWARD,
                **kwargs) -> Dict[str, Any]:
        """
        ??????????

        """
        functions = funcs_of_interest if funcs_of_interest else list(
            self.call_graph.functions)

        if direction == DataFlowDirection.BACKWARD:
            paths = self.analyzer.analyze_backward(
                self.call_graph, functions, self.func_calls)
        else:
            paths = self.analyzer.analyze_forward(
                self.call_graph, functions, self.func_calls)

        self._findings = paths
        return {
            'success': True,
            'total_paths': len(paths),
            'paths': [p.to_dict() for p in paths[:100]],
            'stats': {
                'functions_analyzed': len(functions),
                'call_graph_size': len(self.call_graph.functions),
                'tainted_paths': len(paths),
                'sanitized_paths': sum(1 for p in paths if p.sanitized),
                'critical_paths': sum(1 for p in paths if p.severity == 'critical'),
                'high_severity_paths': sum(1 for p in paths if p.severity == 'high'),
            }
        }

    def generate_report(self) -> Dict[str, Any]:
        """?????????"""
        if not self._findings:
            return {
                'success': True,
                'summary': '??????????',
                'risk_level': 'none',
                'findings': []
            }

        critical = sum(1 for p in self._findings
                      if p.severity == 'critical' and not p.sanitized)
        high = sum(1 for p in self._findings
                  if p.severity == 'high' and not p.sanitized)

        if critical > 0:
            risk = 'critical'
        elif high > 3:
            risk = 'high'
        elif high > 0:
            risk = 'medium'
        else:
            risk = 'low'

        return {
            'success': True,
            'summary': f'?? {len(self._findings)} ??????, '
                      f'?? {critical} critical, {high} high (???)',
            'risk_level': risk,
            'total_paths': len(self._findings),
            'findings': [p.to_dict() for p in self._findings[:200]],
            'sanitized_count': sum(1 for p in self._findings if p.sanitized),
            'recommendations': [
                '?????????????????????????????',
                '??????????????????/?????',
                '??????????? (-fstack-protector, -D_FORTIFY_SOURCE=2)'
            ]
        }


# Analysis entry point

def analyze_interprocedural_dataflow(
    call_edges: List[Tuple[str, str]],
    func_calls: Dict[str, List[Tuple[int, str]]],
    funcs_of_interest: Optional[List[str]] = None,
    direction: str = "backward"
) -> Dict[str, Any]:
    """
    ????????????

    """
    analyzer = InterproceduralDataflow()
    analyzer.load_call_graph(call_edges)

    for func_name, calls in func_calls.items():
        analyzer.load_function_calls(func_name, calls)

    dir_enum = (DataFlowDirection.BACKWARD if direction == "backward"
                else DataFlowDirection.FORWARD)
    result = analyzer.analyze(funcs_of_interest, dir_enum)
    report = analyzer.generate_report()
    result['report'] = report
    return result


__all__ = [
    "InterproceduralDataflow",
    "DataFlowAnalyzer",
    "CallGraph",
    "DataFlowFact",
    "DataFlowPath",
    "FunctionSummary",
    "TaintKind",
    "DataFlowDirection",
    "SourceSpec",
    "SinkSpec",
    "SanitizerSpec",
    "analyze_interprocedural_dataflow"
]
