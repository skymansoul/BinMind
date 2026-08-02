"""
Taint propagation engine — byte-level taint tracking via worklist-driven FP iteration.
Round 4: Ghidra headless-style AnalysisContext for state management between passes.
Error hierarchy replaces bare string errors with typed exceptions.
"""
import os, logging, re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Tuple
from enum import IntFlag, auto
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

# ── Round 4: Error taxonomy ──
# Ghidra headless scripting emphasizes domain-specific error types
# over generic exceptions, enabling precise error recovery strategies.

class TaintError(Exception):
    """污点分析错误基类"""

class VariableNotFoundError(TaintError):
    """变量未在符号表中注册"""

class PropagationCycleError(TaintError):
    """检测到循环传播路径，迭代超限"""

class TaintTag(IntFlag):
    NONE = 0
    USER_INPUT = auto()
    NETWORK_DATA = auto()
    FILE_READ = auto()
    ENV_VARIABLE = auto()
    REGISTRY = auto()
    DERIVED = auto()
    REGISTER = auto()
    CONSTANT = auto()

TaintSource = TaintTag

class TaintSink:
    SYSTEM_CALL = "system_call"
    NETWORK_SEND = "network_send"
    FILE_WRITE = "file_write"
    SHELL_EXEC = "shell_exec"
    FORMAT_STRING = "format_string"

class TaintLevel:
    CLEAN = 0
    TAINTED = 1
    UNKNOWN = 2

@dataclass
class TaintInfo:
    source: Optional[TaintTag] = None
    level: int = TaintLevel.CLEAN
    path: List[str] = field(default_factory=list)
    confidence: float = 0.0
    src_line: int = 0
    src_file: str = ""

# ── BitSet ────────────────────────────────────────────────────────────────────

class BitSet:
    __slots__ = ('_size', '_words', '_data')

    def __init__(self, size: int = 1024):
        self._size = size
        self._words = (size + 63) // 64
        self._data = [0] * self._words

    def set(self, index: int) -> None:
        if index < 0 or index >= self._size:
            raise IndexError("Bit index out of range")
        self._data[index // 64] |= 1 << (index % 64)

    def clear(self, index: int) -> None:
        if index < 0 or index >= self._size:
            raise IndexError("Bit index out of range")
        self._data[index // 64] &= ~(1 << (index % 64))

    def get(self, index: int) -> bool:
        if index < 0 or index >= self._size:
            raise IndexError("Bit index out of range")
        return (self._data[index // 64] & (1 << (index % 64))) != 0

    def union(self, other: 'BitSet') -> 'BitSet':
        result = BitSet(self._size)
        for i in range(self._words):
            result._data[i] = self._data[i] | other._data[i]
        return result

    def intersection(self, other: 'BitSet') -> 'BitSet':
        result = BitSet(self._size)
        for i in range(self._words):
            result._data[i] = self._data[i] & other._data[i]
        return result

    def difference(self, other: 'BitSet') -> 'BitSet':
        result = BitSet(self._size)
        for i in range(self._words):
            result._data[i] = self._data[i] & ~other._data[i]
        return result

    def is_empty(self) -> bool:
        return all(w == 0 for w in self._data)

    def count(self) -> int:
        return sum(bin(w).count('1') for w in self._data)

    def copy(self) -> 'BitSet':
        result = BitSet(self._size)
        result._data = self._data.copy()
        return result

    def __or__(self, other: 'BitSet') -> 'BitSet':
        return self.union(other)

    def __and__(self, other: 'BitSet') -> 'BitSet':
        return self.intersection(other)

    def __sub__(self, other: 'BitSet') -> 'BitSet':
        return self.difference(other)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, BitSet) and self._data == other._data

    def __hash__(self) -> int:
        return hash(tuple(self._data))

    def iter_set_bits(self):
        for word_idx, word in enumerate(self._data):
            if not word:
                continue
            base = word_idx * 64
            for bit in range(64):
                if word & (1 << bit):
                    yield base + bit

# ── TaintMap ──────────────────────────────────────────────────────────────────

class TaintMap:
    def __init__(self):
        self._registers: Dict[str, int] = defaultdict(int)
        self._memory: Dict[int, int] = {}
        self._tag_history: deque = deque(maxlen=200)

    def tag_register(self, reg: str, tag: TaintTag) -> None:
        self._registers[reg] |= tag

    def set_register(self, reg: str, tag: int) -> None:
        self._registers[reg] = tag

    def get_register(self, reg: str) -> int:
        return self._registers.get(reg, 0)

    def clear_register(self, reg: str) -> None:
        self._registers.pop(reg, None)

    def tag_memory(self, addr: int, size: int, tag: TaintTag) -> None:
        for off in range(size):
            k = addr + off
            self._memory[k] = self._memory.get(k, 0) | tag
        self._tag_history.append(('tag_mem', addr, size, tag))

    def set_memory(self, addr: int, tag: int) -> None:
        self._memory[addr] = tag

    def get_memory(self, addr: int) -> int:
        return self._memory.get(addr, 0)

    def get_memory_range(self, addr: int, size: int) -> int:
        combined = 0
        for off in range(size):
            combined |= self._memory.get(addr + off, 0)
        return combined

    def propagate(self, dst_addr: int, src_addr: int, size: int) -> None:
        for off in range(size):
            src_tag = self._memory.get(src_addr + off, 0)
            if src_tag:
                self._memory[dst_addr + off] = src_tag | TaintTag.DERIVED

    def propagate_register_to_memory(self, reg: str, addr: int, size: int) -> None:
        tag = self._registers.get(reg, 0) | TaintTag.DERIVED
        for off in range(size):
            self._memory[addr + off] |= tag

    def propagate_binary_op(self, dst_reg: str, src_regs: List[str]) -> None:
        merged = TaintTag.DERIVED
        for r in src_regs:
            merged |= self._registers.get(r, 0)
        self._registers[dst_reg] = merged

    def is_tainted(self, addr: int, size: int = 1) -> bool:
        return any(self._memory.get(addr + off, 0) != 0 for off in range(size))

    def is_register_tainted(self, reg: str) -> bool:
        return self._registers.get(reg, 0) != 0

# ── Round 4: Ghidra headless-style AnalysisContext ────────────────────────────
# Ghidra的headless分析使用Program/AddressFactory等上下文对象在分析阶段间
# 传递状态。此处AnalysisContext提供等价的符号表+规则集的共享上下文。

@dataclass
class AnalysisContext:
    """Ghidra headless风格的共享分析上下文。
    在多个TaintEngine实例间共享符号表和传播规则。"""
    variable_count: int = 1024
    symbol_table: Dict[str, int] = field(default_factory=dict)
    next_var_id: int = 0
    propagation_rules: List[Tuple[BitSet, BitSet]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def register_variable(self, name: str) -> int:
        if name not in self.symbol_table:
            self.symbol_table[name] = self.next_var_id
            self.next_var_id += 1
        return self.symbol_table[name]

    def add_rule(self, sources: List[int], targets: List[int]) -> None:
        sb = BitSet(self.variable_count)
        for s in sources:
            sb.set(s)
        tb = BitSet(self.variable_count)
        for t in targets:
            tb.set(t)
        self.propagation_rules.append((sb, tb))

class TaintEngine:
    def __init__(self, context: Optional[AnalysisContext] = None):
        self._ctx = context or AnalysisContext()
        self._num_variables = self._ctx.variable_count
        self._tainted_vars = BitSet(self._num_variables)
        self._source_info: Dict[int, TaintInfo] = {}
        self._taint_map = TaintMap()
        self._iteration_cap = 100

    @property
    def taint_map(self) -> TaintMap:
        return self._taint_map

    def add_taint_source(self, var_index: int, source: TaintTag,
                         src_line: int = 0, src_file: str = "") -> None:
        self._tainted_vars.set(var_index)
        self._source_info[var_index] = TaintInfo(
            source=source, level=TaintLevel.TAINTED,
            confidence=1.0, src_line=src_line, src_file=src_file)

    def propagate(self) -> None:
        changed = True
        iteration = 0
        while changed and iteration < self._iteration_cap:
            changed = False
            iteration += 1
            new_tainted = self._tainted_vars.copy()
            for sources, targets in self._ctx.propagation_rules:
                if not (sources & self._tainted_vars).is_empty():
                    new_tainted = new_tainted | targets
            if new_tainted != self._tainted_vars:
                changed = True
                self._tainted_vars = new_tainted

        if iteration >= self._iteration_cap and changed:
            raise PropagationCycleError(
                f"Taint propagation exceeded {self._iteration_cap} iterations")

    def is_tainted(self, var_index: int) -> bool:
        if var_index < 0 or var_index >= self._num_variables:
            return False
        return self._tainted_vars.get(var_index)

    def get_taint_info(self, var_index: int) -> Optional[TaintInfo]:
        return self._source_info.get(var_index)

    def get_all_tainted(self) -> List[int]:
        return [i for i in range(self._num_variables) if self.is_tainted(i)]

    def clear(self) -> None:
        self._tainted_vars = BitSet(self._num_variables)
        self._source_info.clear()
        self._taint_map = TaintMap()

class TaintAnalysis:
    def __init__(self):
        self._ctx = AnalysisContext()
        self._engine = TaintEngine(self._ctx)

    def register_variable(self, var_name: str) -> int:
        return self._ctx.register_variable(var_name)

    def taint_variable(self, var_name: str, source: TaintTag) -> None:
        var_id = self.register_variable(var_name)
        self._engine.add_taint_source(var_id, source)

    def add_propagation(self, source_vars: List[str], target_vars: List[str]) -> None:
        source_ids = [self.register_variable(v) for v in source_vars]
        target_ids = [self.register_variable(v) for v in target_vars]
        self._ctx.add_rule(source_ids, target_ids)

    def run(self) -> None:
        self._engine.propagate()

    def check_taint(self, var_name: str) -> bool:
        var_id = self._ctx.symbol_table.get(var_name)
        if var_id is None:
            return False
        return self._engine.is_tainted(var_id)

    def find_taint_paths(self, sink_var: str) -> List[List[str]]:
        var_id = self._ctx.symbol_table.get(sink_var)
        if var_id is None or not self._engine.is_tainted(var_id):
            return []
        results: List[List[str]] = []
        visited: Set[int] = set()
        self._dfs_paths(var_id, [], visited, results)
        return results

    def _dfs_paths(self, var_id: int, path: List[int],
                   visited: Set[int], results: List[List[str]]):
        visited.add(var_id)
        info = self._engine.get_taint_info(var_id)
        if info and info.source:
            path.append(var_id)
            results.append([self._get_var_name(v) for v in path])
            path.pop()
            visited.discard(var_id)
            return
        path.append(var_id)
        for sources, targets in self._ctx.propagation_rules:
            if targets.get(var_id):
                for src_id in sources.iter_set_bits():
                    if src_id not in visited:
                        self._dfs_paths(src_id, path, visited, results)
        path.pop()
        visited.discard(var_id)

    def _get_var_name(self, var_id: int) -> str:
        for name, vid in self._ctx.symbol_table.items():
            if vid == var_id:
                return name
        return f"var_{var_id}"

    def infer_sources_from_pseudocode(self, sink_func: str,
                                       pseudocode: str) -> List[str]:
        sources = []
        assign_pat = re.compile(r'(\w+)\s*=\s*([^;]+)')
        source_patterns = [
            (r'(?:arg[0-9]+|a[0-9]+|param[0-9]+)', 'function_arg'),
            (r'(?:read|fread|recv|getenv|scanf)\s*\(', 'external_input'),
            (r'(?:global_|g_)\w+', 'global_var'),
            (r'(?:\*|->)\s*\w+', 'memory_deref'),
            (r'\[.*\]', 'array_index'),
        ]
        sink_params = set()
        for m in assign_pat.finditer(pseudocode):
            lhs, rhs = m.group(1), m.group(2)
            if sink_func in rhs:
                sink_params.add(lhs)

        queue = deque(sink_params)
        visited_params = set(sink_params)
        while queue:
            var = queue.popleft()
            for m in assign_pat.finditer(pseudocode):
                lhs, rhs = m.group(1), m.group(2)
                if var in rhs and lhs not in visited_params:
                    visited_params.add(lhs)
                    for pat, cat in source_patterns:
                        if re.search(pat, rhs):
                            sources.append(f"{lhs} ({cat})")
                            break
                    else:
                        queue.append(lhs)
        return sources

    @staticmethod
    def consensus_vote(static_results: List[str],
                       dynamic_results: List[str],
                       frida_results: List[str]) -> Dict[str, Any]:
        all_sources = set(static_results + dynamic_results + frida_results)
        verdicts = {}
        for src in all_sources:
            votes = sum(1 for r in (static_results, dynamic_results, frida_results)
                       if src in r)
            verdicts[src] = {
                'votes': votes,
                'consensus': votes >= 2,
                'severity': 'HIGH' if votes >= 2 else 'LOW',
            }
        return {
            'total_sources': len(all_sources),
            'consensus_sources': sum(1 for v in verdicts.values() if v['consensus']),
            'single_backend_sources': sum(1 for v in verdicts.values()
                                          if not v['consensus']),
            'verdicts': verdicts,
        }

class TaintChecker:
    def __init__(self):
        self._sinks: Dict[str, str] = {}

    def register_sink(self, func_name: str, sink_type: str) -> None:
        self._sinks[func_name] = sink_type

    def check_sinks(self, analysis: TaintAnalysis) -> List[Dict[str, Any]]:
        results = []
        for func_name, sink_type in self._sinks.items():
            if analysis.check_taint(func_name):
                results.append({
                    "function": func_name,
                    "sink_type": sink_type,
                    "is_vulnerable": True,
                    "paths": analysis.find_taint_paths(func_name)
                })
        return results


def create_taint_analysis() -> TaintAnalysis:
    return TaintAnalysis()


def run_taint_analysis(
    sources: List[Tuple[str, TaintTag]],
    propagations: List[Tuple[List[str], List[str]]],
    sinks: List[str]
) -> List[Dict[str, Any]]:
    analysis = TaintAnalysis()
    for var_name, source_type in sources:
        analysis.taint_variable(var_name, source_type)
    for src_vars, tgt_vars in propagations:
        analysis.add_propagation(src_vars, tgt_vars)
    analysis.run()
    checker = TaintChecker()
    for sink in sinks:
        checker.register_sink(sink, TaintSink.SYSTEM_CALL)
    return checker.check_sinks(analysis)
