from __future__ import annotations
import os
import logging
from dataclasses import dataclass, field
import typing

logger = logging.getLogger(__name__)



class TaintSource:
    USER_INPUT = "user_input"
    NETWORK_DATA = "network_data"
    FILE_READ = "file_read"
    ENV_VARIABLE = "env_variable"
    REGISTRY = "registry"
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
    source: typing.Optional[str] = None
    level: int = TaintLevel.CLEAN
    path: typing.List = field(default_factory=list)
    confidence: float = 0.0

class BitSet:
    def __init__(self, size: int = 1024):
        self._size = size
        self._words = (size + 63) // 64
        self._data = [0] * self._words

    def set(self, index: int) -> None:
        if index < 0 or index >= self._size:
            raise IndexError("Bit index out of range")
        word = index // 64
        bit = index % 64
        self._data[word] |= 1 << bit

    def set_range(self, start: int, length: int) -> None:
        """设置 [start, start+length) 区间内的所有位。"""
        for i in range(start, min(start + length, self._size)):
            word = i // 64
            bit = i % 64
            self._data[word] |= 1 << bit

    def clear(self, index: int) -> None:
        if index < 0 or index >= self._size:
            raise IndexError("Bit index out of range")
        word = index // 64
        bit = index % 64
        self._data[word] &= ~(1 << bit)

    def get(self, index: int) -> bool:
        if index < 0 or index >= self._size:
            raise IndexError("Bit index out of range")
        word = index // 64
        bit = index % 64
        return (self._data[word] & (1 << bit)) != 0

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
        if not isinstance(other, BitSet):
            return False
        return self._data == other._data

    def __hash__(self) -> int:
        return hash(tuple(self._data))


class TaintEngine:
    def __init__(self, num_variables: int = 1024):
        self._num_variables = num_variables
        self._tainted_vars = BitSet(num_variables)
        self._source_info: Dict[int, TaintInfo] = {}
        self._propagation_rules: List[Tuple[BitSet, BitSet]] = []

    def add_taint_source(self, var_index: int, source: TaintSource) -> None:
        self._tainted_vars.set(var_index)
        self._source_info[var_index] = TaintInfo(
            source=source,
            level=TaintLevel.TAINTED,
            confidence=1.0
        )

    def add_propagation_rule(self, sources: List[int], targets: List[int]) -> None:
        source_bitset = BitSet(self._num_variables)
        for src in sources:
            source_bitset.set(src)
        target_bitset = BitSet(self._num_variables)
        for tgt in targets:
            target_bitset.set(tgt)
        self._propagation_rules.append((source_bitset, target_bitset))

    def propagate(self) -> None:
        changed = True
        iteration = 0
        max_iterations = 100
        while changed and iteration < max_iterations:
            changed = False
            iteration += 1
            new_tainted = self._tainted_vars.copy()
            for sources, targets in self._propagation_rules:
                if not (sources & self._tainted_vars).is_empty():
                    new_tainted = new_tainted | targets
            if new_tainted != self._tainted_vars:
                changed = True
                self._tainted_vars = new_tainted

    def is_tainted(self, var_index: int) -> bool:
        return self._tainted_vars.get(var_index)

    def get_taint_info(self, var_index: int) -> Optional[TaintInfo]:
        return self._source_info.get(var_index)

    def get_all_tainted(self) -> List[int]:
        return [i for i in range(self._num_variables) if self.is_tainted(i)]

    def clear(self) -> None:
        self._tainted_vars = BitSet(self._num_variables)
        self._source_info.clear()


class TaintAnalysis:
    def __init__(self):
        self._engine = TaintEngine()
        self._var_map: Dict[str, int] = {}
        self._next_var_id = 0

    def register_variable(self, var_name: str) -> int:
        if var_name not in self._var_map:
            self._var_map[var_name] = self._next_var_id
            self._next_var_id += 1
        return self._var_map[var_name]

    def taint_variable(self, var_name: str, source: TaintSource) -> None:
        var_id = self.register_variable(var_name)
        self._engine.add_taint_source(var_id, source)

    def add_propagation(self, source_vars: List[str], target_vars: List[str]) -> None:
        source_ids = [self.register_variable(v) for v in source_vars]
        target_ids = [self.register_variable(v) for v in target_vars]
        self._engine.add_propagation_rule(source_ids, target_ids)

    def run(self) -> None:
        self._engine.propagate()

    def check_taint(self, var_name: str) -> bool:
        var_id = self._var_map.get(var_name)
        if var_id is None:
            return False
        return self._engine.is_tainted(var_id)

    def find_taint_paths(self, sink_var: str) -> List[List[str]]:
        paths = []
        var_id = self._var_map.get(sink_var)
        if var_id is None or not self._engine.is_tainted(var_id):
            return paths
        return self._find_paths(var_id, [], set())

    def _find_paths(self, var_id: int, path: List[int], visited: Set[int]) -> List[List[str]]:
        paths = []
        visited.add(var_id)
        info = self._engine.get_taint_info(var_id)
        if info and info.source:
            path.append(var_id)
            paths.append([self._get_var_name(v) for v in path])
            path.pop()
            return paths
        for sources, targets in self._engine._propagation_rules:
            if targets.get(var_id):
                for src_id in range(self._engine._num_variables):
                    if sources.get(src_id) and src_id not in visited:
                        path.append(var_id)
                        paths.extend(self._find_paths(src_id, path, visited))
                        path.pop()
        return paths

    def _get_var_name(self, var_id: int) -> str:
        for name, vid in self._var_map.items():
            if vid == var_id:
                return name
        return f"var_{var_id}"

class TaintChecker:
    def __init__(self):
        self._sinks: Dict[str, TaintSink] = {}

    def register_sink(self, func_name: str, sink_type: TaintSink) -> None:
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


def run_taint_analysis(sources: List[Tuple[str, TaintSource]], propagations: List[Tuple[List[str], List[str]]], sinks: List[str]) -> List[Dict[str, Any]]:
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
