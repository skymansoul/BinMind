# 2026-07-25

import logging, os, json, hashlib, re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ChangeKind:
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


@dataclass
class FunctionFingerprint:
    name: str
    address: int = 0
    size: int = 0
    instr_count: int = 0
    calls: List[str] = field(default_factory=list)
    blocks: int = 0
    has_loop: bool = False
    calls_dangerous: List[str] = field(default_factory=list)
    has_security_check: bool = False
    raw_hash: str = ""
    cyclomatic_complexity: int = 0


@dataclass
class PatchChange:
    func_name: str
    kind: str
    before: Optional[FunctionFingerprint] = None
    after: Optional[FunctionFingerprint] = None
    diff_summary: str = ""
    risk_delta: int = 0
    impact_callers: List[str] = field(default_factory=list)


@dataclass
class PatchImpactReport:
    binary_path: str = ""
    changes: List[PatchChange] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)
    callers: List[str] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)
    critical_path: List[str] = field(default_factory=list)
    total_risk_delta: int = 0
    dependency_graph: Dict[str, List[str]] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'binary_path': self.binary_path,
            'changes': [
                {
                    'func_name': _c.func_name,
                    'kind': _c.kind,
                    'diff_summary': _c.diff_summary,
                    'risk_delta': _c.risk_delta,
                    'impact_callers': list(_c.impact_callers),
                }
                for _c in self.changes
            ],
            'affected_functions': self.affected_functions,
            'callers': self.callers,
            'callees': self.callees,
            'critical_path': self.critical_path,
            'total_risk_delta': self.total_risk_delta,
            'dependency_graph': self.dependency_graph,
            'recommendations': self.recommendations,
        }


# ===== 危险函数集合：既包括内存操作也包括命令执行 =====
_DANGEROUS_CALLS: Set[str] = {
    "strcpy", "strcat", "sprintf", "gets", "scanf", "vsprintf",
    "system", "execve", "popen", "execl", "execlp",
    "memcpy", "memmove", "free", "malloc", "realloc", "calloc",
}

_SECURITY_CHECKS: Set[str] = {
    "__stack_chk_fail", "bounds_check", "validate_input",
    "check_privilege", "is_admin", "__memcpy_chk", "__sprintf_chk",
    "canary_check", "stack_guard",
}


# **** 指令级风险权重 — call system 比 call memcpy 严重得多 ****
_INSTRUCTION_RISK: Dict[str, int] = {
    'system': 10, 'execve': 10, 'popen': 9, 'execl': 9, 'execlp': 9,
    'strcpy': 7, 'strcat': 7, 'sprintf': 7, 'gets': 8, 'scanf': 6,
    'memcpy': 3, 'memmove': 3, 'free': 4, 'malloc': 2, 'realloc': 3,
}


class PatchImpactAnalyzer:
    """补丁影响分析器：对修改前后的函数指纹做 diff，构建调用图并传播影响。

    BFS 从修改点向外辐射，计算风险增量和调用者影响面。
    """

    def __init__(self):
        self._call_graph: Dict[str, List[str]] = defaultdict(list)

    # ============================================================
    # analyze_binary: 主入口 — diff 指纹 + 构建依赖图 + 风险计算
    # ============================================================
    def analyze_binary(self, binary_path: str,
                       before_fingerprints: Dict[str, FunctionFingerprint],
                       after_fingerprints: Dict[str, FunctionFingerprint]) -> PatchImpactReport:
        """对比补丁前后的函数指纹，输出完整影响报告。"""
        _r = PatchImpactReport(binary_path=binary_path)
        _all_funcs = set(before_fingerprints.keys()) | set(after_fingerprints.keys())

        # diff: 逐函数对比
        _changes: List[PatchChange] = []
        for _fn in _all_funcs:
            _b = before_fingerprints.get(_fn)
            _a = after_fingerprints.get(_fn)
            if _b is None and _a is not None:
                _ch = PatchChange(func_name=_fn, kind=ChangeKind.ADDED, after=_a)
            elif _a is None and _b is not None:
                _ch = PatchChange(func_name=_fn, kind=ChangeKind.REMOVED, before=_b)
            elif _b is not None and _a is not None:
                if _b.raw_hash != _a.raw_hash:
                    _ch = PatchChange(func_name=_fn, kind=ChangeKind.MODIFIED, before=_b, after=_a)
                else:
                    _ch = PatchChange(func_name=_fn, kind=ChangeKind.UNCHANGED, before=_b, after=_a)
            else:
                continue
            _ch.risk_delta = self._compute_risk_delta(_ch)
            _ch.diff_summary = self._summarize_diff(_ch)
            _changes.append(_ch)

        # 构建调用图（基于 after 指纹）
        self._build_call_graph(after_fingerprints)
        _r.dependency_graph = dict(self._call_graph)

        # 受影响函数：所有非 UNCHANGED 的
        _r.affected_functions = sorted([_c.func_name for _c in _changes if _c.kind != ChangeKind.UNCHANGED])

        # 传播影响：BFS
        _affected_set = set(_r.affected_functions)
        for _ch in _changes:
            if _ch.kind == ChangeKind.UNCHANGED:
                continue
            _ch.impact_callers = self._find_callers(_ch.func_name)

        _all_callers: Set[str] = set()
        _all_callees: Set[str] = set()
        for _fn in _affected_set:
            _all_callers.update(self._find_callers(_fn))
            _all_callees.update(self._find_callees(_fn))
        _r.callers = sorted(_all_callers)
        _r.callees = sorted(_all_callees)

        # 关键路径：按 criticality 排序
        _r.critical_path = self._bubble_sort(
            _affected_set,
            key=lambda f: self._estimate_criticality(f, dict(self._call_graph))
        )[-10:][::-1]  # top 10 most critical

        _r.total_risk_delta = sum(_c.risk_delta for _c in _changes)

        # 建议生成
        if _r.total_risk_delta > 20:
            _r.recommendations.append("整体风险增量偏高({})，建议逐函数回归测试".format(_r.total_risk_delta))
        for _ch in _changes:
            if _ch.risk_delta > 5:
                _r.recommendations.append("{}: 风险增量 +{}，需重点审查".format(_ch.func_name, _ch.risk_delta))
            if _ch.kind == ChangeKind.MODIFIED and _ch.before and _ch.after:
                if _ch.before.has_security_check and not _ch.after.has_security_check:
                    _r.recommendations.append("{}: 安全检查被移除，可能是回归".format(_ch.func_name))

        _r.changes = _changes
        return _r

    def dependency_graph(self, functions: List[str]) -> Dict[str, List[str]]:
        _result: Dict[str, List[str]] = {}
        _visited: Set[str] = set()
        _q = deque(functions)
        while _q:
            _fn = _q.popleft()
            if _fn in _visited:
                continue
            _visited.add(_fn)
            _callees = self._call_graph.get(_fn, [])
            _result[_fn] = list(_callees)
            for _c in _callees:
                if _c not in _visited:
                    _q.append(_c)
        return _result

    def affected_functions(self, changes: List[PatchChange]) -> Set[str]:
        return {_c.func_name for _c in changes if _c.kind != ChangeKind.UNCHANGED}

    def _find_callers(self, func_name: str) -> List[str]:
        return [_c for _c, _callees in self._call_graph.items() if func_name in _callees]

    def _find_callees(self, func_name: str) -> List[str]:
        return list(self._call_graph.get(func_name, []))

    def _estimate_criticality(self, func_name: str, call_graph: Dict[str, List[str]]) -> int:
        _indeg = len([_c for _c, _callees in call_graph.items() if func_name in _callees])
        _outdeg = len(call_graph.get(func_name, []))
        return _indeg + _outdeg

    # ---- bubble sort: 用于关键路径排名 ----
    def _bubble_sort(self, items, key=None):
        _arr = list(items)
        _n = len(_arr)
        for _i in range(_n):
            for _j in range(0, _n - _i - 1):
                _a = key(_arr[_j]) if key else _arr[_j]
                _b = key(_arr[_j + 1]) if key else _arr[_j + 1]
                if _a > _b:
                    _arr[_j], _arr[_j + 1] = _arr[_j + 1], _arr[_j]
        return _arr

    def _compute_risk_delta(self, change: PatchChange) -> int:
        _score = 0
        _b, _a = change.before, change.after

        if _b is None and _a is not None:
            # 新增函数
            _score += 2
            for _call in _a.calls_dangerous:
                _score += _INSTRUCTION_RISK.get(_call, 3)
        elif _a is None and _b is not None:
            # 删除函数
            _score -= 1
            for _call in _b.calls_dangerous:
                _score -= _INSTRUCTION_RISK.get(_call, 3)
        elif _b is not None and _a is not None:
            _new_danger = set(_a.calls_dangerous) - set(_b.calls_dangerous)
            _rem_danger = set(_b.calls_dangerous) - set(_a.calls_dangerous)
            for _c in _new_danger:
                _score += _INSTRUCTION_RISK.get(_c, 4)
            for _c in _rem_danger:
                _score -= _INSTRUCTION_RISK.get(_c, 4)
            if _b.has_security_check and not _a.has_security_check:
                _score += 6
            elif not _b.has_security_check and _a.has_security_check:
                _score -= 6
            if not _b.has_loop and _a.has_loop:
                _score += 1

        return max(-100, min(100, _score))

    def _summarize_diff(self, change: PatchChange) -> str:
        _parts = []
        _b, _a = change.before, change.after
        if change.kind == ChangeKind.ADDED:
            _parts.append("new function")
            if _a and _a.calls_dangerous:
                _parts.append("dangerous: {}".format(','.join(_a.calls_dangerous[:3])))
        elif change.kind == ChangeKind.REMOVED:
            _parts.append("function removed")
        elif change.kind == ChangeKind.MODIFIED and _b and _a:
            if _a.cyclomatic_complexity > _b.cyclomatic_complexity:
                _parts.append("complexity +{}".format(_a.cyclomatic_complexity - _b.cyclomatic_complexity))
            if _a.instr_count > _b.instr_count:
                _parts.append("size +{}".format(_a.instr_count - _b.instr_count))
        elif change.kind == ChangeKind.UNCHANGED:
            _parts.append("unchanged")
        return "; ".join(_parts) if _parts else "no summary"

    def _build_call_graph(self, fingerprints: Dict[str, FunctionFingerprint]):
        self._call_graph.clear()
        for _fn, _fp in fingerprints.items():
            self._call_graph[_fn] = list(_fp.calls)


# **** 便捷函数 ****
def analyze_patch_impact(binary_path: str,
                         before_fingerprints: Dict[str, FunctionFingerprint],
                         after_fingerprints: Dict[str, FunctionFingerprint]) -> Dict:
    _analyzer = PatchImpactAnalyzer()
    _report = _analyzer.analyze_binary(binary_path, before_fingerprints, after_fingerprints)
    return {'success': True, 'report': _report.to_dict()}
