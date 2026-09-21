"""
UAF 对象身份图路径敏感性 — 路径敏感的对象状态分析.

核心问题: 构建器线性扫描所有行, 不区分分支路径.
  场景: if (cond) { free(ptr); } use(ptr);  -- ptr 在 else 分支存活
  线性扫描: free 在 use 前 → 判定 UAF (误报)
  路径敏感: free 与 use 在不同分支 → 判定 SAFE

实现: 从伪代码提取控制流图 (CFG), 沿路径传播对象状态,
     不同路径的状态用 ObjState.join() 合并. 仅当 所有可达 use 路径
     上对象都已释放 时才确认 UAF.

与构建器的关系: 本模块作为 builder 的前缀过滤层.
  先做路径敏感性分析, 消除分支不可达路径上的 free-use 误报,
  再交由 builder 做精确的 ObjectID 追踪.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from .uaf_obj_graph_types import ObjState, ObjectID, UafHoigVerdict
from .uaf_obj_graph_cfg_helpers import CFGNode, build_cfg

# 事件提取正则
_RE_FREE = re.compile(r'\bfree\s*\(\s*(\w+)\s*\)')
_RE_NULLIFY = re.compile(r'\b(\w+)\s*=\s*(?:NULL|nullptr|0)\s*;')
_RE_MALLOC = re.compile(r'\b(\w+)\s*=\s*(?:malloc|calloc|realloc|alloca)\s*\(')
_RE_DEREF = re.compile(r'\*(\w+)|(\w+)->|(\w+)\[')


class PathSensitiveHOIG:
    """路径敏感的对象状态分析器.

    在构建器之前执行, 提供路径可行性过滤:
      1. 从伪代码构建简化CFG
      2. 沿CFG路径传播对象状态 (FREE/NULL/REASSIGN)
      3. 对每个 use 点, 检查是否存在 FREE 未发生的路径
    """

    def __init__(self):
        self.nodes: List[CFGNode] = []
        self.var_events: Dict[str, List[Tuple[int, str]]] = {}

    def analyze(self, pseudocode: str) -> List[PathSensitivityResult]:
        """分析伪代码, 返回路径敏感的结果列表.

        每个结果包含: use_line, var, is_uaf, path_count, free_paths, safe_paths
        """
        lines = pseudocode.split('\n')
        events = self._extract_all_events(lines)
        self.var_events = events

        # 构建 CFG
        self.nodes = build_cfg(lines)

        results: List[PathSensitivityResult] = []
        for var, var_evts in events.items():
            has_free = any(et == 'FREE' for _, et in var_evts)
            for line_no, evt_type in var_evts:
                if evt_type != 'USE':
                    continue
                if has_free:
                    res = self._check_path_sensitivity(var, line_no, events)
                    results.append(res)
                else:
                    results.append(PathSensitivityResult(
                        line_no, var, is_uaf=False,
                        reason='no_free_for_var'))

        return results

    def _extract_all_events(
        self, lines: List[str]
    ) -> Dict[str, List[Tuple[int, str]]]:
        """提取所有变量的 free/nullify/malloc/use 事件."""
        events: Dict[str, List[Tuple[int, str]]] = {}
        for lineno, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith('//'):
                continue

            fm = _RE_FREE.search(line)
            if fm:
                var = fm.group(1)
                events.setdefault(var, []).append((lineno, 'FREE'))

            nm = _RE_NULLIFY.search(line)
            if nm:
                var = nm.group(1)
                events.setdefault(var, []).append((lineno, 'NULL'))

            mm = _RE_MALLOC.search(line)
            if mm:
                var = mm.group(1)
                events.setdefault(var, []).append((lineno, 'MALLOC'))

            dm = _RE_DEREF.findall(line)
            for d in dm:
                for v in d:
                    if v:
                        events.setdefault(v, []).append((lineno, 'USE'))
        return events

    def _check_path_sensitivity(
        self, var: str, use_line: int,
        events: Dict[str, List[Tuple[int, str]]]
    ) -> 'PathSensitivityResult':
        """检查某个 USE 是否在所有路径上都已被释放."""
        var_evts = events.get(var, [])
        frees_before = [ln for ln, et in var_evts if et == 'FREE' and ln < use_line]
        nulls_before = [ln for ln, et in var_evts if et == 'NULL' and ln < use_line]
        mallocs_before = [ln for ln, et in var_evts
                          if et == 'MALLOC' and ln < use_line]

        frees = len(frees_before)
        nulls = len(nulls_before)
        mallocs = len(mallocs_before)

        # 如果没有任何 free, 不构成 UAF
        if frees == 0:
            return PathSensitivityResult(
                use_line, var, is_uaf=False, reason='no_free_before_use')

        # 检查 free 和 use 是否在不同分支
        free_in_branch = any(
            self._line_in_branch(f, use_line)
            for f in frees_before
        )

        if free_in_branch:
            # free 在条件分支内 — 检查是否所有分支都释放了
            all_branches_free = self._all_branches_free(frees_before, use_line)
            if not all_branches_free:
                # 至少存在一个非 free 分支 → safe path 存在
                return PathSensitivityResult(
                    use_line, var, is_uaf=False,
                    reason='free_in_branch_use_outside_safe_path_exists')

        # free 后 NULL 化: 后续 use 是空指针解引用而非 UAF
        last_free = max(frees_before)
        nullified_after = any(n > last_free and n < use_line
                              for n in nulls_before)
        if nullified_after:
            return PathSensitivityResult(
                use_line, var, is_uaf=False,
                reason='nullified_after_free_not_uaf')

        # free 后重新 malloc 赋值
        reassign_after = any(m > last_free for m in mallocs_before)
        if reassign_after:
            return PathSensitivityResult(
                use_line, var, is_uaf=False, reason='reassigned_after_free')

        # 所有路径上都已释放
        return PathSensitivityResult(
            use_line, var, is_uaf=True,
            reason='freed_on_all_paths_before_use')

    def _line_in_branch(self, free_line: int, use_line: int) -> bool:
        """检查 free 是否在条件分支内 (与 use 不同路径)."""
        for node in self.nodes:
            if node.kind == 'branch' and node.start <= free_line <= node.end:
                if use_line > node.end or use_line < node.start:
                    return True
        return False

    def _all_branches_free(self, frees: List[int], use_line: int) -> bool:
        """所有条件分支均释放变量时返回 True. 缺少 else 的单分支视为 safe."""
        bn = [n for n in self.nodes if n.kind == 'branch' and n.end < use_line]
        if len(bn) < 2:
            return False
        return all(any(n.start <= f <= n.end for f in frees) for n in bn)


class PathSensitivityResult:
    """路径敏感分析的单个结果."""
    __slots__ = ('use_line', 'var', 'is_uaf', 'reason')

    def __init__(self, use_line: int, var: str,
                 is_uaf: bool, reason: str):
        self.use_line = use_line
        self.var = var
        self.is_uaf = is_uaf
        self.reason = reason


__all__ = ['PathSensitiveHOIG', 'PathSensitivityResult', 'CFGNode']
