"""
PTASM 引擎 — Pointer Temporal Automaton State Machine 核心.

在简化CFG上做指针状态传播: 每个基本块维护 {ptr_name → PtrState},
分支处 fork, 汇合处 join. 仅在全体路径证明安全时 FILTER.

与现有UAF模块的关系:
  - uaf_verifier.py (TARPS): 五阶段正则模式匹配 → 置信度调整
  - uaf_path_verifier.py: CFG可达性 (free块→use块 BFS)
  - 本模块: 形式化状态机 + 路径敏感状态传播 + 别名等价类
  - 三者互补: TARPS做粗筛 → path_verifier做CFG分析 → PTASM做精确判定

方法:
  1. 从C/伪代码构建简化CFG (复用 uaf_cfg_builder 或自建)
  2. 逐行解析操作: free/malloc/nullify/assign/use
  3. 在每个基本块维护指针状态映射
  4. 分支结束时 fork 状态; 汇合时 join (LIVE+NULLIFIED=FREED, 任一路径危险=危险)
  5. 别名传播: q=p 后 free(p) → q 也进入 FREED

保守性保证:
  - 仅当 ALL 可达路径上指针状态为 NULLIFIED 或 REASSIGNED 时才判定 SAFE
  - 任一路径状态为 FREED + 后续use → UAF
  - 无法确定时 → UNCERTAIN (保留候选项)

▎_TRANSITION/_apply_ops → analysis.ptasm_state_machine
▎_path_sensitive_analyze → analysis.ptasm_path_analyzer
▎_scan_free_wrappers → analysis.ptasm_free_wrappers
"""


import re
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from analysis.ptasm_types import (
    PtrState, PtrTransition, PtrInfo, PTASMResult,
    parse_line_operations,
)
from analysis.ptasm_ctrl_flow import (
    normalize_single_line_ifs,
    find_branch_bodies,
    join_ptr_states,
)
from analysis.ptasm_state_machine import apply_ptr_ops
from analysis.ptasm_path_analyzer import path_sensitive_analyze
from analysis.ptasm_free_wrappers import scan_free_wrappers


@dataclass
class PTASMStats:
    """PTASM 分析统计."""
    allocs_found: int = 0
    frees_found: int = 0
    uses_found: int = 0
    aliases_tracked: int = 0
    uaf_confirmed: int = 0
    safe_filtered: int = 0
    uncertain: int = 0
    paths_explored: int = 0


class PTASMEngine:
    """指针时序自动机引擎 — 形式化UAF判定.

    核心: 在CFG上传播指针状态, 利用状态机转移规则判定UAF.
    """

    _CTRL_KW = {'if', 'else', 'for', 'while', 'do', 'switch', 'case',
                'return', 'goto', 'break', 'continue'}

    def __init__(self, max_paths: int = 256):
        self._max_paths = max_paths
        self._alias_map: Dict[str, str] = {}         # ptr → canonical
        self._reverse_alias: Dict[str, Set[str]] = {}  # canonical → {aliases}
        self._free_wrappers: Dict[str, int] = {}      # func_name → param_index
        self.stats = PTASMStats()

    def analyze(self, source: str) -> Tuple[List[PTASMResult], PTASMStats]:
        """主入口: 分析源码中的UAF模式 (递归分段 + 路径敏感)."""
        self.stats = PTASMStats()
        self._alias_map.clear()
        self._reverse_alias.clear()

        lines = source.splitlines()
        lines = normalize_single_line_ifs(lines)
        self._free_wrappers = scan_free_wrappers(lines)

        ptr_states: Dict[str, PtrInfo] = {}
        self._build_alias_graph(lines)
        self._collect_ptr_operations(lines, ptr_states)

        self.stats.allocs_found = sum(1 for p in ptr_states.values()
                                      if p.alloc_line > 0)
        self.stats.frees_found = sum(1 for p in ptr_states.values()
                                     if p.free_line > 0)

        results = path_sensitive_analyze(lines, ptr_states, self)

        for r in results:
            if r.uaf_detected:
                self.stats.uaf_confirmed += 1
            elif r.safe:
                self.stats.safe_filtered += 1
            else:
                self.stats.uncertain += 1

        return results, self.stats

    # 别名图构建

    def _build_alias_graph(self, lines: List[str]) -> None:
        """扫描赋值语句, 构建指针别名等价类.

        q = p → q 是 p 的别名, free(p) 意味着 free(q).
        使用 Union-Find 风格: 所有别名指向 canonical name.

        排除: 函数调用返回值 (buf = func() — 不是别名).
        """
        for line in lines:
            s = line.strip()
            if s.startswith('//') or s.startswith('/*') or s.startswith('*'):
                continue
            ops = parse_line_operations(s)
            for op_type, info in ops:
                if op_type == 'assign':
                    lhs, rhs = info['lhs'], info['rhs']
                    if re.search(r'\b' + re.escape(rhs) + r'\s*\(', s):
                        continue
                    canonical = self._find_canonical(rhs)
                    self._alias_map[lhs] = canonical
                    if canonical not in self._reverse_alias:
                        self._reverse_alias[canonical] = set()
                    self._reverse_alias[canonical].add(lhs)
                    self.stats.aliases_tracked += 1

    def _find_canonical(self, ptr: str) -> str:
        """沿别名链找到 canonical name."""
        seen = {ptr}
        cur = ptr
        while cur in self._alias_map and self._alias_map[cur] != cur:
            cur = self._alias_map[cur]
            if cur in seen:
                break
            seen.add(cur)
        self._alias_map[ptr] = cur
        return cur

    def _all_aliases(self, ptr: str) -> Set[str]:
        """返回 ptr 及其所有别名."""
        canonical = self._find_canonical(ptr)
        result = {canonical}
        if canonical in self._reverse_alias:
            result.update(self._reverse_alias[canonical])
        result.add(ptr)
        return result

    # 操作收集 (仅识别追踪目标, 不做状态判定)

    def _collect_ptr_operations(self, lines: List[str],
                                 ptr_states: Dict[str, PtrInfo]) -> None:
        """逐行扫描, 收集每个指针的操作信息 (仅记录行号, 不做状态判定).

        状态判定全部交给 path_sensitive_analyze 完成.
        """
        for i, line in enumerate(lines):
            line_no = i + 1
            ops = parse_line_operations(line)
            for op_type, info in ops:
                # free-wrapper 调用: 记录实参 free_line
                if op_type == 'call':
                    func_name = info.get('func', '')
                    if func_name in self._free_wrappers:
                        param_idx = self._free_wrappers[func_name]
                        args = info.get('args', [])
                        if param_idx < len(args):
                            ptr = args[param_idx]
                            ptr = re.sub(r'\[[^\]]*\]', '', ptr)
                            all_ptrs = self._all_aliases(ptr)
                            for p in all_ptrs:
                                if p not in ptr_states:
                                    ptr_states[p] = PtrInfo(name=p)
                                pi = ptr_states[p]
                                if pi.free_line == 0:
                                    pi.free_line = line_no
                    continue

                ptr = info.get('ptr', '')
                if not ptr:
                    continue
                ptr = re.sub(r'\[[^\]]*\]', '', ptr)
                all_ptrs = self._all_aliases(ptr)
                for p in all_ptrs:
                    if p not in ptr_states:
                        ptr_states[p] = PtrInfo(name=p)
                    pi = ptr_states[p]
                    if op_type == 'malloc':
                        pi.alloc_line = line_no
                    elif op_type == 'free':
                        if pi.free_line == 0:
                            pi.free_line = line_no


# 管线API层已迁移到 ptasm_pipeline.py
# 为保持向后兼容, 从此处重新导出
from analysis.ptasm_pipeline import (
    PTASM_PROTECTED, PTASM_CONFIRMED, PTASM_UNCERTAIN,
    ptasm_analyze, ptasm_verify_candidates,
    ptasm_detect_uaf, ptasm_pipeline_detect,
)


__all__ = [
    'PTASMEngine', 'PTASMStats',
    'PTASM_PROTECTED', 'PTASM_CONFIRMED', 'PTASM_UNCERTAIN',
    'ptasm_analyze', 'ptasm_verify_candidates',
    'ptasm_detect_uaf', 'ptasm_pipeline_detect',
]
