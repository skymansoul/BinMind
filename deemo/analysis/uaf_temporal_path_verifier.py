"""UAF路径敏感时序验证 — CFG追踪指针生命周期 BFS≤128路径 Union-Find别名 + return截断 + 恒假条件过滤."""

from __future__ import annotations
import re
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from analysis.lpvra_types import build_simple_cfg
from analysis.uaf_interprocedural import InterprocSummarizer
from analysis.uaf_temporal_path_types import (
    PtrState, TemporalVerdict, TemporalResult, _has_nullify_between)
from analysis.uaf_temporal_scanner import TemporalScanner
from analysis.uaf_temporal_path_helpers import detect_double_frees


class TemporalPathVerifier:
    """UAF路径敏感时序验证器 — 委托模式扫描给TemporalScanner."""

    _NULL_RE = re.compile(
        r'(\*?\w+(?:->\w+)?)\s*=\s*(?:NULL|0|nullptr|nil)\s*;', re.IGNORECASE)
    _RETURN_RE = re.compile(r'\b(return|exit|_exit|abort)\b')
    _DEAD_COND_RE = re.compile(
        r'if\s*\(\s*(?:0|false|NULL)\s*\)', re.IGNORECASE)

    def __init__(self, max_paths: int = 128):
        self._max_paths = max_paths
        self._scan = TemporalScanner()

    def verify(self, source: str) -> List[TemporalResult]:
        """对C源码执行路径敏感时序验证 返回UAF发现列表."""
        lines = source.splitlines()
        if not lines:
            return []

        dead_lines = self._find_dead_cond_lines(lines)
        frees = self._scan.find_frees(lines)
        realloc_olds = [(i, m.start(), m.group(1), m.group(2))
                        for i, l in enumerate(lines, start=1)
                        for m in [TemporalScanner._REALLOC_OLD_RE.search(l)] if m]
        all_frees: List[Tuple[int, int, str]] = list(frees)
        for rl, rcol, nv, ov in realloc_olds:
            all_frees.append((rl, rcol, ov))
        all_frees = [(l, c, v) for l, c, v in all_frees if l not in dead_lines]

        summarizer = InterprocSummarizer()
        vfrees, valiases = summarizer.propagate(source)
        all_frees.extend(vfrees)
        if not all_frees:
            return []

        freed_vars = [v for _, _, v in all_frees]
        aliases = self._scan.find_aliases(lines)
        aliases.extend((l, d, s) for l, d, s, _ in valiases)
        alias_closure = self._scan.build_alias_closure(aliases)
        expanded_freed = set(freed_vars)
        for fv in freed_vars:
            expanded_freed |= self._scan.resolve_var(fv, alias_closure)
        uses = self._scan.find_uses(lines, list(expanded_freed))
        blocks, adj = build_simple_cfg(lines)
        if not blocks:
            return []

        # Double-free检测 (委托给helpers)
        alloc_lines: Dict[str, List[int]] = {}
        for i, line in enumerate(lines, start=1):
            am = TemporalScanner._ALLOC_RE.search(line)
            if am:
                alloc_lines.setdefault(am.group(1), []).append(i)
            rm = TemporalScanner._REALLOC_OLD_RE.search(line)
            if rm:
                alloc_lines.setdefault(rm.group(1), []).append(i)
        results = detect_double_frees(
            frees, dead_lines, aliases, alloc_lines, lines)

        for fl, fcol, fvar in all_frees:
            for ul, ucol, uvar in uses:
                resolved = self._scan.resolve_var(fvar, alias_closure)
                if not TemporalScanner.var_matches(fvar, uvar, resolved):
                    continue
                if ul == fl and ucol <= fcol:
                    continue
                if ul < fl:
                    continue
                result = self._check_pair(
                    fvar, fl, fcol, uvar, ul, ucol,
                    blocks, adj, aliases, lines, all_frees)
                if result:
                    results.append(result)
                if len(results) >= 50:
                    break
            if len(results) >= 50:
                break
        return results

    @staticmethod
    def _mark_freed(state: Dict[str, PtrState], v: str,
                    alias_map: Dict[str, str]) -> None:
        """设置v为FREED并传播至所有别名."""
        state[v] = PtrState.FREED
        if v in alias_map:
            state[alias_map[v]] = PtrState.FREED
        for d, src in alias_map.items():
            if src == v:
                state[d] = PtrState.FREED

    def _is_uaf_state(self, state: Dict[str, PtrState],
                       fvar: str, uvar: str,
                       alias_map: Dict[str, str]) -> bool:
        """free→use 构成UAF?"""
        fv = state.get(fvar, PtrState.UNKNOWN)
        uv = state.get(uvar, PtrState.UNKNOWN)
        if fv == PtrState.FREED or uv == PtrState.FREED:
            return True
        if fv == PtrState.NULLIFIED or uv == PtrState.NULLIFIED:
            return False
        return any(
            (s in (fvar, uvar) and state.get(d, PtrState.UNKNOWN) == PtrState.FREED)
            or (d in (fvar, uvar) and state.get(s, PtrState.UNKNOWN) == PtrState.FREED)
            for s, d in alias_map.items())

    def _check_pair(self, fvar: str, fl: int, fcol: int,
                    uvar: str, ul: int, ucol: int,
                    blocks: List[Dict], adj: Dict[int, List[int]],
                    aliases: List[Tuple[int, str, str]],
                    lines: List[str],
                    all_frees: List[Tuple[int, int, str]] = None
                    ) -> Optional[TemporalResult]:
        """BFS探索CFG路径, 逐语句传播指针状态, 在use行评估UAF判定."""
        free_block = use_block = -1
        for b in blocks:
            if b['start'] <= fl - 1 <= b['end']:
                free_block = b['id']
            if b['start'] <= ul - 1 <= b['end']:
                use_block = b['id']
        if free_block < 0 or use_block < 0:
            return None

        # 行号→变量名的virtual free索引
        vfree_map: Dict[int, str] = {}
        if all_frees:
            for vf_l, vf_c, vf_v in all_frees:
                if vf_l <= len(lines):
                    stripped = TemporalScanner._strip_comments(
                        lines[vf_l - 1]).strip()
                    if not TemporalScanner._FREE_RE.search(stripped):
                        vfree_map.setdefault(vf_l, vf_v)

        alias_map = {dst: src for _, dst, src in aliases}
        safe_count = uaf_count = total = 0
        q = deque([(free_block, {})])
        visited = set()

        while q and total < self._max_paths:
            cur_bid, state = q.popleft()
            sk = (cur_bid, tuple(sorted(
                (k, v.value) for k, v in state.items())))
            if sk in visited:
                continue
            visited.add(sk)

            b = blocks[cur_bid] if cur_bid < len(blocks) else None
            if b is None:
                continue

            new_state = dict(state)
            same_eval = False

            for si, stmt in enumerate(b['stmts']):
                s = stmt.strip()
                stmt_line = b['start'] + si + 1

                fm = TemporalScanner._FREE_RE.search(s)
                if fm:
                    self._mark_freed(new_state, fm.group(1), alias_map)

                if stmt_line in vfree_map:
                    self._mark_freed(new_state, vfree_map[stmt_line], alias_map)

                nm = self._NULL_RE.search(s)
                if nm:
                    new_state[nm.group(1)] = PtrState.NULLIFIED

                rm = TemporalScanner._REALLOC_OLD_RE.search(s)
                if rm:
                    nv, ov = rm.group(1), rm.group(2)
                    self._mark_freed(new_state, ov, alias_map)
                    new_state[nv] = PtrState.ALLOCATED

                am = TemporalScanner._ALLOC_RE.search(s)
                if am:
                    new_state[am.group(1)] = PtrState.ALLOCATED

                # return截断: free后遇到return → use不可达
                if self._RETURN_RE.search(s):
                    if stmt_line > fl and stmt_line < ul:
                        safe_count += 1
                        total += 1
                        same_eval = True
                        break
                    elif stmt_line >= fl:
                        break

                if stmt_line == ul and stmt_line == fl:
                    line_src = lines[stmt_line - 1]
                    if _has_nullify_between(line_src, fvar, fcol, ucol):
                        safe_count += 1
                    else:
                        uaf_count += 1
                    total += 1
                    same_eval = True
                    break
                elif cur_bid == use_block and stmt_line == ul:
                    if self._is_uaf_state(new_state, fvar, uvar, alias_map):
                        uaf_count += 1
                    else:
                        safe_count += 1
                    total += 1
                    same_eval = True
                    break

            if same_eval:
                continue
            if cur_bid == use_block and total == 0:
                if self._is_uaf_state(new_state, fvar, uvar, alias_map):
                    uaf_count += 1
                else:
                    safe_count += 1
                total += 1
                continue
            for sid in adj.get(cur_bid, []):
                q.append((sid, dict(new_state)))

        if total == 0:
            return TemporalResult(verdict=TemporalVerdict.UNCERTAIN,
                ptr_var=fvar, free_line=fl, use_line=ul,
                reason="no reachable paths from free to use")
        if uaf_count > 0:
            return TemporalResult(verdict=TemporalVerdict.UAF,
                ptr_var=fvar, free_line=fl, use_line=ul,
                safe_paths=safe_count, uaf_paths=uaf_count,
                total_paths=total, reason=f"UAF: {uaf_count}/{total} paths")
        if safe_count == total:
            return TemporalResult(verdict=TemporalVerdict.SAFE,
                ptr_var=fvar, free_line=fl, use_line=ul,
                safe_paths=safe_count, total_paths=total,
                reason=f"SAFE: all {total} paths safe")
        return TemporalResult(verdict=TemporalVerdict.UNCERTAIN,
            ptr_var=fvar, free_line=fl, use_line=ul,
            total_paths=total, reason="mixed paths")

    def _find_dead_cond_lines(self, lines: List[str]) -> Set[int]:
        """识别恒假条件块内的行号集合(if(0)/if(false)/if(NULL)).

        这些分支永远不会执行, 块内的free/use应被忽略.
        """
        dead = set()
        i = 0
        while i < len(lines):
            m = self._DEAD_COND_RE.search(lines[i])
            if m:
                block_start = i
                depth = 0
                for j in range(i, len(lines)):
                    depth += lines[j].count('{') - lines[j].count('}')
                    if depth <= 0 and '{' in ''.join(lines[i:j+1]):
                        for k in range(block_start, j + 1):
                            dead.add(k + 1)
                        i = j + 1
                        break
                else:
                    i += 1
            else:
                i += 1
        return dead


__all__ = ['TemporalPathVerifier']
