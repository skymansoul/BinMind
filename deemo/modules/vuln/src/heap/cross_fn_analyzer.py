"""跨函数堆操作分析 — 调用链上malloc→write数据流追踪.

创建: 2024-09-02
拆分: 2024-09-02 — 内存追踪方法提取至_crossfn_mem_mixin
沿调用边传播参数绑定, 有界上下文敏感 (MAX_DEPTH=3, MAX_CONTEXTS=16).
Win x64 ABI: rcx=arg1, rdx=arg2, r8=arg3, r9=arg4.
参考: Sui ASE 2019 context-sensitive VFA; Saber ISSTA 2018 sparse value-flow."""

import os
import sys
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

_cur_dir = os.path.dirname(os.path.abspath(__file__))
if _cur_dir not in sys.path:
    sys.path.insert(0, _cur_dir)

from insn_parser import Instruction, is_call_to, extract_register
from func_analyzer import FunctionAnalysis, analyze_function
from _crossfn_mem_mixin import CrossFnMemMixin
from _crossfn_snapshot import CrossFnSnapshotMixin

# Windows x64 arg registers (callee视角: 入口时这些寄存器持有参数)
_ARG_REGS = ['rcx', 'rdx', 'r8', 'r9']


@dataclass
class CrossFnAnalysis:
    """跨函数分析结果 — 合并当前函数及所有被调用函数的发现."""
    function_name: str
    call_depth: int = 0
    mallocs: List[dict] = field(default_factory=list)
    frees: List[dict] = field(default_factory=list)
    writes: List[dict] = field(default_factory=list)
    memcpys: List[dict] = field(default_factory=list)
    callees_analyzed: Set[str] = field(default_factory=set)
    call_sites: List[dict] = field(default_factory=list)


class CrossFnAnalyzer(CrossFnMemMixin, CrossFnSnapshotMixin):
    """跨函数堆操作分析器."""

    MAX_DEPTH = 3
    MAX_CONTEXTS_PER_FUNC = 16

    def __init__(self):
        self._fn_analyses: Dict[str, FunctionAnalysis] = {}
        self._fn_insns: Dict[str, List[Instruction]] = {}
        self._call_graph: Dict[str, List[Tuple[int, str]]] = {}
        self._cross_results: Dict[str, CrossFnAnalysis] = {}
        self._context_count: Dict[str, int] = {}
        self._global_map: Dict[str, object] = {}
        self._field_map: Dict[Tuple[str, int], object] = {}
        self._resolved_free_vals: Dict[Tuple[str, int], str] = {}
        self._resolved_write_vals: Dict[Tuple[str, int], str] = {}
        self._fn_return_vals: Dict[str, str] = {}

    def register(self, fn_name: str, insns: List[Instruction],
                 fa: FunctionAnalysis) -> None:
        """注册单函数分析结果并提取调用边."""
        self._fn_analyses[fn_name] = fa
        self._fn_insns[fn_name] = insns
        self._context_count[fn_name] = 0
        callees = self._extract_callees(insns)
        self._call_graph[fn_name] = callees

    def _extract_callees(self, insns: List[Instruction]
                         ) -> List[Tuple[int, str]]:
        """提取函数中的call指令目标 (已过滤间接调用和库函数)."""
        CRT_EXACT = {
            'malloc', 'calloc', 'realloc', 'free', 'memcpy', 'memmove',
            'memset', 'strcpy', 'strcat', 'strlen', 'printf', 'scanf',
            'fread', 'fwrite', 'fprintf', 'puts', 'gets', 'abort', 'exit',
            'setvbuf', 'strdup',
        }
        callees = []
        for insn in insns:
            if insn.mnemonic != 'call':
                continue
            target = insn.operands.strip()
            if target.startswith('[') or target.startswith('*'):
                continue
            m = re.search(r'<([^+>]+)', target)
            if m:
                target = m.group(1)
            if target in CRT_EXACT:
                continue
            callees.append((insn.addr, target))
        return callees

    def analyze_all(self) -> Dict[str, CrossFnAnalysis]:
        """对所有已注册函数执行跨函数分析."""
        for fn_name in self._fn_analyses:
            if fn_name not in self._cross_results:
                self._analyze_with_context(fn_name, None, 0)
        self._resolve_return_values()
        self._patch_resolved_frees()
        self._patch_resolved_writes()
        return self._cross_results

    def _resolve_return_values(self) -> None:
        """第二遍传播: 重新快照有用户函数返回值的调用者."""
        for fn_name in list(self._cross_results.keys()):
            result = self._cross_results[fn_name]
            if not result.call_sites:
                continue
            has_ret_val = any(
                cs['callee'] in self._fn_return_vals
                for cs in result.call_sites)
            if not has_ret_val:
                continue
            insns = self._fn_insns.get(fn_name)
            if not insns:
                continue
            self._snapshot_call_sites(fn_name, insns)

    def _patch_resolved_frees(self) -> None:
        """用 _snapshot_call_sites 期间解析的 free 值补丁跨函数结果."""
        for result in self._cross_results.values():
            for f in result.frees:
                key = (result.function_name, f.get('addr', 0))
                if key in self._resolved_free_vals:
                    new_val = self._resolved_free_vals[key]
                    old_val = str(f.get('ptr_val', ''))
                    if not old_val or 'malloc' not in old_val:
                        f['ptr_val'] = new_val

    def _patch_resolved_writes(self) -> None:
        """用 snapshot 期间解析的 write base_val 补丁跨函数结果."""
        for result in self._cross_results.values():
            for w in result.writes:
                key = (result.function_name, w.get('addr', 0))
                old_bv = str(w.get('base_val', ''))
                if old_bv and 'malloc' in old_bv:
                    continue
                if key in self._resolved_write_vals:
                    w['base_val'] = self._resolved_write_vals[key]

    def _analyze_with_context(self, fn_name: str,
                               caller_bindings: Optional[Dict[str, object]],
                               depth: int) -> Optional[CrossFnAnalysis]:
        """带调用者上下文分析函数 (递归核心)."""
        if depth > self.MAX_DEPTH:
            return None
        if fn_name not in self._fn_analyses:
            return None

        cnt = self._context_count.get(fn_name, 0)
        if cnt >= self.MAX_CONTEXTS_PER_FUNC:
            return self._cross_results.get(fn_name)
        self._context_count[fn_name] = cnt + 1

        fa = self._fn_analyses[fn_name]
        insns = self._fn_insns[fn_name]

        if caller_bindings:
            fa = analyze_function(fn_name, insns)
            self._patch_entry_bindings(fa, insns, caller_bindings)
        else:
            fa = self._fn_analyses[fn_name]

        existing = self._cross_results.get(fn_name)
        if existing is None:
            result = CrossFnAnalysis(function_name=fn_name, call_depth=depth)
            result.mallocs = list(fa.mallocs)
            result.writes = list(fa.writes)
            result.memcpys = list(fa.memcpys)
            result.frees = list(fa.frees)
        elif caller_bindings:
            result = existing
            result.mallocs = list(fa.mallocs)
            result.writes = list(fa.writes)
            result.memcpys = list(fa.memcpys)
            result.frees = list(fa.frees)
        else:
            result = existing

        self._cross_results[fn_name] = result

        call_snapshots = self._snapshot_call_sites(fn_name, insns, caller_bindings)
        result.call_sites = call_snapshots

        for cs_info in call_snapshots:
            callee = cs_info['callee']
            if callee in self._fn_analyses:
                bindings = cs_info.get('arg_bindings')
                if bindings:
                    self._analyze_with_context(callee, bindings, depth + 1)
                    result.callees_analyzed.add(callee)
                    callee_result = self._cross_results.get(callee)
                    if callee_result:
                        result.mallocs.extend(callee_result.mallocs)
                        result.writes.extend(callee_result.writes)
                        result.memcpys.extend(callee_result.memcpys)
                        result.frees.extend(callee_result.frees)

        self._cross_results[fn_name] = result
        return result

    def _patch_entry_bindings(self, fa: FunctionAnalysis,
                               insns: List[Instruction],
                               bindings: Dict[str, object]) -> None:
        """用caller绑定的值替换callee入口的arg标记."""
        fa2 = analyze_function(fa.name, insns)
        for m in fa2.mallocs:
            if isinstance(m.get('size_val'), str) and m['size_val'] in bindings:
                m['size_val'] = bindings[m['size_val']]
        for w in fa2.writes:
            if isinstance(w.get('base_val'), str) and w['base_val'] in bindings:
                w['base_val'] = bindings[w['base_val']]
        for mc in fa2.memcpys:
            for key in ('dst_val', 'size_val'):
                if isinstance(mc.get(key), str) and mc[key] in bindings:
                    mc[key] = bindings[mc[key]]
        for f in fa2.frees:
            if isinstance(f.get('ptr_val'), str) and f['ptr_val'] in bindings:
                f['ptr_val'] = bindings[f['ptr_val']]
        fa.mallocs = fa2.mallocs
        fa.writes = fa2.writes
        fa.memcpys = fa2.memcpys
        fa.frees = fa2.frees

    def get_all_findings(self) -> Tuple[List[dict], List[dict],
                                          List[dict], List[dict]]:
        """获取所有跨函数分析的合并发现 → (mallocs, writes, memcpys, frees)."""
        all_mallocs, all_writes, all_memcpys = [], [], []
        seen_malloc, seen_write, seen_memcpy = set(), set(), set()
        free_map: Dict[Tuple, dict] = {}

        for result in self._cross_results.values():
            for m in result.mallocs:
                key = (m.get('addr'), str(m.get('size_val')))
                if key not in seen_malloc:
                    seen_malloc.add(key); all_mallocs.append(m)
            for w in result.writes:
                key = (w.get('addr'), w.get('function'))
                if key not in seen_write:
                    seen_write.add(key); all_writes.append(w)
            for mc in result.memcpys:
                key = (mc.get('addr'), mc.get('function'))
                if key not in seen_memcpy:
                    seen_memcpy.add(key); all_memcpys.append(mc)
            for f in result.frees:
                key = (f.get('addr'), f.get('function'))
                free_map[key] = f

        return all_mallocs, all_writes, all_memcpys, list(free_map.values())

    def stats(self) -> dict:
        return {
            'functions_registered': len(self._fn_analyses),
            'cross_results': len(self._cross_results),
            'call_edges': sum(len(v) for v in self._call_graph.values()),
            'contexts_per_func': dict(self._context_count),
        }
