# 跨函数全局变量追踪器-预扫描所有函数, 构建全局数据流映射
# 核心: malloc结果→全局store→跨函数load→free/use模式
# 解决5个UAF跨函数FN(全局指针free/use在不同函数) + 1堆FN(跨函数alloc/copy)
# 理论: 调用图可达性 + 全局变量def-use链
from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_NON_REG = {'qword', 'dword', 'word', 'byte', 'ptr', 'xmmword',
           'ymmword', 'zmmword', 'tbyte', 'oword', 'mmword'}

# CRT/系统函数前缀-跨函数检测需排除
_CRT_PREFIXES = ('__', '_', '.', 'mingw', 'msvc', 'pre_c_init', 'pre_cpp_init',
                 'dyn_tls', 'pei386', 'gnu_exception', 'register_frame',
                 'deregister_frame', 'do_global', 'mark_section', 'restore_',
                 'tmain', 'FindPE', 'GetPE', 'IsNon', 'mingw_')

_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'alloca'}
_FREE_FUNCS = {'free', 'kfree', 'delete'}
_COPY_FUNCS = {'memcpy', 'memmove', 'strcpy', 'strncpy', 'memset',
              'sprintf', 'snprintf', 'gets', 'read', 'fread', 'recv'}
_ARG_REGS = {'rdi', 'rcx', 'edi', 'ecx', 'rsi', 'esi', 'rdx', 'edx'}


@dataclass
class GlobalAccess:
    """单个全局变量的跨函数访问记录"""
    global_ref: str  # RIP相对偏移如"+0x2f0a"
    stored_funcs: Dict[str, List[int]] = field(default_factory=dict)
    loaded_funcs: Dict[str, List[int]] = field(default_factory=dict)
    freed_funcs: Set[str] = field(default_factory=set)
    used_funcs: Set[str] = field(default_factory=set)
    alloc_funcs: Set[str] = field(default_factory=set)


@dataclass
class CrossFunctionMap:
    """跨函数全局数据流映射"""
    globals: Dict[str, GlobalAccess] = field(default_factory=dict)
    call_graph: Dict[str, Set[str]] = field(default_factory=dict)
    func_frees: Dict[str, Set[str]] = field(default_factory=dict)
    func_uses: Dict[str, Set[str]] = field(default_factory=dict)


class CrossFunctionTracker:
    """跨函数全局变量追踪器-RIP相对寻址store/load + 调用图 + free/use摘要"""

    def build_map(self, functions: List) -> CrossFunctionMap:
        """主入口: 从FunctionInfo列表构建跨函数映射"""
        cmap = CrossFunctionMap()
        cmap.call_graph = self._build_call_graph(functions)
        for func in functions:
            if func.instructions:
                self._scan_function(func, cmap)
        return cmap

    def _build_call_graph(self, functions: List) -> Dict[str, Set[str]]:
        cg: Dict[str, Set[str]] = {}
        am: Dict[str, str] = {}
        for f in functions:
            am[f"{f.start_addr:x}"] = f.name
            cg[f.name] = set()
        for f in functions:
            for instr in f.instructions:
                il = instr.strip().lower()
                if 'call' not in il: continue
                m = re.search(r'call\s+(?:qword\s+ptr\s+)?(?:\[rip[+\-]0x[0-9a-f]+\]|'
                              r'0x([0-9a-f]+)|\*?(0x[0-9a-f]+)|([a-z_]\w*(?:@\w+)?))', il)
                if not m: continue
                t = m.group(1) or m.group(2) or m.group(3)
                if t and t.startswith('0x') and t[2:] in am: cg[f.name].add(am[t[2:]])
                elif t and not t.startswith('0x'): cg[f.name].add(t)
        return cg

    def _scan_function(self, func, cmap: CrossFunctionMap):
        instrs = func.instructions
        n = len(instrs)
        is_att = any('%' in i for i in instrs[:min(15, n)]
                     if i.strip() and not i.strip().startswith(';'))
        reg_alloc: Dict[str, Tuple[int, str]] = {}
        reg_global: Dict[str, str] = {}

        for i, instr in enumerate(instrs):
            il = instr.strip().lower()
            if not il or il.startswith(';'):
                continue

            # alloc调用→记录结果寄存器
            if 'call' in il:
                for af in _ALLOC_FUNCS:
                    if af in il:
                        rr = self._alloc_result(instrs, i, is_att)
                        if rr:
                            reg_alloc[rr] = (i, af)
                        break

            # 全局store
            gs = self._parse_gstore(il, is_att)
            if gs:
                g_ref, vr = gs
                ga = self._ensure_global(cmap, g_ref)
                ga.stored_funcs.setdefault(func.name, []).append(i)
                if vr in reg_alloc:
                    ga.alloc_funcs.add(func.name)

            # 全局load
            gl = self._parse_gload(il, is_att)
            if gl:
                dr, g_ref = gl
                ga = self._ensure_global(cmap, g_ref)
                ga.loaded_funcs.setdefault(func.name, []).append(i)
                reg_global[dr] = g_ref
                if self._reg_feeds(instrs, i, dr, _FREE_FUNCS):
                    ga.freed_funcs.add(func.name)
                    cmap.func_frees.setdefault(func.name, set()).add(g_ref)
                if (self._reg_feeds(instrs, i, dr, _COPY_FUNCS)
                        or self._reg_as_mem(instrs, i, dr)
                        or self._reg_feeds_call(instrs, i, dr)):
                    ga.used_funcs.add(func.name)
                    cmap.func_uses.setdefault(func.name, set()).add(g_ref)

            # free调用/尾调用→追溯参数来源 (O3常编译为 jmp free 尾调用)
            if any(kw in il for kw in ('call', 'jmp')) and any(
                    ff in il for ff in _FREE_FUNCS):
                fr = self._free_param(instrs, i, is_att)
                # 兜底: free参数为全局加载寄存器本身(mov rcx,[rip+X]; jmp free)
                if fr is None:
                    for pr in ('rdi', 'rcx', 'edi', 'ecx'):
                        if pr in reg_global:
                            fr = pr
                            break
                if fr and fr in reg_global:
                    g_ref = reg_global[fr]
                    cmap.globals[g_ref].freed_funcs.add(func.name)
                    cmap.func_frees.setdefault(func.name, set()).add(g_ref)

            # 清除被覆盖的全局追踪
            self._clear_overwritten(il, reg_global)

    def _ensure_global(self, cmap, g_ref):
        if g_ref not in cmap.globals:
            cmap.globals[g_ref] = GlobalAccess(global_ref=g_ref)
        return cmap.globals[g_ref]

    def _clear_overwritten(self, il, reg_global):
        for pat in (r'mov\s+\$?(?:0x[0-9a-f]+|\d+),\s*%?(\w+)',
                    r'xor\s+%?(\w+),\s*%?\1\b'):
            m = re.search(pat, il)
            if m and m.group(1) in reg_global:
                del reg_global[m.group(1)]; return

    # 指令解析辅助

    def _alloc_result(self, instrs, ci, is_att):
        for j in range(ci + 1, min(ci + 3, len(instrs))):
            il = instrs[j].strip().lower()
            m = (re.match(r'mov\s+%(?:rax|eax),\s*%(\w+)', il) if is_att
                 else re.match(r'mov\s+(\w+),\s*(?:rax|eax)\b', il))
            if m and m.group(1) not in _NON_REG:
                return m.group(1).lstrip('%')
        return 'rax'

    def _free_param(self, instrs, fi, is_att):
        for pr in ('rdi', 'rcx', 'edi', 'ecx'):
            r = self._trace_src(instrs, fi - 1, pr, is_att)
            if r and r != pr: return r
        return None

    def _trace_src(self, instrs, fi, target, is_att, depth=0):
        if depth > 5 or fi < 0: return target
        cur = target.lower().lstrip('%')
        for j in range(fi, max(-1, fi - 6), -1):
            if j < 0: break
            il = instrs[j].strip().lower()
            src = None
            if is_att:
                m = re.match(rf'mov\s+%(\w+),\s*%{re.escape(cur)}', il)
                if m: src = m.group(1)
            else:
                m = re.match(rf'mov\s+%?{re.escape(cur)},\s*%?(\w+)', il)
                if m: src = m.group(1)
            if src and src not in _NON_REG:
                return cur if src in ('rax', 'eax') else \
                       self._trace_src(instrs, j - 1, src, is_att, depth + 1)
            if re.match(rf'xor\s+%?({re.escape(cur)}),\s*%?\1\b', il): return None
            if re.match(rf'mov\s+\$?(?:0x[0-9a-f]+|\d+),\s*%?({re.escape(cur)})', il): return None
        return cur

    @staticmethod
    def _parse_gstore(instr, is_att):
        if is_att:
            m = re.search(r'mov\s+%(\w+)\s*,\s*([+\-]?0x[0-9a-f]+)\(%rip\)', instr)
            if m and m.group(1) not in _NON_REG:
                return (m.group(2).strip(), m.group(1))
        else:
            m = re.search(r'mov\s+(?:qword\s+ptr\s+)?\[rip([+\-]0x[0-9a-f]+)\]\s*,\s*(\w+)', instr)
            if m and m.group(2) not in _NON_REG:
                return (m.group(1).strip(), m.group(2))
        return None

    @staticmethod
    def _parse_gload(instr, is_att):
        if is_att:
            m = re.search(r'mov\s+([+\-]?0x[0-9a-f]+)\(%rip\)\s*,\s*%(\w+)', instr)
            if m and m.group(2) not in _NON_REG:
                return (m.group(2), m.group(1).strip())
        else:
            m = re.search(r'mov\s+(\w+)\s*,\s*(?:qword\s+ptr\s+)?\[rip([+\-]0x[0-9a-f]+)\]', instr)
            if m and m.group(1) not in _NON_REG:
                return (m.group(1), m.group(2).strip())
        return None

    def _reg_feeds(self, instrs, fi, reg, tset):
        r = re.escape(reg)
        for j in range(fi + 1, min(fi + 20, len(instrs))):
            il = instrs[j].strip().lower()
            if (('call' not in il and 'jmp' not in il)
                    or not any(tf in il for tf in tset)):
                continue
            for pr in _ARG_REGS:
                for k in range(max(fi, j - 6), j):
                    ik = instrs[k].strip().lower()
                    if re.search(rf'mov\s+%?{r},\s*%?{pr}\b', ik) or \
                       re.search(rf'mov\s+%?{pr},\s*%?{r}\b', ik):
                        return True
        return False

    def _reg_as_mem(self, instrs, fi, reg):
        for j in range(fi + 1, min(fi + 20, len(instrs))):
            il = instrs[j].strip().lower()
            if f'({reg})' in il or f'[{reg}]' in il or f'[{reg}+' in il:
                return True
        return False

    def _reg_feeds_call(self, instrs, fi, reg):
        """全局加载寄存器作为用户函数调用/尾调用参数→记use(排除free/alloc/CRT)"""
        r = re.escape(reg)
        reg_is_arg = reg in _ARG_REGS
        for j in range(fi + 1, min(fi + 20, len(instrs))):
            il = instrs[j].strip().lower()
            if 'call' not in il and 'jmp' not in il:
                continue
            if any(tf in il for tf in _FREE_FUNCS) or any(
                    tf in il for tf in _ALLOC_FUNCS):
                continue
            m = re.search(r'(?:call|jmp)\s+.*?([a-z_]\w*(?:@\w+)?)', il)
            if m and self._is_crt_func(m.group(1)):
                continue
            # 加载目标寄存器本身即参数寄存器(mov rcx,[rip+X]; jmp f) → 直接记use
            if reg_is_arg:
                return True
            for pr in _ARG_REGS:
                for k in range(max(fi, j - 6), j):
                    ik = instrs[k].strip().lower()
                    if re.search(rf'mov\s+%?{r},\s*%?{pr}\b', ik) or \
                       re.search(rf'mov\s+%?{pr},\s*%?{r}\b', ik):
                        return True
        return False

    # 跨函数检测

    def detect_cross_function_uaf(self, cmap: CrossFunctionMap) -> List[Dict]:
        """检测跨函数UAF: RIP偏移→绝对地址→按地址分组→跨函数free-use对"""
        resolved = self._resolve_global_addresses(cmap)
        findings = []
        for addr, ga in resolved.items():
            fu = {f for f in ga.freed_funcs if not self._is_crt_func(f)}
            uu = {f for f in ga.used_funcs if not self._is_crt_func(f)}
            if not fu:
                continue
            # 跨函数双重释放: 两个不同函数均free同一全局且无后续use
            if not uu and len(fu) >= 2:
                findings.append({
                    'type': 'cross_function_double_free',
                    'global_ref': f'0x{addr:x}',
                    'free_funcs': sorted(fu), 'use_funcs': [],
                    'alloc_funcs': sorted(
                        {a for a in ga.alloc_funcs if not self._is_crt_func(a)}),
                    'cross_pairs': [],
                    'confidence': 0.75,
                    'evidence': [
                        f"cross-function double free: addr 0x{addr:x}",
                        f"freed in: {', '.join(sorted(fu))}",
                        "no use after free — double free only",
                    ],
                })
                continue
            if not uu:
                continue
            pairs = [(ff, uf) for ff in fu for uf in uu if ff != uf]
            if not pairs:
                continue
            au = {a for a in ga.alloc_funcs if not self._is_crt_func(a)}
            findings.append({
                'type': 'cross_function_uaf', 'global_ref': f'0x{addr:x}',
                'free_funcs': sorted(fu), 'use_funcs': sorted(uu),
                'alloc_funcs': sorted(au), 'cross_pairs': pairs,
                'confidence': 0.8 if au else 0.7,
                'evidence': [
                    f"cross-function UAF: addr 0x{addr:x}",
                    f"freed in: {', '.join(sorted(fu))}",
                    f"used in: {', '.join(sorted(uu))}",
                ] + ([f"alloc: {', '.join(sorted(au))}"] if au else [])
                + [f"pair: {ff}(free)→{uf}(use)" for ff, uf in pairs[:3]],
            })
        return findings

    def _resolve_global_addresses(self, cmap: CrossFunctionMap
                                   ) -> Dict[int, GlobalAccess]:
        """RIP偏移→绝对地址聚合: 256B粒度, 同全局同桶"""
        resolved: Dict[int, GlobalAccess] = {}
        for g_ref, ga in cmap.globals.items():
            try: off = int(g_ref, 16)
            except ValueError: continue
            key = (off & ~0xFF) if off > 0 else (0x10000 + off) & ~0xFF
            if key not in resolved:
                resolved[key] = GlobalAccess(global_ref=f'0x{key:x}')
            ra = resolved[key]
            for fn, idxs in ga.stored_funcs.items():
                ra.stored_funcs.setdefault(fn, []).extend(idxs)
            for fn, idxs in ga.loaded_funcs.items():
                ra.loaded_funcs.setdefault(fn, []).extend(idxs)
            ra.freed_funcs |= ga.freed_funcs
            ra.used_funcs |= ga.used_funcs
            ra.alloc_funcs |= ga.alloc_funcs
        return resolved

    @staticmethod
    def _is_crt_func(name):
        """排除CRT/系统函数"""
        low = name.lower()
        return any(low.startswith(p) for p in _CRT_PREFIXES)

    @staticmethod
    def _reachable(call_graph, from_func, to_func, max_depth=8):
        if from_func == to_func:
            return True
        visited = {from_func}
        queue = [from_func]
        for _ in range(max_depth):
            if not queue:
                break
            cur = queue.pop(0)
            for callee in call_graph.get(cur, set()):
                if callee == to_func:
                    return True
                if callee not in visited:
                    visited.add(callee)
                    queue.append(callee)
        return False
