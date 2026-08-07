# 约束传播分配-拷贝配对器——liveness链追踪关联malloc↔memcpy, 替代最近30条指令启发式

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple, NamedTuple
from dataclasses import dataclass

from .alias_graph import _NON_REG, build_stack_alias_map


class AllocSite(NamedTuple):
    instr_idx: int
    alloc_func: str
    result_reg: str
    size_range_lo: int
    size_range_hi: int


class CopySite(NamedTuple):
    instr_idx: int
    copy_func: str
    dst_reg: str               # 双ABI解析后的一参寄存器
    size_range_lo: int
    size_range_hi: int


@dataclass
class AllocCopyPair:
    alloc: AllocSite
    copy: CopySite
    confidence: float           # 0.0-1.0
    liveness_path: List[str]    # alloc结果→copy dst的寄存器链
    is_definitive: bool         # 链全程可见→True


class ConstraintBasedPairer:
    """约束传播分配-拷贝配对器——liveness链追踪替代'最近30条指令'启发式"""

    _ALLOC_PATTERN = re.compile(
        r'\b(malloc|calloc|realloc|alloca)\b', re.I)
    _COPY_PATTERN = re.compile(
        r'\b(memcpy|memmove|strcpy|strncpy|sprintf|snprintf|gets|read|recv|fread)\b', re.I)
    _PARAM_REGS = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')  # x86_64调用约定

    def __init__(self, max_liveness_depth: int = 20):
        self._max_depth = max_liveness_depth

    def find_pairs(self,
                   instructions: List[str]
                   ) -> Tuple[List[AllocCopyPair], List[AllocSite], List[CopySite]]:
        """在函数指令序列中找到所有分配-拷贝配对→(pairs, unpaired_allocs, unpaired_copies)"""
        allocs = self._find_alloc_sites(instructions)
        copies = self._find_copy_sites(instructions)

        pairs = []
        paired_copy_indices: Set[int] = set()

        for copy_site in copies:
            # 追踪copy dst寄存器的来源
            liveness = self._trace_register_liveness(
                copy_site.instr_idx, copy_site.dst_reg, instructions)

            # 检查liveness链是否指向某个alloc的结果
            best_alloc = None
            best_distance = 999

            for alloc_site in allocs:
                if alloc_site.result_reg in liveness:
                    dist = liveness.index(alloc_site.result_reg)
                    if dist < best_distance:
                        best_distance = dist
                        best_alloc = alloc_site

            if best_alloc is not None:
                paired_copy_indices.add(copy_site.instr_idx)
                # 置信度: liveness越短越确定
                conf = max(0.3, 1.0 - best_distance / self._max_depth)
                pairs.append(AllocCopyPair(
                    alloc=best_alloc, copy=copy_site,
                    confidence=conf,
                    liveness_path=liveness[:best_distance + 1],
                    is_definitive=(best_distance <= 5 and conf >= 0.7)))

        unpaired_allocs = [a for a in allocs if not any(
            p.alloc.instr_idx == a.instr_idx for p in pairs)]
        unpaired_copies = [c for c in copies if c.instr_idx not in paired_copy_indices]

        return pairs, unpaired_allocs, unpaired_copies

    def _find_alloc_sites(self, instructions: List[str]) -> List[AllocSite]:
        """扫描所有堆分配调用点"""
        sites = []
        for i, instr in enumerate(instructions):
            if 'call' not in instr.lower():
                continue
            m = self._ALLOC_PATTERN.search(instr)
            if not m:
                continue

            alloc_func = m.group(1).lower()
            # 分配结果在rax——找下一条mov: mov reg, rax
            result_reg = self._resolve_alloc_result(instructions, i)
            # 推断size参数(rdi/edi中的值)
            size_lo, size_hi = self._infer_param_size(instructions, i, 0)

            sites.append(AllocSite(
                instr_idx=i, alloc_func=alloc_func,
                result_reg=result_reg,
                size_range_lo=size_lo, size_range_hi=size_hi))
        return sites

    def _find_copy_sites(self, instructions: List[str]) -> List[CopySite]:
        """扫描所有危险拷贝调用点"""
        sites = []
        for i, instr in enumerate(instructions):
            if 'call' not in instr.lower():
                continue
            m = self._COPY_PATTERN.search(instr)
            if not m:
                continue

            copy_func = m.group(1).lower()
            # 确定size参数索引
            size_param_idx = self._get_copy_size_param(copy_func)
            # 推断size——双ABI
            size_lo, size_hi = self._infer_param_size(instructions, i, size_param_idx)
            # 解析第一个参数寄存器——双ABI: Linux(rdi)/Windows(rcx)
            dst_reg = self._resolve_copy_dst(instructions, i)

            sites.append(CopySite(
                instr_idx=i, copy_func=copy_func,
                dst_reg=dst_reg,
                size_range_lo=size_lo, size_range_hi=size_hi))
        return sites

    def _get_copy_size_param(self, func: str) -> int:
        """返回拷贝函数的size参数索引(x64 calling convention)"""
        mapping = {'memcpy': 2, 'memmove': 2, 'strncpy': 2,
                   'read': 2, 'recv': 2, 'fread': 1,
                   'sprintf': -1, 'snprintf': 1, 'gets': -1,
                   'strcpy': -1}
        return mapping.get(func, 2)

    def _resolve_copy_dst(self, instructions, call_idx):
        """解析拷贝dst寄存器——双ABI: Linux(rdi)/Windows(rcx)"""
        for j in range(call_idx - 1, max(-1, call_idx - 4), -1):
            instr = instructions[j].strip().lower()
            if not instr:
                continue
            for d in ('rdi', 'rcx'):
                # AT&T: mov/lea ..., %d 或 Intel: mov/lea d, ...
                if re.search(rf'(?:mov|lea)\s+.*%?{d}\b', instr):
                    return d
        return 'rcx'

    def _resolve_alloc_result(self,
                               instructions: List[str],
                               call_idx: int) -> str:
        """malloc返回rax——下一条指令通常将rax移到目标寄存器, 双ABI"""
        for j in range(call_idx + 1, min(call_idx + 3, len(instructions))):
            instr = instructions[j].strip().lower()
            # AT&T: mov %(rax|eax), %reg
            m = re.match(r'mov\s+%?(?:rax|eax),\s*%?(\w+)', instr)
            if m:
                dst = m.group(1)
                if dst not in _NON_REG:
                    return dst
            # Intel: mov reg, rax (dst在逗号前)
            m_i = re.match(r'mov\s+(\w+),\s*(?:rax|eax)\b', instr)
            if m_i:
                dst = m_i.group(1)
                if dst not in _NON_REG:
                    return dst
            if 'test' in instr and 'rax' in instr:
                continue
        return 'rax'

    def _infer_param_size(self, instructions, call_idx, param_idx):
        """推断call参数值: 从调用点向上找立即数或寄存器来源, 双ABI
        Linux x64: rdi/rsi/rdx/rcx/r8/r9
        Windows x64: rcx/rdx/r8/r9"""
        if param_idx < 0:
            return (0, 0xFFFFFFFF)
        # 双ABI: (Linux_32, Linux_64, Win_32, Win_64)
        targets = {
            0: ('edi', 'rdi', 'ecx', 'rcx'),
            1: ('esi', 'rsi', 'edx', 'rdx'),
            2: ('edx', 'rdx', 'r8d', 'r8'),
            3: ('ecx', 'rcx', 'r9d', 'r9'),
        }.get(param_idx, ())
        if not targets:
            return (0, 0xFFFFFFFF)

        for j in range(call_idx - 1, max(-1, call_idx - 10), -1):
            instr = instructions[j].strip().lower()
            if not instr:
                continue
            for t in targets:
                if not t:
                    continue
                # 双ABI立即数: AT&T mov $imm,%reg 或 Intel mov reg,imm
                m = re.match(rf'mov\s+\$?(0x[0-9a-f]+|\d+),\s*%?{t}', instr)
                if not m:
                    m = re.match(rf'mov\s+%?{t},\s*(0x[0-9a-f]+|\d+)', instr)
                if m:
                    raw = m.group(1)
                    val = int(raw, 16) if '0x' in raw.lower() else int(raw)
                    return (val, val)
                # 双ABI寄存器: AT&T mov %src,%t 或 Intel mov t,src
                m = re.match(rf'mov\s+%?(\w+),\s*%?{t}', instr)
                if not m:
                    m = re.match(rf'mov\s+%?{t},\s*%?(\w+)', instr)
                if m:
                    result = self._trace_src_to_constant(instructions, j, m.group(1))
                    # 若有具体值→返回; 若为(0,0)→可能表示xor清零, 继续搜索
                    if result != (0, 0):
                        return result
        return (0, 0xFFFFFFFF)

    def _trace_src_to_constant(self, instructions, from_idx, reg):
        """追踪寄存器到常量来源, 双ABI"""
        current = reg.lower()
        for i in range(from_idx - 1, max(-1, from_idx - 15), -1):
            instr = instructions[i].strip().lower()
            if not instr:
                continue
            # 双ABI: mov imm,reg 或 mov reg,imm
            m = re.match(rf'mov\s+\$?(0x[0-9a-f]+|\d+),\s*%?{current}', instr)
            if not m:
                m = re.match(rf'mov\s+%?{current},\s*(0x[0-9a-f]+|\d+)', instr)
            if m:
                raw = m.group(1)
                return (int(raw, 16) if '0x' in raw.lower() else int(raw),
                        int(raw, 16) if '0x' in raw.lower() else int(raw))
            # 双ABI: mov src,reg 或 mov reg,src (链式追踪)
            m = re.match(rf'mov\s+%?(\w+),\s*%?{current}', instr)
            if not m:
                m = re.match(rf'mov\s+%?{current},\s*%?(\w+)', instr)
            if m:
                current = m.group(1)
                continue
            if re.match(rf'xor\s+%?({re.escape(current)}),\s*%?\1\b', instr):
                return (0, 0)
            if 'call' in instr or '[' in instr:
                break
        return (0, 0xFFFFFFFF)

    def _trace_register_liveness(self, from_idx, target_reg, instructions):
        """反向追踪target_reg的def-use链+栈槽别名, 双ABI。
        栈槽穿透: mov %rax,N(%rbp)存储→mov N(%rbp),%rdi加载→rdi←rax链成立"""
        # 预扫描栈存储映射——委托共享函数(减少20行内联代码)
        stack_map = build_stack_alias_map(instructions)
        chain = [target_reg.lower()]
        current = target_reg.lower()
        for i in range(from_idx - 1, max(-1, from_idx - self._max_depth), -1):
            instr = instructions[i].strip().lower()
            if not instr or instr.startswith(';'):
                continue
            # 栈槽加载→穿透到存储源寄存器
            m_sl = re.match(
                rf'mov\s+([+-]?(?:0x[0-9a-f]+|\d+))\s*\(\s*%?(rbp|rsp)\s*\)\s*,\s*%?{re.escape(current)}', instr)
            if m_sl:
                slot = f"stk_{m_sl.group(2)}_{m_sl.group(1)}"
                if slot in stack_map:
                    current = stack_map[slot]
                    chain.append(current)
                    continue
            # 双ABI: mov src,current (AT&T) 或 mov current,src (Intel)
            m = re.match(rf'mov\s+%?(\w+),\s*%?{current}', instr)
            if not m:
                m = re.match(rf'mov\s+%?{re.escape(current)},\s*%?(\w+)', instr)
            if m:
                src = m.group(1)
                if (not src.startswith(('0x', '['))
                        and src not in _NON_REG):
                    current = src
                    chain.append(current)
                    continue
            # 双ABI: lea offset(%base),%current 或 lea current,[base]
            m = re.match(rf'lea\s+[^(]*\(%?(\w+)', instr)
            if m and re.search(rf'%?{current}\s*$', instr):
                current = m.group(1)
                chain.append(current)
                continue
            m = re.match(rf'lea\s+%?{re.escape(current)},\s*\[(\w+)', instr)
            if m:
                current = m.group(1)
                chain.append(current)
                continue
            if re.search(rf'\b{current}\b', instr):
                if re.match(r'(add|sub|xor|or|and|imul|shl|shr)\s+', instr):
                    break
            if re.match(rf'mov\s+%?{re.escape(current)}\s*,\s*\(', instr):
                break
            if re.match(rf'mov\s+(?:\w+\s+ptr\s+)?\[[^\]]+\],\s*%?{re.escape(current)}', instr):
                break
            if 'call' in instr and i < from_idx - 1:
                break
        return chain
