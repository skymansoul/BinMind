"""内联拷贝检测 — sprintf/循环写入堆溢出 (桥接 inline_copy_detector 到 analysis)."""

from __future__ import annotations

import re as _re
from typing import Dict, List, Optional, Tuple

from .malloc_size_inferrer import MallocSite
from .access_parser import _canon_reg
from .inline_copy_utils import (
    extract_stack_slot, extract_addr, usable_from_site, trace_immediate_arg)

# 隐式写入函数匹配关键字 — 使用包含匹配 (处理 __mingw_sprintf 等包装)
_SPRINTF_KW = ('sprintf', 'vsprintf', 'swprintf')
_IO_READ_KW = ('fread', 'fgets', 'fscanf', 'recv', 'read')
_ALL_IMPLICIT_KW = _SPRINTF_KW + _IO_READ_KW

def _is_implicit_write(call_target: str) -> bool:
    """检查 call 目标是否为隐式堆写入函数 (子串匹配)."""
    t = call_target.lower()
    return any(kw in t for kw in _ALL_IMPLICIT_KW)


class InlineCopyDetector:
    """内联拷贝 + sprintf 堆溢出检测 — 桥接到 analysis 管线."""

    def __init__(self):
        self._heap_regs: Dict[str, int] = {}    # reg → malloc call_idx
        self._stack_ptrs: Dict[str, int] = {}    # 'rbp-0x8' → malloc call_idx

    def scan(self, instructions: List[str],
             malloc_sites: Dict[int, MallocSite],
             function_name: str = "",
             addrs: Optional[List[int]] = None,
             guards: Optional[List] = None) -> List:
        """主入口 — 返回 HeapOverflowFinding 列表."""
        from .heap_overflow_detector import HeapOverflowFinding
        findings: List[HeapOverflowFinding] = []
        if not malloc_sites:
            return findings
        self._track_heap_ptrs(instructions, malloc_sites)
        if not self._heap_regs and not self._stack_ptrs:
            return findings
        findings.extend(self._detect_sprintf(
            instructions, malloc_sites, function_name))
        findings.extend(self._detect_loop_writes(
            instructions, malloc_sites, function_name, addrs=addrs))
        return findings

    def _track_heap_ptrs(self, instructions: List[str],
                         malloc_sites: Dict[int, MallocSite]) -> None:
        """追踪 call malloc 后的 mov rax → reg/[rbp-N] 传播."""
        self._heap_regs.clear()
        self._stack_ptrs.clear()

        for idx, instr in enumerate(instructions):
            il = instr.strip().lower()
            if 'call' not in il:
                continue
            if not any(x in il for x in ('malloc', 'calloc', 'realloc')):
                continue

            # 向前扫描 rax 去向 (最多8条指令)
            for j in range(idx + 1, min(idx + 8, len(instructions))):
                nj = instructions[j].strip().lower()
                if not nj or nj.startswith(';'):
                    continue
                # mov reg, rax/eax
                m = _re.match(r'mov\s+(\w{2,6}),\s*(rax|eax)', nj)
                if m:
                    dst = _canon_reg(m.group(1))
                    if dst and dst not in ('rsp', 'rbp', 'rip'):
                        self._heap_regs[dst] = idx
                    break
                # mov [rbp-N], rax
                m = _re.match(
                    r'mov\s+(.*\[rbp[-+]\s*0x[0-9a-f]+\].*),\s*(rax|eax)', nj)
                if m:
                    off = extract_stack_slot(m.group(1))
                    if off is not None:
                        self._stack_ptrs[off] = idx
                    break

        self._propagate_regs(instructions)
        self._propagate_stack_reloads(instructions)

    def _propagate_regs(self, instructions: List[str]) -> None:
        """mov reg2, reg1 → 继承堆指针 (最多3轮迭代)."""
        for _ in range(3):
            changed = False
            for instr in instructions:
                il = instr.strip().lower()
                m = _re.match(r'mov\s+(\w{2,6}),\s*(\w{2,6})$', il)
                if not m:
                    continue
                dst, src = _canon_reg(m.group(1)), _canon_reg(m.group(2))
                if (dst and src and dst not in self._heap_regs
                        and src in self._heap_regs
                        and dst not in ('rsp', 'rbp', 'rip')):
                    self._heap_regs[dst] = self._heap_regs[src]
                    changed = True
            if not changed:
                break

    def _propagate_stack_reloads(self, instructions: List[str]) -> None:
        """mov reg, [rbp-N] → 从栈槽恢复堆指针."""
        for instr in instructions:
            il = instr.strip().lower()
            m = _re.match(
                r'mov\s+(\w{2,6}),\s*(.*\[rbp[-+]\s*0x[0-9a-f]+\].*)', il)
            if not m:
                continue
            dst = _canon_reg(m.group(1))
            off = extract_stack_slot(m.group(2))
            if (dst and off and off in self._stack_ptrs
                    and dst not in self._heap_regs):
                self._heap_regs[dst] = self._stack_ptrs[off]

# sprintf 检测

    def _detect_sprintf(self, instructions: List[str],
                        malloc_sites: Dict[int, MallocSite],
                        function_name: str) -> List:
        """检测 sprintf(heap_buf, fmt, ...) — 无界写入堆溢出."""
        from .heap_overflow_detector import HeapOverflowFinding
        findings = []
        for idx, instr in enumerate(instructions):
            il = instr.strip().lower()
            if 'call' not in il:
                continue
            called = il.split()[-1].strip()
            if not _is_implicit_write(called):
                continue
            heap_addr = self._trace_arg_to_heap(instructions, idx, 'rcx')
            if heap_addr is None:
                heap_addr = self._trace_arg_to_heap(instructions, idx, 'rdi')
            if heap_addr is None:
                continue
            site = malloc_sites.get(heap_addr)
            if site is None:
                continue
            usable_lo, _ = usable_from_site(site)
            if not self._has_variable_output(instructions, idx, called):
                continue
            est_size = usable_lo + 1
            findings.append(HeapOverflowFinding(
                insn_addr=idx, function_name=function_name,
                description=(
                    f'heap overflow via {called}: dest=malloc(≤{usable_lo}) '
                    f'variable output est≥{est_size} '
                    f'exceeds alloc at {function_name}:0x{idx:x}'),
                alloc_site=site.insn_addr,
                alloc_size_requested=site.size_interval.min_possible(),
                alloc_size_usable=usable_lo,
                access_offset=0, access_size=est_size,
                overflow_bytes=max(0, est_size - usable_lo),
                semantic_score=0.85, is_likely_fp=False, confidence=0.85,
                size_source=f'{called} variable output > alloc={usable_lo}',
            ))
        return findings

    def _trace_arg_to_heap(self, instructions: List[str],
                           call_idx: int, arg_reg: str) -> Optional[int]:
        """后向追踪 arg_reg 是否来自 malloc — 最多20条指令."""
        for j in range(call_idx - 1, max(0, call_idx - 20) - 1, -1):
            il = instructions[j].strip().lower()
            if not il or il.startswith(';'):
                continue
            m = _re.match(rf'(?:mov|lea)\s+{arg_reg},\s*\[?(\w+)', il)
            if m:
                src = _canon_reg(m.group(1))
                if src and src in self._heap_regs:
                    return self._heap_regs[src]
            if _re.match(rf'(mov|lea|xor)\s+{arg_reg},', il):
                break  # arg_reg 被覆盖
        return None

    def _has_variable_output(self, instructions: List[str],
                             call_idx: int, func_name: str) -> bool:
        """判断隐式写入是否有可变/无界输出."""
        t = func_name.lower()
        if any(kw in t for kw in _IO_READ_KW):
            return True  # fread/fgets → 外部输入
        if any(kw in t for kw in _SPRINTF_KW):
            for j in range(call_idx - 1, max(0, call_idx - 10) - 1, -1):
                il = instructions[j].strip().lower()
                if _re.match(r'lea\s+rdx,\s*\[rip[+-]', il):
                    return True  # 静态格式字符串 → 保守假定可变
                if _re.match(r'(mov|lea|xor)\s+rdx,', il):
                    break
        return False

# 循环累积写入检测

    def _detect_loop_writes(self, instructions: List[str],
                            malloc_sites: Dict[int, MallocSite],
                            function_name: str,
                            addrs: Optional[List[int]] = None) -> List:
        """检测循环中 memcpy/memset 累积写入溢出."""
        from .heap_overflow_detector import HeapOverflowFinding
        findings = []
        for loop in self._find_backward_jumps(instructions, addrs=addrs):
            body = instructions[loop['target_idx']:loop['jcc_idx'] + 1]
            for b_idx, instr in enumerate(body):
                il = instr.strip().lower()
                if 'call' not in il:
                    continue
                called = il.split()[-1].strip().strip('<>')
                if called not in ('memcpy', 'memset', 'memmove'):
                    continue
                abs_idx = loop['target_idx'] + b_idx
                heap_addr = self._trace_arg_to_heap(instructions, abs_idx, 'rcx')
                if heap_addr is None:
                    heap_addr = self._trace_arg_to_heap(instructions, abs_idx, 'rdi')
                if heap_addr is None:
                    continue
                site = malloc_sites.get(heap_addr)
                if site is None:
                    continue
                copy_size, _ = trace_immediate_arg(instructions, abs_idx, 'r8')
                if copy_size is None:
                    copy_size, _ = trace_immediate_arg(instructions, abs_idx, 'rdx')
                if copy_size is None or copy_size <= 0:
                    continue
                n_iters = self._infer_loop_iters(body, loop.get('jcc_type', '')) or 2
                total_write = copy_size * n_iters
                usable_lo, _ = usable_from_site(site)
                if total_write <= usable_lo:
                    continue
                findings.append(HeapOverflowFinding(
                    insn_addr=abs_idx, function_name=function_name,
                    description=(
                        f'heap overflow via loop {called}: '
                        f'{n_iters}×{copy_size}B={total_write}B '
                        f'exceeds alloc={usable_lo} '
                        f'at {function_name}:0x{abs_idx:x}'),
                    alloc_site=site.insn_addr,
                    alloc_size_requested=site.size_interval.min_possible(),
                    alloc_size_usable=usable_lo,
                    access_offset=0, access_size=total_write,
                    overflow_bytes=total_write - usable_lo,
                    semantic_score=0.75, is_likely_fp=False, confidence=0.75,
                    size_source=f'loop {n_iters}×{copy_size}',
                ))
        return findings

    def _find_backward_jumps(self, instructions: List[str],
                             addrs: Optional[List[int]] = None) -> List[dict]:
        """找条件跳转向后 (循环)."""
        jcc_re = _re.compile(
            r'(jne|je|jg|jl|jge|jle|jbe|jae|jb|ja|jnz|jz|jnc|jc)\s+'
            r'(0x[0-9a-f]+|[0-9a-f]{5,})')
        addr_map = {}
        if addrs and len(addrs) == len(instructions):
            for idx, a in enumerate(addrs):
                if a is not None:
                    addr_map[a] = idx
        else:
            for idx, instr in enumerate(instructions):
                a = extract_addr(instr)
                if a is not None:
                    addr_map[a] = idx
        loops = []
        for idx, instr in enumerate(instructions):
            il = instr.strip().lower()
            if not il.startswith('j'):
                continue
            m = jcc_re.search(il)
            if not m:
                continue
            target_addr = int(m.group(2), 16)
            cur_addr = addrs[idx] if (addrs and idx < len(addrs)) else extract_addr(instr)
            if cur_addr is None or target_addr >= cur_addr:
                continue
            t_idx = addr_map.get(target_addr, -1)
            if t_idx < 0 or (idx - t_idx) < 3:
                continue
            loops.append({
                'jcc_idx': idx, 'target_idx': t_idx,
                'target_addr': target_addr, 'jcc_type': m.group(1),
            })
        return loops

    def _infer_loop_iters(self, body: List[str], jcc_type: str = '') -> Optional[int]:
        """从 cmp X, const 推断迭代次数 — jle/jbe → cmp_val+1."""
        for instr in reversed(body):
            m = _re.match(r'cmp\s+[^,]+,\s*(0x[0-9a-f]+|\d+)', instr.strip().lower())
            if m:
                try:
                    val = int(m.group(1), 0)
                    return val + 1 if jcc_type in ('jle', 'jbe') else val
                except ValueError:
                    return None
        return None
