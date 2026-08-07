"""跨函数堆指针与size约束传播 — 桥接 interproc_context 到 DP-TVRA 管线.

创建: 2026-07-26
用途: 解决 heap-cve-14 类跨函数漏检:
        caller: p = malloc(64); callee(p, 256);
        callee: memset(p, ..., 256);  # 256 > 64 → OVERFLOW

方法: 两阶段分析
  阶段A (注册): 扫描所有函数, 记录 call callee(args) 时的实参约束
  阶段B (注入): 分析 callee 时, 从 interproc_context 读取约束,
               注入合成 MallocSite 和 size 区间

设计取舍:
  - 只追踪 RSI 模式下显式传参 (rcx/rdx/r8/r9 + rdi/rsi)
  - 栈传参暂不追踪 (MinGW x64 以寄存器传参为主)
  - 单层调用深度 (caller→callee), 不递归展开

  - Saber: 基于值流的跨过程 bug 检测
  - PhASAR: IFDS/IDE 框架的过程间数据流
  - 本模块取其"调用边参数绑定+被杀函数内注入"的思想
"""

from __future__ import annotations

import re as _re
from typing import Dict, List, Optional, Set, Tuple

from .malloc_size_inferrer import MallocSite
from .interval_domain import SInterval

class CrossFunctionPropagator:
    """跨函数堆参数传播器.

    集成到 ImprovedHeapOverflowDetector.analyze() 的前后:
      1. analyze() 前: 调用 inject_from_caller() 注入合成约束
      2. analyze() 后: 调用 register_callsites() 注册调用点
    """

    def __init__(self):
        # (callee_func, param_idx) → [(caller_func, heap_malloc_addr, size_lo, size_hi)]
        self._pending_bindings: Dict[Tuple[str, int], List[Tuple[str, int, int, int]]] = {}
        # func_name → {call_addr → (callee, {param: (heap_site_addr, size)})}
        self._registered_calls: Dict[str, dict] = {}
        # 已注入的合成 malloc sites: callee_func → {insn_idx: MallocSite}
        self._synthetic_sites: Dict[str, Dict[int, MallocSite]] = {}

    def detect_at_callsites(self, instructions: List[str],
                             malloc_sites: Dict[int, MallocSite],
                             function_name: str,
                             heap_regs: Dict[str, int] = None,
                             addrs: Optional[List[int]] = None) -> List:
        """阶段3d: 在 caller 侧检测跨函数调用溢出.

        若 call callee(heap_ptr, size) 且 size > alloc → 生成 finding.
        避免在 callee 内部做合成 site 注入的复杂性.
        """
        from .heap_overflow_detector import HeapOverflowFinding
        from .inline_copy_utils import usable_from_site
        findings = []
        if not malloc_sites or not heap_regs:
            return findings

        for idx, instr in enumerate(instructions):
            il = instr.strip().lower()
            if 'call' not in il:
                continue
            called = il.split()[-1].strip().strip('<>')
            if self._is_libcall(called):
                continue

            # 追踪堆指针参数
            heap_site_addr = None
            for arg_reg in ('rcx', 'rdi'):
                heap_site_addr = self._trace_reg_to_malloc(
                    instructions, idx, arg_reg, malloc_sites, heap_regs)
                if heap_site_addr is not None:
                    break
            if heap_site_addr is None:
                continue

            # 追踪 size 参数
            size_lo, size_hi = self._trace_size_arg(
                instructions, idx, malloc_sites)
            if size_lo == 0 and size_hi == 0xFFFFFFFF:
                continue  # 无法确定 size → 跳过

            site = malloc_sites.get(heap_site_addr)
            if site is None:
                continue
            usable_lo, _ = usable_from_site(site)
            if size_hi <= usable_lo:
                continue  # size ≤ alloc → 安全

            call_addr = addrs[idx] if (addrs and idx < len(addrs)) else idx
            findings.append(HeapOverflowFinding(
                insn_addr=idx, function_name=function_name,
                description=(
                    f'cross-function heap overflow: {called}(heap_ptr, '
                    f'size={size_hi}) exceeds alloc={usable_lo} '
                    f'at {function_name}:0x{call_addr:x}'),
                alloc_site=site.insn_addr,
                alloc_size_requested=site.size_interval.min_possible(),
                alloc_size_usable=usable_lo,
                access_offset=0, access_size=size_hi,
                overflow_bytes=size_hi - usable_lo,
                semantic_score=0.82, is_likely_fp=False, confidence=0.82,
                size_source=f'cross-fn: {function_name}→{called} size={size_hi}',
            ))
        return findings

    def register_callsites(self, instructions: List[str],
                           malloc_sites: Dict[int, MallocSite],
                           function_name: str,
                           heap_regs: Dict[str, int] = None,
                           addrs: Optional[List[int]] = None) -> None:
        """阶段A: 扫描当前函数的 call 指令, 注册跨函数调用.

        若 call target 的参数含已追踪的堆指针, 记录实参约束.
        """
        if not malloc_sites or not heap_regs:
            return

        self._registered_calls.setdefault(function_name, {})

        for idx, instr in enumerate(instructions):
            il = instr.strip().lower()
            if 'call' not in il:
                continue

            called = il.split()[-1].strip().strip('<>')
            # 跳过库函数调用
            if self._is_libcall(called):
                continue

            # 追踪 rcx (MS) / rdi (SystemV) — 堆指针参数
            heap_site_addr = None
            for arg_reg in ('rcx', 'rdi'):
                site = self._trace_reg_to_malloc(
                    instructions, idx, arg_reg, malloc_sites, heap_regs)
                if site is not None:
                    heap_site_addr = site
                    break

            if heap_site_addr is None:
                continue

            # 追踪 rdx (MS) / rsi (SystemV) — size 参数
            size_lo, size_hi = self._trace_size_arg(
                instructions, idx, malloc_sites)

            call_addr = addrs[idx] if (addrs and idx < len(addrs)) else idx

            self._registered_calls[function_name][call_addr] = (
                called, heap_site_addr, size_lo, size_hi)

            # 注册到待注入列表
            key = (called, 0)  # param 0 = heap ptr
            self._pending_bindings.setdefault(key, [])
            self._pending_bindings[key].append(
                (function_name, heap_site_addr, size_lo, size_hi))

    def inject_synthetic_sites(self, function_name: str,
                               ) -> Dict[int, MallocSite]:
        """阶段B: 为 callee 注入合成 MallocSite.

        返回: {synthetic_insn_addr → MallocSite}
        调用方应将返回的 dict 合并到实际的 malloc_sites 中.
        """
        if function_name in self._synthetic_sites:
            return self._synthetic_sites[function_name]

        synthetic: Dict[int, MallocSite] = {}
        key = (function_name, 0)
        bindings = self._pending_bindings.get(key, [])
        if not bindings:
            return synthetic

        # 取最紧的约束 (最小的 alloc, 最大的 size → 最可能溢出)
        # 多个caller: 用最坏情况 (最小的alloc, 最大的size)
        min_alloc = min(b[1] for b in bindings if b[1] > 0) if any(
            b[1] > 0 for b in bindings) else 0
        max_size_hi = max(b[3] for b in bindings)

        # 为被调用函数生成合成 malloc site (地址用负数标识为合成)
        for i, (caller, heap_addr, size_lo, size_hi) in enumerate(bindings):
            synth_addr = -1000 - i  # 负数地址 → 合成 site
            synthetic[synth_addr] = MallocSite(
                insn_addr=synth_addr,
                func_name='malloc',
                size_param_reg='rcx',
                size_interval=SInterval.exact(min_alloc) if min_alloc > 0
                else SInterval.top(),
            )

        self._synthetic_sites[function_name] = synthetic
        return synthetic

    def get_size_bound(self, callee_func: str,
                       param_idx: int = 1) -> Optional[Tuple[int, int]]:
        """获取被调用函数某参数的 size 区间.

        param_idx=1 对应 rdx/rsi (第二个参数, 通常是 size).
        """
        key = (callee_func, param_idx)
        bindings = self._pending_bindings.get(key, [])
        if not bindings:
            return None
        return (0, max(b[3] for b in bindings))

# 内部方法

    def _is_libcall(self, name: str) -> bool:
        """判断是否为库函数 (不需要跨函数追踪)."""
        lib_prefixes = ('malloc', 'calloc', 'realloc', 'free',
                        'memcpy', 'memset', 'memmove', 'strcpy', 'strncpy',
                        'strcat', 'strncat', 'sprintf', 'snprintf',
                        'printf', 'fprintf', 'puts', 'gets', 'fgets',
                        'read', 'write', 'open', 'close', 'fread', 'fwrite',
                        '__mingw_', '__acrt_', '__crt', '__security',
                        '_initterm', '_cexit', 'atexit')
        nl = name.lower()
        return any(nl.startswith(p) for p in lib_prefixes)

    def _trace_reg_to_malloc(self, instructions: List[str],
                              call_idx: int, arg_reg: str,
                              malloc_sites: Dict[int, MallocSite],
                              heap_regs: Dict[str, int]) -> Optional[int]:
        """后向追踪 arg_reg 是否持有堆指针 (返回 malloc call_idx)."""
        # 构建 32/64 位双形式: rcx → (rcx|ecx), rdi → (rdi|edi)
        reg_32 = arg_reg.replace('r', 'e', 1) if arg_reg.startswith('r') else None
        reg_pattern = f"({'|'.join([arg_reg, reg_32])})" if reg_32 else arg_reg
        for j in range(call_idx - 1, max(0, call_idx - 30) - 1, -1):
            il = instructions[j].strip().lower()
            if not il or il.startswith(';'):
                continue
            # mov arg_reg, rax/eax — 标准 malloc 返回传播
            m = _re.match(rf'mov\s+{reg_pattern},\s*(rax|eax)', il)
            if m:
                # 向前找最近的 malloc 调用
                for k in range(j - 1, max(0, j - 10) - 1, -1):
                    kl = instructions[k].strip().lower()
                    if 'call' in kl and any(
                            x in kl for x in ('malloc', 'calloc', 'realloc')):
                        if k in malloc_sites:
                            return k
                    if _re.match(rf'(mov|lea|xor|add)\s+{reg_pattern},', kl):
                        break
                # 也检查 heap_regs 中的寄存器
                for reg, site in heap_regs.items():
                    m2 = _re.match(rf'mov\s+{reg_pattern},\s*{reg}\b', il)
                    if m2:
                        return site
            # mov arg_reg, [rbp-N] — 栈加载
            m = _re.match(
                rf'mov\s+{reg_pattern},\s*.*\[rbp[-+]\s*0x[0-9a-f]+\]', il)
            if m:
                break
            # 其他写入 arg_reg → 追踪终止
            if _re.match(rf'(mov|lea|xor|add|sub|pop)\s+{reg_pattern},', il):
                break
        return None

    def _trace_size_arg(self, instructions: List[str],
                         call_idx: int,
                         malloc_sites: Dict[int, MallocSite]
                         ) -> Tuple[int, int]:
        """追踪 rdx/r8 (MS) / rsi/rcx (SystemV) — 实参 size 值.

        处理 32/64 位双形式: rdx/edx, r8/r8d, rsi/esi.
        """
        # (64b, 32b) 对
        arg_pairs = [('rdx', 'edx'), ('r8', 'r8d'), ('rsi', 'esi'), ('rcx', 'ecx')]
        for arg64, arg32 in arg_pairs:
            pattern = f"({'|'.join([arg64, arg32])})"
            for j in range(call_idx - 1, max(0, call_idx - 10) - 1, -1):
                il = instructions[j].strip().lower()
                m = _re.match(rf'mov\s+{pattern},\s*(0x[0-9a-f]+|\d+)', il)
                if m:
                    try:
                        val = int(m.group(2), 0)
                        return (val, val)
                    except ValueError:
                        pass
                if _re.match(rf'(mov|lea)\s+{pattern},', il):
                    break
        return (0, 0xFFFFFFFF)

    def clear(self) -> None:
        self._synthetic_sites.clear()

    def stats(self) -> dict:
        return {
            'registered_calls': sum(
                len(calls) for calls in self._registered_calls.values()),
            'pending_bindings': len(self._pending_bindings),
            'synthetic_sites': sum(
                len(sites) for sites in self._synthetic_sites.values()),
        }
