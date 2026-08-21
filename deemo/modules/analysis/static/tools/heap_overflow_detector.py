# 初始创建: 基于分配/写入尺寸比较的静态堆溢出检测
# 增加跨函数追踪
# 寄存器宽度归一化: edi/rdi/dil 统一匹配, 解决GCC O2下32-bit传参问题

"""堆溢出静态检测, 分配/写入尺寸比较 + 跨函数传播

不依赖符号执行, 从指令序列提取常量大小做比较。
过滤增强版请用 heap_overflow_filtered.FilteredHeapOverflowDetector
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class HeapOverflowVerdict(Enum):
    CONFIRMED = "confirmed"       # N < M 且均可静态确定
    POTENTIAL = "potential"       # 存在可能的溢出 (大小不确定)
    LIKELY_SAFE = "likely_safe"   # N >= M 或存在显式边界检查


@dataclass
class HeapOverflowFinding:
    function_name: str
    alloc_address: int             # malloc 调用地址
    write_address: int             # memcpy/strcpy 等写入地址
    alloc_size: int                # -1 = 不可确定
    write_size: int                # -1 = 不可确定
    verdict: HeapOverflowVerdict
    confidence: float
    evidence: List[str] = field(default_factory=list)


# 堆分配函数 → (size_arg_position, return_reg)
_HEAP_ALLOCATORS = {
    'malloc':  (0, 'rax'),
    'calloc':  (0, 'rax'),     # calloc(nmemb, size), 简化: 取第一个参数
    'realloc': (1, 'rax'),
    '__libc_malloc': (0, 'rax'),
}

# 堆写入函数 → (dst_arg_position, size_arg_position)
_HEAP_WRITERS = {
    'memcpy':   (0, 2),      # memcpy(dst, src, n)
    'memmove':  (0, 2),
    'strcpy':   (0, -1),     # strcpy(dst, src) → size = strlen(src)+1 (不可静态确定)
    'strncpy':  (0, 2),
    'snprintf': (0, 1),      # snprintf(buf, size, fmt, ...)
    'read':     (0, 2),      # read(fd, buf, count) — buf在堆上
    'fread':    (0, 2),      # 简化: buf在堆上
}

# 边界检查指令模式: 若在写之前存在 cmp/jb, 可能已有安全保护
_SAFETY_CHECK_PATTERN = re.compile(
    r'cmp\s+\w+,\s*\w+\s*\n\s*(?:jb|jbe|jnae)\s+', re.I
)


class HeapOverflowDetector:
    """静态堆溢出检测器

    用法:
      detector = HeapOverflowDetector()
      findings = detector.detect(
          functions={'main': [(0x401000, 'call malloc'), ...]},
          call_graph={'main': ['process'], 'process': []},
      )
    """

    def detect(
        self,
        functions: Dict[str, List[Tuple[int, str]]],
        call_graph: Optional[Dict[str, List[str]]] = None,
    ) -> List[HeapOverflowFinding]:
        """扫描所有函数中的堆溢出"""
        findings: List[HeapOverflowFinding] = []
        cg = call_graph or {}

        for func_name, asm_lines in functions.items():
            findings.extend(self._detect_in_function(
                func_name, asm_lines, cg,
            ))

        # 跨函数追踪
        if cg:
            cross = self._detect_cross_function(functions, cg)
            findings.extend(cross)

        return sorted(findings, key=lambda f: -f.confidence)

    def _detect_in_function(
        self,
        func_name: str,
        asm_lines: List[Tuple[int, str]],
        cg: Dict[str, List[str]],
    ) -> List[HeapOverflowFinding]:
        """单函数内检测"""
        findings: List[HeapOverflowFinding] = []
        allocs: List[Tuple[int, int, str]] = []  # (addr, size, reg)

        for addr, text in asm_lines:
            text_lower = text.lower().strip()

            # 检测堆分配
            alloc_size, alloc_reg = self._match_alloc(text_lower, addr, asm_lines)
            if alloc_size >= 0:
                allocs.append((addr, alloc_size, alloc_reg))

            # 检测堆写入
            write_size, dst_reg = self._match_write(text_lower, addr, asm_lines)
            if write_size >= 0:
                # 检查是否写入到之前分配的堆内存 (同一寄存器)
                for a_addr, a_size, a_reg in allocs:
                    if dst_reg == a_reg or self._same_pointer(
                        a_reg, dst_reg, asm_lines, a_addr, addr,
                    ):
                        verdict, conf = self._compare_sizes(
                            a_size, write_size, asm_lines, addr,
                        )
                        findings.append(HeapOverflowFinding(
                            function_name=func_name,
                            alloc_address=a_addr,
                            write_address=addr,
                            alloc_size=a_size,
                            write_size=write_size,
                            verdict=verdict,
                            confidence=conf,
                            evidence=[
                                f'malloc({a_size}) @ 0x{a_addr:x}',
                                f'write({write_size}) @ 0x{addr:x}',
                            ],
                        ))

        return findings

    def _match_alloc(
        self, text: str, addr: int, asm_lines: List[Tuple[int, str]],
    ) -> Tuple[int, str]:
        """匹配堆分配调用, 提取分配大小, 返回 (size, return_register), size=-1 表示未匹配。"""
        if 'call' not in text:
            return -1, ''
        for alloc_func, (size_arg_idx, ret_reg) in _HEAP_ALLOCATORS.items():
            if alloc_func in text.replace(' ', ''):
                size = self._extract_const_arg(text, asm_lines, addr, size_arg_idx)
                return size, ret_reg
        return -1, ''

    def _match_write(
        self, text: str, addr: int, asm_lines: List[Tuple[int, str]],
    ) -> Tuple[int, str]:
        """匹配堆写入调用, 提取写入大小, 返回 (size, dst_register), size=-1 表示未匹配。"""
        if 'call' not in text:
            return -1, ''
        for write_func, (dst_idx, size_idx) in _HEAP_WRITERS.items():
            if write_func in text.replace(' ', ''):
                if size_idx < 0:
                    return 0, ''  # strcpy: 大小不可确定
                size = self._extract_const_arg(text, asm_lines, addr, size_idx)
                # 提取目标地址寄存器 (简化: 找call前的mov到参数寄存器)
                dst_reg = self._extract_arg_reg(asm_lines, addr, dst_idx)
                return size, dst_reg
        return -1, ''

    def _extract_const_arg(self, call_text: str, asm_lines: List[Tuple[int, str]],
                           call_addr: int, arg_idx: int) -> int:
        """从call前指令提取常量参数 (x86_64: arg0=rdi, arg1=rsi, arg2=rdx)"""
        arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        if arg_idx >= len(arg_regs):
            return -1
        target_reg = arg_regs[arg_idx]

        # 从 call 地址向前找最近的对 target_reg 的 mov/lea
        for i in range(len(asm_lines) - 1, -1, -1):
            a, t = asm_lines[i]
            if a >= call_addr:
                continue
            parts = t.lower().strip().split(None, 1)
            if not parts:
                continue
            mnemonic = parts[0]
            operands = parts[1] if len(parts) > 1 else ''
            if mnemonic in ('mov', 'lea'):
                dest = operands.split(',')[0].strip()
                if self._reg_match(target_reg, dest):
                    src = operands.split(',')[1].strip() if ',' in operands else ''
                    try:
                        return int(src, 0)
                    except ValueError:
                        return -1
            # 最多回溯 5 条指令
            if call_addr - a > 50:
                break
        return -1

    def _extract_arg_reg(self, asm_lines: List[Tuple[int, str]],
                         call_addr: int, arg_idx: int) -> str:
        """提取call前某参数位置的寄存器名"""
        arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        if arg_idx >= len(arg_regs):
            return ''
        dst_reg = arg_regs[arg_idx]
        for i in range(len(asm_lines) - 1, -1, -1):
            a, t = asm_lines[i]
            if a >= call_addr:
                continue
            parts = t.lower().strip().split(None, 1)
            if not parts:
                continue
            mnemonic, ops = parts[0], parts[1] if len(parts) > 1 else ''
            if mnemonic == 'mov':
                dest = ops.split(',')[0].strip()
                src = ops.split(',')[1].strip() if ',' in ops else ''
                if dest == dst_reg:
                    return src if self._is_register(src) else ''
            if call_addr - a > 30:
                break
        return ''

    # x86_64 寄存器宽度别名: 64-bit (rdi) ← 32-bit (edi) ← 16-bit (di) ← 8-bit (dil)
    _REG_WIDTH_ALIASES = {
        'rdi': {'rdi', 'edi', 'di', 'dil'},
        'rsi': {'rsi', 'esi', 'si', 'sil'},
        'rdx': {'rdx', 'edx', 'dx', 'dl'},
        'rcx': {'rcx', 'ecx', 'cx', 'cl'},
        'r8':  {'r8', 'r8d', 'r8w', 'r8b'},
        'r9':  {'r9', 'r9d', 'r9w', 'r9b'},
        'rax': {'rax', 'eax', 'ax', 'al'},
        'rbx': {'rbx', 'ebx', 'bx', 'bl'},
    }

    @staticmethod
    def _reg_match(target: str, actual: str) -> bool:
        """检查 actual 是否为 target 的宽度变体 (如 edi == rdi)"""
        aliases = HeapOverflowDetector._REG_WIDTH_ALIASES.get(target, set())
        return actual in aliases or actual == target

    @staticmethod
    def _is_register(s: str) -> bool:
        return bool(re.match(
            r'^(r(?:ax|bx|cx|dx|si|di|bp|sp|8|9|1[0-5])'
            r'|e(?:ax|bx|cx|dx|si|di|bp|sp))$', s
        ))

    def _same_pointer(
        self, reg_a: str, reg_b: str,
        asm_lines: List[Tuple[int, str]],
        alloc_addr: int, write_addr: int,
    ) -> bool:
        """判断两个寄存器引用是否指向同一堆指针

        简化: 检查 alloc 和 write 之间是否有 mov reg_a, reg_b
        """
        if reg_a == reg_b:
            return True
        for a, t in asm_lines:
            if not (alloc_addr < a < write_addr):
                continue
            parts = t.lower().strip().split(None, 1)
            if not parts or parts[0] != 'mov':
                continue
            ops = parts[1] if len(parts) > 1 else ''
            dest = ops.split(',')[0].strip()
            src = ops.split(',')[1].strip() if ',' in ops else ''
            if dest == reg_b and src == reg_a:
                return True
        return False

    @staticmethod
    def _compare_sizes(
        alloc_sz: int, write_sz: int,
        asm_lines: List[Tuple[int, str]], write_addr: int,
    ) -> Tuple[HeapOverflowVerdict, float]:
        """比较分配大小和写入大小"""
        if alloc_sz < 0 or write_sz < 0:
            return HeapOverflowVerdict.POTENTIAL, 0.40

        if alloc_sz < write_sz:
            # 检查是否有边界保护 (cmp/jb)
            text = '\n'.join(t for _, t in asm_lines)
            if _SAFETY_CHECK_PATTERN.search(text):
                return HeapOverflowVerdict.LIKELY_SAFE, 0.30
            return HeapOverflowVerdict.CONFIRMED, 0.85

        if alloc_sz >= write_sz:
            return HeapOverflowVerdict.LIKELY_SAFE, 0.20

        return HeapOverflowVerdict.POTENTIAL, 0.35

    def _detect_cross_function(
        self,
        functions: Dict[str, List[Tuple[int, str]]],
        cg: Dict[str, List[str]],
    ) -> List[HeapOverflowFinding]:
        """跨函数追踪: alloc在caller, write在callee"""
        cross: List[HeapOverflowFinding] = []
        # 简化: 收集所有 alloc, 然后在 callee 的 write 中查找匹配
        for caller, callees in cg.items():
            if caller not in functions:
                continue
            for callee in callees:
                if callee not in functions:
                    continue
                # 若 caller 有 alloc, callee 有 write, 且指针通过参数传递
                # → 可能存在跨函数堆溢出
                cross.append(HeapOverflowFinding(
                    function_name=f'{caller}->{callee}',
                    alloc_address=0, write_address=0,
                    alloc_size=-1, write_size=-1,
                    verdict=HeapOverflowVerdict.POTENTIAL,
                    confidence=0.30,
                    evidence=[f'cross-function: {caller} alloc, {callee} write'],
                ))
        return cross
