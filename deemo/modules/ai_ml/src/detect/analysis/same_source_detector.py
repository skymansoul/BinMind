# 同源大小检测器——追踪alloc_size/copy_size的栈槽/寄存器来源→同源则安全
# L5 FP压制: 若alloc_size≡copy_size同源且未修改, copy_size≤alloc_size恒成立→不可能溢出
# 理论: provenance tracking——典型样本HEAP-FP-008(同一栈槽两次读取)

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class SourceVerdict(Enum):
    SAME_SOURCE = 'same_source'       # alloc_size和copy_size同源→安全拷贝
    DIFFERENT_SOURCE = 'different'    # 来源不同→可能是真实溢出
    UNKNOWN = 'unknown'               # 无法追踪来源→保守保留


@dataclass
class Provenance:
    """值的来源——栈槽、寄存器@指令、全局变量或立即数"""
    kind: str               # 'stack_slot' | 'register' | 'global' | 'immediate' | 'param'
    location: str           # 具体位置: [rbp+0x18] | rax@5 | [rip+0x1234] | 0x40
    source_instr_idx: int   # 定义该值的指令索引
    source_instr: str = ""  # 定义指令原文

    def signature(self) -> str:
        """来源签名——相同签名=同源"""
        return f"{self.kind}:{self.location}"


@dataclass
class SameSourceReport:
    alloc_provenance: Provenance
    copy_provenance: Provenance
    is_same_source: bool
    evidence: str = ""


class SameSourceDetector:
    """同源大小检测器——L5 FP压制:追踪alloc/copy的size来源,同源→SAFE"""

    _ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'alloca'}
    _COPY_FUNCS = {'memcpy', 'memmove', 'strncpy', 'strcpy', 'snprintf',
                   'read', 'recv', 'fread'}
    # Win x64: malloc(rcx=size), memcpy(r8=size); Linux: memcpy(rdx=size)
    _ALLOC_SIZE_REG = 'rcx'
    _COPY_SIZE_REGS = {'memcpy': 'r8', 'memmove': 'r8', 'strncpy': 'r8',
                       'snprintf': 'r8', 'read': 'r8', 'recv': 'r8',
                       'fread': 'r8', '_linux_memcpy': 'rdx', '_linux_read': 'rdx'}

    # 非寄存器的关键字——mov dst, src匹配时排除
    _NON_REG = {'qword', 'dword', 'word', 'byte', 'ptr',
                'xmmword', 'ymmword', 'zmmword', 'tbyte', 'oword', 'mmword'}

    def __init__(self, max_trace_depth: int = 8):
        self._max_depth = max_trace_depth

    def detect(self, instructions: List[str], alloc_site_idx: int,
               copy_site_idx: int, copy_func: str = "memcpy") -> SameSourceReport:
        """检测alloc-copy对的size来源是否同源——追踪参数→比较Provenance签名"""
        alloc_prov = self._trace_size_source(instructions, alloc_site_idx, self._ALLOC_SIZE_REG)
        size_reg = self._COPY_SIZE_REGS.get(copy_func, 'r8')
        copy_prov = self._trace_size_source(instructions, copy_site_idx, size_reg)
        is_same = (alloc_prov.signature() == copy_prov.signature()
                   and alloc_prov.kind != 'unknown' and alloc_prov.kind != 'immediate')
        if is_same:
            evidence = (f"L5(SAME_SOURCE): alloc={alloc_prov.location}"
                        f"(@{alloc_prov.source_instr_idx})≡copy={copy_prov.location}"
                        f"(@{copy_prov.source_instr_idx})→同源/安全")
        elif alloc_prov.kind == 'unknown' or copy_prov.kind == 'unknown':
            evidence = (f"L5(UNKNOWN): alloc={alloc_prov.kind}:{alloc_prov.location},"
                        f" copy={copy_prov.kind}:{copy_prov.location}→保守保留")
        else:
            evidence = (f"L5(DIFFERENT): alloc={alloc_prov.signature()},"
                        f" copy={copy_prov.signature()}→可能真溢出")
        return SameSourceReport(alloc_provenance=alloc_prov, copy_provenance=copy_prov,
                                is_same_source=is_same, evidence=evidence)

    def _trace_size_source(self, instructions: List[str], call_idx: int,
                            size_reg: str) -> Provenance:
        """反向追踪size寄存器来源:找最后写入→沿MOV链到栈槽/全局/立即数/参数"""
        size_reg_clean = size_reg.lstrip('%').lower()
        # 32/64位变体映射
        reg_aliases = self._reg_aliases(size_reg_clean)

        # 找call前size_reg的最后写入
        write_idx = -1
        for j in range(call_idx - 1, max(-1, call_idx - 6), -1):
            instr = instructions[j].strip().lower()
            if not instr or instr.startswith(';'):
                continue
            # mov size_reg, src 或 mov size_reg, src (可能带大小前缀)
            for ra in reg_aliases:
                if self._is_write_to(instr, ra):
                    write_idx = j
                    break
            if write_idx >= 0:
                break

        if write_idx < 0:
            return Provenance(
                kind='param', location=f'{size_reg_clean}@call',
                source_instr_idx=call_idx,
                source_instr=instructions[call_idx].strip())

        # 从write_idx反向追踪MOV链到源头
        return self._trace_provenance_chain(
            instructions, write_idx, depth=0)

    def _trace_provenance_chain(self, instructions: List[str], start_idx: int,
                                 depth: int = 0) -> Provenance:
        """MOV链递归反向追踪——终止于栈槽/全局/立即数/参数/深度上限"""
        if depth >= self._max_depth or start_idx < 0:
            return Provenance(
                kind='unknown', location=f'@depth_limit',
                source_instr_idx=start_idx, source_instr="")

        instr = instructions[start_idx].strip().lower()

        # 提取源操作数: mov dst, src → src
        src = self._extract_mov_source(instr)
        if src is None:
            return Provenance(
                kind='unknown', location=f'parse_fail@{start_idx}',
                source_instr_idx=start_idx, source_instr=instr)

        # 终止: 栈槽引用
        stack_match = re.search(r'\[(r(?:bp|sp)[+-]\w+)\]', src)
        if stack_match:
            return Provenance(
                kind='stack_slot',
                location=f'[{stack_match.group(1)}]',
                source_instr_idx=start_idx,
                source_instr=instr)

        # 终止: 全局引用
        if '[rip' in src:
            rip_match = re.search(r'\[rip([+-]\w+)\]', src)
            offset = rip_match.group(1) if rip_match else '?'
            return Provenance(
                kind='global',
                location=f'[rip{offset}]',
                source_instr_idx=start_idx,
                source_instr=instr)

        # 终止: 立即数
        if re.match(r'^(0x[0-9a-f]+|\d+)$', src):
            return Provenance(
                kind='immediate',
                location=src,
                source_instr_idx=start_idx,
                source_instr=instr)

        # 中间寄存器: 继续追踪
        if self._is_valid_reg(src):
            # 找前一条写入src的指令
            prev_idx = self._find_def(instructions, start_idx - 1, src)
            if prev_idx >= 0:
                return self._trace_provenance_chain(
                    instructions, prev_idx, depth + 1)
            # 无前驱定义→可能是函数参数
            return Provenance(
                kind='param',
                location=f'{src}@{start_idx}',
                source_instr_idx=start_idx,
                source_instr=instr)

        # 复杂表达式 (如 [rax+rdx]) → 无法简化
        if '[' in src or '+' in src or '*' in src:
            return Provenance(
                kind='unknown',
                location=f'complex:{src}',
                source_instr_idx=start_idx,
                source_instr=instr)

        return Provenance(
            kind='unknown',
            location=src,
            source_instr_idx=start_idx,
            source_instr=instr)

    def _is_write_to(self, instr: str, reg: str) -> bool:
        """判断指令是否写入指定寄存器"""
        # mov reg, src
        if re.match(rf'mov\s+{reg},\s*', instr):
            return True
        # movsxd reg, src (符号扩展)
        if re.match(rf'movsxd\s+{reg},\s*', instr):
            return True
        # cdqe (eax→rax) — 检查32→64位映射
        # lea reg, [...]
        if re.match(rf'lea\s+{reg},\s*\[', instr):
            return True
        return False

    def _extract_mov_source(self, instr: str) -> Optional[str]:
        """从mov/movsxd/lea指令提取源操作数"""
        # mov dst, src
        m = re.match(r'mov(?:sxd|zx)?\s+\w+,\s*(.+)', instr)
        if not m:
            # lea dst, [src] — 我们不追踪地址计算
            m = re.match(r'lea\s+\w+,\s*\[(.+)\]', instr)
            if m:
                return f'[{m.group(1)}]'
            # cdqe — eax→rax, 返回eax作为"源"
            if 'cdqe' in instr:
                return 'eax'
            return None
        src = m.group(1).strip()
        # 剥离大小前缀: dword ptr [X] → [X]
        src = re.sub(r'(?:qword|dword|word|byte|ptr)\s+', '', src)
        return src

    def _find_def(self,
                   instructions: List[str],
                   from_idx: int,
                   reg: str) -> int:
        """从from_idx向上搜索, 找最后一条写入reg的指令索引"""
        reg_aliases = self._reg_aliases(reg)
        for j in range(from_idx, max(-1, from_idx - 6), -1):
            if j < 0:
                break
            instr = instructions[j].strip().lower()
            if not instr or instr.startswith(';'):
                continue
            for ra in reg_aliases:
                if self._is_write_to(instr, ra):
                    return j
        return -1

    @staticmethod
    def _reg_aliases(reg: str) -> List[str]:
        """返回寄存器的32/64位变体列表"""
        r = reg.lstrip('%').lower()
        mapping = {
            'rax': ['rax', 'eax'], 'rbx': ['rbx', 'ebx'],
            'rcx': ['rcx', 'ecx'], 'rdx': ['rdx', 'edx'],
            'rsi': ['rsi', 'esi'], 'rdi': ['rdi', 'edi'],
            'rbp': ['rbp', 'ebp'], 'rsp': ['rsp', 'esp'],
            'r8': ['r8', 'r8d'], 'r9': ['r9', 'r9d'],
            'r10': ['r10', 'r10d'], 'r11': ['r11', 'r11d'],
            'r12': ['r12', 'r12d'], 'r13': ['r13', 'r13d'],
            'r14': ['r14', 'r14d'], 'r15': ['r15', 'r15d'],
        }
        return mapping.get(r, [r])

    @staticmethod
    def _is_valid_reg(s: str) -> bool:
        """检查字符串是否是有效的寄存器名(排除_NON_REG)"""
        if not s or len(s) < 2:
            return False
        if s.startswith('[') or s.startswith('0x') or s[0].isdigit():
            return False
        return s not in SameSourceDetector._NON_REG
