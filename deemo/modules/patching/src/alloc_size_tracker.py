# 创建: 2025-09-28
# 分配大小污点追踪 — 从外部输入到malloc(size)的参数值流分析

"""分配大小污点追踪器。

堆溢出检测的误报根源：现有工具看到 malloc + memcpy 就报警，
但若 malloc(size) 的 size 是编译期常量（如 malloc(256)），
后续 memcpy 不可能溢出——因为 size 不可控。

本模块追踪 malloc 的 size 参数是否来自外部输入：
  1. 在函数入口标记参数寄存器为 taint source（来自调用者）
  2. 沿数据流传播污点标记（mov/add/and 等操作后污点继承）
  3. 到达 malloc(size) 时查询 size 是否被污染
  4. 若 size 未被污染 → 降低该 malloc 关联的堆溢出告警 → 误报消除

与通用污点分析（TaintEngine）的差异：
  TaintEngine 做全寄存器/内存的值域传播，开销大。
  本模块只追踪一条特定的数据流链：source → size_arg → malloc，
  是 demand-driven 的分析——只在遇到 malloc 时才回溯。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import deque

_log = logging.getLogger(__name__)


@dataclass
class AllocSite:
    """一次内存分配调用的完整信息。"""
    address: int = 0
    line_index: int = 0
    alloc_func: str = ""          # malloc / calloc / realloc
    size_operand: str = ""        # 分配大小的操作数（寄存器/立即数）
    size_is_constant: bool = False
    size_constant_value: int = 0
    size_is_tainted: bool = False
    taint_source: str = ""        # 污点来源描述
    taint_path_length: int = 0    # 从source到malloc的步数
    # 约束
    size_upper_bound: int = 2**63 - 1
    size_lower_bound: int = 0
    has_bounds_check: bool = False
    # 风险
    fp_likelihood: float = 1.0    # 1.0=确定是漏洞, 0.0=确定是误报


@dataclass
class AllocSiteReport:
    """分配点分析报告。"""
    function_name: str = ""
    sites: List[AllocSite] = field(default_factory=list)
    total_allocs: int = 0
    tainted_allocs: int = 0       # size受外部控制的分配
    constant_allocs: int = 0      # size为常量的分配（几乎肯定是误报）
    fp_candidates: int = 0        # 被识别为可能误报的分配点数

    def to_dict(self) -> Dict:
        return {
            'function': self.function_name,
            'total_allocs': self.total_allocs,
            'tainted': self.tainted_allocs,
            'constant': self.constant_allocs,
            'fp_candidates': self.fp_candidates,
            'sites': [
                {'func': s.alloc_func, 'tainted': s.size_is_tainted,
                 'constant': s.size_is_constant, 'fp_likelihood': round(s.fp_likelihood, 2),
                 'source': s.taint_source}
                for s in self.sites[:10]
            ],
        }


# ── 分配点扫描器 ──────────────────────────────────────────────────

class AllocSiteScanner:
    """扫描汇编中的所有内存分配调用点。

    识别 malloc/calloc/realloc/alloca 以及其 size 参数。
    x86_64 调用约定: rdi = 第一参数 (size)。
    """

    _ALLOC_FUNCS = re.compile(
        r'\bcall\s+(malloc|calloc|realloc|_Znwm|_Znam|alloca|__builtin_alloca)\b', re.I)

    def scan(self, asm_lines: List[str], base_addr: int = 0) -> List[AllocSite]:
        sites = []
        for i, line in enumerate(asm_lines):
            m = self._ALLOC_FUNCS.search(line)
            if not m:
                continue
            func = m.group(1)
            # 回溯找 rdi 的设置
            size_op, is_const, const_val = self._find_size_arg(asm_lines, i)

            site = AllocSite(
                address=base_addr + i * 4, line_index=i,
                alloc_func=func, size_operand=size_op,
                size_is_constant=is_const, size_constant_value=const_val)
            sites.append(site)
        return sites

    def _find_size_arg(self, asm: List[str], call_idx: int
                       ) -> Tuple[str, bool, int]:
        """回溯找 call malloc 前对 rdi 的设置。"""
        for j in range(call_idx - 1, max(call_idx - 8, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')
            # mov rdi, imm
            m = re.search(r'\bmov\s+rdi,?\s*(0x[0-9a-f]+|\d+)', line)
            if m:
                v = m.group(1)
                val = int(v, 16) if v.lower().startswith('0x') else int(v)
                return 'rdi', True, val
            # mov rdi, reg
            m = re.search(r'\bmov\s+rdi,?\s*(\w+)', line)
            if m:
                return m.group(1), False, 0
            # lea rdi, [reg+off]
            m = re.search(r'\blea\s+rdi,?\s*\[', line)
            if m:
                return 'rdi (lea)', False, 0
            # xor edi, edi → rdi=0
            if re.search(r'\bxor\s+edi,?\s*edi', line):
                return 'rdi', True, 0
        return 'rdi', False, 0


# ── 需求驱动的污点回溯器 ──────────────────────────────────────────

class DemandDrivenTaintTracker:
    """仅在遇到 malloc 调用时才从 size 参数反向追踪污点。

    算法：从 call malloc 处的 size 参数寄存器出发，
    沿 def-use 链逆向步进。每步检查定义指令是否为 source。
    遇到立即数 → 立即截断（常量不可控）。
    遇到净化操作 → 降低置信度但不截断。
    max_depth=15 限制回溯步数。
    """

    _SOURCE_PATTERNS = re.compile(
        r'\bcall\s+(read|recv|recvfrom|fgets|scanf|getenv|fread|getc|gets)\b|'
        r'\bargv\b|\bargc\b', re.I)

    def trace(self, asm_lines: List[str], call_idx: int,
              size_reg: str) -> Tuple[bool, str, int]:
        """从 malloc 调用回溯 size 的污点来源。

        返回 (is_tainted, source_description, path_length)。
        """
        if not size_reg or size_reg == 'rdi':
            pass

        # 找到 call 前设置 rdi 的寄存器
        target_reg = self._find_rdi_source_reg(asm_lines, call_idx)
        if not target_reg:
            # rdi 可能是通过 lea 计算的，保守标记为潜在污点
            return True, "rdi via LEA (conservative)", 1

        visited = set()
        queue = deque([(call_idx - 1, target_reg, 0, [])])

        while queue:
            pos, reg, depth, path = queue.popleft()
            if depth > 15 or pos < 0:
                continue
            state_key = (pos, reg)
            if state_key in visited:
                continue
            visited.add(state_key)

            line = asm_lines[pos].strip().lower().replace(',', ' ')

            # 终止条件1: source
            if self._SOURCE_PATTERNS.search(line):
                src_name = self._extract_source(line)
                return True, src_name, depth + 1

            # 终止条件2: 立即数定义
            m = re.search(r'\bmov\s+' + re.escape(reg) + r',?\s*(0x[0-9a-f]+|\d+)', line)
            if m:
                return False, "constant", depth + 1
            m = re.search(r'\bxor\s+' + re.escape(reg) + r',?\s*' + re.escape(reg), line)
            if m:
                return False, "zero-init", depth + 1

            # 传播: mov reg, src_reg → 继续追溯src_reg
            m = re.search(r'\bmov\s+' + re.escape(reg) + r',?\s*(\w+)', line)
            if m and m.group(1) != reg:
                queue.append((pos - 1, m.group(1), depth + 1, path + [pos]))
                continue

            # 传播: add reg, imm → 值变化但非完全可控（保守：继续追）
            m = re.search(r'\badd\s+' + re.escape(reg) + r',?\s*(0x[0-9a-f]+|\d+)', line)
            if m:
                queue.append((pos - 1, reg, depth + 1, path + [pos]))
                continue

            # 传播: 上一条指令 → 继续搜索
            if pos > 0:
                queue.append((pos - 1, reg, depth + 1, path + [pos]))

        # 回溯耗尽 → 保守标记为潜在污点（可能通过间接方式到达）
        return True, "indirect (depth limit)", 15

    def _find_rdi_source_reg(self, asm: List[str], call_idx: int) -> Optional[str]:
        """找到设置 rdi 的源寄存器。"""
        for j in range(call_idx - 1, max(call_idx - 8, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')
            m = re.search(r'\bmov\s+rdi,?\s*(\w+)', line)
            if m:
                reg = m.group(1)
                if reg not in ('rdi',):
                    return reg
            # mov rdi, [mem] — 内存加载，保守返回None
            if re.search(r'\bmov\s+rdi,?\s*\[', line):
                return None
        return 'rdi'

    @staticmethod
    def _extract_source(line: str) -> str:
        m = re.search(r'\b(read|recv|recvfrom|fgets|scanf|getenv|fread|getc|gets)\b', line)
        return m.group(1) if m else "unknown_source"
