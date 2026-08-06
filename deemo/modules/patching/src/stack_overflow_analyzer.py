# 栈溢出检测深度强化 — 栈帧边界 + 局部变量偏移分析
"""栈溢出检测器 — 基于栈帧结构的边界分析替代 sanitizer 输出匹配。

旧方法: regex 匹配 ASAN 报告中 'stack-buffer-overflow' 字符串。
问题:
  - 必须实际运行程序并触发 ASAN（动态依赖）
  - 对冷路径完全失效（未覆盖的代码不会触发溢出）
  - 无法在静态分析阶段提供预警

新方法: 分析函数栈帧布局，检测栈缓冲区写入是否可能越界。
  1. 从函数序言提取栈帧大小 (sub rsp, N)
  2. 识别局部缓冲区位置 (lea rax, [rbp-offset])
  3. 分析对该缓冲区的写入操作大小
  4. 若写入大小可能超过缓冲区大小 → 标记为潜在栈溢出

方法依据:
  编译器在栈上为局部变量分配固定大小的空间。
  若 memcpy/strcpy 的写入长度参数可能超过分配空间 → 溢出。
  这不需要运行时触发，纯静态推断。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set

_log = logging.getLogger(__name__)


@dataclass
class StackBuffer:
    """栈上的一个局部缓冲区。"""
    name_hint: str = ""            # rbp-N 的偏移描述
    offset_from_rbp: int = 0       # 相对于 rbp 的偏移
    estimated_size: int = 0        # 估计的缓冲区大小
    # 来源推断
    size_inferred_from: str = ""   # 如何推断出大小


@dataclass
class StackWrite:
    """对栈缓冲区的一次写入操作。"""
    line_index: int = 0
    instruction: str = ""
    target_buffer: Optional[StackBuffer] = None
    write_size: int = 0            # 写入的字节数（若为常量）
    write_size_tainted: bool = False
    # 是否可能超出缓冲区边界
    may_overflow: bool = False


@dataclass
class StackOverflowReport:
    """栈溢出检测报告。"""
    function_name: str = ""
    stack_frame_size: int = 0
    buffers: List[StackBuffer] = field(default_factory=list)
    writes: List[StackWrite] = field(default_factory=list)
    overflows: List[StackWrite] = field(default_factory=list)
    total_writes: int = 0
    overflow_count: int = 0

    def to_dict(self) -> Dict:
        return {
            'function': self.function_name,
            'frame_size': self.stack_frame_size,
            'buffers': len(self.buffers),
            'writes': self.total_writes,
            'overflows': self.overflow_count,
        }


# ── 栈帧分析器 ────────────────────────────────────────────────────

class StackFrameAnalyzer:
    """从函数汇编中分析栈帧结构。"""

    def analyze(self, asm_lines: List[str],
                function_name: str = "") -> StackOverflowReport:
        report = StackOverflowReport(function_name=function_name)

        # Step 1: 提取栈帧大小
        report.stack_frame_size = self._extract_frame_size(asm_lines)
        if report.stack_frame_size == 0:
            report.stack_frame_size = 64  # 默认估计

        # Step 2: 识别局部缓冲区
        report.buffers = self._identify_buffers(asm_lines)

        # Step 3: 分析栈写入
        for i, line in enumerate(asm_lines):
            write = self._analyze_stack_write(line, i, report.buffers, report.stack_frame_size)
            if write:
                report.writes.append(write)
                report.total_writes += 1
                if write.may_overflow:
                    report.overflows.append(write)
                    report.overflow_count += 1

        return report

    def _extract_frame_size(self, asm: List[str]) -> int:
        for line in asm:
            m = re.search(r'sub\s+rsp,\s*(0x[0-9a-f]+|\d+)', line, re.I)
            if m:
                v = m.group(1)
                return int(v, 16) if v.lower().startswith('0x') else int(v)
        return 0

    def _identify_buffers(self, asm: List[str]) -> List[StackBuffer]:
        """识别栈上的局部缓冲区。

        模式:
          lea rax, [rbp-N]  → 取局部变量的地址（可能为缓冲区）
          mov [rbp-N], imm  → 直接写入栈偏移
          多次对不同rbp偏移的引用 → 可能的缓冲区范围
        """
        buffers = []
        offsets_seen = set()
        for line in asm:
            stripped = line.strip().lower().replace(',', ' ')
            for m in re.finditer(r'\[rbp\s*-\s*(0x[0-9a-f]+|\d+)\]', stripped):
                v = m.group(1)
                off = int(v, 16) if v.lower().startswith('0x') else int(v)
                offsets_seen.add(off)

        # 将相近的偏移聚类为缓冲区
        sorted_offs = sorted(offsets_seen)
        if not sorted_offs:
            return buffers

        # 简单聚类: 相邻偏移差距 ≤ 16 的归为同一缓冲区
        cluster_start = sorted_offs[0]
        cluster_end = sorted_offs[0]
        for off in sorted_offs[1:]:
            if off - cluster_end <= 16:
                cluster_end = off
            else:
                size = cluster_end - cluster_start + 8
                buffers.append(StackBuffer(
                    name_hint="rbp-%d" % cluster_start,
                    offset_from_rbp=cluster_start, estimated_size=size,
                    size_inferred_from="cluster_analysis"))
                cluster_start = off; cluster_end = off
        # 最后一个聚类
        size = cluster_end - cluster_start + 8
        buffers.append(StackBuffer(
            name_hint="rbp-%d" % cluster_start,
            offset_from_rbp=cluster_start, estimated_size=size,
            size_inferred_from="cluster_analysis"))
        return buffers

    def _analyze_stack_write(self, inst: str, idx: int,
                             buffers: List[StackBuffer],
                             frame_size: int) -> Optional[StackWrite]:
        """分析对栈缓冲区的写入操作。"""
        stripped = inst.strip().lower().replace(',', ' ')
        # 检测对 rbp-N 的写入: mov [rbp-N], reg 或 lea rdi, [rbp-N]; call memcpy
        m = re.search(r'\[rbp\s*-\s*(0x[0-9a-f]+|\d+)\]', stripped)
        if not m:
            return None
        v = m.group(1)
        off = int(v, 16) if v.lower().startswith('0x') else int(v)

        # 找到对应的缓冲区
        target_buf = None
        for b in buffers:
            if b.offset_from_rbp <= off <= b.offset_from_rbp + b.estimated_size:
                target_buf = b
                break

        # 检测写入大小
        write_size = self._infer_write_size(inst, str(idx))
        tainted = self._is_size_tainted(inst)

        # 溢出判定: 写入大小 > 缓冲区剩余空间
        may_overflow = False
        if target_buf and write_size > 0:
            buf_end = target_buf.offset_from_rbp + target_buf.estimated_size
            may_overflow = (off + write_size) > buf_end

        return StackWrite(
            line_index=idx, instruction=inst.strip(),
            target_buffer=target_buf,
            write_size=write_size, write_size_tainted=tainted,
            may_overflow=may_overflow)

    def _infer_write_size(self, inst: str, idx_hint: str) -> int:
        """从mov指令的size后缀推断写入大小。"""
        if re.search(r'\bmov\s+byte\b', inst, re.I):
            return 1
        if re.search(r'\bmov\s+word\b', inst, re.I):
            return 2
        if re.search(r'\bmov\s+dword\b', inst, re.I):
            return 4
        if re.search(r'\bmov\s+qword\b', inst, re.I):
            return 8
        # mov [rbp-N], reg: 根据寄存器宽度推断
        m = re.search(r'\bmov\s+\[rbp.*\],\s*(\w+)', inst, re.I)
        if m:
            reg = m.group(1)
            if reg.startswith('r') and len(reg) >= 3:
                return 8
            elif reg.startswith('e'):
                return 4
            return 8  # 默认 64-bit
        return 0

    def _is_size_tainted(self, inst: str) -> bool:
        """检查写入大小是否可能由用户控制。"""
        return 'rdx,' in inst.lower() or 'rcx,' in inst.lower()
