"""
栈帧大小静态推断 — 不执行符号执行, 从汇编指令推断栈缓冲区边界。
方法: 解析序言 sub rsp N 推断帧大小, 搜索 lea rax,[rbp-N] 定位缓冲区,
对比危险写入偏移是否越界。局限: alloca/VLA 无法推断, 仅 x86_64。
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class StackFrame:
    func_name: str
    frame_size: int        # sub rsp, N 的值
    has_frame_pointer: bool
    buffer_refs: List["StackBuffer"] = field(default_factory=list)


@dataclass
class StackBuffer:
    var_name: str          # 反编译中的变量名
    rbp_offset: int        # [rbp - offset] 中的 offset
    estimated_size: int    # 估计的缓冲区大小 (字节)
    source_line: str = ""  # 对应的伪代码行


@dataclass
class FrameOverflowRisk:
    func_name: str
    buffer: StackBuffer
    write_offset: int      # 写入操作距离 rbp 的偏移
    write_size: int         # 写入字节数
    exceeds_buffer: bool    # 写入偏移+大小是否超出缓冲区估计大小
    confidence: float


class StackFrameInferrer:
    """
    栈帧大小推断器。

    在反汇编文本上做纯静态分析。
    """

    _SUB_RSP_PAT = re.compile(r'sub\s+(?:rsp|esp),\s*(0x[0-9a-fA-F]+|\d+)')
    _LEA_BUF_PAT = re.compile(
        r'lea\s+(?:rax|rcx|rdx|rbx|rsi|rdi|r8|r9),\s*\[rbp\s*-\s*(0x[0-9a-fA-F]+|\d+)\]'
    )
    _MOV_BUF_PAT = re.compile(
        r'mov\s+(?:rax|rcx|rdx|rbx|rsi|rdi),\s*\[rbp\s*-\s*(0x[0-9a-fA-F]+|\d+)\]'
    )
    _WRITE_PAT = re.compile(
        r'(?:call|mov|rep\s+movs).*?(0x[0-9a-fA-F]+|\d+)'
    )

    def infer_frame(self, disasm_text: str, func_name: str = "") -> StackFrame:
        """从反汇编文本推断栈帧结构。"""
        frame_size = 0
        for m in self._SUB_RSP_PAT.finditer(disasm_text):
            val = int(m.group(1), 16 if m.group(1).startswith('0x') else 10)
            if val > frame_size:
                frame_size = val

        frame_size = max(frame_size, 32)

        buffers: List[StackBuffer] = []
        seen_offsets: set = set()
        for m in self._LEA_BUF_PAT.finditer(disasm_text):
            offset = int(m.group(1), 16 if m.group(1).startswith('0x') else 10)
            if offset not in seen_offsets:
                seen_offsets.add(offset)
                est_size = min(offset, 256)
                buffers.append(StackBuffer(
                    var_name=f'buf_{offset:x}',
                    rbp_offset=offset,
                    estimated_size=est_size,
                    source_line=m.group(0),
                ))

        return StackFrame(
            func_name=func_name,
            frame_size=frame_size,
            has_frame_pointer='push rbp' in disasm_text,
            buffer_refs=buffers,
        )

    def check_overflow(
        self, frame: StackFrame, write_offset: int, write_size: int,
    ) -> List[FrameOverflowRisk]:
        """
        检查写入操作是否溢出栈缓冲区。

        write_offset: 写入操作访问的 rbp 偏移量
        write_size: 写入的字节数
        """
        risks: List[FrameOverflowRisk] = []
        for buf in frame.buffer_refs:
            # 缓冲区起始位置 (离 rbp 的距离) <= write_offset
            # 检查 write_offset + write_size 是否超出 rbp_offset (缓冲区起始)
            buf_end = buf.rbp_offset
            write_end = write_offset + write_size

            exceeds = write_end > buf.rbp_offset and write_offset < buf.rbp_offset
            conf = 0.70 if exceeds else 0.20

            if exceeds or write_offset >= buf.rbp_offset - 32:
                risks.append(FrameOverflowRisk(
                    func_name=frame.func_name,
                    buffer=buf,
                    write_offset=write_offset,
                    write_size=write_size,
                    exceeds_buffer=exceeds,
                    confidence=conf if exceeds else 0.35,
                ))

        return risks


__all__ = ['StackFrame', 'StackBuffer', 'FrameOverflowRisk', 'StackFrameInferrer']
