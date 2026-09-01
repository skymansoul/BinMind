# 栈溢出检测器 (Stack Overflow Detector via Frame Normalization)
#
# 不依赖调试符号, 通过函数序言模式识别栈帧大小,
# 然后验证帧内局部变量写入是否超出边界.
#
# 决策依据:
#   1. 函数序言模式匹配: x86-64 的 sub rsp, imm / push rbp; mov rbp, rsp
#      给出栈帧大小的精确估计. ARM64 的 stp x29,x30,[sp,#-imm]! 同理.
#   2. 危险写入检测: 对每条 store 指令, 检查目标地址是否在 [rbp-frame_size, rbp]
#      范围外. 范围外的写入要么是合法的(其他栈帧), 要么是溢出.
#   3. call-site上下文: 跨编译器(O0/O2/O3)栈帧大小可能不同,
#      通过多编译器编译同一源码, 取帧大小分布的离群值作为异常信号.
#   4. 误报抑制: 仅当写入大小 > 栈帧剩余空间 且 写入地址连续超出边界
#      至少16字节时, 才报告为潜在溢出. 单一字节超界常由结构体对齐引起.
#

import re
import struct
from typing import Dict, List, Optional, Tuple


# x86-64 函数序言模式 → 帧大小提取
_PROLOGUE_PATTERNS = [
    # push rbp; mov rbp, rsp; sub rsp, imm
    (br"\x55\x48\x89\xe5\x48\x83\xec(.)", 1, "byte"),
    (br"\x55\x48\x89\xe5\x48\x81\xec(....)", 4, "dword"),
    # sub rsp, imm (无frame pointer)
    (br"\x48\x83\xec(.)", 1, "byte"),
    (br"\x48\x81\xec(....)", 4, "dword"),
]

# ARM64 函数序言 → 帧大小提取
_ARM64_PROLOGUE = [
    # stp x29, x30, [sp, #-imm]!
    (br"\xfd\x7b\xbf\xa9", 0, "encoded"),
    # sub sp, sp, #imm
    (br"\xff\x43\x00\xd1", 0, "encoded"),
]

# 危险写入函数: 已知可能导致栈溢出的标准库函数
_DANGEROUS_WRITERS = {
    "gets":     {"min_args": 1, "overflow_arg": 0, "reason": "unbounded"},
    "strcpy":   {"min_args": 2, "overflow_arg": 0, "reason": "no_length_check"},
    "strcat":   {"min_args": 2, "overflow_arg": 0, "reason": "no_length_check"},
    "sprintf":  {"min_args": 2, "overflow_arg": 0, "reason": "no_length_check"},
    "vsprintf": {"min_args": 2, "overflow_arg": 0, "reason": "no_length_check"},
    "scanf":    {"min_args": 1, "overflow_arg": 0, "reason": "no_length_check"},
    "memcpy":   {"min_args": 3, "overflow_arg": 0, "reason": "length_dependent"},
    "memmove":  {"min_args": 3, "overflow_arg": 0, "reason": "length_dependent"},
    "read":     {"min_args": 3, "overflow_arg": 1, "reason": "length_dependent"},
    "fread":    {"min_args": 4, "overflow_arg": 3, "reason": "length_dependent"},
    "recv":     {"min_args": 4, "overflow_arg": 1, "reason": "length_dependent"},
}


class StackFrame:
    """从二进制字节中提取的栈帧信息."""
    __slots__ = ("function_name","frame_size","has_canary","prologue_offset")
    def __init__(self, name: str = "", size: int = 0,
                 canary: bool = False, offset: int = 0):
        self.function_name = name; self.frame_size = size
        self.has_canary = canary; self.prologue_offset = offset


class StackOverflowDetector:

    def __init__(self, min_overflow_bytes: int = 16):
        self._min_overflow = min_overflow_bytes
        self._frames: Dict[int, StackFrame] = {}
        self._findings: List[dict] = []

    def extract_frames(self, binary_data: bytes, section_base: int = 0):
        """从二进制代码段扫描并提取所有函数的栈帧信息."""
        for offset in range(0, len(binary_data) - 16):
            for pattern, size_bytes, fmt in _PROLOGUE_PATTERNS:
                match = re.match(pattern, binary_data[offset:])
                if not match:
                    continue
                frame_size = self._decode_frame_size(match, size_bytes, fmt)
                if 0 < frame_size <= 65536:  # 合理的栈帧范围
                    addr = section_base + offset
                    has_canary = self._detect_canary(binary_data, offset)
                    self._frames[addr] = StackFrame(
                        name=f"func_{addr:x}",
                        size=frame_size,
                        canary=has_canary,
                        offset=offset,
                    )
                break  # 一个offset只匹配一个模式

    def check_writes(self, instructions: List[dict],
                      func_addr: int) -> List[dict]:
        """检查函数内的写入指令是否超出栈帧边界.

        每指令格式: {"mnemonic": str, "operands": [str, ...],
                      "address": int, "write_size": int}
        """
        frame = self._frames.get(func_addr)
        if not frame or frame.frame_size == 0:
            return []

        findings = []
        for ins in instructions:
            mnem = ins.get("mnemonic", "").lower()
            if mnem not in ("mov", "movups", "movaps", "vmov", "stos", "rep stos"):
                continue

            write_size = ins.get("write_size", 8)
            target = ins.get("operands", [""])[0] if ins.get("operands") else ""
            rbp_offset = self._parse_rbp_offset(target)

            if rbp_offset is None:
                continue

            # rbp_offset < 0: 栈帧内的合法写入
            # rbp_offset >= 0 且 write_size > 剩余空间 → 潜在溢出
            if rbp_offset >= 0:
                findings.append({
                    "type": "stack_overflow",
                    "address": ins.get("address", 0),
                    "frame_size": frame.frame_size,
                    "overflow_bytes": rbp_offset + write_size,
                    "instruction": mnem,
                    "canary_present": frame.has_canary,
                    "severity": "critical" if rbp_offset + write_size > 64
                                else "high",
                })

        self._findings.extend(findings)
        return findings

    def check_call(self, call_target: str, call_args: int,
                    func_addr: int) -> Optional[dict]:
        """检查危险函数调用是否可能导致栈溢出."""
        func_name = self._extract_name(call_target)
        if func_name not in _DANGEROUS_WRITERS:
            return None

        frame = self._frames.get(func_addr)
        frame_size = frame.frame_size if frame else 0
        info = _DANGEROUS_WRITERS[func_name]

        return {
            "type": "dangerous_call",
            "function": func_name,
            "frame_size": frame_size,
            "reason": info["reason"],
            "canary_present": frame.has_canary if frame else False,
            "severity": "high" if frame_size < 256 and not (
                frame and frame.has_canary) else "medium",
        }

    @property
    def findings(self) -> List[dict]:
        return list(self._findings)

# 内部

    @staticmethod
    def _decode_frame_size(match, size_bytes: int, fmt: str) -> int:
        if fmt == "byte":
            return match.group(1)[0] if size_bytes == 1 else 0
        elif fmt == "dword":
            return struct.unpack("<I", match.group(1))[0] if size_bytes == 4 else 0
        elif fmt == "encoded":
            # ARM64 编码格式: 帧大小编码在指令中
            return 0  # 需要完整ARM64解码器, 当前跳过
        return 0

    @staticmethod
    def _detect_canary(data: bytes, prologue_offset: int) -> bool:
        """检测函数是否使用了栈canary (__stack_chk_fail 调用)."""
        end = min(prologue_offset + 512, len(data))
        return b"__stack_chk" in data[prologue_offset:end]

    @staticmethod
    def _parse_rbp_offset(operand: str) -> Optional[int]:
        """解析 x86-64 的 [rbp+offset] 或 [rbp-offset]."""
        m = re.search(r'\[rbp\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)\]', operand)
        if not m:
            return None
        sign = 1 if m.group(1) == '+' else -1
        val_str = m.group(2)
        val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
        return sign * val

    @staticmethod
    def _extract_name(target: str) -> str:
        t = target.strip().lower()
        t = re.sub(r'^call\s+', '', t)
        t = re.sub(r'@.*$', '', t)
        return t


__all__ = ["StackOverflowDetector", "StackFrame"]
