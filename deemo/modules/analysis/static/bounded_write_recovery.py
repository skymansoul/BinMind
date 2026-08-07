# 有界写尺寸恢复引擎 (Bounded Write-Size Recovery)
#
# 核心决策:
#   无界写入函数(strcpy/strcat/sprintf/gets)的写尺寸由源字符串长度
#   决定, 静态检测器通常整体跳过, 既不确认溢出也不判定安全.
#   本模块从源操作数的实际存储来源恢复写尺寸上界:
# 源为.rodata字符串字面量 → 上界 = 字面量长度(+NUL)
# 源为栈缓冲区[rbp-X] → 上界 = 缓冲区跨度
# 源为已追踪的堆分配 → 上界 = 该分配的可写尺寸
#   恢复成功且上界 ≤ 分配可用区 → 判定安全(消除误报);
#   上界 > 分配可用区 → 判定溢出(召回提升);
#   无法恢复 → 保持跳过(不引入新误报).
#
#   核心不动摇原则: 只做 under-approximation of danger,
#   不确定即保守跳过, 绝不猜安全.
#
# 理论依据:
#   "Automated Discovery of Discrepancy Attacks" 中
#   通过恢复字面量/缓冲区尺寸剔除内存API误用误报;
#   CWE-787/CWE-121 的静态检测同样依赖写入量上界的可靠恢复.
#
# 创建: 2026-07-05

import re
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .disasm_util import norm_reg, extract_stack_slot, extract_func_name
from .heap_alloc_model import HeapAllocModel


class BWRSrcKind(Enum):
    LITERAL = "literal"
    STACK = "stack"
    HEAP = "heap"
    UNKNOWN = "unknown"


class SourceInfo:
    """写源操作数的存储来源与尺寸."""
    __slots__ = ("kind", "size", "detail")

    def __init__(self, kind: BWRSrcKind, size: int = 0, detail: str = ""):
        self.kind = kind
        self.size = size
        self.detail = detail


class BWRVerdict:
    """BWR判定结果."""
    __slots__ = ("kind", "bound", "reason", "src")

    def __init__(self, kind: str, bound: int = 0,
                 reason: str = "", src: Optional[SourceInfo] = None):
        self.kind = kind          # safe | overflow | unknown
        self.bound = bound
        self.reason = reason
        self.src = src


class BoundedWriteRecovery:
    """有界写尺寸恢复引擎.

    输入: 指令序列 + 危险调用索引 + 目标分配信息.
    输出: BWRVerdict.
    """

    # 恢复源的符号名到尺寸的解析
    _SCAN_WINDOW = 80

    _LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

    def __init__(self, alloc_model: Optional[HeapAllocModel] = None,
                 rodata: Optional[Dict[int, bytes]] = None):
        self._alloc_model = alloc_model or HeapAllocModel()
        self._rodata = rodata or {}
        self._stats = {"safe": 0, "overflow": 0, "unknown": 0}

    def set_rodata(self, rodata: Dict[int, bytes]):
        self._rodata = rodata

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def recover(self, instructions: List[dict], call_idx: int, func: str,
                alloc_tracker, dst_reg: str, src_reg: str) -> BWRVerdict:
        """恢复无界写入的最大写入量.

        func: strcpy/strcat/sprintf/gets等.
        dst_reg: 目标指针所在寄存器.
        src_reg: 源操作数寄存器 (strcpy/strcat/sprintf的源/格式串).
        返回: BWRVerdict.
        """
        if func == "gets":
            self._stats["unknown"] += 1
            return BWRVerdict("unknown", reason="gets unbounded")
        if func in ("sprintf", "vsprintf"):
            return self._recover_sprintf(instructions, call_idx, alloc_tracker,
                                         dst_reg, src_reg)
        if func in ("strcpy", "stpcpy"):
            return self._recover_strcpy(instructions, call_idx, func,
                                        alloc_tracker, dst_reg, src_reg)
        if func == "strcat":
            return self._recover_strcat(instructions, call_idx, alloc_tracker,
                                        dst_reg, src_reg)
        self._stats["unknown"] += 1
        return BWRVerdict("unknown", reason=f"unhandled {func}")

    def _recover_strcpy(self, instructions, call_idx, func, alloc_tracker,
                        dst_reg, src_reg) -> BWRVerdict:
        src = self._resolve_src(instructions, call_idx, src_reg, alloc_tracker)
        if src.kind == BWRSrcKind.UNKNOWN:
            self._stats["unknown"] += 1
            return BWRVerdict("unknown", reason="src unbounded", src=src)
        bound = src.size + 1  # 终止NUL
        return self._compare(alloc_tracker, dst_reg, bound, src)

    def _recover_strcat(self, instructions, call_idx, alloc_tracker,
                        dst_reg, src_reg) -> BWRVerdict:
        if not self._dst_zero_initialized(
                instructions, call_idx, dst_reg):
            self._stats["unknown"] += 1
            return BWRVerdict("unknown", reason="strcat dst state unknown")
        src = self._resolve_src(instructions, call_idx, src_reg, alloc_tracker)
        if src.kind == BWRSrcKind.UNKNOWN:
            self._stats["unknown"] += 1
            return BWRVerdict("unknown", reason="strcat src unbounded", src=src)
        bound = src.size + 1
        return self._compare(alloc_tracker, dst_reg, bound, src)

    def _recover_sprintf(self, instructions, call_idx, alloc_tracker,
                         dst_reg, fmt_reg) -> BWRVerdict:
        fmt = self._resolve_src(instructions, call_idx, fmt_reg, alloc_tracker)
        if fmt.kind != BWRSrcKind.LITERAL:
            self._stats["unknown"] += 1
            return BWRVerdict("unknown", reason="fmt not literal", src=fmt)
        max_out = self._format_max_len(fmt.detail, instructions, call_idx)
        if max_out is None:
            # 格式串含无界 %s: 无法静态定界. 若目标是固定小分配,
            # 无界输入必然可溢出 → 判定溢出; 否则保持跳过 (不臆断安全).
            self._stats["unknown"] += 1
            return self._unbounded_into_fixed(alloc_tracker, dst_reg, fmt)
        bound = max_out + 1  # NUL
        return self._compare(alloc_tracker, dst_reg, bound, fmt)

    def _unbounded_into_fixed(self, alloc_tracker, dst_reg,
                              src: SourceInfo) -> BWRVerdict:
        """无界写入 vs 固定分配: 固定小缓冲 + 无界输入 → 溢出.

        仅当分配大小可静态确定为常量时判溢出; 分配大小未知时
        无法证明有界, 保守跳过 (under-approximation of danger).
        """
        alloc_addr = alloc_tracker._ptr_to_alloc.get(norm_reg(dst_reg))
        if alloc_addr is None:
            return BWRVerdict("unknown", reason="dst alloc unknown", src=src)
        alloc = alloc_tracker._allocations.get(alloc_addr)
        if alloc is None:
            return BWRVerdict("unknown", reason="dst alloc not tracked", src=src)
        raw = getattr(alloc, "raw_alloc_size", alloc.alloc_size)
        if not raw.is_singleton or raw.hi <= 0 or raw.hi >= 2**31 - 1:
            return BWRVerdict("unknown", reason="alloc size unbounded", src=src)
        usable = self._alloc_model.usable_size(raw.hi)
        bound = usable + 1
        self._stats["overflow"] += 1
        return BWRVerdict(
            "overflow", bound=bound,
            reason=f"bwr_overflow: unbounded %s into fixed "
                   f"alloc({raw.hi}B, usable {usable}B)", src=src)

    def _compare(self, alloc_tracker, dst_reg, bound: int,
                 src: SourceInfo) -> BWRVerdict:
        alloc_addr = alloc_tracker._ptr_to_alloc.get(norm_reg(dst_reg))
        if alloc_addr is None:
            self._stats["unknown"] += 1
            return BWRVerdict("unknown", reason="dst alloc unknown", src=src)
        alloc = alloc_tracker._allocations.get(alloc_addr)
        if alloc is None:
            self._stats["unknown"] += 1
            return BWRVerdict("unknown", reason="dst alloc not tracked", src=src)
        raw = getattr(alloc, "raw_alloc_size", alloc.alloc_size)
        usable = self._alloc_model.usable_size(raw.hi)
        if bound <= usable:
            self._stats["safe"] += 1
            return BWRVerdict("safe", bound=bound,
                              reason=f"bwr_safe: src={src.detail} "
                                     f"bound={bound} <= usable={usable}",
                              src=src)
        self._stats["overflow"] += 1
        return BWRVerdict("overflow", bound=bound,
                          reason=f"bwr_overflow: src={src.detail} "
                                 f"bound={bound} > usable={usable}",
                          src=src)

    def _resolve_src(self, instructions, call_idx, reg, alloc_tracker,
                     depth: int = 0) -> SourceInfo:
        """从调用点反向解析reg指向的存储来源."""
        if depth > 5:
            return SourceInfo(BWRSrcKind.UNKNOWN, detail=f"depth>{depth}")
        reg = norm_reg(reg)
        start = max(0, call_idx - self._SCAN_WINDOW)
        for i in range(call_idx - 1, start - 1, -1):
            ins = instructions[i]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if len(ops) < 2:
                continue
            dst = norm_reg(ops[0])
            if dst != reg:
                continue
            src_op = ops[1].strip()
            if mnem == "lea":
                return self._resolve_lea(src_op, instructions, i)
            if mnem in ("mov", "movsxd", "movzx", "movsx", "movabs"):
                src_lower = src_op.lower()
                if "rip" in src_lower or "[" in src_lower:
                    return self._resolve_mem_load(src_op, instructions,
                                                  call_idx, alloc_tracker,
                                                  depth)
                imm = self._parse_imm(src_op)
                if imm is not None:
                    return SourceInfo(BWRSrcKind.UNKNOWN, detail="const_ptr")
                return self._resolve_src(instructions, call_idx,
                                         norm_reg(src_op), alloc_tracker,
                                         depth + 1)
        # 未找到定义: 查分配映射 (如直接传 malloc 返回值)
        if reg in alloc_tracker._ptr_to_alloc:
            return self._heap_source(alloc_tracker, reg)
        return SourceInfo(BWRSrcKind.UNKNOWN, detail=f"undef {reg}")

    def _resolve_lea(self, src_op: str, instructions, idx: int) -> SourceInfo:
        src_lower = src_op.lower()
        lit = self._literal_in_comment(src_op)
        if lit is not None:
            return SourceInfo(BWRSrcKind.LITERAL, size=len(lit.encode("utf-8")),
                              detail=f"literal[{len(lit.encode('utf-8'))}]")
        if "rip" in src_lower:
            abs_addr = self._rip_abs(src_op, instructions, idx)
            if abs_addr is not None:
                lit = self._read_rodata_string(abs_addr)
                if lit is not None:
                    return SourceInfo(BWRSrcKind.LITERAL, size=len(lit),
                                      detail=lit)
            return SourceInfo(BWRSrcKind.UNKNOWN, detail="rodata_noliteral")
        if "[rbp" in src_lower or "[rsp" in src_lower:
            size = self._stack_buffer_size(src_op, instructions, idx)
            if size is not None:
                return SourceInfo(BWRSrcKind.STACK, size=size,
                                  detail=f"stack[{size}]")
        return SourceInfo(BWRSrcKind.UNKNOWN, detail="lea_other")

    def _resolve_mem_load(self, src_op, instructions, call_idx,
                          alloc_tracker, depth) -> SourceInfo:
        slot = extract_stack_slot(src_op)
        if slot:
            store = self._find_slot_store(instructions, call_idx, slot)
            if store is not None:
                st_ops = store.get("operands", [])
                if len(st_ops) >= 2:
                    st_src = st_ops[1].strip()
                    st_lower = st_src.lower()
                    if "[" not in st_lower:
                        return self._resolve_src(instructions, call_idx,
                                                 norm_reg(st_src),
                                                 alloc_tracker, depth + 1)
            return SourceInfo(BWRSrcKind.UNKNOWN, detail=f"slot {slot}")
        return SourceInfo(BWRSrcKind.UNKNOWN, detail="mem_load")

    def _stack_buffer_size(self, src_op: str, instructions,
                           idx: int) -> Optional[int]:
        """栈缓冲区跨度恢复.

        [rbp-0x50] → 0x50 (局部数组从槽位延伸到rbp).
        [rsp+0x28] → 需在函数序言找到 sub rsp, N 得出帧大小 N-0x28.
        """
        m = re.search(r'\[(r[bs]p)([-+]\s*0x[0-9a-f]+)\]', src_op.lower())
        if not m:
            return None
        base, off = m.group(1), m.group(2).replace(" ", "")
        try:
            off_val = int(off, 16) if "0x" in off else int(off)
        except ValueError:
            return None
        if base == "rbp":
            return abs(off_val) if off_val <= 0 else None
        frame = self._find_frame_size(instructions, idx)
        if frame is None or off_val < 0:
            return None
        return max(0, frame - off_val)

    def _find_frame_size(self, instructions, idx: int) -> Optional[int]:
        for i in range(idx - 1, max(0, idx - 60), -1):
            ins = instructions[i]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem == "push" and ops:
                if norm_reg(ops[0]) == "rbp":
                    continue
            if mnem in ("sub", "and") and len(ops) >= 2:
                dst = norm_reg(ops[0])
                if dst in ("rsp", "esp") and mnem == "sub":
                    imm = self._parse_imm(ops[1])
                    if imm is not None and imm > 0:
                        return imm
            if mnem == "call":
                return None
        return None

    def _find_slot_store(self, instructions, call_idx, slot: str):
        for i in range(call_idx - 1, max(0, call_idx - self._SCAN_WINDOW), -1):
            ins = instructions[i]
            mnem = ins.get("mnemonic", "").lower()
            if mnem not in ("mov", "movsxd"):
                continue
            ops = ins.get("operands", [])
            if len(ops) < 2:
                continue
            if extract_stack_slot(ops[0]) == slot:
                return ins
        return None

    def _heap_source(self, alloc_tracker, reg: str) -> SourceInfo:
        alloc_addr = alloc_tracker._ptr_to_alloc.get(norm_reg(reg))
        if alloc_addr is None:
            return SourceInfo(BWRSrcKind.UNKNOWN, detail="heap?")
        alloc = alloc_tracker._allocations.get(alloc_addr)
        if alloc is None:
            return SourceInfo(BWRSrcKind.UNKNOWN, detail="heap?")
        raw = getattr(alloc, "raw_alloc_size", alloc.alloc_size)
        return SourceInfo(BWRSrcKind.HEAP,
                          size=self._alloc_model.usable_size(raw.hi),
                          detail=f"heap[{raw.hi}]")

    def _dst_zero_initialized(self, instructions, call_idx,
                              dst_reg: str) -> bool:
        """检测strcat目标是否先被memset清零(常用初始化模式)."""
        dst_reg = norm_reg(dst_reg)
        for i in range(call_idx - 1, max(0, call_idx - self._SCAN_WINDOW), -1):
            ins = instructions[i]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem == "call" and ops:
                func = extract_func_name(ops[0])
                if func == "memset":
                    return True
                return False
        return False

    def _format_max_len(self, fmt: str, instructions, call_idx) -> Optional[int]:
        """计算sprintf格式串的最大输出字节数.

        只统计可确定上界的指令; 遇到无界 %s → 返回None.
        """
        total = 0
        i = 0
        n = len(fmt)
        while i < n:
            if fmt[i] != "%":
                total += 1
                i += 1
                continue
            m = re.match(r'%([+\-#0 ]*)(\d*)(?:\.(\d+))?([hljztL]*)([diouxXeEfFgGaAcspn%])',
                         fmt[i:])
            if not m:
                total += 1
                i += 1
                continue
            flags, width, prec, length, conv = m.groups()
            i += m.end()
            if conv == "%":
                total += 1
                continue
            if conv == "n":
                continue
            if conv == "c":
                total += max(int(width or 1), 1)
                continue
            if conv in "diouxX":
                total += max(int(width or 1), 1)
                continue
            if conv in "eEfFgGaA":
                p = int(prec) if prec else 6
                total += max(int(width or 0), p + 1)
                continue
            if conv == "s":
                w = int(width) if width else 0
                p = int(prec) if prec else 0
                if w or p:
                    total += max(w, p)
                    continue
                return None  # 无界 %s
            return None
        return total

    def _arg_reg(self, instructions, call_idx: int, idx: int) -> Optional[str]:
        """从call指令操作数解析第idx个实参寄存器.

        objdump intel格式: call操作数为函数名(1个operand),
        实参寄存器信息丢失, 只能从调用前的指令窗口推导.
        实际取值由调用方(_handle_write_call)提供, 此处仅为兜底.
        """
        return None

    @staticmethod
    def _literal_in_comment(op: str) -> Optional[str]:
        """从操作数内联注释提取字符串字面量. 如 <"hello"> 或 # "hi"."""
        m = BoundedWriteRecovery._LITERAL_RE.search(op)
        if not m:
            return None
        raw = m.group(1)
        try:
            return raw.encode().decode("unicode_escape")
        except Exception:
            return raw

    @staticmethod
    def _rip_abs(src_op: str, instructions, idx: int) -> Optional[int]:
        """解析 lea reg,[rip+disp] 的目标绝对地址."""
        from .disasm_util import resolve_rip_relative
        ins = instructions[idx]
        return resolve_rip_relative(ins, src_op, ins.get("address", 0))

    def _read_rodata_string(self, abs_addr: int) -> Optional[str]:
        """从.rodata映射读取NUL终止字符串; 无映射或不可读返回None."""
        if not self._rodata:
            return None
        from .rodata_extract import read_cstring
        raw = read_cstring(self._rodata, abs_addr)
        if not raw:
            return None
        if not all(32 <= b < 127 for b in raw):
            return None
        return raw.decode("utf-8", errors="replace")

    @staticmethod
    def _parse_imm(op: str) -> Optional[int]:
        s = op.strip().lower().lstrip("%").replace("$", "").split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None


__all__ = ["BoundedWriteRecovery", "BWRVerdict", "SourceInfo", "BWRSrcKind"]
