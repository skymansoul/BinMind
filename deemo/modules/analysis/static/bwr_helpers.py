# -*- coding: utf-8 -*-
"""BWR 无界写恢复辅助函数族.

决策:
  集中无界写分析的辅助逻辑: 源操作数存储来源解析 (立即数/注释
  字面量/rodata/栈缓冲区跨度), 各写函数族 (strcpy/strcat/sprintf)
  的写入上界恢复与越界判定, sprintf 格式串最大输出长度解析.
  原拆分为独立模块的同类函数合并于此, 保持单一内聚单元.

创建: 2024-01-03
"""

import re
from typing import Optional

from .disasm_util import norm_reg, extract_stack_slot

# sprintf 格式说明符解析: 标志/宽度/精度/长度/转换符
_FMT_RE = re.compile(
    r"%([+\-#0 ]*)(\d*)(?:\.(\d+))?([hljztL]*)([diouxXeEfFgGaAcspn%])")


def parse_imm(op: str) -> Optional[int]:
    s = op.strip().lower().lstrip("%").replace("$", "")
    s = s.split("#")[0].strip()
    try:
        if s.startswith("0x"):
            return int(s, 16)
        if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
            return int(s)
    except ValueError:
        pass
    return None


def literal_in_comment(op: str) -> Optional[str]:
    """从 objdump 注释中提取字符串字面量 (如 # "HELLO")."""
    m = re.search(r'"(?:[^"\\]|\\.)*"', op)
    if m:
        try:
            return m.group(0).encode("utf-8").decode("unicode_escape")
        except Exception:
            return m.group(0)
    return None


def rip_abs(src_op: str, instructions: list, idx: int) -> Optional[int]:
    """解析 lea [rip+disp] 的绝对地址."""
    m = re.search(r"rip\s*([+-]\s*0x[0-9a-f]+|[+-]\s*\d+)", src_op.lower())
    if not m:
        return None
    off_str = m.group(1).replace(" ", "")
    try:
        off = int(off_str, 16) if "0x" in off_str.lower() else int(off_str)
    except ValueError:
        return None
    if idx < 0 or idx >= len(instructions):
        return None
    ins = instructions[idx]
    addr = ins.get("address", 0)
    ins_len = _estimate_len(ins)
    return addr + ins_len + off


def _estimate_len(ins: dict) -> int:
    """RIP 相对 lea 通常 7 字节 (REX.W+8D+ModR/M+disp32)."""
    mnem = ins.get("mnemonic", "").lower()
    if mnem in ("lea", "mov"):
        return 7
    return 6


def read_rodata_string(rodata: dict, abs_addr: int) -> Optional[str]:
    """从只读节字节映射读取 C 字符串."""
    if not rodata:
        return None
    data = rodata.get(abs_addr)
    if data is None:
        return None
    if isinstance(data, str):
        s = data.split("\x00", 1)[0]
        return s if s else None
    if isinstance(data, (bytes, bytearray)):
        s = bytes(data).split(b"\x00", 1)[0]
        try:
            return s.decode("utf-8", errors="replace")
        except Exception:
            return None
    return None


def format_max_len(fmt: str) -> Optional[int]:
    """计算格式串可能输出的最大字节数, 无界 %s 返回 None."""
    total = 0
    i = 0
    n = len(fmt)
    while i < n:
        if fmt[i] != "%":
            total += 1
            i += 1
            continue
        m = _FMT_RE.match(fmt[i:])
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
            return None
        return None
    return total


def stack_buffer_size(instructions, src_op: str, idx: int) -> Optional[int]:
    """栈缓冲区跨度恢复.

    [rbp-0x50] → 0x50 (局部数组从槽位延伸到rbp).
    [rsp+0x28] → 需在函数序言找到 sub rsp, N 得出帧大小 N-0x28.
    """
    m = re.search(r"\[(r[bs]p)([-+]\s*0x[0-9a-f]+)\]", src_op.lower())
    if not m:
        return None
    base, off = m.group(1), m.group(2).replace(" ", "")
    try:
        off_val = int(off, 16) if "0x" in off else int(off)
    except ValueError:
        return None
    if base == "rbp":
        return abs(off_val) if off_val <= 0 else None
    frame = find_frame_size(instructions, idx)
    if frame is None or off_val < 0:
        return None
    return max(0, frame - off_val)


def find_frame_size(instructions, idx: int) -> Optional[int]:
    """从函数序言恢复帧大小 (sub rsp, N 或 and rsp, -N)."""
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
                imm = parse_imm(ops[1])
                if imm is not None and imm > 0:
                    return imm
        if mnem == "call":
            return None
    return None


def find_slot_store(instructions, upper, slot: str, scan_window: int):
    """返回 (store指令索引, store指令), 或None."""
    for i in range(upper - 1, max(0, upper - scan_window), -1):
        ins = instructions[i]
        mnem = ins.get("mnemonic", "").lower()
        if mnem == "ret":
            break
        if mnem not in ("mov", "movsxd"):
            continue
        ops = ins.get("operands", [])
        if len(ops) < 2:
            continue
        if extract_stack_slot(ops[0]) == slot:
            return i, ins
    return None


def recover_strcpy(self, instructions, call_idx, func, alloc_tracker,
                   dst_reg, src_reg, dst_alloc_addr=None):
    from .bounded_write_recovery import BWRSrcKind, BWRVerdict
    src = self._resolve_src(instructions, call_idx, src_reg, alloc_tracker)
    if src.kind == BWRSrcKind.UNKNOWN:
        self._stats["unknown"] += 1
        return BWRVerdict("unknown", reason="src unbounded", src=src)
    bound = src.size + 1  # 终止NUL
    return self._compare(alloc_tracker, dst_reg, bound, src,
                         dst_alloc_addr)


def recover_strcat(self, instructions, call_idx, alloc_tracker,
                   dst_reg, src_reg, dst_alloc_addr=None):
    from .bounded_write_recovery import BWRSrcKind, BWRVerdict
    if not self._dst_zero_initialized(instructions, call_idx, dst_reg):
        self._stats["unknown"] += 1
        return BWRVerdict("unknown", reason="strcat dst state unknown")
    src = self._resolve_src(instructions, call_idx, src_reg, alloc_tracker)
    if src.kind == BWRSrcKind.UNKNOWN:
        self._stats["unknown"] += 1
        return BWRVerdict("unknown", reason="strcat src unbounded", src=src)
    bound = src.size + 1
    return self._compare(alloc_tracker, dst_reg, bound, src,
                         dst_alloc_addr)


def recover_sprintf(self, instructions, call_idx, alloc_tracker,
                    dst_reg, fmt_reg, dst_alloc_addr=None):
    from .bounded_write_recovery import BWRSrcKind, BWRVerdict
    fmt = self._resolve_src(instructions, call_idx, fmt_reg, alloc_tracker)
    if fmt.kind != BWRSrcKind.LITERAL:
        self._stats["unknown"] += 1
        return BWRVerdict("unknown", reason="fmt not literal", src=fmt)
    max_out = self._format_max_len(fmt.detail, instructions, call_idx)
    if max_out is None:
        # 格式串含无界 %s: 目标为固定小分配则判溢出, 否则跳过.
        self._stats["unknown"] += 1
        return unbounded_into_fixed(self, alloc_tracker, dst_reg, fmt,
                                    dst_alloc_addr)
    bound = max_out + 1  # NUL
    return self._compare(alloc_tracker, dst_reg, bound, fmt,
                         dst_alloc_addr)


def unbounded_into_fixed(self, alloc_tracker, dst_reg,
                         src, dst_alloc_addr=None):
    """无界写入 vs 固定分配: 固定小缓冲 + 无界输入 → 溢出.

    仅当分配大小可静态确定为常量时判溢出; 未知时保守跳过.
    usable 基于原始请求 (raw_alloc_size.lo), 与 allocator 层一致.
    """
    from .bounded_write_recovery import BWRVerdict
    alloc_addr = dst_alloc_addr or alloc_tracker._ptr_to_alloc.get(
        norm_reg(dst_reg))
    if alloc_addr is None:
        return BWRVerdict("unknown", reason="dst alloc unknown", src=src)
    alloc = alloc_tracker._allocations.get(alloc_addr)
    if alloc is None:
        return BWRVerdict("unknown", reason="dst alloc not tracked", src=src)
    raw = getattr(alloc, "raw_alloc_size", alloc.alloc_size)
    if not raw.is_singleton or raw.hi <= 0 or raw.hi >= 2**31 - 1:
        return BWRVerdict("unknown", reason="alloc size unbounded", src=src)
    request = max(0, raw.lo - 15)
    usable = self._alloc_model.usable_size(request)
    bound = usable + 1
    self._stats["overflow"] += 1
    return BWRVerdict(
        "overflow", bound=bound,
        reason=f"bwr_overflow: unbounded %s into fixed "
               f"alloc({raw.hi}B, usable {usable}B)", src=src)


__all__ = ["parse_imm", "literal_in_comment", "rip_abs",
           "read_rodata_string", "format_max_len", "stack_buffer_size",
           "find_frame_size", "find_slot_store", "recover_strcpy",
           "recover_strcat", "recover_sprintf", "unbounded_into_fixed"]
