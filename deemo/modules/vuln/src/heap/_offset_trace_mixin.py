# 偏移值域追踪器后向追踪 — 从offset_range_tracker.py拆分.
# 包含后向追踪和静态工具方法.
# 增加顶层导入回退, 与offset_proof_filter的导入模式保持一致.

import re
from typing import Optional

try:
    from ._offset_types import OffsetRange, OffsetProvenance
except ImportError:
    from _offset_types import (  # type: ignore[no-redef]
        OffsetRange, OffsetProvenance)


class OffsetTraceMixin:
    """后向追踪和工具方法, 由OffsetRangeTracker继承."""

    def _backward_trace(self, target_reg: str, start_idx: int,
                        insns) -> Optional[OffsetRange]:
        """从 start_idx 后向追踪 target_reg 的值来源."""
        range_lo = 0
        range_hi = 0xFFFFFFFF
        provenance = OffsetProvenance.UNKNOWN
        steps = []

        for j in range(start_idx - 1, max(0, start_idx - self.MAX_BACKWARD) - 1, -1):
            insn = insns[j]
            mn = insn.mnemonic
            op = insn.operands

            if mn in ('mov', 'movsxd', 'movzx'):
                if ',' in op:
                    dst, src = [x.strip() for x in op.split(',', 1)]
                    dst_r = self._reg(dst)
                    src_r = self._reg(src)
                    if dst_r == target_reg:
                        if src_r:
                            target_reg = src_r
                            steps.append(f"mov {dst_r}←{src_r} @ {insn.addr:x}")
                            continue
                        c = self._parse_imm(src)
                        if c is not None:
                            range_lo = c; range_hi = c
                            provenance = OffsetProvenance.CONSTANT
                            steps.append(f"imm={c} @ {insn.addr:x}")
                        break

            if mn == 'lea' and ',' in op:
                dst, src = [x.strip() for x in op.split(',', 1)]
                dst_r = self._reg(dst)
                if dst_r == target_reg:
                    c = self._parse_lea_const(src)
                    if c is not None:
                        range_lo = c; range_hi = c
                        provenance = OffsetProvenance.CONSTANT
                        steps.append(f"lea→imm={c} @ {insn.addr:x}")
                    break

            if mn in ('xor', 'pxor') and ',' in op:
                parts = [x.strip() for x in op.split(',')]
                if len(parts) >= 2 and parts[0] == parts[1]:
                    r = self._reg(parts[0])
                    if r == target_reg:
                        range_lo = 0; range_hi = 0
                        provenance = OffsetProvenance.CONSTANT
                        steps.append(f"zero @ {insn.addr:x}")
                        break

            if mn in ('add', 'sub') and ',' in op:
                parts = [x.strip() for x in op.split(',')]
                dst_r = self._reg(parts[0]) if parts else ''
                if dst_r == target_reg:
                    c = self._parse_imm(parts[-1])
                    if c is not None:
                        if mn == 'add':
                            range_lo += c; range_hi += c
                        else:
                            range_lo = max(0, range_lo - c)
                            range_hi = max(0, range_hi - c)
                        steps.append(f"{mn}={c:+d} @ {insn.addr:x}")
                        provenance = OffsetProvenance.REGISTER_CHAIN

            if mn in ('shl', 'sal') and ',' in op:
                parts = [x.strip() for x in op.split(',')]
                dst_r = self._reg(parts[0]) if parts else ''
                if dst_r == target_reg:
                    c = self._parse_imm(parts[-1])
                    if c is not None:
                        range_lo <<= c; range_hi <<= c
                        steps.append(f"shl={c} @ {insn.addr:x}")

        if steps:
            return OffsetRange(lo=range_lo, hi=range_hi,
                              provenance=provenance, narrow_steps=steps)
        return None

    @staticmethod
    def _reg(op: str) -> str:
        """提取操作数中的寄存器."""
        m = re.search(r'\b([er]?[a-d]x|[er]?[sd]i|[er]?[sb]p|r\d+[bwd]?)\b',
                      op.lower())
        return m.group(1) if m else ''

    @staticmethod
    def _parse_imm(op: str) -> Optional[int]:
        """解析立即数."""
        m = re.search(r'(0x[0-9a-fA-F]+)', op)
        if m:
            return int(m.group(1), 16)
        m = re.search(r'\b(\d+)\b', op)
        if m:
            v = int(m.group(1))
            if v < 0x100000:
                return v
        return None

    @staticmethod
    def _parse_lea_const(lea_src: str) -> Optional[int]:
        """从 lea 源操作数提取常量部分. '[rdx+rdx*4+0x10]' → 16."""
        m = re.findall(r'[+\-]\s*(0x[0-9a-fA-F]+|\d+)\b', lea_src)
        if m:
            return sum(int(x, 0) for x in m)
        if 'rip' in lea_src.lower() or 'rbp' in lea_src.lower():
            return 0
        return None
