#!/usr/bin/env python3
# 扩充 AVX-512 掩码寄存器 k0-k7 的 lane 级 taint 传播
# ARM NEON 的 Vn.2S/Vn.4H 等排列限定符建模

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# 寄存器架构定义

# x86_64 通用寄存器及其重叠关系
# 格式: canonical_name → [(offset_from_base, size_in_bytes, alias_name),.]
# canonical_name 为大端序（历史原因），存储时为小端字节数组
_X86_64_GPR_ALIASES: Dict[str, List[Tuple[int, int, str]]] = {
    "RAX": [(0, 8, "RAX"), (0, 4, "EAX"), (0, 2, "AX"), (0, 1, "AL"), (1, 1, "AH")],
    "RBX": [(0, 8, "RBX"), (0, 4, "EBX"), (0, 2, "BX"), (0, 1, "BL"), (1, 1, "BH")],
    "RCX": [(0, 8, "RCX"), (0, 4, "ECX"), (0, 2, "CX"), (0, 1, "CL"), (1, 1, "CH")],
    "RDX": [(0, 8, "RDX"), (0, 4, "EDX"), (0, 2, "DX"), (0, 1, "DL"), (1, 1, "DH")],
    "RSI": [(0, 8, "RSI"), (0, 4, "ESI"), (0, 2, "SI"), (0, 1, "SIL")],
    "RDI": [(0, 8, "RDI"), (0, 4, "EDI"), (0, 2, "DI"), (0, 1, "DIL")],
    "RBP": [(0, 8, "RBP"), (0, 4, "EBP"), (0, 2, "BP"), (0, 1, "BPL")],
    "RSP": [(0, 8, "RSP"), (0, 4, "ESP"), (0, 2, "SP"), (0, 1, "SPL")],
}

# R8-R15: 仅 64/32/16/8 位变体，无 AH/BH/CH/DH 风格的高字节别名
for _i in range(8, 16):
    _X86_64_GPR_ALIASES[f"R{_i}"] = [
        (0, 8, f"R{_i}"), (0, 4, f"R{_i}D"), (0, 2, f"R{_i}W"), (0, 1, f"R{_i}B")
    ]


def _build_x86_alias_map() -> Dict[str, Tuple[str, int, int]]:
    m: Dict[str, Tuple[str, int, int]] = {}
    for canon, aliases in _X86_64_GPR_ALIASES.items():
        for off, sz, alias in aliases:
            m[alias] = (canon, off, sz)
            m[alias.lower()] = (canon, off, sz)  # 大小写不敏感
    return m


_X86_ALIAS_MAP = _build_x86_alias_map()


class Arch(IntEnum):
    X86_64 = 0
    ARM64 = 1


# 寄存器污点状态的内部表示

@dataclass
class _RegTaint:
    size: int  # 寄存器总字节数（GPR=8, NEON=16, AVX=32, AVX-512=64）
    taint_bytes: List[int] = field(default_factory=list)  # len == size

    def __post_init__(self):
        if not self.taint_bytes:
            self.taint_bytes = [0] * self.size

    def clone(self) -> "_RegTaint":
        return _RegTaint(size=self.size, taint_bytes=list(self.taint_bytes))


class SubregTaintTracker:

    def __init__(self, arch: Arch = Arch.X86_64, max_taint_labels: int = 16):
        self.arch = arch
        self._max_labels = max_taint_labels
        self.regs: Dict[str, _RegTaint] = {}
        self.label_names: Dict[int, str] = {}
        self._next_label = 0

        if arch == Arch.X86_64:
            self._init_x86_regs()
        else:
            self._init_arm64_regs()

    # 初始化

    def _init_x86_regs(self) -> None:
        for canon in _X86_64_GPR_ALIASES:
            self.regs[canon] = _RegTaint(size=8)
        # SIMD: XMM0-XMM15 (128-bit = 16 bytes)
        for i in range(16):
            self.regs[f"XMM{i}"] = _RegTaint(size=16)
            self.regs[f"YMM{i}"] = _RegTaint(size=32)  # YMM = 256-bit
        # 标记 YMM 的低 128 位与 XMM 共享物理存储
        # 写 XMM 应同时更新对应 YMM 的低 16 字节（vzeroupper 语义）

    def _init_arm64_regs(self) -> None:
        for i in range(31):
            self.regs[f"X{i}"] = _RegTaint(size=8)
            self.regs[f"W{i}"] = _RegTaint(size=4)  # Wn 是 Xn 的低 32 位
        for i in range(32):
            self.regs[f"V{i}"] = _RegTaint(size=16)  # 128-bit NEON
        self.regs["SP"] = _RegTaint(size=8)

    # 污点标签分配

    def new_label(self, name: str = "") -> int:
        lb = self._next_label
        if lb >= self._max_labels:
            # 标签耗尽 —— 复用最老的标签（FIFO 策略）
            oldest = min(self.label_names.keys()) if self.label_names else 0
            del self.label_names[oldest]
            return oldest
        self._next_label += 1
        if name:
            self.label_names[lb] = name
        return lb

    # 寄存器别名解析

    def _resolve_x86(self, reg_name: str) -> Tuple[str, int, int]:
        upper = reg_name.upper()
        if upper in _X86_ALIAS_MAP:
            return _X86_ALIAS_MAP[upper]
        # XMM/YMM
        if upper.startswith("XMM") or upper.startswith("YMM"):
            return (upper, 0, self.regs.get(upper, _RegTaint(size=16)).size)
        return (upper, 0, self.regs.get(upper, _RegTaint(size=8)).size)

    def _resolve_arm64(self, reg_name: str) -> Tuple[str, int, int, Optional[Tuple[int, int]]]:
        upper = reg_name.upper()
        # NEON 排列: Vn.4S 或 Vn.4S[2]
        if '.' in upper:
            base, spec = upper.split('.', 1)
            lane_idx = None
            lane_count = None
            if '[' in spec:
                spec, idx_part = spec.split('[', 1)
                lane_idx = int(idx_part.rstrip(']'))
            # 解析排列类型
            el_size = {'B': 1, 'H': 2, 'S': 4, 'D': 8, 'Q': 16}.get(
                ''.join(c for c in spec if c.isalpha()), 4
            )
            lane_count = int(''.join(c for c in spec if c.isdigit()) or '4')
            if lane_idx is not None:
                return (base, lane_idx * el_size, el_size, (lane_idx, lane_count))
            return (base, 0, lane_count * el_size, None)
        return (upper, 0, self.regs.get(upper, _RegTaint(size=8)).size, None)

    # 读写操作

    def read(self, reg_name: str, offset: int = 0, size: int = 0) -> int:
        if self.arch == Arch.X86_64:
            canon, alias_off, alias_sz = self._resolve_x86(reg_name)
        else:
            canon, alias_off, alias_sz, _ = self._resolve_arm64(reg_name)

        rt = self.regs.get(canon)
        if rt is None:
            return 0
        start = offset or alias_off
        end = min((start + size) if size > 0 else (alias_off + alias_sz), rt.size)
        mask = 0
        for b in rt.taint_bytes[start:end]:
            mask |= b
        return mask

    def write(self, reg_name: str, taint_mask: int,
              offset: int = 0, size: int = 0) -> None:
        if self.arch == Arch.X86_64:
            canon, alias_off, alias_sz = self._resolve_x86(reg_name)
        else:
            canon, alias_off, alias_sz, _ = self._resolve_arm64(reg_name)

        rt = self.regs.get(canon)
        if rt is None:
            return
        start = offset or alias_off
        end = min((start + size) if size > 0 else (alias_off + alias_sz), rt.size)
        for i in range(start, end):
            rt.taint_bytes[i] |= taint_mask

        # x86_64: 写 EAX 时同步更新 RAX 的低 4 字节 + 清空高 4 字节
        # Intel SDM: 32-bit 操作数写入时高 32 位清零
        if self.arch == Arch.X86_64 and alias_sz == 4 and alias_off == 0:
            for i in range(4, rt.size):
                rt.taint_bytes[i] = 0
        # 写 YMM 时同步 XMM 低 128 位
        if canon.startswith("YMM"):
            xmm_name = canon.replace("YMM", "XMM")
            if xmm_name in self.regs:
                for i in range(min(16, end)):
                    self.regs[xmm_name].taint_bytes[i] = rt.taint_bytes[i]
        # 写 XMM 时同步 YMM 低 128 位
        if canon.startswith("XMM"):
            ymm_name = canon.replace("XMM", "YMM")
            if ymm_name in self.regs:
                for i in range(min(16, end)):
                    self.regs[ymm_name].taint_bytes[i] = rt.taint_bytes[i]

    # SIMD lane 操作

    def read_lane(self, reg_name: str, lane: int, el_size: int) -> int:
        byte_offset = lane * el_size
        return self.read(reg_name, offset=byte_offset, size=el_size)

    def write_lane(self, reg_name: str, lane: int, el_size: int,
                   taint_mask: int) -> None:
        byte_offset = lane * el_size
        self.write(reg_name, taint_mask, offset=byte_offset, size=el_size)

    # 污点传播 —— 按常见指令语义

    def propagate_mov(self, dst: str, src: str) -> None:
        if self.arch == Arch.X86_64:
            _, _, src_sz = self._resolve_x86(src)
            taint = self.read(src)
            self.write(dst, taint, size=src_sz)
        else:
            taint = self.read(src)
            self.write(dst, taint)

    def propagate_shift(self, dst: str, count_reg: str, direction: str = "right") -> None:
        if self.arch == Arch.X86_64:
            canon, off, sz = self._resolve_x86(dst)
        else:
            canon, off, sz, _ = self._resolve_arm64(dst)
        rt = self.regs.get(canon)
        if rt is None:
            return
        old = rt.clone()
        count_taint = self.read(count_reg)
        for i in range(sz):
            merged = old.taint_bytes[i] | count_taint
            if direction == "right" and i < sz - 1:
                merged |= old.taint_bytes[i + 1]
            elif direction == "left" and i > 0:
                merged |= old.taint_bytes[i - 1]
            rt.taint_bytes[off + i] = merged

    def propagate_arith(self, dst: str, *srcs: str) -> None:
        merged = 0
        for s in srcs:
            merged |= self.read(s)
        self.write(dst, merged)

    def propagate_clear(self, reg_name: str) -> None:
        if self.arch == Arch.X86_64:
            canon, off, sz = self._resolve_x86(reg_name)
        else:
            canon, off, sz, _ = self._resolve_arm64(reg_name)
        rt = self.regs.get(canon)
        if rt is not None:
            for i in range(off, off + sz):
                rt.taint_bytes[i] = 0
            # 清零的传播：x86 XOR EAX,EAX 同时清零 RAX 高 32 位
            if self.arch == Arch.X86_64 and sz == 4 and off == 0:
                for i in range(4, rt.size):
                    rt.taint_bytes[i] = 0

    # 查询与序列化

    def is_tainted(self, reg_name: str, labels: Optional[Set[int]] = None) -> bool:
        mask = self.read(reg_name)
        if labels is not None:
            label_mask = 0
            for lb in labels:
                label_mask |= (1 << lb)
            return (mask & label_mask) != 0
        return mask != 0

    def tainted_bytes(self, reg_name: str) -> List[int]:
        if self.arch == Arch.X86_64:
            canon, off, sz = self._resolve_x86(reg_name)
        else:
            canon, off, sz, _ = self._resolve_arm64(reg_name)
        rt = self.regs.get(canon)
        if rt is None:
            return []
        return [i for i in range(off, off + sz) if rt.taint_bytes[i] != 0]

    def to_dict(self) -> Dict[str, List[int]]:
        return {name: list(rt.taint_bytes) for name, rt in self.regs.items()
                if any(rt.taint_bytes)}

    def stats(self) -> Dict[str, Any]:
        total_bytes = sum(rt.size for rt in self.regs.values())
        tainted = sum(1 for rt in self.regs.values() for b in rt.taint_bytes if b)
        return {
            "arch": self.arch.name,
            "total_regs": len(self.regs),
            "total_bytes": total_bytes,
            "tainted_bytes": tainted,
            "taint_ratio": round(tainted / max(total_bytes, 1), 4),
            "active_labels": self._next_label,
        }
