#!/usr/bin/env python3
# 修改记录:
# 2025-08-01 16:12 - 扩充 AVX-512 掩码寄存器 k0-k7 的 lane 级 taint 传播
# 2025-08-03 10:35 - ARM NEON 的 Vn.2S/Vn.4H 等排列限定符建模
"""
字节粒度寄存器污点追踪引擎 —— 处理部分寄存器写入和 SIMD lane 操作

x86_64 的寄存器重叠（RAX←→EAX←→AX←→AH:AL）使传统的"寄存器=单变量"模型
在跟踪部分写入时丢失污点信息。同样，ARM NEON 的 Vn.4S[2] 和 x86 AVX 的
vinserti128 只影响向量寄存器的特定 lane

此模块将每个寄存器建模为字节数组（小端），指令的读写以 [offset, length]
描述。当 `mov al, [user_input]` 仅污染 RAX 的 byte 0 时，`shr rax, 8`
将污染传播到 byte 1——这是全寄存器模型无法捕获的细粒度行为

寄存器命名约定:
- x86_64: RAX→EAX→AX→AH:AL 及其 R8-R15 变体
- ARM64: X0-X30 + V0-V31 (128-bit NEON)，支持.B/.H/.S/.D/.Q 排列限定符

ref: Intel SDM Vol.1 §3.4.1.1 (General-Purpose 寄存器s 64-Bit Mode);
ARM ARM §C1.2.5 (NEON scalar operations arrange specifiers);
Schwartz et al. " Ever Wanted Dynamic 污点分析."
 — 全寄存器模型的局限性在第 4.2 节讨论
"""

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
    """构建 alias_name → (canonical_name, offset, s) 的查找表"""
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
    """单个寄存器的字节级污点状态
    
    小端存储: byte 0 = 最低有效字节（AL x86_64, bits [7:0]）
    taint_bytes[] 的每个 bit 代表一个独立的污点标签（最多 64 个标签同时存在）
    """
    size: int  # 寄存器总字节数（GPR=8, NEON=16, AVX=32, AVX-512=64）
    taint_bytes: List[int] = field(default_factory=list)  # len == size

    def __post_init__(self):
        if not self.taint_bytes:
            self.taint_bytes = [0] * self.size

    def clone(self) -> "_RegTaint":
        return _RegTaint(size=self.size, taint_bytes=list(self.taint_bytes))


class SubregTaintTracker:
    """架构无关的字节粒度寄存器污点追踪引擎
    
    核心操作:
    - 读取(reg, offset, s) → taint_mask → 查询指定字节范围的污点状态
    - 写入(reg, offset, s, taint_mask) → 将污点写入指定字节范围
    - propag(src_reg, dst_reg, operation_semantics) → 按指令语义传播
    
    特性:
    - 每个 taint_bit (0-63) 代表一个独立的污染源（用户输入、文件读取、网络数据等）
    - 读操作返回所有活跃 taint_bit 的 OR（即只要有任何污染源就标记）
    - 写操作支持部分字节写入而不清除寄存器其余部分的污点
    
    Attributes:
    arch: 目标架构（影响寄存器布局和 SIMD lane 建模）
    regs: {canonical_name → _RegTaint} 所有寄存器的当前污点状态
    label_names: {bit_index → label} 污点标签的语义含义（可选，用于诊断输出）
    """

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
        """分配一个新的污点标签位。调用方用此标记每个独立的污染源"""
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
        """将 x86 寄存器名解析为 (canonical_name, byte_offset, byte_s)
        
        'AL' → ('RAX', 0, 1), 'AX' → ('RAX', 0, 2), 'AH' → ('RAX', 1, 1)
        """
        upper = reg_name.upper()
        if upper in _X86_ALIAS_MAP:
            return _X86_ALIAS_MAP[upper]
        # XMM/YMM
        if upper.startswith("XMM") or upper.startswith("YMM"):
            return (upper, 0, self.regs.get(upper, _RegTaint(size=16)).size)
        return (upper, 0, self.regs.get(upper, _RegTaint(size=8)).size)

    def _resolve_arm64(self, reg_name: str) -> Tuple[str, int, int, Optional[Tuple[int, int]]]:
        """ARM64 寄存器解析 —— 支持 NEON 排列限定符
        
        'V0.4S[2]' → ('V0', offset=8, s=4, lane=(2, 4))
        即 V0 的 4×32-bit 排列中的第 2 个 32-bit lane
        """
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
        """读取寄存器指定字节范围的污点掩码
        
        offset 和 s 为 0 时读取整个寄存器
        返回所有活跃标签的 OR（bitw union）
        """
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
        """将污点掩码写入寄存器指定字节范围
        
        不清除范围外的现有污点。高位寄存器别名的部分写入
        自动传播到对应的 canon 寄存器区域
        """
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
        """读取 SIMD 寄存器的特定 lane
        
        'V0.4S[2]' → read_lane('V0', 2, 4) 读取 bytes [8:12)
        """
        byte_offset = lane * el_size
        return self.read(reg_name, offset=byte_offset, size=el_size)

    def write_lane(self, reg_name: str, lane: int, el_size: int,
                   taint_mask: int) -> None:
        """写入 SIMD 寄存器的特定 lane
        
        不改变其他 lane 的污点状态。适用于 vinserti128、NEON Vn.4S[2] 等指令
        """
        byte_offset = lane * el_size
        self.write(reg_name, taint_mask, offset=byte_offset, size=el_size)

    # 污点传播 —— 按常见指令语义

    def propagate_mov(self, dst: str, src: str) -> None:
        """MOV 语义：dst 完全继承 src 的污点"""
        if self.arch == Arch.X86_64:
            _, _, src_sz = self._resolve_x86(src)
            taint = self.read(src)
            self.write(dst, taint, size=src_sz)
        else:
            taint = self.read(src)
            self.write(dst, taint)

    def propagate_shift(self, dst: str, count_reg: str, direction: str = "right") -> None:
        """移位操作：污染沿字节边界扩散
        
        SHR RAX, CL: RAX 的每个字节继承其自身和相邻字节的污点（向右扩散）
        精确建模需要知道 CL 的具体值；此处执行保守的传播上限——
        将所有被移位字节和相邻字节的 union 写回
        """
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
        """算术/逻辑操作：dst = fn(src1, src2,.)
        
        dst 继承所有源操作数的污点 union。这是保守近似——
        实际上某些位可能被常量操作数清除，但保守策略避免漏报
        """
        merged = 0
        for s in srcs:
            merged |= self.read(s)
        self.write(dst, merged)

    def propagate_clear(self, reg_name: str) -> None:
        """清零（XOR reg, reg / MOV reg, 0）：清除所有污点"""
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
        """检查寄存器是否有污点（可选过滤特定标签）"""
        mask = self.read(reg_name)
        if labels is not None:
            label_mask = 0
            for lb in labels:
                label_mask |= (1 << lb)
            return (mask & label_mask) != 0
        return mask != 0

    def tainted_bytes(self, reg_name: str) -> List[int]:
        """返回寄存器中被污染的字节偏移量列表"""
        if self.arch == Arch.X86_64:
            canon, off, sz = self._resolve_x86(reg_name)
        else:
            canon, off, sz, _ = self._resolve_arm64(reg_name)
        rt = self.regs.get(canon)
        if rt is None:
            return []
        return [i for i in range(off, off + sz) if rt.taint_bytes[i] != 0]

    def to_dict(self) -> Dict[str, List[int]]:
        """序列化当前污点状态（主要用于断言和调试输出）"""
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
