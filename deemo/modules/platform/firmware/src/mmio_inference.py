# T0-T4 MMIO 寄存器分类 + LMS 模式检测
"""
MMIO 外设模型推断 — 从裸机固件中自动识别外设寄存器和中断映射。

裸机固件通过 MMIO (Memory-Mapped I/O) 与硬件外设交互，没有标准驱动框架,
没有设备树, 没有 datasheet。传统分析依赖手工标注 MMIO 地址范围。

本模块实现全自动 MMIO 推断管线:
  1. 寄存器访问分类 (T0–T4): 基于 access pattern 对每个 MMIO 地址分类
  2. 外设边界检测: DBSCAN 风格的空间-行为聚类, 推断外设边界
  3. 中断向量表关联: 从 IVT 到 ISR 到 MMIO 的追溯链

MMIO 寄存器类型 (ref: μEmu, ES-Fuzz):
  T0 (Write-Only/Control): 仅被写入, 用于配置外设
  T1 (Read-Only/Status): 仅被读取, 用于轮询状态
  T2 (Read-Write/Data): 读写均有, 通常是数据寄存器
  T3 (Interrupt-Related): 在 ISR 中被访问, 关联中断源
  T4 (Unclassified): 不匹配以上任何模式

外设推断: 同时考虑地址邻近性和行为相似性，两个 MMIO 地址即使不相邻,
如果共享相同的访问模式(LMS/func/ISR), 也可能属于同一外设。

ref: XtractIO — LMS/FRI/SIV 模式检测,
     本项目将其扩展到 T0-T4 类型分类 + ISR 关联
ref: ES-Fuzz — adaptive MMIO data-chunk
     modeling, 本项目取其"多读合并"思路用于寄存器类型推断
ref: μEmu — T0-T3 寄存器分类的原始定义
ref: Pretender (Gustafson et al.) — DBSCAN 外设边界聚类
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import math


class RegType(Enum):
    T0_CONTROL = 'T0_control'      # 仅写入 — 命令/控制寄存器
    T1_STATUS = 'T1_status'        # 仅读取 — 状态/标志寄存器
    T2_DATA = 'T2_data'            # 读写 — 数据寄存器
    T3_INTERRUPT = 'T3_interrupt'  # ISR 中访问 — 中断相关
    T4_UNCLASSIFIED = 'T4_unclassified'


@dataclass
class MMIORegister:
    """单个 MMIO 地址的访问签名。"""
    address: int
    read_count: int = 0
    write_count: int = 0
    lms_count: int = 0           # Load-Modify-Store 模式出现次数
    isr_access_count: int = 0    # 在 ISR 上下文中被访问的次数
    accessed_functions: set[int] = field(default_factory=set)
    reg_type: RegType = RegType.T4_UNCLASSIFIED
    # 推断
    inferred_bit_width: int = 32
    is_volatile: bool = False    # 连续两次读取值不同 → volatile


@dataclass
class Peripheral:
    """推断出的外设，MMIO 寄存器组 + 中断关联。"""
    base_addr: int
    end_addr: int
    registers: list[int] = field(default_factory=list)
    irq_number: int = -1
    name_hint: str = ''          # 从固件符号表推断的名称


# 寄存器分类器

class MMIORegisterClassifier:
    """基于访问模式的 MMIO 寄存器 T0-T4 分类。"""

    def classify(self, registers: dict[int, MMIORegister]) -> None:
        for reg in registers.values():
            has_read = reg.read_count > 0
            has_write = reg.write_count > 0
            has_lms = reg.lms_count > 0
            is_isr = reg.isr_access_count > 0

            if is_isr:
                reg.reg_type = RegType.T3_INTERRUPT
            elif has_lms and has_read and has_write:
                # LMS 模式: load → modify → store → 典型控制寄存器
                reg.reg_type = RegType.T0_CONTROL
            elif has_read and not has_write:
                reg.reg_type = RegType.T1_STATUS
            elif has_read and has_write and not has_lms:
                reg.reg_type = RegType.T2_DATA
            elif has_write and not has_read:
                reg.reg_type = RegType.T0_CONTROL
            else:
                reg.reg_type = RegType.T4_UNCLASSIFIED


# LMS (Load-Modify-Store) 模式检测
# XtractIO 的核心贡献: LMS 模式是 MMIO 寄存器最可靠的信号。
# 模式: load reg, [mmio_addr] → modify reg (and/or/xor) → store reg, [mmio_addr]
# 同一函数内, 对同一 MMIO 地址的先读后写, 中间有 ALU 操作。

def detect_lms_patterns(instructions: list[dict],
                        mmio_range: tuple[int, int]) -> dict[int, int]:
    """在指令序列中检测 LMS 模式。返回 {mmio_addr: lms_count}。

    检测逻辑: 对每条 store 到 MMIO 的指令, 回溯同一函数内的最近 load,
    若两者指向同一 MMIO 地址且中间有 ALU 指令 (and/or/xor),
    则标记为 LMS。"""
    mmio_lo, mmio_hi = mmio_range
    lms_hits: dict[int, int] = defaultdict(int)
    func_boundaries = _find_function_boundaries(instructions)

    for func_start, func_end in func_boundaries:
        # 收集此函数内对 MMIO 的访问
        mmio_accesses: list[tuple[int, str, int]] = []  # (idx, load/store, addr)
        for i in range(func_start, func_end):
            ins = instructions[i]
            addr = _extract_mmio_addr(ins, mmio_lo, mmio_hi)
            if addr is None:
                continue
            mnemonic = ins.get('mnemonic', '').lower()
            if mnemonic in ('ldr', 'ldrb', 'ldrh', 'ldr.w', 'mov', 'ldmia'):
                mmio_accesses.append((i, 'load', addr))
            elif mnemonic in ('str', 'strb', 'strh', 'str.w', 'stmia'):
                mmio_accesses.append((i, 'store', addr))

        # LMS 检测: 对每个 store, 找前面最近的 load (同地址)
        for j, (si, stype, saddr) in enumerate(mmio_accesses):
            if stype != 'store':
                continue
            for li, ltype, laddr in reversed(mmio_accesses[:j]):
                if ltype == 'load' and laddr == saddr:
                    # 检查 load 和 store 之间是否有 ALU 操作
                    has_alu = any(
                        instructions[k].get('mnemonic', '').lower()
                        in ('and', 'orr', 'eor', 'bic', 'orn', 'lsl', 'lsr')
                        for k in range(li + 1, si)
                    )
                    if has_alu:
                        lms_hits[saddr] = lms_hits.get(saddr, 0) + 1
                    break
    return dict(lms_hits)


# 外设边界检测
# 空间聚类 + 行为相似性 = 外设边界推断。
# DBSCAN 风格: 两个寄存器属于同一外设 if (address proximity) AND
# (behavior similarity: 相同 T-type 或相同 function set 交集 ≥50%)。

def infer_peripherals(registers: dict[int, MMIORegister],
                      cluster_radius: int = 0x100,
                      behavior_threshold: float = 0.5) -> list[Peripheral]:
    """从 MMIO 寄存器集合推断外设边界。

    cluster_radius: 空间邻近阈值 (字节)，ARM Cortex-M 外设通常 ≤256B
    behavior_threshold: 行为相似度阈值，共享 ≥50% 的访问函数 → 同外设"""
    if not registers:
        return []

    addrs = sorted(registers.keys())
    visited: set[int] = set()
    peripherals: list[Peripheral] = []

    for addr in addrs:
        if addr in visited:
            continue
        cluster = [addr]
        visited.add(addr)
        reg_a = registers[addr]

        # 扩展聚类: 找所有满足双重条件的邻近寄存器
        changed = True
        while changed:
            changed = False
            for other in addrs:
                if other in visited:
                    continue
                if abs(other - addr) > cluster_radius * 4:
                    continue  # 太远
                # 检查与聚类内任一成员的邻近性
                for member in cluster[:]:
                    if abs(other - member) <= cluster_radius:
                        reg_b = registers[other]
                        sim = _behavior_similarity(reg_a, reg_b)
                        if sim >= behavior_threshold:
                            cluster.append(other)
                            visited.add(other)
                            changed = True
                            break

        cluster.sort()
        periph = Peripheral(
            base_addr=cluster[0],
            end_addr=cluster[-1] + 4,
            registers=list(cluster),
        )
        peripherals.append(periph)

    return peripherals


def _behavior_similarity(a: MMIORegister, b: MMIORegister) -> float:
    """两个 MMIO 寄存器的行为相似度 [0, 1]。
    相同 T-type → +0.4; 函数集 Jaccard → +0.6。"""
    score = 0.0
    if a.reg_type == b.reg_type:
        score += 0.4
    fa = a.accessed_functions
    fb = b.accessed_functions
    if fa and fb:
        inter = len(fa & fb)
        union = len(fa | fb)
        score += 0.6 * (inter / union if union > 0 else 0.0)
    elif not fa and not fb:
        score += 0.3
    return score


# 中断向量表关联

def link_isr_to_mmio(
    ivt: dict[int, int],           # {vector_index: isr_address}
    registers: dict[int, MMIORegister],
    instructions: list[dict],
) -> dict[int, list[int]]:
    """将 ISR 地址关联到其访问的 MMIO 寄存器。返回 {isr_addr: [mmio_addr, ...]}。

    对 IVT 中的每个 ISR, 收集该 ISR 函数内访问的所有 MMIO 地址。
    若同一 ISR 访问多个 T3 类型寄存器, 标记外设的 IRQ 关联。"""
    isr_mmio: dict[int, list[int]] = {}
    func_bounds = _find_function_boundaries(instructions)

    for irq_num, isr_addr in ivt.items():
        mmio_set: set[int] = set()
        for start, end in func_bounds:
            if instructions[start].get('address', 0) == isr_addr:
                for i in range(start, end):
                    ins = instructions[i]
                    addr = _extract_mmio_addr(ins, 0x40000000, 0x60000000)
                    if addr and addr in registers:
                        mmio_set.add(addr)
                        registers[addr].isr_access_count += 1
                break
        if mmio_set:
            isr_mmio[isr_addr] = sorted(mmio_set)

    return isr_mmio


# 助手函数

def _find_function_boundaries(ins: list[dict]) -> list[tuple[int, int]]:
    """从指令列表推断函数边界 (简单启发式)。"""
    bounds = []
    start = 0
    for i, instruction in enumerate(ins):
        m = instruction.get('mnemonic', '').lower()
        if m in ('bx', 'bxeq', 'bxne', 'pop', 'b', 'b.w') and i > start + 2:
            bounds.append((start, i + 1))
            start = i + 1
    if start < len(ins):
        bounds.append((start, len(ins)))
    return bounds


def _extract_mmio_addr(ins: dict, lo: int, hi: int) -> int | None:
    """从指令中提取 MMIO 地址 (如果在指定范围内)。"""
    operands = ins.get('operands', '')
    import re
    for m in re.finditer(r'(?:0x)?([0-9a-fA-F]{7,8})', str(operands)):
        addr = int(m.group(1), 16)
        if lo <= addr <= hi:
            return addr
    # 也检查 immediates
    imm = ins.get('immediate')
    if isinstance(imm, int) and lo <= imm <= hi:
        return imm
    return None


import re as _re
from collections import defaultdict


__all__ = [
    'MMIORegister', 'MMIORegisterClassifier', 'Peripheral', 'RegType',
    'detect_lms_patterns', 'infer_peripherals', 'link_isr_to_mmio',
]
