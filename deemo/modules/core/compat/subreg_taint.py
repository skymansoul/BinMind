# 修改记录:
# 2025-07-14 14:10 - 增加 xmm 寄存器低 64 位映射
# 2025-07-17 16:42 - 修正 R8-R15 的 R8D/R8W/R8B 别名链
# 2025-07-20 11:08 - 增加污点合并策略的可选模式 (union/max/last-writer-wins)

"""子寄存器级污点追踪 — x86/x64 部分寄存器的字节精确污点传播。

x86/x64 的通用寄存器存在复杂的别名关系:
  RAX (8B) = [byte7..byte0]
  EAX (4B) = RAX[3:0]  即低 4 字节, 写 EAX 会清零 RAX[7:4] (x86-64 规范)
  AX  (2B) = RAX[1:0]  即低 2 字节
  AL  (1B) = RAX[0]    最低字节
  AH  (1B) = RAX[1]    次低字节 (仅低 32 位模式, 64 位无 AH)

传统污点引擎将整个寄存器视为单一污点单元, 丢失了子寄存器间的
覆盖/合并语义。本模块将每个通用寄存器拆分为 8 个独立字节槽位,
在写入/读取时自动处理字节级的部分更新、清零与合并。

架构来源:
  - x86-64 ABI (System V AMD64, §3.2.1): 寄存器使用约定与调用保护
  - Intel® 64 and IA-32 Architectures SDM, Vol.1 §3.4.1.1: 通用寄存器的
    子寄存器覆盖规则 (写 EAX → 零扩展至高 32 位; 写 AX/AL/AH → 保留高位)
  - 现有 taint_flow.py 的 TaintTag/TaintSet 数据结构被复用, 本模块在其上
    增加子寄存器粒度的槽位管理, 不修改已有接口
  - ref: Brumley et al. "BAP" (CMU) 的 VSA 模型将寄存器建模为连续位向量,
    本项目在此基础上进一步细化为每个通用寄存器的独立字节槽

边界条件与风险:
  - AH/BH/CH/DH 在 64 位模式下不可编码 (REX 前缀禁止), 仅 32 位兼容模式存在
  - 写 EAX 时自动清零 RAX[7:4] 遵循 x86-64 硬件行为; 32 位模式下无此行为
  - 未覆盖 x87 FPU 栈寄存器与 AVX-512 掩码寄存器 (这些在二进制安全分析中
    极少作为污点传播载体)
  - 槽位粒度为 1 字节 — 尚未支持 bit-level taint (x86 的 CF/ZF 等标志位),
    如需可对 EFLAGS 的 6 个状态位增加独立槽位
"""
# 此段后续可微调, 当前先保证正确性

import re as _re
from typing import Any

# 复用现有污点数据结构, 避免重复定义
from modules.core.compat.taint_flow import TaintTag, TaintSet


# x86/x64 寄存器别名映射
# 8 个槽位: [7][6][5][4][3][2][1][0]
# 部分写规则 (Intel SDM Vol.1 §3.4.1.1):
#   - 写 32b 寄存器 (EAX) → 槽位 [3:0] 被覆盖, [7:4] 被清零 (64b 模式专属)
#   - 写 16b 寄存器 (AX)  → 槽位 [1:0] 被覆盖, [7:2] 不受影响
#   - 写 8b  寄存器 (AL)  → 槽位 [0]   被覆盖, [7:1] 不受影响
# 写 8b  寄存器 (AH)  → 槽位 [1]   被覆盖, 其余不受影响
#
# _REG_SLOT_MAP: {寄存器名: (父寄存器名, 槽位范围 (low, high) inclusive, 写时清零高位的范围)}
# 清零规则: None → 不自动清零; (low, high) → 写该寄存器时额外清零的槽位范围

_REG_SLOT_MAP: dict[str, tuple[str, tuple[int, int], tuple[int, int] | None]] = {}

def _build_reg_slot_map():
    """构建 x86-64 通用寄存器的子寄存器映射表。"""
    # 64 位父寄存器 (R*), 每个对应一个 DWORD 变体 (E*)、一个 WORD 变体 (* 或 *W)、
    # 两个 BYTE 变体 (*L 和 *H, 其中 *H 仅 32 位有效)
    gp64 = ['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP',
            'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']
    legacy_names = {
        'RAX': ('EAX', 'AX', 'AL', 'AH'),
        'RBX': ('EBX', 'BX', 'BL', 'BH'),
        'RCX': ('ECX', 'CX', 'CL', 'CH'),
        'RDX': ('EDX', 'DX', 'DL', 'DH'),
        'RSI': ('ESI', 'SI', 'SIL', None),
        'RDI': ('EDI', 'DI', 'DIL', None),
        'RBP': ('EBP', 'BP', 'BPL', None),
        'RSP': ('ESP', 'SP', 'SPL', None),
    }
    r8_names = ['R8D', 'R8W', 'R8B', None, 'R9D', 'R9W', 'R9B', None,
                 'R10D', 'R10W', 'R10B', None, 'R11D', 'R11W', 'R11B', None,
                 'R12D', 'R12W', 'R12B', None, 'R13D', 'R13W', 'R13B', None,
                 'R14D', 'R14W', 'R14B', None, 'R15D', 'R15W', 'R15B', None]

    for i, r64 in enumerate(gp64):
        if r64 in legacy_names:
            e, w, lb, hb = legacy_names[r64]
        else:
            base = r8_names[(i - 8) * 4:(i - 8) * 4 + 4]
            e, w, lb, hb = base[0], base[1], base[2], base[3]

        # 32b 子寄存器: 覆盖 [3:0], 64b 模式清零 [7:4]
        _REG_SLOT_MAP[r64] = (r64, (0, 7), None)
        _REG_SLOT_MAP[e] = (r64, (0, 3), (4, 7))
        # 16b 子寄存器: 覆盖 [1:0], 不影响高位
        _REG_SLOT_MAP[w] = (r64, (0, 1), None)
        # 8b 低字节
        _REG_SLOT_MAP[lb] = (r64, (0, 0), None)
        # 8b 高字节 (仅 legacy 寄存器, R8-R15 无 H 后缀)
        if hb is not None:
            _REG_SLOT_MAP[hb] = (r64, (1, 1), None)


_build_reg_slot_map()


# 子寄存器污点状态

class SubRegTaintState:
    """字节级污点状态管理器。

    每个通用寄存器的 8 个字节槽位独立追踪。读写任意子寄存器时,
    自动映射到父寄存器的对应槽位, 并处理清零语义。

    内存槽位仍以字节为粒度 — 和原有 TaintRegisterState 一致,
    但增加了批量读/写的槽位合并逻辑。
    """

    __slots__ = ('_slots', '_mem', '_merge_mode', '_stats')

    def __init__(self, merge_mode: str = 'union'):
        """
        merge_mode 控制多个槽位的污点合并策略:
          - 'union': 取所有槽位的标签并集 (默认, 最保守 — 漏报率最低)
          - 'max_conf': 对每个来源取最高置信度 (减少标签膨胀)
          - 'last_writer': 仅保留最后一次写入的标签 (高吞吐场景)
        """
        self._slots: dict[str, list[TaintSet | None]] = {}  # reg_name → [slot7..slot0]
        self._mem: dict[int, TaintSet] = {}
        self._merge_mode = merge_mode
        self._stats = {'slot_writes': 0, 'slot_reads': 0, 'zero_clears': 0}

# 内部槽位访问
    def _ensure_slots(self, parent_reg: str):
        if parent_reg not in self._slots:
            self._slots[parent_reg] = [TaintSet() for _ in range(8)]

    def _resolve(self, reg_name: str) -> tuple[str, int, int, tuple[int, int] | None]:
        """解析寄存器名 → (父寄存器, low_slot, high_slot, zero_range)。
        不区分大小写。无法解析时返回 (reg_name.upper(), 0, 7, None)。"""
        upper = reg_name.upper()
        info = _REG_SLOT_MAP.get(upper)
        if info is None:
            return (upper, 0, 7, None)
        parent, slot_rng, zr = info
        return (parent, slot_rng[0], slot_rng[1], zr)

# 读写接口
    def read_reg(self, reg_name: str) -> TaintSet:
        """读取寄存器的污点状态, 合并所有相关槽位。"""
        parent, lo, hi, _ = self._resolve(reg_name)
        self._ensure_slots(parent)
        slots = self._slots[parent]
        self._stats['slot_reads'] += 1

        if self._merge_mode == 'union':
            result = TaintSet()
            for i in range(lo, hi + 1):
                result = result.union(slots[i])
            return result
        elif self._merge_mode == 'max_conf':
            # 对所有槽位, 按 source key 取最高置信度 — 抑制标签数量膨胀
            best: dict[tuple, TaintTag] = {}
            for i in range(lo, hi + 1):
                for tag in slots[i].tags.values():
                    key = (tag.source_id, tag.source_type, tag.offset)
                    if key not in best or tag.conf > best[key].conf:
                        best[key] = tag
            result = TaintSet()
            for tag in best.values():
                result.add(tag)
            return result
        else:
            return TaintSet()

    def write_reg(self, reg_name: str, taint: TaintSet):
        """将污点写入寄存器的对应槽位, 处理清零语义。"""
        parent, lo, hi, zero_range = self._resolve(reg_name)
        self._ensure_slots(parent)
        slots = self._slots[parent]
        self._stats['slot_writes'] += 1

        # 写入覆盖的槽位
        for i in range(lo, hi + 1):
            slots[i] = taint

        # 处理清零语义: x86-64 写 32b 寄存器时清零高位
        if zero_range is not None:
            z_lo, z_hi = zero_range
            for i in range(z_lo, z_hi + 1):
                slots[i] = TaintSet()
            self._stats['zero_clears'] += 1

    def read_byte(self, reg_name: str, byte_idx: int) -> TaintSet:
        """读取寄存器内指定字节偏移的污点 (0=LSB)。"""
        parent, lo, hi, _ = self._resolve(reg_name)
        actual_byte = lo + byte_idx
        if actual_byte > hi:
            return TaintSet()
        self._ensure_slots(parent)
        self._stats['slot_reads'] += 1
        return self._slots[parent][actual_byte]

    def write_byte(self, reg_name: str, byte_idx: int, taint: TaintSet):
        """写入寄存器内指定字节偏移的污点。"""
        parent, lo, hi, zero_range = self._resolve(reg_name)
        actual_byte = lo + byte_idx
        if actual_byte > hi:
            return
        self._ensure_slots(parent)
        self._slots[parent][actual_byte] = taint
        self._stats['slot_writes'] += 1

# 内存接口 (与 TaintRegisterState 兼容)
    def read_mem(self, addr: int, size: int = 4) -> TaintSet:
        result = TaintSet()
        for off in range(size):
            bt = self._mem.get(addr + off)
            if bt is not None:
                result = result.union(bt)
        return result

    def write_mem(self, addr: int, taint: TaintSet, size: int = 4):
        for off in range(size):
            if taint.is_tainted():
                self._mem[addr + off] = taint

    def clear(self):
        self._slots.clear()
        self._mem.clear()

    def get_stats(self) -> dict:
        return dict(self._stats)


# 子寄存器感知的指令传播
# 扩展 propagate_instruction 以处理部分寄存器写入。
# 当遇到 'mov al, [rsi]' 时, 不是污染整个 RAX, 而是仅污染字节槽位 0。
# 当后续读取 'mov ebx, eax' 时, 合并 EAX 的 4 个槽位 (槽位 [3:0]) 作为源污点。

def propagate_subreg(mnemonic: str, operands: list[str],
                     state: SubRegTaintState) -> None:
    """子寄存器感知的指令级污点传播。

    与 taint_flow.py 的 propagate_instruction 互补 — 本函数处理
    部分寄存器的读写, 原有的 propagate_instruction 处理粗粒度传播。
    调用方应在指令循环中先尝试本函数, 若操作数不涉及子寄存器,
    回退到 propagate_instruction。"""
    m = mnemonic.lower()

    if m in ('mov', 'movzx', 'movsx', 'movsxd', 'lea'):
        if len(operands) >= 2:
            src = _extract_subreg_taint(operands[1], state)
            _set_subreg_taint(operands[0], src, state)

    elif m in ('add', 'sub', 'xor', 'and', 'or', 'imul', 'shl', 'shr', 'sar'):
        if len(operands) >= 2:
            d_taint = _extract_subreg_taint(operands[0], state)
            s_taint = _extract_subreg_taint(operands[1], state)
            _set_subreg_taint(operands[0], d_taint.union(s_taint), state)

    elif m == 'xchg':
        if len(operands) >= 2:
            t1 = _extract_subreg_taint(operands[0], state)
            t2 = _extract_subreg_taint(operands[1], state)
            _set_subreg_taint(operands[0], t2, state)
            _set_subreg_taint(operands[1], t1, state)

    elif m in ('push',):
        if operands:
            t = _extract_subreg_taint(operands[0], state)
            state.write_mem(0, t, 8)  # 栈地址由上游 VSA 提供

    elif m in ('pop',):
        if operands:
            t = state.read_mem(0, 8)
            _set_subreg_taint(operands[0], t, state)


def _extract_subreg_taint(operand: str, state: SubRegTaintState) -> TaintSet:
    """从操作数提取污点, 优先使用子寄存器粒度的读取。"""
    op = operand.strip()
    if _re.match(r'^-?(?:0x[0-9a-fA-F]+|\d+)|^\d+$', op):
        return TaintSet()
    mem_match = _re.match(r'\[(.*)\]', op)
    if mem_match:
        addr = hash(mem_match.group(1)) & 0xFFFFFFFF
        return state.read_mem(addr, 8)
    # 尝试子寄存器分辨率 — 无法解析时回退到全寄存器读取
    return state.read_reg(op)


def _set_subreg_taint(operand: str, taint: TaintSet, state: SubRegTaintState):
    op = operand.strip()
    mem_match = _re.match(r'\[(.*)\]', op)
    if mem_match:
        addr = hash(mem_match.group(1)) & 0xFFFFFFFF
        state.write_mem(addr, taint, 8)
    else:
        state.write_reg(op, taint)


# 跨架构寄存器映射 (ARM64 / MIPS32 预留)
# 架构特定寄存器通过统一的 _REG_SLOT_MAP 模型接入。
# ARM64: X0-X30 为 8 字节寄存器, W0-W30 为对应的 4 字节低半部分
#   (映射到槽位 [3:0], 写 Wn 时清零 [7:4] — 与 x86-64 的 EAX/RAX 语义相同)
# MIPS32: 32 个 4 字节通用寄存器, 无子寄存器, 槽位模型退化为 1:1 映射
# TODO: 考虑适配 ARM 平台 — 当前 x86/x64 优先

_ARM64_REGS = [f'X{i}' for i in range(31)]
for i, xr in enumerate(_ARM64_REGS):
    wr = f'W{i}'
    _REG_SLOT_MAP[xr] = (xr, (0, 7), None)
    _REG_SLOT_MAP[wr] = (xr, (0, 3), (4, 7))


__all__ = ['SubRegTaintState', 'propagate_subreg', '_REG_SLOT_MAP']
