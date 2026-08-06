# 修改记录:
# 2025-08-04 15:10 — 初始实现：约束感知的输入变异引擎
# 2025-08-06 10:28 — 增加拓扑保持变异（维护输入的内部结构不变仅改关键字节）

"""Constraint-Guided Mutator — 补丁约束感知的输入变异引擎。

传统 fuzzer 的变异策略（bit flip / byte substitution / arithmetic）不考虑
补丁的语义约束。本模块在变异时：
  1. 分析补丁汇编指令提取数值约束（cmp 阈值、边界检查常数）
  2. 定向变异输入中与约束相关的字节位置
  3. 保持输入结构拓扑（JSON/PNG/ELF header 等不变，仅变异 payload 部分）

变异策略分层：
  L1: 约束定向变异 —— 改变与补丁 cmp/jbe 等指令参数相关的输入字节
  L2: 边界试探变异 —— 在约束边界附近做微扰 (±1, ±8, ±16)
  L3: 拓扑保持变异 —— 识别输入中的结构边界，仅变异自由字段
  L4: 随机多样性变异 —— 传统 bit/byte 变异，防止卡在局部最优

L1-L2 是本模块的创新点：将补丁约束反推回输入空间的定向修改。
"""

import re
import math
import struct
import random
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

from .bypass_fitness import PatchSite


class MutationLevel(int, Enum):
    L1_CONSTRAINT = 1    # 约束定向变异
    L2_BOUNDARY = 2      # 边界微扰
    L3_TOPOLOGY = 3      # 拓扑保持
    L4_DIVERSITY = 4     # 随机探索


@dataclass
class ConstraintHint:
    """从补丁汇编中提取的约束线索。"""
    cmp_value: int = 0             # 比较的立即数值
    cmp_register: str = ""         # 比较涉及的寄存器
    input_offset_range: Tuple[int, int] = (0, 0)
    # 输入中与此约束相关的字节范围
    check_type: str = ""           # size_check | null_check | range_check
    operand_size: int = 4          # 操作数字节大小


class ConstraintExtractor:
    """从补丁汇编中提取约束。

    解析 cmp/jbe/ja/jb 等指令，识别补丁添加的安全检查。
    返回可用于变异引导的 ConstraintHint 列表。
    """

    # x86-64 比较指令模式 — 逗号在 norm() 中已被替换为空格
    _CMP_PATTERNS = [
        # cmp reg, imm  →  cmp reg imm or cmp reg, imm
        (re.compile(r'cmp\s+(\w+),?\s*(0x[0-9a-f]+|\d+)', re.I), 2),
        # cmp [mem], imm
        (re.compile(r'cmp\s+\w+\s+\[(\w+)\+?(0x[0-9a-f]+)?\],?\s*(0x[0-9a-f]+|\d+)', re.I), 3),
    ]

    # 条件跳转模式（补丁的安全检查通常以条件跳转绕过漏洞代码）
    _CHECK_JUMPS = {'jb', 'jbe', 'ja', 'jae', 'je', 'jne', 'jl', 'jle', 'jg', 'jge'}

    def extract(self, patch_sites: List[PatchSite]) -> List[ConstraintHint]:
        """从所有补丁位置提取约束线索。"""
        hints: List[ConstraintHint] = []
        for site in patch_sites:
            for instr in site.surrounding_instrs:
                hints.extend(self._parse_instruction(instr, site))
        return hints

    def _parse_instruction(self, instr: str, site: PatchSite) -> List[ConstraintHint]:
        hints: List[ConstraintHint] = []
        norm = instr.lower().strip().replace(',', ' ')

        for pattern, imm_group in self._CMP_PATTERNS:
            m = pattern.search(norm)
            if not m:
                continue
            try:
                raw = m.group(imm_group)
                cmp_val = int(raw, 16) if raw.startswith('0x') else int(raw)
            except (ValueError, IndexError):
                continue

            hint = ConstraintHint(
                cmp_value=cmp_val,
                cmp_register=m.group(1) if m.lastindex and m.lastindex >= 1 else "",
                input_offset_range=(0, 16),  # 默认前 16 字节
                check_type=site.check_kind,
                operand_size=self._infer_operand_size(instr),
            )
            hints.append(hint)

        return hints

    @staticmethod
    def _infer_operand_size(instr: str) -> int:
        """从指令中的寄存器名推断操作数大小。"""
        if re.search(r'\b(rax|rbx|rcx|rdx|rsi|rdi|r8|r9)\b', instr):
            return 8
        if re.search(r'\b(eax|ebx|ecx|edx|esi|edi)\b', instr):
            return 4
        if re.search(r'\b(ax|bx|cx|dx)\b', instr):
            return 2
        return 4  # 默认 32-bit


# ── 约束导向变异器 ────────────────────────────────────────────────

class ConstraintGuidedMutator:
    """约束感知的变异引擎。

    接收补丁约束线索和当前最佳输入，生成下一代变异体。
    使用模拟退火式的能量调度：搜索早期高随机性，后期精细调整。
    """

    def __init__(self, seed: int = 11):
        self._rng = random.Random(seed)
        self._energy = 1.0      # 0..1，搜索能量（随迭代衰减）
        self._iteration = 0
        self._hint_cache: Dict[str, List[ConstraintHint]] = {}

    def set_hints(self, patch_id: str, hints: List[ConstraintHint]):
        self._hint_cache[patch_id] = hints

    def set_energy(self, energy: float):
        """设置搜索能量：0=纯利用，1=纯探索。"""
        self._energy = max(0.0, min(1.0, energy))

    def mutate(self, seed_data: bytes, patch_id: str = "",
               n_variants: int = 8) -> List[Tuple[str, bytes]]:
        """生成变异体集合。

        按能量分配变异类型：
          高能量：L4 (随机探索) 占比高
          低能量：L1（约束定向）+ L2（边界微扰）占比高
        """
        hints = self._hint_cache.get(patch_id, [])
        variants: List[Tuple[str, bytes]] = []
        self._iteration += 1

        l1_count = max(1, int(n_variants * 0.25 * (1 - self._energy + 0.3)))
        l2_count = max(1, int(n_variants * 0.20 * (1 - self._energy + 0.3)))
        l3_count = max(1, int(n_variants * 0.15))
        l4_count = max(1, int(n_variants * 0.40 * (self._energy + 0.3)))

        for i in range(l1_count):
            v = self._mutate_constraint_aware(seed_data, hints, i)
            if v:
                variants.append((f"L1_c{i}", v))

        for i in range(l2_count):
            v = self._mutate_boundary_probe(seed_data, hints, i)
            if v:
                variants.append((f"L2_b{i}", v))

        for i in range(l3_count):
            v = self._mutate_topology_preserving(seed_data, i)
            if v:
                variants.append((f"L3_t{i}", v))

        for i in range(l4_count):
            v = self._mutate_diversity(seed_data, i)
            if v:
                variants.append((f"L4_d{i}", v))

        return variants

    # ── L1: 约束定向变异 ──────────────────────────────────────────

    def _mutate_constraint_aware(self, data: bytes,
                                 hints: List[ConstraintHint],
                                 idx: int) -> Optional[bytes]:
        """根据约束阈值定向修改输入。

        如果 hint.cmp_value 是 size 检查，将输入长度微调到阈值附近。
        如果 hint 涉及特定偏移的数值，修改偏移处的值为 cmp_value ± delta。
        """
        if not data:
            return None
        buf = bytearray(data)

        for hint in hints:
            if hint.check_type == 'size_check':
                # 调整输入长度到阈值附近
                target_len = hint.cmp_value + self._rng.choice([-1, 0, 1, -8, 8])
                target_len = max(0, min(target_len, len(buf) * 4))
                if target_len < len(buf):
                    buf = buf[:target_len]
                else:
                    extra = bytes(self._rng.randint(0, 255)
                                 for _ in range(target_len - len(buf)))
                    buf.extend(extra)
                return bytes(buf)

            if hint.check_type in ('null_check', 'range_check'):
                lo, hi = hint.input_offset_range
                if lo < len(buf):
                    # 在相关偏移处写入接近约束阈值的值
                    pos = lo + self._rng.randint(0, min(hi - lo, max(len(buf) - lo - 1, 0)))
                    if pos < len(buf):
                        delta = self._rng.choice([-2, -1, 0, 1, 2, 16])
                        new_val = max(0, min(255, hint.cmp_value + delta))
                        buf[pos] = new_val & 0xFF

        return bytes(buf)

    # ── L2: 边界微扰变异 ──────────────────────────────────────────

    def _mutate_boundary_probe(self, data: bytes,
                               hints: List[ConstraintHint],
                               idx: int) -> Optional[bytes]:
        """在约束边界附近做微小扰动。

        对每个 hint 的 cmp_value，生成 cmp_value, cmp_value±1, cmp_value±8
        的输入长度/字节值变体。专门探测 off-by-one 和边界条件错误。
        """
        if not data:
            return None

        deltas = [-8, -1, 0, 1, 8, 16, -16]
        delta = deltas[idx % len(deltas)]
        buf = bytearray(data)

        modified = False
        for hint in hints:
            if hint.check_type == 'size_check':
                new_len = max(0, len(buf) + delta)
                if new_len < len(buf):
                    buf = buf[:new_len]
                    modified = True
                elif new_len > len(buf):
                    buf.extend(bytes([0x41] * (new_len - len(buf))))
                    modified = True
            else:
                lo, hi = hint.input_offset_range
                if lo < len(buf):
                    for pos in range(lo, min(hi, len(buf))):
                        new_val = (buf[pos] + delta) & 0xFF
                        if new_val != buf[pos]:
                            buf[pos] = new_val
                            modified = True

        return bytes(buf) if modified else None

    # ── L3: 拓扑保持变异 ──────────────────────────────────────────

    def _mutate_topology_preserving(self, data: bytes, idx: int) -> Optional[bytes]:
        """保持输入结构，仅修改 payload 区域。

        对已知格式的输入（ELF / PNG / JSON）识别头部和结构边界，
        仅在非关键的 payload 区域做变异。
        对于未知格式，保守处理：跳过前 64 字节（假设为头部）。
        """
        if not data or len(data) < 16:
            return None
        buf = bytearray(data)

        # 格式检测
        header_skip = self._detect_header_size(data)

        # payload 区域: header_skip 到末尾
        if header_skip >= len(buf):
            return None

        payload_start = header_skip
        payload_len = len(buf) - payload_start

        # 在 payload 区随机修改 1-4 字节
        n_mutations = self._rng.randint(1, min(4, payload_len))
        for _ in range(n_mutations):
            pos = payload_start + self._rng.randint(0, max(payload_len - 1, 0))
            if pos < len(buf):
                buf[pos] = self._rng.randint(0, 255)

        return bytes(buf)

    @staticmethod
    def _detect_header_size(data: bytes) -> int:
        """检测常见文件格式的头部大小。"""
        if len(data) >= 4:
            if data[:4] == b'\x7fELF':
                # ELF header: 64 bytes (64-bit) or 52 bytes (32-bit)
                ei_class = data[4] if len(data) > 4 else 1
                return 64 if ei_class == 2 else 52
            if data[:2] == b'MZ':
                return 64  # PE header 的 DOS 部分
            if data[:8] == b'\x89PNG\r\n\x1a\n':
                return 33  # PNG header + IHDR 起始
            if data[:2] in (b'\xff\xd8', b'\x00\x00'):
                return 20
        # 检测 JSON/文本格式
        if data and data[0] in (0x7b, 0x5b):  # '{' or '['
            return 4
        return 64  # 默认保守跳过

    # ── L4: 多样性探索变异 ────────────────────────────────────────

    def _mutate_diversity(self, data: bytes, idx: int) -> Optional[bytes]:
        """随机探索变异 — 基于传统 fuzzing 策略。

        操作池：bit flip, byte set, interesting values, random splice。
        按 idx 模运算选择策略，避免模式化重复。
        """
        if not data:
            return None
        buf = bytearray(data)

        op = idx % 6
        if op == 0 and len(buf) > 0:
            # bit flip
            pos = self._rng.randint(0, len(buf) - 1)
            bit = self._rng.randint(0, 7)
            buf[pos] ^= (1 << bit)

        elif op == 1 and len(buf) > 0:
            # byte set to interesting value
            pos = self._rng.randint(0, len(buf) - 1)
            interesting = [0, 1, 0x7f, 0x80, 0xff, 0x0a, 0x0d, 0x20, 0x3c, 0x3e]
            buf[pos] = self._rng.choice(interesting)

        elif op == 2 and len(buf) >= 4:
            # arithmetic on 4-byte word
            pos = self._rng.randint(0, max(len(buf) - 4, 0))
            val = int.from_bytes(buf[pos:pos+4], 'little')
            delta = self._rng.choice([-32768, -256, -1, 0, 1, 256, 32768])
            buf[pos:pos+4] = (val + delta).to_bytes(4, 'little', signed=True)

        elif op == 3 and len(buf) >= 2:
            # random 2-byte block replace
            pos = self._rng.randint(0, max(len(buf) - 2, 0))
            buf[pos] = self._rng.randint(0, 255)
            if pos + 1 < len(buf):
                buf[pos + 1] = self._rng.randint(0, 255)

        elif op == 4:
            # append random bytes
            extra = bytes(self._rng.randint(0, 255)
                         for _ in range(self._rng.randint(1, 16)))
            buf.extend(extra)

        elif op == 5 and len(buf) > 2:
            # random delete
            pos = self._rng.randint(0, len(buf) - 1)
            del buf[pos]

        return bytes(buf)
