# 内存访问模式引导的变异器 — 识别影响缓冲区边界的输入字节并定向变异
#
# 核心问题:
#   现有变异器 (adaptive_mutator, interaction_bandit, divergence_mutator)
#   基于覆盖反馈选择操作符/字节——但这些反馈不直接关联内存安全。
#   对缓冲区溢出漏洞, 最关键的输入字节是那些影响内存分配大小的字节。
#   若变异器不知道"字节4-7是长度字段, 控制malloc大小",
#   就不会优先变异这些字节以触发溢出。
#
# 本模块的方法 — 内存访问模式+堆布局推断→变异目标:
#   1. 从 memory_pattern.py 收集内存分配/访问记录
#   2. 识别哪些输入字节影响了分配大小参数
#   3. 多崩溃堆布局推断: 当同一大小字段的不同值导致不同崩溃结果时,
#      推断底层分配器的chunk大小类别边界
#   4. 生成"边界+1"变异——精确攻击推断的chunk边界
#   5. 对偏移敏感字节做越界访问变异
#
# 参考文献:
#   CtxFuzz (TASE 2024) — 上下文堆操作序列引导fuzzing;
#   malloc maleficarum (Phrack 2009) — 堆布局利用的经典参考

from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

# 桥接 memory_pattern.py: analyze_allocs() 接受 AllocRecord 列表
# (需含 size 属性), 通过 duck-typing 消费——调用方从
# MemoryAccessPatternAnalyzer._allocations 提取后传入。
# 桥接 subreg_taint.py: taint_map 格式为 offset→{reg_indices},
# 由调用方从 SubRegTaintTracker 状态构建后传入。


class SensitiveKind(str, Enum):
    """敏感字节类别"""
    ALLOC_SIZE = "alloc_size"      # 影响malloc/realloc大小
    BUFFER_OFFSET = "buffer_offset" # 用作缓冲区索引
    MEMCPY_LENGTH = "memcpy_length" # 影响memcpy长度
    FREE_ADDR = "free_addr"        # 影响free的指针参数


@dataclass
class SensitiveByte:
    """敏感输入字节——其值影响内存操作"""
    offset: int                     # 输入字节偏移
    kind: SensitiveKind
    # 影响大小 (字节宽度): 1/2/4/8
    width: int = 4
    # 是从哪条指令识别出的
    source_insn_addr: int = 0
    # 该字节当前的值
    current_value: int = 0
    # 置信度
    confidence: float = 0.5


@dataclass
class MutationTarget:
    """变异目标——描述对哪个字节做何种变异"""
    offset: int
    width: int = 1
    # 推荐的新值
    suggested_values: List[int] = field(default_factory=list)
    # 变异理由
    rationale: str = ""


class MemAccessMutator:
    """内存访问引导的变异器。

    典型用法:
        mutator = MemAccessMutator()
        # 从 memory_pattern 的分配记录中分析敏感字节:
        mutator.analyze_allocs(alloc_records, taint_map)
        # 生成变异计划:
        targets = mutator.plan_mutations(input_data)
        # 执行变异:
        mutated = mutator.mutate(input_data, targets)
    """

    # 边界值: 每种宽度的溢出触发值
    _BOUNDARY_VALUES = {
        1: [0x00, 0x7F, 0x80, 0xFF],
        2: [0x0000, 0x7FFF, 0x8000, 0xFFFF],
        4: [0x00000000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF],
        8: [0x0000000000000000, 0x7FFFFFFFFFFFFFFF,
            0x8000000000000000, 0xFFFFFFFFFFFFFFFF],
    }

    def __init__(self):
        self._sensitive_bytes: Dict[int, SensitiveByte] = {}
        self._mutations_applied = 0

    def mark_sensitive(self, offset: int, kind: SensitiveKind,
                        width: int = 4, confidence: float = 0.5,
                        source_addr: int = 0) -> None:
        """标记一个输入字节为内存敏感字节"""
        self._sensitive_bytes[offset] = SensitiveByte(
            offset=offset, kind=kind, width=width,
            source_insn_addr=source_addr, confidence=confidence)

    def analyze_allocs(self, alloc_records: List[Any],
                        taint_map: Dict[int, Set[int]] = None) -> int:
        """从内存分配记录中自动识别敏感字节。

        alloc_records: 来自 memory_pattern.AllocRecord 的列表。
        taint_map: 输入字节偏移→污染寄存器集合。
        """
        count = 0
        for rec in alloc_records:
            size = getattr(rec, 'size', 0)
            if taint_map and size > 0:
                # 查找哪些输入字节影响了此分配大小
                for off, regs in (taint_map or {}).items():
                    if off not in self._sensitive_bytes:
                        self.mark_sensitive(
                            off, SensitiveKind.ALLOC_SIZE,
                            width=self._guess_width(size),
                            confidence=0.6)
                        count += 1
        return count

    def plan_mutations(self, input_data: bytes,
                        max_targets: int = 8) -> List[MutationTarget]:
        """生成变异计划——优先变异高分敏感字节"""
        targets: List[MutationTarget] = []
        data_len = len(input_data)

        for off, sb in sorted(self._sensitive_bytes.items(),
                               key=lambda x: -x[1].confidence):
            if off >= data_len:
                continue
            if len(targets) >= max_targets:
                break

            sb.current_value = input_data[off]

            if sb.kind == SensitiveKind.ALLOC_SIZE:
                vals = self._BOUNDARY_VALUES.get(sb.width, [0, 0xFF])
                targets.append(MutationTarget(
                    offset=off, width=sb.width,
                    suggested_values=list(vals),
                    rationale=f"alloc_size字段[{off}], 宽{sb.width}B",
                ))

            elif sb.kind in (SensitiveKind.BUFFER_OFFSET,
                              SensitiveKind.MEMCPY_LENGTH):
                # 缓冲区偏移: 尝试超出分配范围的值
                vals = [0x00, 0xFF, 0x100, 0x1000, 0xFFFF]
                targets.append(MutationTarget(
                    offset=off, width=sb.width,
                    suggested_values=[v & ((1 << (sb.width * 8)) - 1)
                                       for v in vals],
                    rationale=f"{sb.kind.value}字段[{off}]",
                ))

        return targets

    def mutate(self, data: bytes, targets: List[MutationTarget],
                rng_seed: Optional[int] = None) -> bytes:
        """应用变异计划——修改敏感字节为边界值"""
        import random as _rnd
        rng = _rnd.Random(rng_seed)
        buf = bytearray(data)

        for t in targets:
            if t.offset + t.width > len(buf):
                continue
            if t.suggested_values:
                new_val = rng.choice(t.suggested_values)
                # 按宽度打包为大端序字节
                packed = new_val.to_bytes(t.width, 'big')
                for i in range(t.width):
                    if t.offset + i < len(buf):
                        buf[t.offset + i] = packed[i]

        self._mutations_applied += len(targets)
        return bytes(buf)

    @staticmethod
    def _guess_width(size: int) -> int:
        if size <= 255:
            return 1
        if size <= 65535:
            return 2
        return 4

    def infer_heap_layout(self, crash_observations: List[Tuple[int, bool]],
                            ) -> List[int]:
        """多崩溃堆布局推断: 从(大小字段值, 是否崩溃)对中推断chunk边界。

        当同一大小字段的不同值导致不同结果时, 说明跨越了分配器的
        chunk大小类别边界。例如: size=8正常, size=9崩溃 → 8是边界。

        返回推断的边界值列表 (升序), 可直接用于变异目标。
        """
        if len(crash_observations) < 3:
            return []

        # 按大小值排序
        sorted_obs = sorted(crash_observations, key=lambda x: x[0])
        boundaries: List[int] = []

        for i in range(1, len(sorted_obs)):
            prev_size, prev_crash = sorted_obs[i - 1]
            curr_size, curr_crash = sorted_obs[i]
            # 跨越边界: 一个崩溃一个不崩溃
            if prev_crash != curr_crash and curr_size - prev_size <= 16:
                boundary = prev_size if curr_crash else curr_size
                if boundary > 0 and boundary not in boundaries:
                    boundaries.append(boundary)

        return sorted(boundaries)

    def plan_boundary_mutations(self, input_data: bytes,
                                 boundaries: List[int],
                                 sensitive_offsets: List[int],
                                 width: int = 4) -> List[MutationTarget]:
        """基于推断的堆边界生成精确边界攻击变异。

        对每个边界b, 生成: b-1, b, b+1, b*2, b*2+1.
        这些值最可能触发off-by-one、chunk重叠和整数溢出。
        """
        targets: List[MutationTarget] = []
        for off in sensitive_offsets:
            if off + width > len(input_data):
                continue
            vals = []
            for b in boundaries:
                vals.extend([max(0, b - 1), b, b + 1, b * 2, b * 2 + 1])
            # 去重+裁剪到宽度范围
            max_val = (1 << (width * 8)) - 1
            unique = sorted(set(v for v in vals if v <= max_val))[:12]
            if unique:
                targets.append(MutationTarget(
                    offset=off, width=width,
                    suggested_values=unique,
                    rationale=f"推断chunk边界: {boundaries}",
                ))
        return targets

    def stats(self) -> Dict[str, Any]:
        return {
            "sensitive_bytes": len(self._sensitive_bytes),
            "mutations_applied": self._mutations_applied,
            "by_kind": {
                k.value: sum(1 for b in self._sensitive_bytes.values()
                             if b.kind == k)
                for k in SensitiveKind
            },
        }

    def reset(self) -> None:
        self._sensitive_bytes.clear()
        self._mutations_applied = 0
