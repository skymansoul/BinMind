"""堆安全证明器 — 利用窄化值区间 + 分配器模型证明访问安全/不安全.

创建: 2025-03-28

核心算法:
  用路径守卫窄化后的 malloc size 区间, 配合 ptmalloc2 分配器模型,
  证明一次堆访问是 DEFINITELY_SAFE (可消去) 或 DEFINITELY_UNSAFE (必然溢出).

三态判定:
  - DEFINITELY_SAFE: 窄化后的最大可用空间 ≥ 偏移+访问大小 → 明确安全, 直接丢弃
  - DEFINITELY_UNSAFE: 窄化后最小可用空间 < 偏移+访问大小 → 必然溢出, 高置信度
  - POTENTIALLY_UNSAFE: 窄化后区间仍跨越边界 → 需进一步语义分析, 走 FP filter

设计决策:
  - 为什么在阶段2.5 (malloc推断后、FP filter前) 插入证明器:
    证明器的目标是消除 DEFINITELY_SAFE 的 finding, 减少 FP filter 的输入量,
    同时升级 DEFINITELY_UNSAFE 的置信度. 这是"先证明, 再评分"的两阶段策略.
  - 与 semantic_fp_filter 的关系:
    semantic_fp_filter 是启发式评分 (14特征加权), 输出连续分值;
    heap_safety_prover 是形式证明 (区间+守卫+分配器), 输出三值逻辑.
    后者比前者更可靠, 但覆盖面更窄 (仅成功窄化区间时可用).
    两者互补: 先走 prover 做三值判定 → POTENTIALLY_UNSAFE 走 FP filter 做精筛.
  - 为什么同时检查 alloc-site 守卫和 write-site 守卫:
    两者提供的约束是独立的: alloc-site 约束分配量, write-site 约束写入量.
    即使 alloc-site 守卫无法窄化区间, write-site 守卫也可能直接证明写入安全.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

from .interval_domain import SInterval, AllocatorModel, DEFAULT_ALLOCATOR
from .path_guard_collector import PathGuard, collect_guards
from .value_range_narrowing import (
    ValueRangeNarrower, NarrowedValue, apply_guard_to_interval)


class SafetyVerdict(Enum):
    """三态安全判定."""
    DEFINITELY_SAFE = auto()      # 证明安全 → 丢弃 finding
    POTENTIALLY_UNSAFE = auto()   # 区间跨越边界 → 走 FP filter
    DEFINITELY_UNSAFE = auto()    # 证明溢出 → 高置信度 finding


@dataclass
class SafetyProof:
    """一次堆访问的安全性证明结果."""
    verdict: SafetyVerdict
    alloc_size_requested: int          # 请求大小 (窄化后)
    alloc_size_usable: int             # 分配器返回的可用大小
    access_end: int                    # offset + access_size
    safety_margin: int                 # 安全裕度 (usable - access_end, 可为负)
    narrowed_size: Optional[NarrowedValue] = None  # 窄化详情
    narrowed_write: Optional[NarrowedValue] = None  # 写大小窄化详情
    proof_trace: str = ""              # 证明过程描述


class HeapSafetyProver:
    """利用窄化区间做堆安全证明.

    使用方式:
      prove(alloc_site, offset, access_size, guards, instructions)
        → SafetyProof

    集成点: 在 heap_overflow_detector.analyze() 的阶段2后,
    对每个内存访问调用 prove(), 根据 verdict 决定后续流程:
      - DEFINITELY_SAFE → 跳过, 不生成 finding
      - DEFINITELY_UNSAFE → 生成高置信度 finding (confidence > 0.90)
      - POTENTIALLY_UNSAFE → 生成 finding 并走 FP filter 评分
    """

    def __init__(self,
                 allocator: Optional[AllocatorModel] = None,
                 param_reg: str = 'rcx'):
        self._allocator = allocator or DEFAULT_ALLOCATOR
        self._narrower = ValueRangeNarrower()
        self._param_reg = param_reg
        self._stats: Dict[str, int] = {
            'proved_safe': 0, 'proved_unsafe': 0, 'ambiguous': 0,
            'total_proved': 0,
        }

    def prove(self,
              alloc_insn_addr: int,
              size_interval: SInterval,
              offset: int,
              access_size: int,
              guards: List[PathGuard],
              write_insn_addr: int = 0,
              write_size_interval: Optional[SInterval] = None,
              param_reg: str = 'rcx',
              write_reg: str = 'r8',
              ) -> SafetyProof:
        """证明一次堆访问的安全性.

        Args:
          alloc_insn_addr: malloc 调用地址
          size_interval: backward_trace 得到的 size 区间 (可能为 TOP)
          offset: 内存访问偏移
          access_size: 访问字节数
          guards: 函数内的所有路径守卫
          write_insn_addr: memcpy/memset 调用地址 (可选, 用于写大小约束)
          write_size_interval: memcpy/memset 的 size 参数区间 (可选)
          param_reg: alloc 的 size 寄存器
          write_reg: memcpy 的 size 寄存器

        Returns: SafetyProof
        """
        self._stats['total_proved'] += 1

        # 窄化 malloc size
        nv_alloc = self._narrower.narrow_alloc_size(
            alloc_insn_addr, size_interval, guards, param_reg)

        alloc_min = nv_alloc.narrowed.min_possible()
        alloc_max = nv_alloc.narrowed.max_possible()

        # 映射到可用空间
        usable_min = self._allocator.usable_size(alloc_min)
        usable_max = self._allocator.usable_size(alloc_max)

        # 窄化写入大小 (若提供)
        nv_write: Optional[NarrowedValue] = None
        effective_access_size = access_size
        if write_size_interval is not None and write_insn_addr > 0:
            nv_write = self._narrower.narrow_write_size(
                write_insn_addr, write_size_interval, guards, write_reg)
            effective_access_size = nv_write.narrowed.max_possible()

        access_end = offset + effective_access_size

        # 三态判定
        if access_end <= usable_min:
            # 即使最小可用空间也足够 → DEFINITELY_SAFE
            self._stats['proved_safe'] += 1
            return SafetyProof(
                verdict=SafetyVerdict.DEFINITELY_SAFE,
                alloc_size_requested=alloc_min,
                alloc_size_usable=usable_min,
                access_end=access_end,
                safety_margin=usable_min - access_end,
                narrowed_size=nv_alloc,
                narrowed_write=nv_write,
                proof_trace=(
                    f'proved_safe: {offset}+{effective_access_size}={access_end}'
                    f' ≤ usable({alloc_min})={usable_min}'
                    f' [guard: {nv_alloc.narrowing_effect}]'))

        elif access_end > usable_max:
            # 即使最大可用空间也不够 → DEFINITELY_UNSAFE
            self._stats['proved_unsafe'] += 1
            return SafetyProof(
                verdict=SafetyVerdict.DEFINITELY_UNSAFE,
                alloc_size_requested=alloc_max,
                alloc_size_usable=usable_max,
                access_end=access_end,
                safety_margin=usable_max - access_end,
                narrowed_size=nv_alloc,
                narrowed_write=nv_write,
                proof_trace=(
                    f'proved_unsafe: {offset}+{effective_access_size}={access_end}'
                    f' > usable({alloc_max})={usable_max}'
                    f' [overflow by {-usable_max + access_end} bytes]'))

        else:
            # 区间跨越边界 → 不确定
            self._stats['ambiguous'] += 1
            return SafetyProof(
                verdict=SafetyVerdict.POTENTIALLY_UNSAFE,
                alloc_size_requested=alloc_max,
                alloc_size_usable=usable_max,
                access_end=access_end,
                safety_margin=usable_min - access_end,
                narrowed_size=nv_alloc,
                narrowed_write=nv_write,
                proof_trace=(
                    f'ambiguous: usable=[{usable_min},{usable_max}],'
                    f' access_end={access_end} crosses boundary'))

    def prove_call_overflow(self,
                            alloc_insn_addr: int,
                            size_interval: SInterval,
                            call_size: int,
                            guards: List[PathGuard],
                            dest_offset: int = 0,
                            param_reg: str = 'rcx',
                            ) -> SafetyProof:
        """证明函数调用型溢出 (memcpy(dst, src, n) 中 n > alloc_size).

        与 prove() 的区别: access_size 来自 call 指令的 size 参数,
        而非内存访问模式 [reg+offset] 的解析结果。
        """
        return self.prove(
            alloc_insn_addr=alloc_insn_addr,
            size_interval=size_interval,
            offset=dest_offset,
            access_size=call_size,
            guards=guards,
            write_insn_addr=alloc_insn_addr,
            write_size_interval=SInterval.exact(call_size),
            param_reg=param_reg,
        )

    @property
    def stats(self) -> dict:
        d = dict(self._stats)
        total = max(1, d['total_proved'])
        d['safe_rate'] = round(d['proved_safe'] / total, 3)
        d['unsafe_rate'] = round(d['proved_unsafe'] / total, 3)
        d['ambiguous_rate'] = round(d['ambiguous'] / total, 3)
        d['narrower'] = self._narrower.stats
        return d

    def clear(self) -> None:
        for k in self._stats:
            self._stats[k] = 0
        self._narrower.clear()
