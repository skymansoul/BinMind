"""堆重用概率估计器 — free 后同大小块被重新分配的概率.

创建: 2024-08-14
目的: UAF 的利用难度取决于 free(p) 后 p 指向的内存是否被新分配重用。
      若同大小块频繁分配 (如 64B 的 HTTP header buffer), p 的 UAF 高度可利用。
      若该大小罕见, UAF 可能仅导致 crash 而非可控写。

方法依据: UAF 生命周期验证的 typestate 分析中,
          "reallocation probability" 是评估 UAF 严重性的关键因子。
          本模块从反汇编中统计同大小 malloc 调用频率,
          估计 free 后窗口内的重用概率。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class ReuseEstimate:
    """一次 free 后堆重用的估计."""
    ptr_name: str
    freed_size: int              # free 的块大小
    same_size_allocs_nearby: int # 同大小 malloc 在附近出现的次数
    reuse_probability: float     # [0,1] — free 后被重用的概率
    exploitability: str          # 'high'|'medium'|'low'


class HeapReuseEstimator:
    """堆重用概率估计器 — 从分配模式推断 UAF 利用难度.

    评估三类重用模式:
      1. 快速重用 (fastbin): 同大小 free 后几乎立即被下一个同大小 malloc 返回
      2. tcache 重用: glibc 2.26+, 每线程缓存 → UAF 线程内高度可预测
      3. 大小罕见: 该大小在程序中只分配一次 → 可能永不重用

    使用方式:
      hre = HeapReuseEstimator()
      hre.add_malloc(0x1000, 64)    # malloc(64) at 0x1000
      hre.add_malloc(0x1020, 64)    # another malloc(64) → same size
      hre.add_free(0x1050, 64)      # free the 64B block
      est = hre.estimate(64, 0x1050)
      print(f'Reuse prob: {est.reuse_probability:.2f}')
    """

    def __init__(self):
        # 每种大小的 malloc 出现次数
        self._size_freq: Dict[int, int] = {}
        # 每种大小的总分配次数
        self._total_allocs: int = 0
        # 最近的同大小分配窗口
        self._recent_same_size: Dict[int, List[int]] = {}
        # 已释放的大小
        self._freed_sizes: Dict[int, int] = {}

    def add_malloc(self, insn_addr: int, size: int) -> None:
        """记录 malloc(size) 调用."""
        self._size_freq[size] = self._size_freq.get(size, 0) + 1
        self._total_allocs += 1
        self._recent_same_size.setdefault(
            size, []).append(insn_addr)
        if len(self._recent_same_size[size]) > 20:
            self._recent_same_size[size] = (
                self._recent_same_size[size][-10:])

    def add_free(self, insn_addr: int, size: int) -> None:
        """记录 free(ptr) 调用."""
        self._freed_sizes[size] = self._freed_sizes.get(size, 0) + 1

    def estimate(self, freed_size: int,
                 free_addr: int = 0) -> ReuseEstimate:
        """估计释放块的堆重用概率."""
        freq = self._size_freq.get(freed_size, 0)
        total = max(1, self._total_allocs)

        # 基础概率: 该大小的相对频率
        base_prob = freq / total

        # 快速重用加成: 若 free 后附近有同大小 malloc
        nearby = self._count_nearby_allocs(freed_size, free_addr)
        fast_reuse_bonus = min(0.4, nearby * 0.1)

        # tcache 加成: 小尺寸 (< 1024) 更可能被 tcache 快速返回
        tcache_bonus = 0.2 if freed_size < 1024 else 0.0

        # 大小罕见度惩罚: 仅分配过一次 → 几乎不重用
        rarity_penalty = 0.0
        if freq <= 1:
            rarity_penalty = 0.5

        prob = min(1.0, max(0.0,
            base_prob * 5.0 + fast_reuse_bonus + tcache_bonus
            - rarity_penalty))

        if prob > 0.6:
            exploitability = 'high'
        elif prob > 0.3:
            exploitability = 'medium'
        else:
            exploitability = 'low'

        return ReuseEstimate(
            ptr_name=f'ptr@{free_addr:x}',
            freed_size=freed_size,
            same_size_allocs_nearby=nearby,
            reuse_probability=prob,
            exploitability=exploitability)

    def _count_nearby_allocs(self, size: int,
                              free_addr: int) -> int:
        """统计 free 地址附近的同大小分配数."""
        recent = self._recent_same_size.get(size, [])
        if free_addr <= 0:
            return len(recent)
        # 256 字节窗口内视为"附近"
        return sum(1 for a in recent
                   if abs(a - free_addr) <= 256)

    def stats(self) -> dict:
        unique_sizes = len(self._size_freq)
        reusable_sizes = sum(
            1 for s, f in self._size_freq.items()
            if f >= 2 and s > 0)
        return {
            'unique_allocation_sizes': unique_sizes,
            'reusable_sizes': reusable_sizes,
            'total_allocs': self._total_allocs,
            'total_frees': sum(self._freed_sizes.values()),
            'mean_freq_per_size': (
                sum(self._size_freq.values()) / max(1, unique_sizes)),
        }

    def clear(self) -> None:
        self._size_freq.clear()
        self._total_allocs = 0
        self._recent_same_size.clear()
        self._freed_sizes.clear()
