# 通过分析程序在执行特定输入时的内存分配/访问模式，识别:
#   1. 空间内存安全: 缓冲区溢出（分配N字节但访问N+K偏移）
#   2. 时间内存安全: use-after-free（访问已释放区域的地址）
#   3. 分配异常: 异常大的分配请求、整数溢出导致过小分配
#   4. 内存泄漏模式: 持续增长的内存占用、无对应释放的分配
#
#   MemLock — memory consumption guided fuzzing
#   Cheng et al. 2023, "MemAIFuzz" — memory access pattern aware fuzzing
#   ASan (AddressSanitizer) — shadow memory instrumentation model
#   valgrind/memcheck — memory error detection heuristics
import math
import time
import struct
from typing import List, Dict, Tuple, Optional, Set, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class AllocRecord:
    """单次内存分配记录。"""
    alloc_id: int
    address: int                # 分配的起始地址
    size: int                   # 分配大小（字节）
    alloc_site: str = ""       # 分配调用点 (函数名或地址)
    alloc_time: float = 0.0
    freed: bool = False
    free_time: float = 0.0


@dataclass
class AccessRecord:
    """单次内存访问记录。"""
    address: int                # 访问地址
    size: int                   # 访问大小（字节）
    is_write: bool = False
    access_site: str = ""      # 访问调用点
    timestamp: float = 0.0


@dataclass
class MemoryViolation:
    """检测到的内存违规。"""
    violation_type: str         # buffer_overflow / use_after_free / double_free / leak
    severity: str               # critical / high / medium
    detail: str
    alloc_record: Optional[AllocRecord] = None
    access_record: Optional[AccessRecord] = None
    offset_violation: int = 0   # 违规偏移量（用于overflow）


class MemoryAccessPatternAnalyzer:
    """内存访问模式分析引擎。

    工作流:
      1. record_alloc/record_free -> 维护活跃分配集合
      2. record_access -> 对每次访问检查是否在合法范围内
      3. analyze -> 产出MemoryViolation列表
      4. compute_memory_pressure -> 评估当前内存压力值 [0, 1]

    内存压力 = f(活跃分配数, 碎片化程度, 泄漏嫌疑),
    高压力下应降低变异复杂度（AFL的-m限制类比）。
    """

    def __init__(self, max_alloc_table: int = 16384):
        """
        max_alloc_table: 同时追踪的最大分配数。超出后淘汰最旧记录
        （LRU策略），用于控制长期fuzzing下的内存占用。
        """
        self._allocations: Dict[int, AllocRecord] = {}
        self._active_allocs: Set[int] = set()    # 未释放的allocation id
        self._freed_addrs: Dict[int, float] = {}  # 已释放地址 -> 释放时间
        self._access_history: deque[AccessRecord] = deque(maxlen=256)
        self._violations: List[MemoryViolation] = []
        self._max_allocs = max_alloc_table
        self._alloc_counter = 0
        self._total_alloc_bytes = 0
        self._total_free_bytes = 0
        # 内存泄漏追踪: 每1000次分配记录一次水位
        self._watermark_history: List[Tuple[float, int]] = []

    # 记录API
    def record_alloc(self, address: int, size: int,
                     alloc_site: str = "") -> int:
        """记录一次内存分配。返回alloc_id。"""
        self._alloc_counter += 1

        # LRU淘汰
        if len(self._allocations) >= self._max_allocs:
            self._evict_lru()

        alloc = AllocRecord(
            alloc_id=self._alloc_counter, address=address,
            size=size, alloc_site=alloc_site,
            alloc_time=time.time())
        self._allocations[alloc.alloc_id] = alloc
        self._active_allocs.add(alloc.alloc_id)
        self._total_alloc_bytes += size

        # 水位记录
        if self._alloc_counter % 1000 == 0:
            self._watermark_history.append(
                (time.time(), self.current_usage()))

        return alloc.alloc_id

    def record_free(self, alloc_id: int, free_site: str = "") -> bool:
        """记录一次释放。若alloc_id已释放 -> double free违规。"""
        alloc = self._allocations.get(alloc_id)
        if alloc is None:
            return False

        if alloc.freed:
            # double free检测
            self._violations.append(MemoryViolation(
                violation_type='double_free',
                severity='high',
                detail=f'Double free of alloc_id={alloc_id} '
                       f'(addr=0x{alloc.address:x}, size={alloc.size})',
                alloc_record=alloc))
            return False

        alloc.freed = True
        alloc.free_time = time.time()
        self._active_allocs.discard(alloc_id)
        self._freed_addrs[alloc.address] = time.time()
        self._total_free_bytes += alloc.size
        return True

    def record_access(self, address: int, size: int,
                      is_write: bool = False,
                      access_site: str = "") -> None:
        """记录一次内存访问并做实时违规检查。"""
        access = AccessRecord(
            address=address, size=size,
            is_write=is_write, access_site=access_site,
            timestamp=time.time())
        self._access_history.append(access)

        # 检查1: 是否踩在已释放内存上 (UAF)
        for freed_addr, freed_time in list(self._freed_addrs.items()):
            if (freed_addr <= address < freed_addr + 4096
                    and time.time() - freed_time < 300.0):
                self._violations.append(MemoryViolation(
                    violation_type='use_after_free',
                    severity='critical',
                    detail=f'访问已释放内存: addr=0x{address:x} '
                           f'size={size}, 临近释放地址=0x{freed_addr:x}',
                    access_record=access))
                del self._freed_addrs[freed_addr]
                break

        # 检查2: 是否在某个活跃分配范围内越界
        for alloc_id in list(self._active_allocs)[:128]:
            alloc = self._allocations.get(alloc_id)
            if alloc is None:
                continue
            alloc_end = alloc.address + alloc.size
            access_end = address + size
            # 部分重叠但不完全在分配内 -> 可能溢出
            if (address < alloc_end and access_end > alloc_end
                    and address >= alloc.address):
                overflow = access_end - alloc_end
                self._violations.append(MemoryViolation(
                    violation_type='buffer_overflow',
                    severity='critical',
                    detail=f'溢出 {overflow} 字节: 在 alloc #{alloc_id} '
                           f'(0x{alloc.address:x} + {alloc.size}) 之后写入',
                    alloc_record=alloc, access_record=access,
                    offset_violation=overflow))
                break
            if (address >= alloc.address and access_end <= alloc_end
                    and address < alloc.address):
                underflow = alloc.address - address
                self._violations.append(MemoryViolation(
                    violation_type='buffer_underflow',
                    severity='high',
                    detail=f'下溢 {underflow} 字节: 在 alloc #{alloc_id} '
                           f'(0x{alloc.address:x}) 之前写入',
                    alloc_record=alloc, access_record=access))
                break

    # 分析
    def analyze(self) -> List[MemoryViolation]:
        """产出当前检测到的所有违规（不移除历史违规）。"""
        self._check_memory_leaks()
        return list(self._violations)

    def _check_memory_leaks(self) -> None:
        """检查内存泄漏: 活跃分配中超过5分钟且无对应释放的。"""
        now = time.time()
        stale_threshold = 300.0  # 5分钟
        leak_count = 0
        for alloc_id in self._active_allocs:
            alloc = self._allocations.get(alloc_id)
            if alloc is None or alloc.freed:
                continue
            if now - alloc.alloc_time > stale_threshold:
                leak_count += 1
        if leak_count >= 10:
            self._violations.append(MemoryViolation(
                violation_type='memory_leak',
                severity='medium',
                detail=f'{leak_count} 个活跃分配超过5分钟未释放，疑似内存泄漏'))

    def compute_memory_pressure(self) -> float:
        """计算内存压力值 [0, 1]。

        压力 = 加权和(活跃分配数饱和比, 碎片率, 泄漏嫌疑比, 违规密度)
        """
        if not self._allocations:
            return 0.0

        # 因子1: 分配表饱和度
        saturation = min(1.0, len(self._active_allocs) / self._max_allocs)

        # 因子2: 碎片率（已释放 vs 总分配）
        fragmentation = 1.0 - (self._total_free_bytes /
                               max(1, self._total_alloc_bytes))

        # 因子3: 泄漏嫌疑（水位持续上升）
        leak_suspect = 0.0
        if len(self._watermark_history) >= 3:
            recent = self._watermark_history[-3:]
            if all(recent[i][1] <= recent[i + 1][1]
                   for i in range(len(recent) - 1)):
                leak_suspect = 0.7

        # 因子4: 违规密度（过去256次访问中的违规数）
        violation_density = min(
            1.0, len(self._violations) / max(1, len(self._access_history)))

        pressure = (
            0.3 * saturation + 0.25 * fragmentation
            + 0.25 * leak_suspect + 0.2 * violation_density)
        return round(pressure, 3)

    def current_usage(self) -> int:
        """当前活跃分配的总字节数。"""
        return sum(
            self._allocations[aid].size
            for aid in self._active_allocs
            if aid in self._allocations)

    def _evict_lru(self) -> None:
        """移除最旧的已释放记录，或最旧的活跃记录（不得已时）。"""
        # 优先移除已释放的
        freed = [(aid, a.alloc_time) for aid, a in self._allocations.items()
                 if a.freed]
        if freed:
            victim = min(freed, key=lambda x: x[1])[0]
            del self._allocations[victim]
            return
        # 否则移除最老的活跃分配
        active = [(aid, a.alloc_time) for aid, a in self._allocations.items()
                  if not a.freed]
        if active:
            victim = min(active, key=lambda x: x[1])[0]
            self._active_allocs.discard(victim)
            del self._allocations[victim]

    # 报告
    def stats(self) -> Dict[str, Any]:
        return {
            'total_allocations': len(self._allocations),
            'active_allocations': len(self._active_allocs),
            'current_usage_bytes': self.current_usage(),
            'total_allocated_bytes': self._total_alloc_bytes,
            'total_freed_bytes': self._total_free_bytes,
            'memory_pressure': self.compute_memory_pressure(),
            'violations': len(self._violations),
            'violations_by_type': self._violation_distribution(),
        }

    def _violation_distribution(self) -> Dict[str, int]:
        dist = defaultdict(int)
        for v in self._violations:
            dist[v.violation_type] += 1
        return dict(dist)

    def reset(self) -> None:
        self._allocations.clear()
        self._active_allocs.clear()
        self._freed_addrs.clear()
        self._access_history.clear()
        self._violations.clear()
        self._alloc_counter = 0
        self._total_alloc_bytes = 0
        self._total_free_bytes = 0
        self._watermark_history.clear()


class AllocationPatternProfiler:
    """分配模式分析: 识别分配大小分布、常见分配序列、高频调用点。

    喂入fuzzer种子调度决策: 对触发异常分配模式的种子施加更多变异压力。

    参考MemLock的内存消耗建模。
    """

    def __init__(self):
        self._size_distribution: Dict[int, int] = defaultdict(int)
        self._site_counts: Dict[str, int] = defaultdict(int)
        self._sequence_signatures: Set[str] = set()

    def record_sequence(self, alloc_sizes: List[int],
                        alloc_sites: List[str]) -> None:
        """记录一次分配序列（如单次fuzz输入引发的分配序列）。"""
        for sz in alloc_sizes:
            self._size_distribution[sz] += 1
        for site in alloc_sites:
            self._site_counts[site] += 1
        # 序列签名
        sig = '|'.join(f"{s}:{t}" for s, t in zip(alloc_sizes, alloc_sites))
        self._sequence_signatures.add(sig)

    def anomalous_sequence(self, sizes: List[int],
                           threshold_z: float = 2.0) -> bool:
        if not sizes or not self._size_distribution:
            return False
        all_sizes = list(self._size_distribution.keys())
        mean_sz = sum(all_sizes) / max(1, len(all_sizes))
        mean_seq = sum(sizes) / len(sizes) if sizes else 0
        return mean_seq > mean_sz * 3

    def top_sites(self, k: int = 10) -> List[Tuple[str, int]]:
        return sorted(self._site_counts.items(), key=lambda x: -x[1])[:k]

    def unique_sequences(self) -> int:
        return len(self._sequence_signatures)


def check_overflow_pattern(alloc_size: int, access_offset: int,
                           access_len: int) -> Optional[MemoryViolation]:
    """独立校验: 给定分配大小和访问范围，判断是否存在溢出。

    不依赖内存地址，仅按语义判断。可用于静态分析结果二次确认。
    """
    if access_offset + access_len > alloc_size:
        overflow = access_offset + access_len - alloc_size
        return MemoryViolation(
            violation_type='buffer_overflow',
            severity='critical',
            detail=f'分配 {alloc_size}B 但尝试访问偏移 {access_offset}+{access_len}'
                   f'（超出 {overflow}B）',
            offset_violation=overflow)
    return None
