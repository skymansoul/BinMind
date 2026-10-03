"""DT-HSA ptmalloc2 空闲链表模拟器 — UAF 时间维度验证核心引擎.

创建: 2024-11-05
方法依据: UAF 生命周期验证 typestate + Lancet 所有权语义
         + glibc malloc.c bin 管理 (fastbin LIFO/tcache LIFO 7/smallbin FIFO).

设计决策:
  - 保守分析: 仅可证明 chunk 未被重分配时确认 UAF; 同大小 malloc → possible
  - 不依赖堆元数据: strip 二进制中从 malloc size 参数推断 chunk 大小
  - usable = max(req, MINSIZE) 对齐 MALLOC_ALIGNMENT, 与 checked_request2size 一致
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

MINSIZE = 32; MALLOC_ALIGNMENT = 16; TCACHE_MAX_COUNT = 7
FASTBIN_MAX_SIZE = 128; TCACHE_MAX_SIZE = 1040; SMALLBIN_MAX_SIZE = 1008


def usable_size(request: int) -> int:
    s = max(request, MINSIZE)
    return (s + MALLOC_ALIGNMENT - 1) & ~(MALLOC_ALIGNMENT - 1)


def bin_index(size: int) -> str:
    us = usable_size(size)
    if us <= FASTBIN_MAX_SIZE: return 'fastbin'
    if us <= TCACHE_MAX_SIZE: return 'tcache'
    if us <= SMALLBIN_MAX_SIZE: return 'smallbin'
    return 'largebin'


@dataclass
class ChunkState:
    addr: int; request_size: int; usable: int
    alloc_time: int = 0; free_time: int = 0
    in_freelist: bool = False; bin_type: str = ''


@dataclass
class TemporalVerdict:
    chunk_addr: int; is_uaf: bool; confidence: str; reason: str
    freed_at_time: int = 0; accessed_at_time: int = 0
    intervening_allocs: int = 0; intervening_same_size: int = 0


class Ptmalloc2FreelistSim:
    """ptmalloc2 空闲链表模拟器 — UAF 时间验证引擎.

    模拟 fastbin(LIFO)/tcache(LIFO,≤7)/smallbin(FIFO) 三种 bin,
    追踪 malloc→free→realloc→use 时序, 判定 free(p) 后 p 是否仍指向已释放 chunk.
    """

    def __init__(self):
        self._fastbins: Dict[int, List[int]] = {}
        self._tcache: Dict[int, List[int]] = {}
        self._smallbins: Dict[int, List[int]] = {}
        self._chunks: Dict[int, ChunkState] = {}
        self._addr_to_size: Dict[int, int] = {}
        self._clock: int = 0
        self._history: List[str] = []

    # //// 核心操作 ////

    def record_malloc(self, addr: int, request_size: int) -> Optional[ChunkState]:
        self._clock += 1
        us = usable_size(request_size)
        reused = self._try_allocate_from_bins(addr, us, request_size)
        if reused:
            self._history.append(
                f"t={self._clock}: malloc({request_size})@{addr:#x} REUSED")
            return reused
        cs = ChunkState(addr=addr, request_size=request_size, usable=us,
                        alloc_time=self._clock)
        self._chunks[addr] = cs
        self._addr_to_size[addr] = request_size
        self._history.append(
            f"t={self._clock}: malloc({request_size})@{addr:#x} NEW us={us}")
        return cs

    def record_calloc(self, addr: int, nmemb: int, size: int) -> Optional[ChunkState]:
        return self.record_malloc(addr, nmemb * size)

    def record_realloc(self, old_addr: int, new_addr: int,
                       new_size: int) -> Tuple[Optional[ChunkState], bool]:
        old_freed = False
        if old_addr in self._chunks:
            self.record_free(old_addr)
            old_freed = True
        return self.record_malloc(new_addr, new_size), old_freed

    def record_free(self, addr: int) -> bool:
        self._clock += 1
        if addr not in self._addr_to_size:
            self._history.append(
                f"t={self._clock}: free({addr:#x}) UNKNOWN PTR")
            return False
        request_size = self._addr_to_size[addr]
        us = usable_size(request_size)
        cs = self._chunks.get(addr)
        if cs and cs.in_freelist:  # double-free
            self._history.append(
                f"t={self._clock}: free({addr:#x}) DOUBLE FREE")
            return False
        # 放入合适的 bin
        if us <= FASTBIN_MAX_SIZE:
            self._fastbins.setdefault(us, []).append(addr)
            bn = 'fastbin'
        elif us <= TCACHE_MAX_SIZE:
            tcl = self._tcache.setdefault(us, [])
            if len(tcl) >= TCACHE_MAX_COUNT:
                self._smallbins.setdefault(us, []).append(addr)
                bn = 'smallbin(tcache_full)'
            else:
                tcl.append(addr)
                bn = 'tcache'
        else:
            self._smallbins.setdefault(us, []).append(addr)
            bn = 'smallbin'
        if cs:
            cs.free_time = self._clock; cs.in_freelist = True; cs.bin_type = bn
        else:
            self._chunks[addr] = ChunkState(
                addr=addr, request_size=request_size, usable=us,
                free_time=self._clock, in_freelist=True, bin_type=bn)
        self._history.append(
            f"t={self._clock}: free({addr:#x}) sz={request_size} us={us} → {bn}")
        return True

    # //// UAF 检查 ////

    def check_uaf(self, addr: int, access_time: int = None) -> TemporalVerdict:
        """检查 access_time 时 addr 是否指向已释放 chunk.

        保守策略: 仅同大小 malloc 复用时降级为 possible;
        非同大小复用仍算 UAF (原数据可能部分保留).
        """
        if access_time is None:
            access_time = self._clock
        cs = self._chunks.get(addr)
        if cs is None:
            return TemporalVerdict(
                chunk_addr=addr, is_uaf=True, confidence='possible',
                reason='未追踪的地址', accessed_at_time=access_time)
        if cs.free_time == 0:
            return TemporalVerdict(
                chunk_addr=addr, is_uaf=False, confidence='safe',
                reason='chunk 从未释放', accessed_at_time=access_time)
        if cs.in_freelist:
            return TemporalVerdict(
                chunk_addr=addr, is_uaf=True, confidence='confirmed',
                reason=f'仍在 {cs.bin_type} 中, free→access={access_time - cs.free_time}t',
                freed_at_time=cs.free_time, accessed_at_time=access_time,
                intervening_allocs=self._count_intervening(cs.free_time, access_time),
                intervening_same_size=self._count_same_size(
                    cs.usable, cs.free_time, access_time))
        same = self._count_same_size(cs.usable, cs.free_time, access_time)
        return TemporalVerdict(
            chunk_addr=addr, is_uaf=True, confidence='possible',
            reason=f'已重分配(us={cs.usable}), 同大小重分配={same}次',
            freed_at_time=cs.free_time, accessed_at_time=access_time,
            intervening_allocs=self._count_intervening(cs.free_time, access_time),
            intervening_same_size=same)

    def is_chunk_free(self, addr: int) -> bool:
        cs = self._chunks.get(addr)
        return cs is not None and cs.in_freelist

    # //// 内部 ////

    def _try_allocate_from_bins(self, addr: int, usable: int,
                                 request: int) -> Optional[ChunkState]:
        # tcache 优先 (LIFO)
        if usable in self._tcache and self._tcache[usable]:
            return self._reuse_chunk(
                self._tcache[usable].pop(), addr, usable, request, 'tcache')
        # fastbin (LIFO)
        if usable in self._fastbins and self._fastbins[usable]:
            return self._reuse_chunk(
                self._fastbins[usable].pop(), addr, usable, request, 'fastbin')
        # smallbin — best fit (≥usable 的最小块, FIFO)
        for sz in sorted(self._smallbins.keys()):
            if sz >= usable and self._smallbins[sz]:
                return self._reuse_chunk(
                    self._smallbins[sz].pop(0), addr, sz, request, 'smallbin')
        return None

    def _reuse_chunk(self, old_addr: int, new_addr: int,
                     usable: int, request: int, bn: str) -> ChunkState:
        old_cs = self._chunks.get(old_addr)
        if old_cs:
            old_cs.in_freelist = False; old_cs.bin_type = ''
        cs = ChunkState(addr=new_addr, request_size=request, usable=usable,
                        alloc_time=self._clock)
        self._chunks[new_addr] = cs
        self._addr_to_size[new_addr] = request
        return cs

    def _count_intervening(self, t0: int, t1: int) -> int:
        return sum(1 for cs in self._chunks.values()
                   if t0 < cs.alloc_time <= t1)

    def _count_same_size(self, usable: int, t0: int, t1: int) -> int:
        return sum(1 for cs in self._chunks.values()
                   if t0 < cs.alloc_time <= t1 and cs.usable == usable)

    # //// 查询 ////

    def get_chunk_info(self, addr: int) -> Optional[ChunkState]:
        return self._chunks.get(addr)

    def get_bin_counts(self) -> dict:
        return {'fastbin': sum(len(v) for v in self._fastbins.values()),
                'tcache': sum(len(v) for v in self._tcache.values()),
                'smallbin': sum(len(v) for v in self._smallbins.values())}

    def stats(self) -> dict:
        n_freed = sum(1 for cs in self._chunks.values() if cs.free_time > 0)
        n_fl = sum(1 for cs in self._chunks.values() if cs.in_freelist)
        return {'total_allocs': len(self._addr_to_size),
                'total_frees': n_freed,
                'chunks_in_freelist': n_fl,
                'total_chunks': len(self._chunks),
                'logical_clock': self._clock,
                **self.get_bin_counts()}

    def clear(self) -> None:
        self._fastbins.clear(); self._tcache.clear(); self._smallbins.clear()
        self._chunks.clear(); self._addr_to_size.clear()
        self._clock = 0; self._history.clear()
