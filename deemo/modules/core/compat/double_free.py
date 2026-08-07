# coding: utf-8
"""
Double-Free 检测 — UAF 管线的自然扩展.

核心洞察: Double-free 是 UAF 的对称漏洞 — 都是 alloc/free 时序约束违反.
  UAF: alloc → free → use (时间线违反: 使用已释放的内存)
  Double-free: alloc → free → free (引用计数违反: 重复释放)
  Double-free→UAF: alloc → free → free → use (两次释放后使用, 最危险)

glibc 防御绕过:
  - glibc 2.26+ 有 tcache key 检查 (简单的 double-free 被阻止)
  - 但 fastbin double-free 可通过中间释放绕过 (free A → free B → free A)
  - tcache double-free 可通过覆写 key 绕过

层次化检测管线:
  L1: 直接 double-free — 同一指针连续两次 free
  L2: 间接 double-free — 通过别名指针 (p1, p2 指向同一 chunk, 各 free 一次)
  L3: 时序间隔 double-free — free(A)→free(B)→free(A) (绕过 tcache 检查)
  L4: 上下文利用分析 — double-free 是否可转化为重叠分配利用

与 UAF 管线的协同:
  UAF 检测 use-after-free pattern, Double-free 检测 free-after-free pattern.
  两者共享 AliasGraph (别名追踪) 和 LifetimeInterval (生命周期分析).

"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict


class DFPattern(Enum):
    """Double-free 模式."""
    DIRECT = auto()         # free(p); free(p) — 最简单形式
    ALIAS = auto()          # free(p1); free(p2) where p1, p2 别名
    BRIDGED = auto()        # free(A); free(B); free(A) — 绕过 tcache 检查
    REALLOC = auto()        # free(p); p=realloc(p,size); free(p) — realloc 变体


@dataclass
class FreeEvent:
    """一次 free 调用的事件记录."""
    address: int            # 代码地址
    ptr_name: str           # 被释放的指针名
    chunk_addr: int         # 实际 chunk 地址 (经过别名解析)
    timestamp: int          # 时序序号
    callee: str = 'free'    # 调用的函数名


@dataclass
class DFDetection:
    """Double-free 检测结果."""
    pattern: DFPattern
    first_free: FreeEvent
    second_free: FreeEvent
    intermediate_events: List[FreeEvent]  # 两次 free 之间的中间事件
    is_exploitable: bool
    glibc_version_mitigated: bool  # glibc >=2.26 tcache check 是否阻止
    confidence: float
    description: str


class FreeHistory:
    """释放历史追踪器 — 记录所有 free 事件并检测重复."""

    def __init__(self):
        # chunk_addr → [FreeEvent, ...] (按时间排序)
        self._free_timeline: Dict[int, List[FreeEvent]] = defaultdict(list)
        # ptr_name → chunk_addr 映射 (通过别名解析)
        self._ptr_to_chunk: Dict[str, int] = {}
        self._total_events: int = 0
        self._all_events: List[FreeEvent] = []

    def record_free(self, address: int, ptr_name: str,
                    chunk_addr: Optional[int] = None,
                    callee: str = 'free'):
        """记录一次 free 事件."""
        if chunk_addr is None:
            chunk_addr = hash(ptr_name) & 0xFFFFFFFF

        event = FreeEvent(
            address=address, ptr_name=ptr_name,
            chunk_addr=chunk_addr,
            timestamp=self._total_events,
            callee=callee)

        self._total_events += 1
        self._all_events.append(event)
        self._free_timeline[chunk_addr].append(event)
        self._ptr_to_chunk[ptr_name] = chunk_addr

    def record_from_alias(self, address: int, ptr_name: str,
                          alias_graph: Any):
        """使用别名图解析指针后记录 free."""
        chunk = alias_graph.resolve_ptr(ptr_name) if alias_graph else ptr_name
        chunk_addr = hash(chunk) & 0xFFFFFFFF
        self.record_free(address, ptr_name, chunk_addr)

    def check_direct_double_free(self) -> List[DFDetection]:
        """L1: 检测直接 double-free (同一 chunk 连续两次 free)."""
        detections = []
        for chunk_addr, events in self._free_timeline.items():
            if len(events) >= 2:
                for i in range(len(events) - 1):
                    e1, e2 = events[i], events[i + 1]
                    # L1: 相邻两次 free, 中间无其他事件
                    if e2.timestamp - e1.timestamp == 1:
                        detections.append(DFDetection(
                            pattern=DFPattern.DIRECT,
                            first_free=e1, second_free=e2,
                            intermediate_events=[],
                            is_exploitable=True,
                            glibc_version_mitigated=True,
                            # glibc >=2.26 tcache 直接检测
                            confidence=0.95,
                            description=(
                                f'直接 double-free: {e1.ptr_name} 连续释放两次 '
                                f'(@0x{e1.address:x} → @0x{e2.address:x}), '
                                f'glibc 2.26+ tcache 可阻止直接模式但 fastbin 不保护'),
                        ))
        return detections

    def check_indirect_double_free(self,
                                    alias_graph: Any = None) -> List[DFDetection]:
        """L2: 检测间接 double-free (通过别名)."""
        detections = []
        # 检查不同 ptr_name 是否指向同一 chunk
        chunk_ptrs: Dict[int, Set[str]] = defaultdict(set)
        for ptr_name, chunk_addr in self._ptr_to_chunk.items():
            chunk_ptrs[chunk_addr].add(ptr_name)

        for chunk_addr, ptrs in chunk_ptrs.items():
            if len(ptrs) >= 2:
                ptr_list = sorted(ptrs)
                events = self._free_timeline.get(chunk_addr, [])
                if len(events) >= 2:
                    e1, e2 = events[0], events[-1]
                    if e1.ptr_name != e2.ptr_name:
                        detections.append(DFDetection(
                            pattern=DFPattern.ALIAS,
                            first_free=e1, second_free=e2,
                            intermediate_events=events[1:-1],
                            is_exploitable=True,
                            glibc_version_mitigated=False,
                            confidence=0.85,
                            description=(
                                f'别名 double-free: {e1.ptr_name}→{e2.ptr_name} '
                                f'指向同一 chunk (0x{chunk_addr:x}), '
                                f'别名集: {", ".join(ptr_list)}'),
                        ))
        return detections

    def check_bridged_double_free(self) -> List[DFDetection]:
        """L3: 桥接 double-free: free(A)→free(B)→free(A)."""
        detections = []
        for chunk_addr, events in self._free_timeline.items():
            if len(events) >= 2:
                e1 = events[0]
                e2 = events[-1]
                if len(events) >= 2 and e1 != e2:
                    # 检查中间是否有其他 chunk 的 free
                    mid_events = [
                        ev for ev in self._all_events
                        if e1.timestamp < ev.timestamp < e2.timestamp
                    ]
                    other_chunk_mids = [
                        ev for ev in mid_events
                        if ev.chunk_addr != chunk_addr
                    ]
                    if other_chunk_mids:
                        detections.append(DFDetection(
                            pattern=DFPattern.BRIDGED,
                            first_free=e1, second_free=e2,
                            intermediate_events=other_chunk_mids,
                            is_exploitable=True,
                            glibc_version_mitigated=False,
                            confidence=0.90,
                            description=(
                                f'桥接 double-free: {e1.ptr_name} → '
                                f'{len(other_chunk_mids)} 个中间 free → '
                                f'{e2.ptr_name}, 绕过 tcache key 检查'),
                        ))
        return detections

    def detect_all(self, alias_graph: Any = None) -> List[DFDetection]:
        """全管线检测 — L1→L3."""
        all_detections = []
        all_detections.extend(self.check_direct_double_free())
        all_detections.extend(self.check_indirect_double_free(alias_graph))
        all_detections.extend(self.check_bridged_double_free())

        # 按置信度降序, 去重
        all_detections.sort(key=lambda d: d.confidence, reverse=True)
        seen = set()
        deduped = []
        for d in all_detections:
            key = (d.first_free.address, d.second_free.address,
                   d.pattern.name)
            if key not in seen:
                seen.add(key)
                deduped.append(d)
        return deduped


def classify_df_severity(detection: DFDetection) -> str:
    """分类 double-free 严重程度."""
    if detection.pattern == DFPattern.DIRECT:
        if detection.glibc_version_mitigated:
            return 'MEDIUM (tcache mitigated)'
        return 'HIGH'
    elif detection.pattern == DFPattern.BRIDGED:
        return 'CRITICAL (绕过 tcache)'
    elif detection.pattern == DFPattern.ALIAS:
        return 'HIGH'
    return 'MEDIUM'


def demonstrate_fastbin_dup() -> Dict:
    """演示经典的 fastbin double-free 场景.

    fastbin 不检查 double-free (glibc < 2.26), 可以被直接利用.
    """
    return {
        'technique': 'Fastbin dup (fastbin double-free)',
        'mitigation': 'glibc 2.26+ tcache key check, 但仍可通过桥接绕过',
        'steps': [
            '1. void *p = malloc(24)  // fastbin size',
            '2. free(p)               // p → fastbin[0x20]',
            '3. free(p)               // p → fastbin[0x20] (再次入链)',
            '4. void *q = malloc(24)  // q = p (第一次取出)',
            '5. void *r = malloc(24)  // r = p (第二次取出, q==r!)',
            '6. 现在 q 和 r 指向同一内存 → 重叠分配 → 任意写',
        ],
        'detection': (
            'L1 直接检测: free(p) 后同一指针再次 free 于 @free_site2'),
        'real_world': 'CVE-2017-6884 (libquicktime)',
    }
