# coding: utf-8
"""
键生命周期管理 — 基于 DAG 拓扑 + 钩子模式签名, 计算每个 context 键的最后消费者,
在其执行后主动回收内存.

Spark LCRD 在 RDD 级做 DAG 感知缓存回收, 但基于重用频率的启发式,
不清楚某个中间结果是否还会被使用. 本模块的差异:
  1. 精确的最后消费者判定 — 结合 schema_inference 的读写签名, 确定性计算
  2. 键级粒度 — 不是整个 RDD/DataFrame, 而是 context dict 中的单个键
  3. 可选 spill-to-disk — 对标记为 checkpointable 的键, 回收前先序列化到磁盘

典型场景:
  大二进制分析中, 'decompiled_functions' 键持有数十 MB 的伪代码列表.
  schema 显示该键仅被 'vuln_scan' 和 'exploit_gen' 读取, 且在 DAG 中
  'exploit_gen' 是最后消费者. 一但 'exploit_gen' 执行完毕, 该键即可回收.
"""

import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.core.schema_inference import HookSignature, SchemaModel


@dataclass
class KeyLifetime:
    """单个 context 键的完整生命周期描述."""
    key: str
    producers: List[str]           # 产出该键的钩子名列表
    consumers: List[str]           # 读取该键的钩子名列表 (required + optional)
    last_consumer: str = ''        # 拓扑序中最后的消费者
    evict_after_hook: str = ''     # 该钩子执行后即可安全回收
    spillable: bool = False        # 回收前是否应 spill 到磁盘
    estimated_bytes: int = 0       # 估算的内存占用

    @property
    def is_terminal(self) -> bool:
        """该键被标记为最终输出, 不应回收."""
        return not self.last_consumer


@dataclass
class EvictionRecord:
    """一次键回收操作的记录."""
    key: str
    freed_bytes: int
    spilled: bool = False
    spill_path: str = ''


class KeyLifetimeAnalyzer:
    """键生命周期分析器 — 结合 DAG 拓扑 + 钩子签名计算每个键的回收点.

    用法:
      kla = KeyLifetimeAnalyzer(schema_model)
      lifetimes = kla.analyze(edges, initial_keys, final_output_keys)
      # lifetimes['decompiled_functions'].evict_after_hook → 'exploit_gen'
    """

    def __init__(self, schema_model: SchemaModel):
        self._model = schema_model

    def analyze(
        self, edges: Dict[str, List[str]],
        initial_context_keys: Optional[Set[str]] = None,
        final_output_keys: Optional[Set[str]] = None,
    ) -> Dict[str, KeyLifetime]:
        """计算每个 context 键的生命周期.

        edges: {hook_name → [dependent_hook, ...]}
        initial_context_keys: 管道入口即存在的键 (不归任何钩子产出)
        final_output_keys: 最终需要的输出键 (永不回收)
        """
        ickeys = initial_context_keys or set()
        okeys = final_output_keys or set()

        # 拓扑排序
        all_nodes: Set[str] = set(edges)
        for dsts in edges.values():
            all_nodes.update(dsts)
        in_deg = {n: 0 for n in all_nodes}
        for src, dsts in edges.items():
            in_deg[src] = in_deg.get(src, 0)
            for d in dsts:
                in_deg[d] = in_deg.get(d, 0) + 1
        from collections import deque
        q = deque([n for n, d in in_deg.items() if d == 0])
        topo: List[str] = []
        while q:
            n = q.popleft(); topo.append(n)
            for d in edges.get(n, []):
                in_deg[d] -= 1
                if in_deg[d] == 0: q.append(d)

        # 构建: key → {producers}, key → {consumers}
        key_producers: Dict[str, List[str]] = defaultdict(list)
        key_consumers: Dict[str, List[str]] = defaultdict(list)

        for node in topo:
            sig = self._model.signature(node)
            if sig is None:
                continue
            for k in sig.written_keys:
                key_producers[k].append(node)
            for k in sig.all_reads:
                key_consumers[k].append(node)

        # 初始键的 "producer" 是 __init__
        for k in ickeys:
            if k not in key_producers:
                key_producers[k].append('__init__')

        # 为每个键计算生命周期
        lifetimes: Dict[str, KeyLifetime] = {}
        all_keys = set(key_producers) | set(key_consumers) | set(ickeys) | set(okeys)

        # 构建拓扑位置索引
        topo_idx = {n: i for i, n in enumerate(topo)}
        topo_idx['__init__'] = -1

        for key in all_keys:
            producers = key_producers.get(key, ['__init__'])
            consumers = key_consumers.get(key, [])

            if not consumers:
                # 无消费者: 要么是最终输出, 要么是死输出
                if key in okeys:
                    lifetimes[key] = KeyLifetime(
                        key=key, producers=producers, consumers=[],
                        last_consumer='', evict_after_hook='',
                        spillable=False,
                    )
                else:
                    # 死输出: 可在所有生产者执行后立即回收
                    last_prod_idx = max((topo_idx.get(p, -1) for p in producers), default=-1)
                    last_prod = producers[0] if producers else '__init__'
                    lifetimes[key] = KeyLifetime(
                        key=key, producers=producers, consumers=[],
                        last_consumer='', evict_after_hook=last_prod,
                        spillable=False,
                    )
                continue

            # 找到最后的消费者
            last_cons_idx = max(topo_idx.get(c, -1) for c in consumers)
            last_cons = max(consumers, key=lambda c: topo_idx.get(c, -1))

            # 回收点: 最后消费者执行后
            # 若最后消费者无下游, 则 evict_after = last_consumer
            # 若有下游, 则在下游中取拓扑序最前的 (确保消费者完全执行完)
            evict_after = last_cons

            lifetimes[key] = KeyLifetime(
                key=key, producers=producers, consumers=consumers,
                last_consumer=last_cons, evict_after_hook=evict_after,
                spillable=key not in okeys,
            )

        return lifetimes

    def analyze_from_scheduler(self, scheduler, **kw) -> Dict[str, KeyLifetime]:
        if hasattr(scheduler, 'graph_edges'):
            edges = scheduler.graph_edges()
        elif hasattr(scheduler, '_succ'):
            edges = dict(scheduler._succ)
        else:
            edges = {}
        return self.analyze(edges, **kw)


class KeyEvictionManager:
    """键回收管理器 — 在 DAG 执行过程中主动回收已完成生命周期的键.

    集成方式:
      sched = HookDAGScheduler()
      lifetimes = kla.analyze(edges, ...)
      evictor = KeyEvictionManager(lifetimes)
      ctx = evictor.wrap_and_execute(sched, context)

    行为:
      - 每个钩子执行后检查是否有键到达回收点
      - 若键标记为 spillable + 体积超过阈值, 先 spill 到磁盘再回收
      - 回收的键从 context 中删除, 释放内存
    """

    def __init__(self, lifetimes: Dict[str, KeyLifetime],
                 spill_dir: str = '',
                 spill_min_bytes: int = 102400,   # 100KB 以上才 spill
                 track_sizes: bool = True):
        self._lifetimes = lifetimes
        self._spill_dir = spill_dir
        self._spill_min = spill_min_bytes
        self._track_sizes = track_sizes
        self._eviction_records: List[EvictionRecord] = []
        self._total_freed = 0

    def wrap_and_execute(
        self, scheduler, context: Optional[Dict[str, Any]] = None,
        max_workers: Optional[int] = None, parallel: bool = True,
    ) -> Dict[str, Any]:
        """执行调度器, 在每个钩子完成后自动检查并回收键."""
        if context is None:
            context = {}
        self._eviction_records.clear()
        self._total_freed = 0

        if not scheduler._built:
            scheduler.build()

        orig_exec = scheduler._execute_one
        lifetimes = self._lifetimes

        def _evicting_exec(name: str, ctx: dict, failed: set, skipped: set) -> None:
            orig_exec(name, ctx, failed, skipped)
            # 钩子执行后: 检查是否有键到达回收点
            if name in failed or name in skipped:
                return
            to_evict = [
                k for k, lt in lifetimes.items()
                if lt.evict_after_hook == name and k in ctx
            ]
            for k in to_evict:
                self._evict_key(k, ctx)

        scheduler._execute_one = _evicting_exec
        try:
            result = scheduler.execute(context, max_workers=max_workers, parallel=parallel)
        finally:
            scheduler._execute_one = orig_exec

        # 管道结束后: 回收剩余的非输出键 (防御性清理)
        final_outputs = {k for k, lt in lifetimes.items() if lt.is_terminal}
        for k in list(context):
            if k not in final_outputs:
                self._evict_key(k, context)

        return result

    def _evict_key(self, key: str, ctx: dict) -> None:
        """回收单个键, 可选 spill 到磁盘."""
        lt = self._lifetimes.get(key)
        spillable = lt.spillable if lt else False
        val = ctx.get(key)
        size = self._estimate_size(val) if self._track_sizes else 0

        spilled = False
        spill_path = ''
        if spillable and size >= self._spill_min and self._spill_dir:
            spilled = self._try_spill(key, val)
            if spilled:
                spill_path = os.path.join(self._spill_dir, f'{key}.spill')

        ctx.pop(key, None)
        self._eviction_records.append(EvictionRecord(
            key=key, freed_bytes=size, spilled=spilled, spill_path=spill_path,
        ))
        self._total_freed += size

    def _try_spill(self, key: str, val: Any) -> bool:
        """尝试将键值序列化到磁盘. 失败不阻断回收."""
        try:
            os.makedirs(self._spill_dir, exist_ok=True)
            path = os.path.join(self._spill_dir, f'{key}.spill')
            import pickle
            with open(path, 'wb') as f:
                pickle.dump(val, f, protocol=pickle.HIGHEST_PROTOCOL)
            return True
        except Exception:
            return False

    @staticmethod
    def _estimate_size(val: Any) -> int:
        """估算 Python 对象的内存占用 (粗略)."""
        size = sys.getsizeof(val)
        if isinstance(val, dict):
            size += sum(KeyEvictionManager._estimate_size(v) for v in val.values())
            size += sum(KeyEvictionManager._estimate_size(k) for k in val.keys())
        elif isinstance(val, (list, tuple, set)):
            size += sum(KeyEvictionManager._estimate_size(v) for v in val)
        return size

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            'total_freed_bytes': self._total_freed,
            'keys_evicted': len(self._eviction_records),
            'spilled_keys': sum(1 for r in self._eviction_records if r.spilled),
            'records': [{'key': r.key, 'bytes': r.freed_bytes, 'spilled': r.spilled}
                       for r in self._eviction_records],
        }

    def evicted_keys(self) -> List[str]:
        return [r.key for r in self._eviction_records]
