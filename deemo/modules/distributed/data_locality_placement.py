"""
数据局部性感知任务放置 (Data Locality-Aware Task Placement, DLTP)
-------------------------------------------------------------------
将任务调度到已缓存目标二进制的 worker 上, 减少网络传输.

设计依据:
  分布式二进制分析中, 目标文件 (PE/ELF/Firmware) 可达数百 MB.
  每次任务迁移需传输整个文件——在 1Gbps 网络上, 100MB 文件传输
  约需 0.8s, 对秒级分析任务而言是不可忽略的开销.
  将任务放置到已有文件副本的 worker 可消除此开销.

  借鉴 Hadoop/HDFS 的数据局部性调度, 但适配二进制分析的差异:
    1. 文件是独立的二进制 (非 HDFS 块), 无自动副本管理
    2. 分析任务可能修改/追加元数据, 需处理写冲突
    3. 缓存驱逐策略需考虑二进制大小和分析频率

算法:
  1. 维护 WorkerFileIndex: worker_id → Set[binary_hash]
  2. 调度时查询哪些 worker 已有目标二进制
  3. 优先级: local_node > same_rack > random (三级局部性)
  4. LRU 驱逐: 当 worker 缓存超限时驱逐最少访问的二进制
"""
import time
import hashlib
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class WorkerNode:
    """Worker 节点信息."""
    worker_id: str
    host: str = ""
    rack: str = ""            # 机架标识 (用于二级局部性)
    cached_binaries: Set[str] = field(default_factory=set)
    cache_capacity_mb: int = 10240  # 10 GB
    cache_used_mb: int = 0
    last_heartbeat: float = 0.0
    available_memory_mb: int = 0
    cpu_cores: int = 1


class DataLocalityScheduler:
    """数据局部性感知调度器.

    用法:
      dls = DataLocalityScheduler()
      dls.register_worker('w1', host='10.0.1.5', rack='r1')
      dls.cache_binary('w1', 'binary_hash_abc', size_mb=150)
      best_worker = dls.select_worker('binary_hash_abc')
    """

    def __init__(self, cache_max_per_worker_mb: int = 10240):
        self._workers: Dict[str, WorkerNode] = {}
        self._binary_sizes: Dict[str, int] = {}  # hash → size_mb
        self._cache_max = cache_max_per_worker_mb
        # LRU 追踪: (worker_id, binary_hash) → last_access_time
        self._access_tracker: Dict[Tuple[str, str], float] = {}

    def register_worker(self, worker_id: str, host: str = "",
                        rack: str = "", cpu_cores: int = 1,
                        memory_mb: int = 0):
        self._workers[worker_id] = WorkerNode(
            worker_id=worker_id, host=host, rack=rack,
            cpu_cores=cpu_cores, available_memory_mb=memory_mb,
        )

    def cache_binary(self, worker_id: str, binary_hash: str,
                     size_mb: int = 0):
        """标记某 worker 已缓存某二进制."""
        w = self._workers.get(worker_id)
        if w is None:
            return
        if binary_hash not in w.cached_binaries:
            w.cached_binaries.add(binary_hash)
            w.cache_used_mb += size_mb
            self._binary_sizes[binary_hash] = size_mb
            # 缓存超限 → LRU 驱逐
            while w.cache_used_mb > w.cache_capacity_mb and w.cached_binaries:
                victim = self._evict_lru(worker_id)
                if victim is None:
                    break
                w.cached_binaries.discard(victim)
                w.cache_used_mb -= self._binary_sizes.get(victim, 0)
        self._access_tracker[(worker_id, binary_hash)] = time.time()

    def _evict_lru(self, worker_id: str) -> Optional[str]:
        """LRU 驱逐: 返回应移除的 binary_hash."""
        worker_keys = [(bh, ts) for (wid, bh), ts
                       in self._access_tracker.items()
                       if wid == worker_id]
        if not worker_keys:
            return None
        worker_keys.sort(key=lambda x: x[1])
        return worker_keys[0][0]

    def select_worker(self, binary_hash: str,
                      exclude_workers: Optional[List[str]] = None
                      ) -> Optional[str]:
        """选择最优 worker (三级局部性)."""
        exclude = set(exclude_workers or [])
        candidates = [
            w for wid, w in self._workers.items()
            if wid not in exclude and w.last_heartbeat > time.time() - 30
        ]
        if not candidates:
            return None

        # Level 1: 本地缓存命中
        local_hits = [w for w in candidates if binary_hash in w.cached_binaries]
        if local_hits:
            # 选缓存命中且负载最低的
            return min(local_hits, key=lambda w: len(w.cached_binaries)).worker_id

        # Level 2: 同 rack (网络距离近)
        # 需要至少一个 worker 有已知 rack
        racks = set(w.rack for w in candidates if w.rack)
        if racks:
            for rack in racks:
                rack_workers = [w for w in candidates if w.rack == rack]
                if rack_workers:
                    return rack_workers[0].worker_id

        # Level 3: 随机 (或最少加载)
        return min(candidates, key=lambda w: len(w.cached_binaries)).worker_id

    def transfer_cost_ms(self, worker_id: str, binary_hash: str,
                         bandwidth_mbps: float = 1000.0) -> float:
        """估算从当前 worker 获取二进制的传输耗时 (ms)."""
        w = self._workers.get(worker_id)
        if w and binary_hash in w.cached_binaries:
            return 0.0  # 已缓存
        size_mb = self._binary_sizes.get(binary_hash, 50)
        return (size_mb * 8) / bandwidth_mbps * 1000.0

    def predicted_fetch_time(self, binary_hash: str,
                             bandwidth_mbps: float = 1000.0) -> float:
        """预测获取某二进制的最小耗时 (寻找最近的缓存副本)."""
        size_mb = self._binary_sizes.get(binary_hash, 50)
        cached_workers = [
            w for w in self._workers.values()
            if binary_hash in w.cached_binaries
        ]
        if cached_workers:
            return 0.0
        return (size_mb * 8) / bandwidth_mbps * 1000.0

    def worker_stats(self, worker_id: str) -> Dict[str, Any]:
        w = self._workers.get(worker_id)
        if w is None:
            return {}
        return {
            'worker_id': w.worker_id,
            'cached_binaries': len(w.cached_binaries),
            'cache_used_mb': w.cache_used_mb,
            'cache_utilization': round(
                w.cache_used_mb / w.cache_capacity_mb, 3
            ) if w.cache_capacity_mb > 0 else 0,
        }
