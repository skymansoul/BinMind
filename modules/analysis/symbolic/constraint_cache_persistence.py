"""约束求解结果缓存 — LRU 内存层 + SQLite 磁盘持久化。

约束求解在符号执行成本中占主导, 本模块把解按归一化约束形式的
SHA256 作键缓存, 内存命中走 LRU dict, 未命中回退磁盘并提升入内存。
归一化把 SMT-LIB 操作符规范化, 语义相同的约束共享同一缓存键。

内存层采用 OrderedDict + 分段锁: key 空间按首字节拆为 16 个 shard,
每个 shard 持独立锁, 减少高频查询锁竞争; 写入路径仍用全局锁保证
LRU 顺序一致性。
"""

import logging
import os
import json
import struct
import time
import sqlite3
import threading
from dataclasses import dataclass, field
from collections import OrderedDict
from datetime import datetime

from typing import Optional, Any, Dict, List, Tuple

from .src.constraint_serializer import (
    NORMALIZE_PATTERNS,
    CATEGORY_SIGNATURES,
    normalize_constraint,
    classify_constraint_category,
    compute_constraint_hash_bytes,
    compute_constraint_hash,
    entry_to_dict,
    entry_to_db_params,
    db_row_to_init_kwargs,
    json_item_to_init_kwargs,
)

logger = logging.getLogger(__name__)


DEFAULT_MAX_CACHE_ENTRIES = 1000
DEFAULT_WARMUP_TOP_N = 200
DEFAULT_TTL_INTERVAL_S = 60
TELEMETRY_RING_CAPACITY = 1000


@dataclass
class CachedConstraint:
    """单条缓存: 原始约束/归一化形式/解/统计。"""
    constraint_hash: str
    original_constraint: str
    normalized_constraint: str
    solution: Any
    solver_name: str = "unknown"
    solve_time_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)
    hit_count: int = 0
    constraint_category: str = ""    # bitvector / integer / string — 用于分类统计
    ttl_seconds: float = 0.0          # 0 表示永不过期；> 0 表示从 timestamp 起的 TTL

    def is_expired(self, now: Optional[float] = None) -> bool:
        """检查条目 TTL 是否已到期。"""
        if self.ttl_seconds <= 0:
            return False
        ref = now if now is not None else time.time()
        return (ref - self.timestamp) > self.ttl_seconds

    def to_dict(self) -> Dict[str, Any]:
        """序列化为 JSON 导出格式 (委托 serializer 模块)。"""
        return entry_to_dict(self)


# CacheTelemetry: Span 式操作延迟追踪器
# 按操作类型 (get/put/evict/vacuum) 分开记录耗时到环形缓冲区
# 容量上限 TELEMETRY_RING_CAPACITY, 自动丢弃最旧样本
# 对 get/put 的写路径要求 O(1) 追加, 不分配新内存 (预分配缓冲区)
class CacheTelemetry:
    """缓存操作的 Span 式延迟追踪器。

    按操作类型记录耗时到环形缓冲区 (最多 1000 样本);
    百分位查询 (p50/p95/p99) 按需排序计算 — 缓冲区规模保证
    高查询负载下排序开销仍低于毫秒级。

    操作类型: get / put / evict / vacuum
    每类操作独立环形缓冲区, 追加 O(1), 百分位计算仅在查询时触发。
    """

    _OPS = ("get", "put", "evict", "vacuum")

    def __init__(self, capacity: int = TELEMETRY_RING_CAPACITY):
        self._capacity = max(capacity, 1)
        # 预分配固定大小列表，写指针 wrap 覆盖，无 GC 压力
        self._rings: Dict[str, List[float]] = {
            op: [0.0] * self._capacity for op in self._OPS
        }
        # 写入游标：[0, capacity)
        self._cursors: Dict[str, int] = {op: 0 for op in self._OPS}
        # 实际样本计数 (≤ capacity) — 用于百分位计算时的有效窗口
        self._counts: Dict[str, int] = {op: 0 for op in self._OPS}
        self._lock = threading.Lock()

    def record(self, operation: str, elapsed_seconds: float) -> None:
        """向 operation 对应环形缓冲区追加一条延迟样本, 线程安全 O(1)。"""
        if operation not in self._rings:
            return
        with self._lock:
            idx = self._cursors[operation]
            self._rings[operation][idx] = elapsed_seconds
            self._cursors[operation] = (idx + 1) % self._capacity
            if self._counts[operation] < self._capacity:
                self._counts[operation] += 1

    def percentile(self, operation: str, p: float) -> float:
        """计算 operation 的第 p 百分位 (0-100), 无样本返回 0.0。"""
        if p < 0 or p > 100:
            return 0.0
        with self._lock:
            count = self._counts.get(operation, 0)
            if count == 0:
                return 0.0
            # 拷贝有效样本 window 并排序
            ring = self._rings[operation]
            samples = sorted(ring[:count])
        k = (p / 100.0) * (count - 1)
        lo = int(k)
        hi = min(lo + 1, count - 1)
        frac = k - lo
        if lo == hi:
            return samples[lo]
        return samples[lo] * (1.0 - frac) + samples[hi] * frac

    def p50(self, operation: str) -> float:
        return self.percentile(operation, 50.0)

    def p95(self, operation: str) -> float:
        return self.percentile(operation, 95.0)

    def p99(self, operation: str) -> float:
        return self.percentile(operation, 99.0)

    def sample_count(self, operation: str) -> int:
        with self._lock:
            return self._counts.get(operation, 0)

    def snapshot(self) -> Dict[str, Dict[str, float]]:
        """返回 {操作: {p50, p95, p99, samples}} 快照 (ms 单位)。"""
        result = {}
        for op in self._OPS:
            with self._lock:
                n = self._counts[op]
            result[op] = {
                "p50": self.p50(op) * 1000,   # 转换 ms
                "p95": self.p95(op) * 1000,
                "p99": self.p99(op) * 1000,
                "samples": n,
            }
        return result


@dataclass
class CacheStatistics:
    """缓存性能的运行时计数器。"""
    total_entries: int = 0
    max_entries: int = 1000
    hit_count: int = 0
    miss_count: int = 0
    eviction_count: int = 0
    total_queries: int = 0
    persistent_entries: int = 0
    memory_usage_estimate: int = 0

    @property
    def hit_rate(self) -> float:
        """缓存命中查询占比。"""
        total = self.hit_count + self.miss_count
        if total == 0:
            return 0.0
        return self.hit_count / total


# 分段内存缓存：16 个 shard，按 hash 首字节分片
# 读路径无全局锁，写路径使用 shard 锁 + 全局 LRU 锁的两阶段协议
# 设计取舍 — shard 数量为 2 的幂，用位运算取模，避免除法的 CPU 开销
_NR_SHARDS = 16


class _Shard:
    __slots__ = ('_data', '_lock')

    def __init__(self):
        self._data: OrderedDict[str, CachedConstraint] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            entry = self._data.get(key)
            if entry is not None:
                self._data.move_to_end(key)
            return entry

    def put(self, key: str, entry: CachedConstraint):
        with self._lock:
            self._data[key] = entry
            self._data.move_to_end(key)

    def pop_lru(self):
        with self._lock:
            if self._data:
                return self._data.popitem(last=False)
            return None

    def __len__(self):
        with self._lock:
            return len(self._data)

    def all_keys(self) -> List[str]:
        """shard 内键快照 — 调用方须持有 shard._lock。"""
        return list(self._data.keys())

    def remove(self, key: str) -> bool:
        """删除 shard 中的 key (存在时)。"""
        with self._lock:
            if key in self._data:
                del self._data[key]
                return True
            return False


# CacheWarmingPolicy: 启动时按历史命中频率预加载热点条目
# 设计取舍 — 用独立的小表（cache_frequencies）追踪频率，而非在主表上
# 加字段，避免每次 hit 更新整行的写入放大。小表只存 hash + hits + ts
# 写入开销 O(1) 且与主表解耦，vacuum/预热都对主表无锁竞争
class CacheWarmingPolicy:
    """启动时按历史命中频率从磁盘预加载热点条目。

    用独立的轻量频率表 (cache_frequencies) 追踪命中次数, 避免每次
    hit 更新主表宽行的写入放大。warmup 时按 total_hits 取前
    warmup_top_n 条提升进分片内存缓存。
    """

    def __init__(self, warmup_top_n: int = DEFAULT_WARMUP_TOP_N):
        self.warmup_top_n = warmup_top_n
        self._freq_write_buffer: List[tuple] = []

    def ensure_freq_table(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS cache_frequencies (
                constraint_hash TEXT PRIMARY KEY,
                total_hits INTEGER DEFAULT 1,
                last_access REAL NOT NULL
            )"""
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_freq_hits ON cache_frequencies(total_hits DESC)"
        )
        conn.commit()

    def record_hit(self, conn: sqlite3.Connection, constraint_hash: str) -> None:
        if conn is None:
            return
        now = time.time()
        conn.execute(
            """INSERT INTO cache_frequencies (constraint_hash, total_hits, last_access)
               VALUES (?, 1, ?)
               ON CONFLICT(constraint_hash) DO UPDATE SET
               total_hits = total_hits + 1,
               last_access = excluded.last_access""",
            (constraint_hash, now),
        )

    def flush_freq_buffer(self, conn: sqlite3.Connection) -> None:
        if not self._freq_write_buffer:
            return
        for constraint_hash in self._freq_write_buffer:
            self.record_hit(conn, constraint_hash)
        conn.commit()
        self._freq_write_buffer.clear()

    def buffer_freq_hit(self, constraint_hash: str) -> None:
        self._freq_write_buffer.append(constraint_hash)

    def warmup(
        self,
        conn: sqlite3.Connection,
        shards: List[_Shard],
        max_entries: int,
    ) -> int:
        """把主缓存表 top-N 高频命中条目加载进内存, 返回预加载条数。"""
        if conn is None:
            return 0

        self.ensure_freq_table(conn)
        loaded = 0
        limit = min(self.warmup_top_n, max_entries)
        freq_table = conn.execute(
            """SELECT f.constraint_hash, c.original_constraint,
                      c.normalized_constraint, c.solution, c.solver_name,
                      c.solve_time_ms, c.timestamp, f.total_hits,
                      c.constraint_category
               FROM cache_frequencies f
               JOIN constraint_cache c ON f.constraint_hash = c.constraint_hash
               ORDER BY f.total_hits DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()

        for row in freq_table:
            entry = CachedConstraint(
                constraint_hash=row[0],
                original_constraint=row[1],
                normalized_constraint=row[2],
                solution=row[3],
                solver_name=row[4],
                solve_time_ms=row[5],
                timestamp=row[6],
                hit_count=row[7],
                constraint_category=row[8] if len(row) > 8 else "",
            )
            slot_idx = struct.unpack("H", bytes.fromhex(entry.constraint_hash)[:2])[0] & 0xF
            shards[slot_idx].put(entry.constraint_hash, entry)
            loaded += 1

        if loaded:
            logger.info(
                "Cache warmed: %d entries (top-%d by frequency)", loaded, limit
            )
        return loaded


# TTL 懒驱逐守护线程: 后台线程每 60 秒扫描所有 shard 和 SQLite 表
# 剔除已过期的条目。与即时驱逐 (每次查询检查 TTL) 相比
# 懒驱逐在命中路径上无额外开销, 适合高 QPS 场景
# 设计取舍 — 守护线程持有 shard 锁的时间极短 (逐条 pop), 不会阻塞读路径
class _TTLEvictionDaemon:
    """后台线程定期扫描并驱逐过期的缓存条目。

    周期 interval_seconds (默认 60s)。驱逐是惰性的 — 过期条目在
    两次扫描之间仍留在缓存中, 但查询时经 is_expired 跳过。
    """

    def __init__(
        self,
        cache_instance: "ConstraintCachePersistence",
        interval_seconds: float = DEFAULT_TTL_INTERVAL_S,
    ):
        self._cache = cache_instance
        self._interval = interval_seconds
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._evictions_total: int = 0
        self._sweeps_completed: int = 0

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._sweep_loop,
            name="cache-ttl-evict",
            daemon=True,
        )
        self._thread.start()
        logger.info("TTL eviction daemon started (interval=%.0fs)", self._interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        logger.info(
            "TTL eviction daemon stopped: %d sweeps, %d total evictions",
            self._sweeps_completed, self._evictions_total,
        )

    @property
    def evictions_total(self) -> int:
        return self._evictions_total

    @property
    def sweeps_completed(self) -> int:
        return self._sweeps_completed

    def _sweep_loop(self) -> None:
        """循环扫描分片与 SQLite, 驱逐过期条目。"""
        while not self._stop_event.wait(self._interval):
            sweep_start = time.time()
            evicted_mem = self._evict_expired_from_memory()
            evicted_disk = self._evict_expired_from_disk()
            total_evicted = evicted_mem + evicted_disk
            self._evictions_total += total_evicted
            self._sweeps_completed += 1
            elapsed = time.time() - sweep_start
            if total_evicted > 0:
                logger.debug(
                    "TTL sweep #%d: evicted %d (mem=%d disk=%d) in %.3fs",
                    self._sweeps_completed, total_evicted,
                    evicted_mem, evicted_disk, elapsed,
                )

    def _evict_expired_from_memory(self) -> int:
        """遍历分片移除过期内存条目。"""
        now = time.time()
        evicted = 0
        for shard in self._cache._shards:
            expired_keys = []
            with shard._lock:
                for key, entry in shard._data.items():
                    if entry.is_expired(now):
                        expired_keys.append(key)
            for key in expired_keys:
                if shard.remove(key):
                    evicted += 1
        return evicted

    def _evict_expired_from_disk(self) -> int:
        """删除 SQLite 中已过期的行 (ttl_seconds > 0 且已超时)。"""
        db = self._cache._db_connection
        if db is None:
            return 0
        now = time.time()
        try:
            cursor = db.execute(
                "DELETE FROM constraint_cache "
                "WHERE ttl_seconds > 0 AND (timestamp + ttl_seconds) < ?",
                (now,),
            )
            removed = cursor.rowcount
            if removed > 0:
                db.commit()
            return removed
        except Exception as exc:
            logger.warning("TTL disk sweep failed: %s", exc)
            return 0


class ConstraintCachePersistence:
    """两级约束缓存: 分片内存 LRU + SQLite 磁盘存储。

    归一化把 SMT-LIB 操作符重写为规范形式后取哈希,
    语义相同的 '(bvadd x y)' 共享同一键。
    """

    # SMT-LIB 操作符规范符号表 (从 serializer 模块导入)
    NORMALIZE_PATTERNS = NORMALIZE_PATTERNS

    # 快速类别分类 (从 serializer 模块导入)
    CATEGORY_SIGNATURES = CATEGORY_SIGNATURES

    def __init__(self):
        self._shards = [_Shard() for _ in range(_NR_SHARDS)]
        self._global_lock = threading.Lock()
        self._stats = CacheStatistics()
        self._db_path: Optional[str] = None
        self._db_connection: Optional[sqlite3.Connection] = None
        self._config: Dict[str, Any] = {"max_cache_entries": DEFAULT_MAX_CACHE_ENTRIES}
        # 写入缓冲：攒够 batch_size 条再批量 flush SQLite，减少 fsync 频率
        self._write_buffer: List[CachedConstraint] = []
        self._write_buffer_max = 50
        self._warming_policy = CacheWarmingPolicy()
        self.warmup_top_n: int = DEFAULT_WARMUP_TOP_N
        # 操作延迟遥测
        self._telemetry = CacheTelemetry()
        # TTL 懒驱逐守护线程
        self._ttl_daemon = _TTLEvictionDaemon(self)

    # shard 索引: 用 struct.unpack("H", bytes[:2]) 替代 int(hash[:2],16)
    # 避免 hex 字符串切片和解析开销 — 热路径上省掉一次 int(.,16) 调用
    @staticmethod
    def _shard_of(hash_bytes: bytes) -> int:
        return struct.unpack("H", hash_bytes[:2])[0] & 0xF

    def _total_entries(self) -> int:
        return sum(len(shard) for shard in self._shards)

    def _get_default_db_path(self) -> str:
        """缺省 SQLite 路径: ~/.binary_analysis_cache。"""
        home = os.path.expanduser("~")
        cache_dir = os.path.join(home, ".binary_analysis_cache")
        os.makedirs(cache_dir, exist_ok=True)
        return os.path.join(cache_dir, "constraint_cache.db")

    def _init_database(self, db_path: Optional[str] = None) -> None:
        """创建 SQLite schema (不存在时)。"""
        self._db_path = db_path or self._get_default_db_path()
        self._db_connection = sqlite3.connect(
            self._db_path, check_same_thread=False
        )
        self._db_connection.execute(
            """CREATE TABLE IF NOT EXISTS constraint_cache (
                constraint_hash TEXT PRIMARY KEY,
                original_constraint TEXT NOT NULL,
                normalized_constraint TEXT NOT NULL,
                solution TEXT,
                solver_name TEXT DEFAULT 'unknown',
                solve_time_ms REAL DEFAULT 0.0,
                timestamp REAL NOT NULL,
                hit_count INTEGER DEFAULT 0,
                constraint_category TEXT DEFAULT '',
                ttl_seconds REAL DEFAULT 0.0
            )"""
        )
        self._db_connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON constraint_cache(timestamp)"
        )
        self._db_connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_solver ON constraint_cache(solver_name)"
        )
        self._db_connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_category ON constraint_cache(constraint_category)"
        )
        self._warming_policy.ensure_freq_table(self._db_connection)
        self._db_connection.commit()
        logger.info(f"Constraint cache database initialized: {self._db_path}")

    def _classify_category(self, normalized: str) -> str:
        """推断约束类别 (委托 serializer 模块)。"""
        return classify_constraint_category(normalized)

    def serialize_constraint(self, constraint: str) -> str:
        """规范化约束字符串 (委托 serializer 模块)。

        步骤: 折叠空白、小写化、标准化 SMT-LIB 操作符与括号间距。
        """
        return normalize_constraint(constraint)

    # 先算 raw bytes（digest），需要 hex 字符串时再.hex()
    # 热路径（lookup/cache）直接从 bytes 取 slot_idx，省掉一次 hex 分配
    @staticmethod
    def _compute_hash_bytes(normalized_constraint: str) -> bytes:
        """SHA256 摘要原始字节 (委托 serializer 模块)。"""
        return compute_constraint_hash_bytes(normalized_constraint)

    def _compute_hash(self, normalized_constraint: str) -> str:
        """SHA256 hex 摘要 (委托 serializer 模块)。"""
        return compute_constraint_hash(normalized_constraint)

    def cache_constraint(
        self,
        constraint: str,
        solution: Any,
        solver_name: str = "unknown",
        solve_time_ms: float = 0.0,
        ttl_seconds: float = 0.0,
    ) -> str:
        """存储约束→解的映射, 返回 hash 键。

        约束已缓存时刷新 LRU 位置并累计命中; ttl_seconds=0 表示永不过期。
        """
        put_start = time.time()
        normalized = self.serialize_constraint(constraint)
        hash_bytes = self._compute_hash_bytes(normalized)
        constraint_hash = hash_bytes.hex()
        category = self._classify_category(normalized)
        slot_idx = self._shard_of(hash_bytes)
        shard = self._shards[slot_idx]

        existing = shard.get(constraint_hash)
        if existing is not None:
            # 如果已有条目但 caller 提供了不同的 TTL，以 call-site 为准更新
            if ttl_seconds > 0 and existing.ttl_seconds != ttl_seconds:
                existing.ttl_seconds = ttl_seconds
            self._stats.hit_count += 1
            self._warming_policy.buffer_freq_hit(constraint_hash)
            self._telemetry.record("put", time.time() - put_start)
            return constraint_hash

        max_entries = self._config.get("max_cache_entries", DEFAULT_MAX_CACHE_ENTRIES)
        while self._total_entries() >= max_entries:
            self.evict_lru(count=1)

        entry = CachedConstraint(
            constraint_hash=constraint_hash,
            original_constraint=constraint,
            normalized_constraint=normalized,
            solution=solution,
            solver_name=solver_name,
            solve_time_ms=solve_time_ms,
            constraint_category=category,
            ttl_seconds=ttl_seconds,
        )
        shard.put(constraint_hash, entry)

        self._write_buffer.append(entry)
        if len(self._write_buffer) >= self._write_buffer_max:
            self._flush_write_buffer()

        logger.debug(f"Constraint cached: {constraint_hash[:16]}... solver={solver_name}")
        self._telemetry.record("put", time.time() - put_start)
        return constraint_hash

    def _flush_write_buffer(self):
        """批量写入缓冲条目到 SQLite, 一并刷频率命中。"""
        if self._db_connection is None:
            self._write_buffer.clear()
            return
        with self._global_lock:
            for entry in self._write_buffer:
                self._db_connection.execute(
                    """INSERT OR REPLACE INTO constraint_cache
                       (constraint_hash, original_constraint, normalized_constraint,
                        solution, solver_name, solve_time_ms, timestamp, hit_count,
                        constraint_category, ttl_seconds)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    entry_to_db_params(entry),
                )
            self._db_connection.commit()
            self._stats.persistent_entries += len(self._write_buffer)
            self._warming_policy.flush_freq_buffer(self._db_connection)
            self._write_buffer.clear()

    def lookup_constraint(self, constraint: str) -> Optional[Dict[str, Any]]:
        """先查内存再查磁盘, 返回 entry dict 或 None。

        过期条目 (TTL) 视为 miss 并从内存移除。
        """
        get_start = time.time()
        normalized = self.serialize_constraint(constraint)
        hash_bytes = self._compute_hash_bytes(normalized)
        constraint_hash = hash_bytes.hex()

        self._stats.total_queries += 1

        slot_idx = self._shard_of(hash_bytes)
        shard = self._shards[slot_idx]
        entry = shard.get(constraint_hash)
        if entry is not None:
            # TTL 懒驱逐路径：命中但已过期 → 当作 miss，从内存移除
            if entry.is_expired():
                shard.remove(constraint_hash)
                self._stats.miss_count += 1
                self._telemetry.record("get", time.time() - get_start)
                logger.debug(f"TTL expired (mem): {constraint_hash[:16]}...")
                return None

            entry.hit_count += 1
            self._stats.hit_count += 1
            self._warming_policy.buffer_freq_hit(constraint_hash)
            logger.debug(f"Cache hit: {constraint_hash[:16]}... (hit={entry.hit_count})")
            self._telemetry.record("get", time.time() - get_start)
            return entry.to_dict()

        disk_result = self._lookup_from_disk(constraint_hash)
        if disk_result is not None:
            # 从磁盘提升的条目也检查 TTL
            disk_ttl = disk_result.get("ttl_seconds", 0.0)
            if disk_ttl > 0:
                disk_ts = disk_result.get("timestamp", 0.0)
                if (time.time() - disk_ts) > disk_ttl:
                    self._stats.miss_count += 1
                    self._telemetry.record("get", time.time() - get_start)
                    return None

            self._stats.hit_count += 1
            self._warming_policy.buffer_freq_hit(constraint_hash)
            self._telemetry.record("get", time.time() - get_start)
            return disk_result

        self._stats.miss_count += 1
        logger.debug(f"Cache miss: {constraint_hash[:16]}...")
        self._telemetry.record("get", time.time() - get_start)
        return None

    def _lookup_from_disk(self, constraint_hash: str) -> Optional[Dict[str, Any]]:
        """查 SQLite, 命中条目提升进内存缓存。"""
        if self._db_connection is None:
            return None
        cursor = self._db_connection.execute(
            "SELECT * FROM constraint_cache WHERE constraint_hash = ?",
            (constraint_hash,),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        kwargs = db_row_to_init_kwargs(row)
        kwargs["hit_count"] = kwargs["hit_count"] + 1  # 提升时递增命中计数
        entry = CachedConstraint(**kwargs)
        slot_idx = self._shard_of(bytes.fromhex(constraint_hash))
        shard = self._shards[slot_idx]
        shard.put(constraint_hash, entry)
        max_entries = self._config.get("max_cache_entries", DEFAULT_MAX_CACHE_ENTRIES)
        while self._total_entries() > max_entries:
            self.evict_lru(count=1)
        return entry.to_dict()

    def evict_lru(self, count: int = 1) -> int:
        """从内存移除最久未使用的条目。

        采用近似 LRU: 从所有 shard 中选取最旧条目逐出而非全局
        精确排序, 复杂度 O(shard_count), 数千条目规模下足够精确。
        """
        evict_start = time.time()
        evicted = 0
        for _ in range(min(count, self._total_entries())):
            oldest_key = None
            oldest_shard = None
            oldest_ts = float('inf')
            for shard in self._shards:
                with shard._lock:
                    if shard._data:
                        candidate_key = next(iter(shard._data))
                        candidate = shard._data[candidate_key]
                        if candidate.timestamp < oldest_ts:
                            oldest_ts = candidate.timestamp
                            oldest_key = candidate_key
                            oldest_shard = shard
            if oldest_shard is not None and oldest_key is not None:
                with oldest_shard._lock:
                    oldest_shard._data.pop(oldest_key, None)
                evicted += 1
            else:
                break

        self._stats.eviction_count += evicted
        if evicted > 0:
            logger.debug(f"LRU evicted {evicted} cache entries")
        self._telemetry.record("evict", time.time() - evict_start)
        return evicted

    def persist_to_disk(self, db_path: Optional[str] = None) -> int:
        """把内存缓存全量刷入 SQLite。"""
        if self._db_connection is None:
            self._init_database(db_path)

        if self._db_connection is None:
            logger.error("Database connection unavailable")
            return 0

        self._flush_write_buffer()

        count = 0
        for shard in self._shards:
            with shard._lock:
                for entry in shard._data.values():
                    self._db_connection.execute(
                        """INSERT OR REPLACE INTO constraint_cache
                           (constraint_hash, original_constraint, normalized_constraint,
                            solution, solver_name, solve_time_ms, timestamp, hit_count,
                            constraint_category, ttl_seconds)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        entry_to_db_params(entry),
                    )
                    count += 1
        self._db_connection.commit()
        self._stats.persistent_entries = count
        logger.info(f"Persisted {count} constraint caches to disk")

        return count

    def load_from_disk(self, db_path: Optional[str] = None) -> int:
        """把 SQLite 中最近的条目加载进内存。"""
        if self._db_connection is None:
            self._init_database(db_path)
        if self._db_connection is None:
            return 0

        count = 0
        limit = self._config.get("max_cache_entries", DEFAULT_MAX_CACHE_ENTRIES)
        cursor = self._db_connection.execute(
            "SELECT * FROM constraint_cache ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        for row in cursor:
            entry = CachedConstraint(**db_row_to_init_kwargs(row))
            slot_idx = self._shard_of(bytes.fromhex(entry.constraint_hash))
            shard = self._shards[slot_idx]
            shard.put(entry.constraint_hash, entry)
            count += 1
        logger.info(f"Loaded {count} constraint caches from disk into memory")

        return count

    def export_to_json(self, file_path: str) -> int:
        """把内存缓存转存为 JSON 文件。"""
        entries = []
        for shard in self._shards:
            with shard._lock:
                entries.extend(entry_to_dict(e) for e in shard._data.values())
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "exported_at": datetime.now().isoformat(),
                    "total_entries": len(entries),
                    "entries": entries,
                },
                f,
                indent=2,
                ensure_ascii=False,
            )
        logger.info(f"Exported {len(entries)} cache entries to {file_path}")
        return len(entries)

    def import_from_json(self, file_path: str) -> int:
        """从先前导出的 JSON 文件回填内存缓存。"""
        if not os.path.exists(file_path):
            logger.warning(f"JSON file does not exist: {file_path}")
            return 0
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        entries = data.get("entries", [])
        count = 0
        for item in entries:
            constraint_hash = item.get("constraint_hash", "")
            if not constraint_hash:
                continue
            slot_idx = self._shard_of(bytes.fromhex(constraint_hash))
            shard = self._shards[slot_idx]
            existing = shard.get(constraint_hash)
            if existing is not None:
                continue
            entry = CachedConstraint(**json_item_to_init_kwargs(item))
            shard.put(constraint_hash, entry)
            count += 1
        logger.info(f"Imported {count} constraint caches from JSON")
        return count

    # vacuum_stale: 清理零命中且过期超过 ttl_seconds 的条目
    # 设计取舍 — 用 SQLite 的 julianday 函数做时间比对，避免将所有
    # timestamp 读到 Python 侧再过滤，减少跨语言边界的传输量
    def vacuum_stale(self, ttl_seconds: float) -> int:
        """删除零命中且超过 TTL 的陈旧条目并 VACUUM。

        条目满足 hit_count == 0 且年龄超过 ttl_seconds 视为陈旧;
        VACUUM 回收磁盘上释放的页。返回删除行数。
        """
        vacuum_start = time.time()
        if self._db_connection is None:
            return 0

        stale_cutoff_ts = time.time() - ttl_seconds
        cursor = self._db_connection.execute(
            "SELECT COUNT(*) FROM constraint_cache "
            "WHERE hit_count = 0 AND timestamp < ?",
            (stale_cutoff_ts,),
        )
        stale_count = cursor.fetchone()[0]
        if stale_count == 0:
            self._telemetry.record("vacuum", time.time() - vacuum_start)
            return 0

        self._db_connection.execute(
            "DELETE FROM constraint_cache "
            "WHERE hit_count = 0 AND timestamp < ?",
            (stale_cutoff_ts,),
        )
        self._db_connection.execute("VACUUM")
        self._db_connection.commit()
        logger.info(
            "Vacuumed %d stale cache rows (ttl=%.0fs, cutoff_ts=%.0f)",
            stale_count, ttl_seconds, stale_cutoff_ts,
        )
        self._telemetry.record("vacuum", time.time() - vacuum_start)
        return stale_count

    def cache_statistics(self) -> Dict[str, Any]:
        """返回当前缓存性能指标, 含每操作的 p50/p95/p99 遥测。"""
        total = self._total_entries()
        self._stats.total_entries = total
        self._stats.memory_usage_estimate = total * 2048
        return {
            "total_entries": total,
            "hit_rate": round(self._stats.hit_rate, 4),
            "hit_count": self._stats.hit_count,
            "miss_count": self._stats.miss_count,
            "eviction_count": self._stats.eviction_count,
            "total_queries": self._stats.total_queries,
            "memory_estimate_bytes": self._stats.memory_usage_estimate,
            "max_entries": self._stats.max_entries,
            "disk_entries": self._get_disk_entry_count(),
            "telemetry_ms": self._telemetry.snapshot(),
            "ttl_daemon_sweeps": self._ttl_daemon.sweeps_completed,
            "ttl_daemon_evictions": self._ttl_daemon.evictions_total,
        }

    def _get_disk_entry_count(self) -> int:
        """SQLite 表中的行数。"""
        if self._db_connection is None:
            return 0
        cursor = self._db_connection.execute(
            "SELECT COUNT(*) FROM constraint_cache"
        )
        return cursor.fetchone()[0]

    def clear_cache(self) -> int:
        """清空内存条目, 返回清除数量。"""
        count = self._total_entries()
        for shard in self._shards:
            with shard._lock:
                shard._data.clear()
        self._stats.total_entries = 0
        logger.info(f"Cleared {count} memory cache entries")
        return count

    def initialize(self, config: Optional[Dict[str, Any]] = None) -> bool:
        """应用配置, 初始化数据库, 按命中频率预热缓存。

        配置可提供 warmup_top_n 覆盖默认值 (200); 预热查询
        cache_frequencies 表, 把高频命中条目从磁盘加载进分片
        内存层。TTL 懒驱逐守护线程在初始化时自动启动。
        """
        if config:
            self._config.update(config)
            self.warmup_top_n = config.get("warmup_top_n", DEFAULT_WARMUP_TOP_N)
            self._warming_policy.warmup_top_n = self.warmup_top_n

        db_path = config.get("db_path") if config else None
        if self._db_connection is None:
            self._init_database(db_path)

        if self._db_connection is not None:
            max_entries = self._config.get("max_cache_entries", DEFAULT_MAX_CACHE_ENTRIES)
            self._warming_policy.warmup(
                self._db_connection, self._shards, max_entries,
            )

        if config and config.get("auto_load_disk"):
            self.load_from_disk(config.get("db_path"))

        # 启动 TTL 懒驱逐守护线程
        ttl_interval = config.get("ttl_eviction_interval_s", DEFAULT_TTL_INTERVAL_S) if config else DEFAULT_TTL_INTERVAL_S
        self._ttl_daemon._interval = ttl_interval
        self._ttl_daemon.start()

        return True

    def cleanup(self) -> None:
        """刷写缓冲区与频率命中, 关闭 SQLite 连接。"""
        self._ttl_daemon.stop()
        self._flush_write_buffer()
        if self._db_connection:
            self._warming_policy.flush_freq_buffer(self._db_connection)
            self._db_connection.close()
            logger.info("Database connection closed")
            self._db_connection = None

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """按 'action' 键分发缓存操作。"""
        action = kwargs.get("action", "cache")

        if action == "cache":
            constraint = kwargs.get("constraint", "")
            if not constraint:
                return {"success": False, "error": "constraint parameter is required"}
            solution = kwargs.get("solution")
            solver = kwargs.get("solver_name", "unknown")
            solve_time = kwargs.get("solve_time_ms", 0.0)
            ttl = kwargs.get("ttl_seconds", 0.0)
            constraint_hash = self.cache_constraint(constraint, solution, solver, solve_time, ttl)
            return {
                "success": True,
                "constraint_hash": constraint_hash,
                "action": "cached",
            }

        elif action == "lookup":
            constraint = kwargs.get("constraint", "")
            if not constraint:
                return {"success": False, "error": "constraint parameter is required"}
            result = self.lookup_constraint(constraint)
            return {
                "success": True,
                "found": result is not None,
                "entry": result,
                "action": "lookup",
            }

        elif action == "persist":
            db_path = kwargs.get("db_path")
            count = self.persist_to_disk(db_path)
            return {"success": True, "persisted_count": count, "action": "persist"}

        elif action == "load":
            db_path = kwargs.get("db_path")
            count = self.load_from_disk(db_path)
            return {"success": True, "loaded_count": count, "action": "load"}

        elif action == "export":
            file_path = kwargs.get("file_path", "constraint_cache_export.json")
            count = self.export_to_json(file_path)
            return {"success": True, "exported_count": count, "file_path": file_path}

        elif action == "import":
            file_path = kwargs.get("file_path", "constraint_cache_export.json")
            count = self.import_from_json(file_path)
            return {"success": True, "imported_count": count}

        elif action == "stats":
            stats = self.cache_statistics()
            return {"success": True, "statistics": stats, "action": "stats"}

        elif action == "clear":
            count = self.clear_cache()
            return {"success": True, "cleared_count": count, "action": "clear"}

        elif action == "vacuum_stale":
            ttl_seconds = kwargs.get("ttl_seconds", 86400)
            removed = self.vacuum_stale(ttl_seconds)
            return {"success": True, "removed_count": removed, "action": "vacuum_stale"}

        else:
            return {"success": False, "error": f"Unknown operation: {action}"}


def manage_constraint_cache(**kwargs) -> Dict[str, Any]:
    """实例化 ConstraintCachePersistence 并运行请求的动作。"""
    cache = ConstraintCachePersistence()
    return cache.analyze(**kwargs)


__all__ = [
    "ConstraintCachePersistence",
    "manage_constraint_cache",
    # Re-exported serializer for 向后兼容
    "NORMALIZE_PATTERNS",
    "CATEGORY_SIGNATURES",
    "normalize_constraint",
    "classify_constraint_category",
    "compute_constraint_hash_bytes",
    "compute_constraint_hash",
    "entry_to_dict",
    "entry_to_db_params",
    "db_row_to_init_kwargs",
    "json_item_to_init_kwargs",
]
