# 基准测试结果缓存 — SQLite持久化, 支持历史对比和趋势追踪
# 设计: 按模块/函数/版本查询和统计

from __future__ import annotations
import os
import json
import time
import math
import sqlite3
import hashlib
import threading
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from contextlib import contextmanager

logger = logging.getLogger(__name__)


# 数据模型

@dataclass
class BenchmarkEntry:
    id: Optional[int] = None
    module: str = ''
    function: str = ''
    version_hash: str = ''        # 代码版本标识
    input_size: int = 0           # 输入规模 (样本数/字节数等)
    iterations: int = 10
    mean_us: float = 0.0
    median_us: float = 0.0
    std_us: float = 0.0
    p95_us: float = 0.0
    p99_us: float = 0.0
    ops_per_sec: float = 0.0
    memory_kb: float = 0.0       # 内存占用 (估算)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

    def to_dict(self) -> dict:
        return {
            'module': self.module, 'function': self.function,
            'version': self.version_hash[:8], 'input_size': self.input_size,
            'mean_us': self.mean_us, 'p95_us': self.p95_us,
            'ops_per_sec': self.ops_per_sec, 'timestamp': self.timestamp,
        }


class BenchmarkCache:
    # SQLite后端, Schema见_init_db

    # 默认缓存路径
    DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), '.benchmark_cache.db')

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or self.DEFAULT_DB_PATH
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS benchmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module TEXT NOT NULL,
                function TEXT NOT NULL,
                version_hash TEXT NOT NULL DEFAULT '',
                input_size INTEGER NOT NULL DEFAULT 0,
                iterations INTEGER NOT NULL DEFAULT 10,
                mean_us REAL NOT NULL DEFAULT 0.0,
                median_us REAL NOT NULL DEFAULT 0.0,
                std_us REAL NOT NULL DEFAULT 0.0,
                p95_us REAL NOT NULL DEFAULT 0.0,
                p99_us REAL NOT NULL DEFAULT 0.0,
                ops_per_sec REAL NOT NULL DEFAULT 0.0,
                memory_kb REAL NOT NULL DEFAULT 0.0,
                metadata TEXT NOT NULL DEFAULT '{}',
                timestamp REAL NOT NULL DEFAULT 0.0
            )''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_module_func ON benchmarks(module, function)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_version ON benchmarks(version_hash)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON benchmarks(timestamp)')
            conn.commit()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

# CRUD

    def insert(self, entry: BenchmarkEntry) -> int:
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    '''INSERT INTO benchmarks
                    (module, function, version_hash, input_size, iterations,
                     mean_us, median_us, std_us, p95_us, p99_us, ops_per_sec,
                     memory_kb, metadata, timestamp)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (entry.module, entry.function, entry.version_hash,
                     entry.input_size, entry.iterations,
                     entry.mean_us, entry.median_us, entry.std_us,
                     entry.p95_us, entry.p99_us, entry.ops_per_sec,
                     entry.memory_kb, json.dumps(entry.metadata),
                     entry.timestamp or time.time())
                )
                conn.commit()
                return cur.lastrowid

    def insert_batch(self, entries: List[BenchmarkEntry]) -> List[int]:
        ids = []
        with self._lock:
            with self._get_conn() as conn:
                for entry in entries:
                    cur = conn.execute(
                        '''INSERT INTO benchmarks
                        (module, function, version_hash, input_size, iterations,
                         mean_us, median_us, std_us, p95_us, p99_us, ops_per_sec,
                         memory_kb, metadata, timestamp)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                        (entry.module, entry.function, entry.version_hash,
                         entry.input_size, entry.iterations,
                         entry.mean_us, entry.median_us, entry.std_us,
                         entry.p95_us, entry.p99_us, entry.ops_per_sec,
                         entry.memory_kb, json.dumps(entry.metadata),
                         entry.timestamp or time.time())
                    )
                    ids.append(cur.lastrowid)
                conn.commit()
        return ids

    def query(self, module: Optional[str] = None,
              function: Optional[str] = None,
              version_hash: Optional[str] = None,
              since: Optional[float] = None,
              limit: int = 100) -> List[BenchmarkEntry]:
        conditions = []
        params = []

        if module:
            conditions.append('module = ?')
            params.append(module)
        if function:
            conditions.append('function = ?')
            params.append(function)
        if version_hash:
            conditions.append('version_hash = ?')
            params.append(version_hash)
        if since:
            conditions.append('timestamp >= ?')
            params.append(since)

        where = ' AND '.join(conditions) if conditions else '1=1'
        query_str = f'SELECT * FROM benchmarks WHERE {where} ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)

        with self._get_conn() as conn:
            rows = conn.execute(query_str, params).fetchall()

        return [self._row_to_entry(r) for r in rows]

    def get_latest(self, module: str, function: str,
                   version_hash: Optional[str] = None) -> Optional[BenchmarkEntry]:
        if version_hash:
            rows = self.query(module=module, function=function,
                             version_hash=version_hash, limit=1)
        else:
            rows = self.query(module=module, function=function, limit=1)
        return rows[0] if rows else None

    def compare_versions(self, module: str, function: str,
                         version_a: str, version_b: str) -> Dict[str, Any]:
        entries_a = self.query(module=module, function=function,
                               version_hash=version_a, limit=5)
        entries_b = self.query(module=module, function=function,
                               version_hash=version_b, limit=5)

        if not entries_a or not entries_b:
            return {'error': 'missing data', 'version_a_count': len(entries_a),
                    'version_b_count': len(entries_b)}

        # 取各自最新
        a = entries_a[0]
        b = entries_b[0]

        speedup = a.mean_us / max(b.mean_us, 1e-6)
        mem_delta = b.memory_kb - a.memory_kb if a.memory_kb and b.memory_kb else 0.0

        trend = 'improved' if speedup > 1.05 else ('degraded' if speedup < 0.95 else 'unchanged')

        return {
            'module': module, 'function': function,
            'version_a': version_a[:8], 'version_b': version_b[:8],
            'mean_us_a': a.mean_us, 'mean_us_b': b.mean_us,
            'speedup': speedup,
            'ops_a': a.ops_per_sec, 'ops_b': b.ops_per_sec,
            'memory_delta_kb': mem_delta,
            'trend': trend,
        }

    def get_trend(self, module: str, function: str,
                  days: int = 30) -> List[Dict[str, Any]]:
        since = time.time() - days * 86400
        entries = self.query(module=module, function=function, since=since, limit=1000)

        if not entries:
            return []

        # 按天分组
        daily: Dict[str, List[float]] = defaultdict(list)
        for e in entries:
            day = time.strftime('%Y-%m-%d', time.localtime(e.timestamp))
            daily[day].append(e.mean_us)

        trend = []
        for day in sorted(daily):
            vals = daily[day]
            trend.append({
                'date': day,
                'n': len(vals),
                'mean_us': sum(vals) / len(vals),
                'min_us': min(vals),
                'max_us': max(vals),
            })

        return trend

    def get_stats(self, module: Optional[str] = None) -> Dict[str, Any]:
        with self._get_conn() as conn:
            if module:
                row = conn.execute(
                    'SELECT COUNT(*) as n, MIN(timestamp) as earliest, MAX(timestamp) as latest FROM benchmarks WHERE module = ?',
                    (module,)).fetchone()
            else:
                row = conn.execute(
                    'SELECT COUNT(*) as n, MIN(timestamp) as earliest, MAX(timestamp) as latest FROM benchmarks').fetchone()

            modules = conn.execute(
                'SELECT DISTINCT module FROM benchmarks').fetchall()

        return {
            'total_entries': row['n'],
            'earliest': row['earliest'],
            'latest': row['latest'],
            'modules': [m['module'] for m in modules],
            'db_size_kb': os.path.getsize(self._db_path) / 1024 if os.path.exists(self._db_path) else 0,
        }

    def cleanup(self, older_than_days: int = 90):
        cutoff = time.time() - older_than_days * 86400
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute('DELETE FROM benchmarks WHERE timestamp < ?', (cutoff,))
                conn.commit()
                deleted = cur.rowcount
        logger.info(f'Cleaned {deleted} old benchmark entries')
        return deleted

    def _row_to_entry(self, row) -> BenchmarkEntry:
        return BenchmarkEntry(
            id=row['id'], module=row['module'], function=row['function'],
            version_hash=row['version_hash'], input_size=row['input_size'],
            iterations=row['iterations'],
            mean_us=row['mean_us'], median_us=row['median_us'],
            std_us=row['std_us'], p95_us=row['p95_us'], p99_us=row['p99_us'],
            ops_per_sec=row['ops_per_sec'], memory_kb=row['memory_kb'],
            metadata=json.loads(row['metadata']) if row['metadata'] else {},
            timestamp=row['timestamp'],
        )


# 性能计时器

class BenchmarkTimer:
    # 带缓存记录的微基准计时器

    def __init__(self, module: str, cache: Optional[BenchmarkCache] = None,
                 version_hash: Optional[str] = None):
        self.module = module
        self.cache = cache or BenchmarkCache()
        self.version = version_hash or 'unknown'

    def measure(self, func_name: str, func: Callable, *args,
                iterations: int = 10, warmup: int = 3,
                input_size: int = 0, **kwargs) -> BenchmarkEntry:

        # 预热
        for _ in range(warmup):
            func(*args, **kwargs)

        # 测量
        times = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            func(*args, **kwargs)
            t1 = time.perf_counter_ns()
            times.append((t1 - t0) / 1000.0)  # ns -> us

        times.sort()
        n = len(times)
        mean = sum(times) / n
        std = math.sqrt(sum((t - mean) ** 2 for t in times) / n)
        median = times[n // 2]
        p95_idx = int(n * 0.95)
        p99_idx = int(n * 0.99)
        p95 = times[min(p95_idx, n - 1)]
        p99 = times[min(p99_idx, n - 1)]
        ops = 1_000_000.0 / mean if mean > 0 else 0.0

        entry = BenchmarkEntry(
            module=self.module, function=func_name,
            version_hash=self.version, input_size=input_size,
            iterations=iterations, mean_us=mean, median_us=median,
            std_us=std, p95_us=p95, p99_us=p99, ops_per_sec=ops,
        )

        self.cache.insert(entry)
        return entry

    def compare_with_baseline(self, func_name: str, func: Callable, *args,
                              **kwargs) -> Dict[str, Any]:
        current = self.measure(func_name, func, *args, **kwargs)
        baseline = self.cache.get_latest(self.module, func_name)

        result = {'current': current.to_dict()}
        if baseline and baseline.id != current.id:
            speedup = baseline.mean_us / max(current.mean_us, 1e-6)
            result['baseline'] = baseline.to_dict()
            result['speedup'] = speedup
            if speedup > 1.10:
                result['verdict'] = 'faster'
            elif speedup < 0.90:
                result['verdict'] = 'slower'
            else:
                result['verdict'] = 'similar'
        else:
            result['baseline'] = None
            result['verdict'] = 'first_run'

        return result


# 工厂

_global_cache: Optional[BenchmarkCache] = None


def get_benchmark_cache() -> BenchmarkCache:
    global _global_cache
    if _global_cache is None:
        _global_cache = BenchmarkCache()
    return _global_cache


def create_benchmark_timer(module: str) -> BenchmarkTimer:
    return BenchmarkTimer(module, cache=get_benchmark_cache())
