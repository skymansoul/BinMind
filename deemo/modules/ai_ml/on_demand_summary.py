#!/usr/bin/env python3
# On-demand symbolic summary generator with caching and incremental updates.
# 2026-07-31: added SummaryCache with LRU eviction; SummaryIncrementalUpdater.
# 2026-08-01: added async request coalescing (避免重复生成 — 多调用者共享同一pending结果);
#             added cache serialization via export_cache/import_cache (持久化缓存 — 跨会话复用);
#             added adaptive TTL extension on cache hit (热点摘要自动延长生命周期).

import logging as _logging
import json as _json
import hashlib as _hashlib
import time as _time
import threading as _thr
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from collections import defaultdict as _defaultdict, OrderedDict as _OrderedDict
from pathlib import Path as _Path

__dbg = _logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SummaryLevel(Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    DETAILED = "detailed"
    EXHAUSTIVE = "exhaustive"


class SummaryType(Enum):
    FUNCTION = "function"
    BASIC_BLOCK = "basic_block"
    PATH = "path"
    VULNERABILITY = "vulnerability"
    MODULE = "module"
    BINARY = "binary"
    CUSTOM = "custom"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SymbolicSummary:
    """A cached symbolic execution summary."""
    summary_id: str = ""
    target_type: SummaryType = SummaryType.FUNCTION
    target_name: str = ""
    target_address: int = 0
    level: SummaryLevel = SummaryLevel.STANDARD
    content: str = ""
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)
    input_constraints: List[str] = field(default_factory=list)
    output_range: Dict[str, Any] = field(default_factory=dict)
    path_count: int = 0
    instruction_count: int = 0
    symbolic_variables: List[str] = field(default_factory=list)
    branch_dependencies: List[Dict[str, Any]] = field(default_factory=list)
    compute_time_ms: float = 0.0
    created_at: float = 0.0
    expires_at: float = 0.0
    ttl_seconds: int = 3600
    dependencies: List[str] = field(default_factory=list)
    checksum: str = ""
    # 访问计数 — 用于自适应TTL调节
    access_count: int = 0

    def __post_init__(self):
        if not self.summary_id:
            self.summary_id = _hashlib.sha256(
                f"{self.target_name}:{self.target_address}:{self.level.value}".encode()
            ).hexdigest()[:16]
        if self.created_at == 0.0:
            self.created_at = _time.time()
        if self.expires_at == 0.0:
            self.expires_at = self.created_at + self.ttl_seconds

    def is_expired(self) -> bool:
        return _time.time() > self.expires_at

    def remaining_ttl(self) -> float:
        return max(0.0, self.expires_at - _time.time())

    def content_hash(self) -> str:
        return _hashlib.sha256(self.content.encode('utf-8')).hexdigest()[:16]

    def touch(self, extension_seconds: int = 0):
        """记录一次访问并可选延长TTL — 热点数据活得更久."""
        self.access_count += 1
        if extension_seconds > 0:
            self.expires_at = max(self.expires_at, _time.time() + extension_seconds)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为普通字典 (不含内部状态)."""
        return {
            "summary_id": self.summary_id,
            "target_type": self.target_type.value,
            "target_name": self.target_name,
            "target_address": self.target_address,
            "level": self.level.value,
            "content": self.content,
            "preconditions": self.preconditions,
            "postconditions": self.postconditions,
            "side_effects": self.side_effects,
            "input_constraints": self.input_constraints,
            "output_range": self.output_range,
            "path_count": self.path_count,
            "instruction_count": self.instruction_count,
            "symbolic_variables": self.symbolic_variables,
            "branch_dependencies": self.branch_dependencies,
            "compute_time_ms": self.compute_time_ms,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "ttl_seconds": self.ttl_seconds,
            "dependencies": self.dependencies,
            "checksum": self.checksum,
            "access_count": self.access_count,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SymbolicSummary":
        """从字典反序列化 — 导入缓存时使用."""
        return cls(
            summary_id=d.get("summary_id", ""),
            target_type=SummaryType(d.get("target_type", "function")),
            target_name=d.get("target_name", ""),
            target_address=d.get("target_address", 0),
            level=SummaryLevel(d.get("level", "standard")),
            content=d.get("content", ""),
            preconditions=d.get("preconditions", []),
            postconditions=d.get("postconditions", []),
            side_effects=d.get("side_effects", []),
            input_constraints=d.get("input_constraints", []),
            output_range=d.get("output_range", {}),
            path_count=d.get("path_count", 0),
            instruction_count=d.get("instruction_count", 0),
            symbolic_variables=d.get("symbolic_variables", []),
            branch_dependencies=d.get("branch_dependencies", []),
            compute_time_ms=d.get("compute_time_ms", 0.0),
            created_at=d.get("created_at", 0.0),
            expires_at=d.get("expires_at", 0.0),
            ttl_seconds=d.get("ttl_seconds", 3600),
            dependencies=d.get("dependencies", []),
            checksum=d.get("checksum", ""),
            access_count=d.get("access_count", 0),
        )


@dataclass
class RequestContext:
    """Context for a summary generation request."""
    target_name: str = ""
    target_address: int = 0
    target_type: SummaryType = SummaryType.FUNCTION
    level: SummaryLevel = SummaryLevel.STANDARD
    include_preconditions: bool = True
    include_postconditions: bool = True
    include_side_effects: bool = False
    max_paths: int = 100
    timeout_ms: int = 5000
    force_refresh: bool = False
    extra_params: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Summary Cache (LRU)
# ---------------------------------------------------------------------------

class SummaryCache:
    """LRU cache for symbolic summaries with TTL-based expiration.

    新增：自适应TTL延长 — 频繁访问的条目自动续期，减少热数据再生开销.
    """

    __slots__ = ('m_cache', 'm_max_size', 'm_hits', 'm_misses',
                 'm_evictions', 'm_lock', 'm_adaptive_ttl_ratio')

    def __init__(self, max_size: int = 1000, adaptive_ttl_ratio: float = 0.5):
        self.m_cache: _OrderedDict[str, SymbolicSummary] = _OrderedDict()
        self.m_max_size = max_size
        self.m_hits = 0
        self.m_misses = 0
        self.m_evictions = 0
        self.m_lock = _thr.Lock()
        # 自适应TTL比例: 每次命中时延长 original_ttl * ratio 秒
        self.m_adaptive_ttl_ratio = adaptive_ttl_ratio

    def get(self, key: str) -> Optional[SymbolicSummary]:
        with self.m_lock:
            if key not in self.m_cache:
                self.m_misses += 1
                return None

            summary = self.m_cache[key]
            if summary.is_expired():
                del self.m_cache[key]
                self.m_evictions += 1
                self.m_misses += 1
                return None

            # Move to end (most recently used)
            self.m_cache.move_to_end(key)
            # 自适应TTL: 热点条目自动续期 (但不是无限延长 — 仅延长一个比例)
            extension = int(summary.ttl_seconds * self.m_adaptive_ttl_ratio)
            summary.touch(extension_seconds=extension)
            self.m_hits += 1
            return summary

    def put(self, key: str, summary: SymbolicSummary):
        with self.m_lock:
            if key in self.m_cache:
                self.m_cache.move_to_end(key)
            else:
                while len(self.m_cache) >= self.m_max_size:
                    self.m_cache.popitem(last=False)
                    self.m_evictions += 1

            self.m_cache[key] = summary

    def invalidate(self, key: str):
        with self.m_lock:
            if key in self.m_cache:
                del self.m_cache[key]

    def invalidate_by_target(self, target_name: str):
        with self.m_lock:
            to_remove = [k for k, v in self.m_cache.items() if v.target_name == target_name]
            for k in to_remove:
                del self.m_cache[k]

    def clear(self):
        with self.m_lock:
            self.m_cache.clear()

    def size(self) -> int:
        with self.m_lock:
            return len(self.m_cache)

    def stats(self) -> Dict[str, Any]:
        with self.m_lock:
            total = self.m_hits + self.m_misses
            return {
                "size": len(self.m_cache),
                "max_size": self.m_max_size,
                "hits": self.m_hits,
                "misses": self.m_misses,
                "hit_rate": self.m_hits / max(total, 1),
                "evictions": self.m_evictions,
            }

    def get_all_valid(self) -> List[Tuple[str, SymbolicSummary]]:
        """返回所有未过期的缓存条目 (用于导出)."""
        with self.m_lock:
            valid = []
            for k, v in self.m_cache.items():
                if not v.is_expired():
                    valid.append((k, v))
            return valid


# ---------------------------------------------------------------------------
# 异步请求合并 — 避免同一key的并发重复生成
# ---------------------------------------------------------------------------

class _PendingCoalesced:
    """一个pending槽位: 记录所有等待同一key的callback + 最终结果."""

    __slots__ = ('callbacks', 'result', 'condition', 'completed')

    def __init__(self):
        self.callbacks: List[Callable[[Optional[SymbolicSummary]], None]] = []
        self.result: Optional[SymbolicSummary] = None
        self.condition = _thr.Condition()
        self.completed = False

    def add_callback(self, cb: Callable[[Optional[SymbolicSummary]], None]):
        self.callbacks.append(cb)

    def resolve(self, summary: Optional[SymbolicSummary]):
        """所有等待者统一唤醒 — 一次生成，多方受益."""
        with self.condition:
            self.result = summary
            self.completed = True
            self.condition.notify_all()
        for cb in self.callbacks:
            try:
                cb(summary)
            except Exception as exc:
                __dbg.warning("Pending callback raised: %s", exc)


# ---------------------------------------------------------------------------
# Symbolic Executor Proxy
# ---------------------------------------------------------------------------

class SymbolicExecutorProxy:
    """Abstract proxy for a symbolic execution engine (e.g., angr, KLEE)."""

    def generate_summary(self, ctx: RequestContext) -> Optional[SymbolicSummary]:
        raise NotImplementedError

    def is_available(self) -> bool:
        raise NotImplementedError


class MockSymbolicExecutor(SymbolicExecutorProxy):
    """Mock symbolic executor for testing/demo purposes."""

    __slots__ = ('m_delay_factor',)

    def __init__(self, delay_factor: float = 0.0):
        self.m_delay_factor = delay_factor

    def generate_summary(self, ctx: RequestContext) -> Optional[SymbolicSummary]:
        import random as _rnd

        if self.m_delay_factor > 0:
            _time.sleep(self.m_delay_factor * _rnd.uniform(0.5, 1.5))

        summary = SymbolicSummary(
            target_type=ctx.target_type,
            target_name=ctx.target_name,
            target_address=ctx.target_address,
            level=ctx.level,
        )

        # Generate mock content
        if ctx.target_type == SummaryType.FUNCTION:
            summary.content = self._generate_function_summary(ctx)
        elif ctx.target_type == SummaryType.BASIC_BLOCK:
            summary.content = self._generate_block_summary(ctx)
        elif ctx.target_type == SummaryType.PATH:
            summary.content = self._generate_path_summary(ctx)
        else:
            summary.content = f"Summary for {ctx.target_name} @ {ctx.target_address:#x}"

        # Mock preconditions
        summary.preconditions = [
            f"arg0 is a valid pointer to {_rnd.randint(16, 256)}-byte buffer",
            f"arg1 >= 0 and arg1 <= {_rnd.randint(64, 1024)}",
        ]

        # Mock postconditions
        summary.postconditions = [
            "Returns 0 on success, -1 on failure",
            "errno set on failure",
        ]

        # Mock side effects
        if ctx.include_side_effects:
            summary.side_effects = [
                "Writes to memory pointed by arg0",
                "May allocate heap memory via malloc",
                "Sets errno on error path",
            ]

        summary.path_count = _rnd.randint(1, 50)
        summary.instruction_count = _rnd.randint(10, 500)
        summary.symbolic_variables = ["arg0", "arg1", "ret_val"]
        summary.compute_time_ms = _rnd.uniform(5, 200)
        summary.checksum = summary.content_hash()

        return summary

    def _generate_function_summary(self, ctx: RequestContext) -> str:
        name = ctx.target_name or "unknown"
        addr = ctx.target_address

        lines = [
            f"Function: {name} @ {addr:#010x}",
            f"Summary level: {ctx.level.value}",
            "",
            "Interface:",
            f"  int {name}(void *buf, size_t len);",
            "",
            "Behavior:",
            f"  Reads up to 'len' bytes from 'buf', processes them,",
            f"  and writes results back to 'buf'.",
            "",
        ]

        if ctx.level in (SummaryLevel.DETAILED, SummaryLevel.EXHAUSTIVE):
            lines.extend([
                "Symbolic constraints:",
                "  len <= 0x1000 (checked at entry)",
                "  buf alignment: 8-byte (SIGBUS guard)",
                "",
                "Memory access pattern:",
                "  [buf, buf+len) - read",
                "  [buf, buf+len) - write",
                "  [rbp-0x20] - stack scratch",
            ])

        if ctx.level == SummaryLevel.EXHAUSTIVE:
            lines.extend([
                "",
                "Path enumeration:",
                "  Path 1 (len==0): early return 0",
                "  Path 2 (len>0, no error): process + return 0",
                "  Path 3 (len>0, buf==NULL): return -EINVAL",
                "  Path 4 (len>0, allocation fail): return -ENOMEM",
            ])

        return "\n".join(lines)

    def _generate_block_summary(self, ctx: RequestContext) -> str:
        return (
            f"Basic Block @ {ctx.target_address:#010x}\n"
            f"  Instructions: mov, cmp, jne\n"
            f"  Live variables: rax, rdi, rsi\n"
            f"  Successors: 0x{ctx.target_address + 0x10:x}, 0x{ctx.target_address + 0x30:x}"
        )

    def _generate_path_summary(self, ctx: RequestContext) -> str:
        return (
            f"Path through {ctx.target_name}\n"
            f"  Block sequence: [0x401000, 0x401020, 0x401050, 0x401080]\n"
            f"  Path condition: (arg0 != NULL) AND (len < 0x100)\n"
            f"  Termination: normal return"
        )

    def is_available(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# On-Demand Summary Generator
# ---------------------------------------------------------------------------

class OnDemandSummaryGenerator:
    """Generates symbolic summaries on demand with caching and async options.

    2026-08-01 增强：
    - generate_async 内建请求合并: 同一pending key只跑一次symbolic执行，
      所有等待者共享结果 (避免N个调用者触发N次angr/KLEE运行).
    """

    __slots__ = ('m_executor', 'm_cache', 'm_pending', 'm_lock',
                 'm_stats', 'm_default_ttl', 'm_coalesce_map',
                 'm_coalesce_lock')

    def __init__(self, executor: Optional[SymbolicExecutorProxy] = None,
                 cache_size: int = 1000, default_ttl: int = 3600):
        self.m_executor = executor if executor is not None else MockSymbolicExecutor()
        self.m_cache = SummaryCache(max_size=cache_size)
        self.m_default_ttl = default_ttl
        self.m_pending: Dict[str, _thr.Thread] = {}
        self.m_lock = _thr.Lock()
        self.m_stats: Dict[str, int] = _defaultdict(int)
        # 合并请求: key -> _PendingCoalesced (多个调用者共享一次执行)
        self.m_coalesce_map: Dict[str, _PendingCoalesced] = {}
        self.m_coalesce_lock = _thr.Lock()

    def _cache_key(self, ctx: RequestContext) -> str:
        raw = f"{ctx.target_type.value}:{ctx.target_name}:{ctx.target_address}:{ctx.level.value}"
        return _hashlib.sha256(raw.encode()).hexdigest()[:16]

    def generate(self, ctx: RequestContext) -> Optional[SymbolicSummary]:
        """Generate or retrieve from cache a symbolic summary."""
        cache_key = self._cache_key(ctx)

        # Check cache
        if not ctx.force_refresh:
            cached = self.m_cache.get(cache_key)
            if cached is not None:
                self.m_stats["cache_hits"] += 1
                return cached

        self.m_stats["cache_misses"] += 1

        # Generate fresh summary
        try:
            summary = self.m_executor.generate_summary(ctx)
            if summary:
                summary.ttl_seconds = self.m_default_ttl
                summary.created_at = _time.time()
                summary.expires_at = summary.created_at + self.m_default_ttl
                summary.checksum = summary.content_hash()
                self.m_cache.put(cache_key, summary)
                self.m_stats["generated"] += 1
            else:
                self.m_stats["failed"] += 1
            return summary
        except Exception as e:
            __dbg.error("Summary generation failed: %s", e)
            self.m_stats["errors"] += 1
            return None

    def generate_async(self, ctx: RequestContext,
                       callback: Optional[Callable[[SymbolicSummary], None]] = None):
        """Generate a summary asynchronously in a background thread.

        关键优化: 如果同一cache_key已有一个pending生成任务，不启动新线程，
        而是将callback挂到已有任务的回调链上 — 等它完成后统一通知.
        """
        cache_key = self._cache_key(ctx)

        # Check cache first (synchronous is fine — cache access is fast)
        if not ctx.force_refresh:
            cached = self.m_cache.get(cache_key)
            if cached is not None:
                self.m_stats["cache_hits"] += 1
                if callback:
                    callback(cached)
                return

        # --- 合并检查: 是否有正在进行中的同key请求? ---
        with self.m_coalesce_lock:
            existing = self.m_coalesce_map.get(cache_key)
            if existing is not None:
                # 已经有人在跑了 — 只挂callback，不启新线程
                if callback:
                    existing.add_callback(callback)
                self.m_stats.setdefault("coalesced", 0)
                self.m_stats["coalesced"] += 1
                return
            # 新建合并槽位 — 我们是第一个请求者
            coalesced = _PendingCoalesced()
            if callback:
                coalesced.add_callback(callback)
            self.m_coalesce_map[cache_key] = coalesced

        def _worker():
            try:
                summary = self.m_executor.generate_summary(ctx)
                if summary:
                    summary.ttl_seconds = self.m_default_ttl
                    summary.created_at = _time.time()
                    summary.expires_at = summary.created_at + self.m_default_ttl
                    summary.checksum = summary.content_hash()
                    self.m_cache.put(cache_key, summary)
                    self.m_stats["generated"] += 1
                else:
                    self.m_stats["failed"] += 1
                # 唤醒所有等待者
                coalesced.resolve(summary)
            except Exception as e:
                __dbg.error("Async summary generation failed: %s", e)
                self.m_stats["errors"] += 1
                coalesced.resolve(None)
            finally:
                with self.m_lock:
                    self.m_pending.pop(cache_key, None)
                with self.m_coalesce_lock:
                    self.m_coalesce_map.pop(cache_key, None)

        thread = _thr.Thread(target=_worker, daemon=True)
        with self.m_lock:
            self.m_pending[cache_key] = thread
        thread.start()

    def get_summary(self, target_name: str, target_address: int = 0,
                    target_type: SummaryType = SummaryType.FUNCTION,
                    level: SummaryLevel = SummaryLevel.STANDARD,
                    force_refresh: bool = False) -> Optional[SymbolicSummary]:
        """Convenience method with individual parameters."""
        ctx = RequestContext(
            target_name=target_name,
            target_address=target_address,
            target_type=target_type,
            level=level,
            force_refresh=force_refresh,
        )
        return self.generate(ctx)

    def batch_generate(self, contexts: List[RequestContext]) -> List[Optional[SymbolicSummary]]:
        results: List[Optional[SymbolicSummary]] = []
        ci = 0
        while ci < len(contexts):
            results.append(self.generate(contexts[ci]))
            ci += 1
        return results

    def invalidate(self, target_name: str):
        self.m_cache.invalidate_by_target(target_name)
        self.m_stats["invalidations"] += 1

    def get_stats(self) -> Dict[str, Any]:
        stats = dict(self.m_stats)
        stats.update(self.m_cache.stats())
        stats["pending"] = len(self.m_pending)
        stats["coalescing"] = len(self.m_coalesce_map)
        return stats

    def is_pending(self, ctx: RequestContext) -> bool:
        cache_key = self._cache_key(ctx)
        with self.m_lock:
            return cache_key in self.m_pending

    def clear(self):
        self.m_cache.clear()
        with self.m_lock:
            self.m_pending.clear()
        self.m_stats.clear()
        with self.m_coalesce_lock:
            self.m_coalesce_map.clear()

    # -----------------------------------------------------------------------
    # 缓存序列化 — 导出/导入，支持跨会话复用
    # -----------------------------------------------------------------------

    def export_cache(self, file_path: str) -> int:
        """将当前缓存导出为JSON文件 — 持久化热点摘要，下次启动时可import_cache恢复."""
        entries = self.m_cache.get_all_valid()
        data: Dict[str, Dict[str, Any]] = {}
        for key, summary in entries:
            data[key] = summary.to_dict()

        payload = {
            "version": 1,
            "exported_at": _time.time(),
            "default_ttl": self.m_default_ttl,
            "entry_count": len(data),
            "entries": data,
        }

        out = _Path(file_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as fh:
            _json.dump(payload, fh, ensure_ascii=False, indent=2)
        __dbg.info("Exported %d cache entries to %s", len(data), file_path)
        return len(data)

    def import_cache(self, file_path: str, skip_expired: bool = True) -> int:
        """从JSON文件导入缓存 — 恢复之前持久化的摘要.

        skip_expired=True 时只导入尚未过期的条目 (基于expires_at字段).
        """
        src = _Path(file_path)
        if not src.is_file():
            __dbg.warning("Cache import file not found: %s", file_path)
            return 0

        with open(file_path, 'r', encoding='utf-8') as fh:
            payload = _json.load(fh)

        entries = payload.get("entries", {})
        imported = 0
        now = _time.time()
        ci = 0
        keys = list(entries.keys())
        while ci < len(keys):
            key = keys[ci]
            try:
                summary = SymbolicSummary.from_dict(entries[key])
                if skip_expired and summary.is_expired():
                    ci += 1
                    continue
                # 过期的条目给它一次被动续命 (从导入时间算起30分钟宽限期)
                if summary.is_expired():
                    summary.expires_at = now + min(summary.ttl_seconds, 1800)
                self.m_cache.put(key, summary)
                imported += 1
            except Exception as exc:
                __dbg.warning("Failed to import entry %s: %s", key, exc)
            ci += 1

        __dbg.info("Imported %d/%d cache entries from %s", imported, len(entries), file_path)
        return imported


# ---------------------------------------------------------------------------
# Summary Incremental Updater
# ---------------------------------------------------------------------------

class SummaryIncrementalUpdater:
    """Incrementally updates cached summaries when code changes.

    Tracks dependencies and invalidates summaries that are affected
    by code modifications.
    """

    __slots__ = ('m_dep_graph', 'm_generator', 'm_change_log')

    def __init__(self, generator: OnDemandSummaryGenerator):
        self.m_generator = generator
        self.m_dep_graph: Dict[str, Set[str]] = _defaultdict(set)
        self.m_change_log: List[Dict[str, Any]] = []

    def register_dependency(self, target_name: str, depends_on: str):
        self.m_dep_graph[target_name].add(depends_on)

    def register_dependencies(self, target_name: str, depends_on: List[str]):
        di = 0
        while di < len(depends_on):
            self.register_dependency(target_name, depends_on[di])
            di += 1

    def on_code_change(self, changed_target: str,
                       change_type: str = "modified",
                       change_details: str = ""):
        """Handle a code change by invalidating affected summaries."""
        self.m_change_log.append({
            "timestamp": _time.time(),
            "target": changed_target,
            "type": change_type,
            "details": change_details,
        })

        # Invalidate the changed target
        self.m_generator.invalidate(changed_target)

        # Find and invalidate dependents
        affected: Set[str] = {changed_target}
        queue = [changed_target]

        while queue:
            current = queue.pop(0)
            for dep in self.m_dep_graph.get(current, set()):
                if dep not in affected:
                    affected.add(dep)
                    queue.append(dep)
                    self.m_generator.invalidate(dep)

        __dbg.info("Code change '%s': invalidated %d cached summaries",
                    changed_target, len(affected))

        return list(affected)

    def get_dependents(self, target_name: str) -> List[str]:
        return list(self.m_dep_graph.get(target_name, set()))

    def get_dependencies(self, target_name: str) -> List[str]:
        deps: List[str] = []
        for src, targets in self.m_dep_graph.items():
            if target_name in targets:
                deps.append(src)
        return deps

    def get_change_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.m_change_log[-limit:]


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def generate_summary(target_name: str, target_address: int = 0,
                     target_type: SummaryType = SummaryType.FUNCTION,
                     level: SummaryLevel = SummaryLevel.STANDARD,
                     executor: Optional[SymbolicExecutorProxy] = None) -> Optional[SymbolicSummary]:
    gen = OnDemandSummaryGenerator(executor=executor)
    ctx = RequestContext(
        target_name=target_name,
        target_address=target_address,
        target_type=target_type,
        level=level,
    )
    return gen.generate(ctx)
