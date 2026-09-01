"""Constraint-solving result cache with LRU eviction and SQLite persistence.

Constraint solving dominates symbolic execution cost. This module caches
solutions keyed by SHA-256 of a normalized constraint form, serving hits
from memory (LRU dict) and promoting disk entries on access. Normalization
canonicalizes SMT-LIB operators so semantically identical constraints
share a cache key.
"""

import logging
import os
import json
import time
import hashlib
import sqlite3
import threading
from dataclasses import dataclass, field
from collections import OrderedDict
from datetime import datetime

import typing
from typing import Optional, Dict, Any
logger = logging.getLogger(__name__)


DEFAULT_MAX_CACHE_ENTRIES = 1000


@dataclass
class CachedConstraint:
    """One entry: original constraint, normalized form, solution, and stats."""
    constraint_hash: str
    original_constraint: str
    normalized_constraint: str
    solution: Any
    solver_name: str = "unknown"
    solve_time_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)
    hit_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for JSON export."""
        return {
            "constraint_hash": self.constraint_hash,
            "original_constraint": self.original_constraint,
            "normalized_constraint": self.normalized_constraint,
            "solution": str(self.solution) if self.solution is not None else None,
            "solver_name": self.solver_name,
            "solve_time_ms": self.solve_time_ms,
            "timestamp": self.timestamp,
            "hit_count": self.hit_count,
        }


@dataclass
class CacheStatistics:
    """Running counters for cache performance monitoring."""
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
        """Fraction of queries served from cache."""
        total = self.hit_count + self.miss_count
        if total == 0:
            return 0.0
        return self.hit_count / total


class ConstraintCachePersistence:
    """Two-tier constraint cache: memory LRU + SQLite disk store.

    Normalization rewrites SMT-LIB operators to a canonical form before
    hashing, so '(bvadd x y)' and '(bvadd  x  y)' share a key."""

    # SMT-LIB operator to canonical-symbol lookup for normalization
    NORMALIZE_PATTERNS = [
        ("bvadd", "+"),
        ("bvmul", "*"),
        ("bvsub", "-"),
        ("bvsdiv", "/"),
        ("bvand", "&"),
        ("bvor", "|"),
        ("bvxor", "^"),
        ("bvshl", "<<"),
        ("bvlshr", ">>"),
        ("bvult", "<"),
        ("bvule", "<="),
        ("bvugt", ">"),
        ("bvuge", ">="),
    ]

    def __init__(self):
        self._cache: OrderedDict[str, CachedConstraint] = OrderedDict()
        self._lock = threading.Lock()
        self._stats = CacheStatistics()
        self._db_path: typing.Optional[str] = None
        self._db_connection: typing.Optional[sqlite3.Connection] = None
        self._config: dict[str, Any] = {"max_cache_entries": DEFAULT_MAX_CACHE_ENTRIES}

    def _get_default_db_path(self) -> str:
        """Default SQLite path under ~/.binary_analysis_cache."""
        home = os.path.expanduser("~")
        cache_dir = os.path.join(home, ".binary_analysis_cache")
        os.makedirs(cache_dir, exist_ok=True)
        return os.path.join(cache_dir, "constraint_cache.db")

    def _init_database(self, db_path: typing.Optional[str] = None) -> None:
        """Create SQLite schema if absent."""
        self._db_path = db_path or self._get_default_db_path()
        try:
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
                    hit_count INTEGER DEFAULT 0
                )"""
            )
            self._db_connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_timestamp ON constraint_cache(timestamp)"
            )
            self._db_connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_solver ON constraint_cache(solver_name)"
            )
            self._db_connection.commit()
            logger.info(f"Constraint cache database initialized: {self._db_path}")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            self._db_connection = None

    def serialize_constraint(self, constraint: str) -> str:
        """Canonicalize a constraint string for consistent hashing.

        Steps: collapse whitespace, lowercase, normalize SMT-LIB operators,
        clean parenthesis spacing."""
        normalized = " ".join(constraint.split())
        normalized = normalized.lower()

        for old, new in self.NORMALIZE_PATTERNS:
            normalized = normalized.replace(f"({old} ", f"({new} ")

        while "  " in normalized:
            normalized = normalized.replace("  ", " ")
        normalized = normalized.replace("( ", "(")
        normalized = normalized.replace(" )", ")")

        return normalized

    def _compute_hash(self, normalized_constraint: str) -> str:
        """SHA-256 over the normalized form."""
        return hashlib.sha256(normalized_constraint.encode("utf-8")).hexdigest()

    def cache_constraint(
        self,
        constraint: str,
        solution: Any,
        solver_name: str = "unknown",
        solve_time_ms: float = 0.0,
    ) -> str:
        """Store a constraint→solution mapping. Returns the hash key.

        If the constraint is already cached, its LRU position refreshes
        and the hit count increments."""
        normalized = self.serialize_constraint(constraint)
        constraint_hash = self._compute_hash(normalized)

        with self._lock:
            if constraint_hash in self._cache:
                self._cache.move_to_end(constraint_hash)
                existing = self._cache[constraint_hash]
                existing.hit_count += 1
                existing.timestamp = time.time()
                logger.debug(f"Constraint already in cache: {constraint_hash[:16]}...")
                return constraint_hash

            self._stats.max_entries = self._config.get("max_cache_entries", DEFAULT_MAX_CACHE_ENTRIES)
            while len(self._cache) >= self._stats.max_entries:
                self.evict_lru(count=1)

            entry = CachedConstraint(
                constraint_hash=constraint_hash,
                original_constraint=constraint,
                normalized_constraint=normalized,
                solution=solution,
                solver_name=solver_name,
                solve_time_ms=solve_time_ms,
            )
            self._cache[constraint_hash] = entry
            self._stats.total_entries = len(self._cache)
            logger.debug(f"Constraint cached: {constraint_hash[:16]}... solver={solver_name}")

        return constraint_hash

    def lookup_constraint(self, constraint: str) -> typing.Optional[Dict[str, Any]]:
        """Query memory first, then disk. Returns entry dict or None."""
        normalized = self.serialize_constraint(constraint)
        constraint_hash = self._compute_hash(normalized)

        with self._lock:
            self._stats.total_queries += 1

            if constraint_hash in self._cache:
                self._cache.move_to_end(constraint_hash)
                entry = self._cache[constraint_hash]
                entry.hit_count += 1
                self._stats.hit_count += 1
                logger.debug(f"Cache hit: {constraint_hash[:16]}... (hit={entry.hit_count})")
                return entry.to_dict()

        disk_result = self._lookup_from_disk(constraint_hash)
        if disk_result is not None:
            self._stats.hit_count += 1
            return disk_result

        self._stats.miss_count += 1
        logger.debug(f"Cache miss: {constraint_hash[:16]}...")
        return None

    def _lookup_from_disk(self, constraint_hash: str) -> typing.Optional[Dict[str, Any]]:
        """Search SQLite; promote any hit to the memory cache."""
        if self._db_connection is None:
            return None
        try:
            cursor = self._db_connection.execute(
                "SELECT * FROM constraint_cache WHERE constraint_hash = ?",
                (constraint_hash,),
            )
            row = cursor.fetchone()
            if row:
                entry = CachedConstraint(
                    constraint_hash=row[0],
                    original_constraint=row[1],
                    normalized_constraint=row[2],
                    solution=row[3],
                    solver_name=row[4],
                    solve_time_ms=row[5],
                    timestamp=row[6],
                    hit_count=row[7] + 1,
                )
                with self._lock:
                    if constraint_hash not in self._cache:
                        self._cache[constraint_hash] = entry
                        limit = self._config.get("max_cache_entries", DEFAULT_MAX_CACHE_ENTRIES)
                        while len(self._cache) > limit:
                            self.evict_lru(count=1)
                return entry.to_dict()
            return None
        except Exception as e:
            logger.warning(f"Disk cache lookup failed: {e}")
            return None

    def evict_lru(self, count: int = 1) -> int:
        """Remove the least-recently-used entries from memory."""
        evicted = 0
        with self._lock:
            for _ in range(min(count, len(self._cache))):
                self._cache.popitem(last=False)
                evicted += 1
            self._stats.eviction_count += evicted
            self._stats.total_entries = len(self._cache)
        if evicted > 0:
            logger.debug(f"LRU evicted {evicted} cache entries")
        return evicted

    def persist_to_disk(self, db_path: typing.Optional[str] = None) -> int:
        """Flush the in-memory cache to SQLite."""
        if self._db_connection is None:
            self._init_database(db_path)

        if self._db_connection is None:
            logger.error("Database connection unavailable")
            return 0

        count = 0
        try:
            with self._lock:
                for entry in self._cache.values():
                    self._db_connection.execute(
                        """INSERT OR REPLACE INTO constraint_cache
                           (constraint_hash, original_constraint, normalized_constraint,
                            solution, solver_name, solve_time_ms, timestamp, hit_count)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            entry.constraint_hash,
                            entry.original_constraint,
                            entry.normalized_constraint,
                            str(entry.solution) if entry.solution is not None else None,
                            entry.solver_name,
                            entry.solve_time_ms,
                            entry.timestamp,
                            entry.hit_count,
                        ),
                    )
                    count += 1
            self._db_connection.commit()
            self._stats.persistent_entries = count
            logger.info(f"Persisted {count} constraint caches to disk")
        except Exception as e:
            logger.error(f"Persistence failed: {e}")

        return count

    def load_from_disk(self, db_path: typing.Optional[str] = None) -> int:
        """Load the most recent entries from SQLite into memory."""
        if self._db_connection is None:
            self._init_database(db_path)
        if self._db_connection is None:
            return 0

        count = 0
        limit = self._config.get("max_cache_entries", DEFAULT_MAX_CACHE_ENTRIES)
        try:
            cursor = self._db_connection.execute(
                "SELECT * FROM constraint_cache ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            with self._lock:
                for row in cursor:
                    if len(self._cache) >= limit:
                        break
                    entry = CachedConstraint(
                        constraint_hash=row[0],
                        original_constraint=row[1],
                        normalized_constraint=row[2],
                        solution=row[3],
                        solver_name=row[4],
                        solve_time_ms=row[5],
                        timestamp=row[6],
                        hit_count=row[7],
                    )
                    self._cache[entry.constraint_hash] = entry
                    count += 1
            self._stats.total_entries = len(self._cache)
            logger.info(f"Loaded {count} constraint caches from disk into memory")
        except Exception as e:
            logger.error(f"Disk cache load failed: {e}")

        return count

    def export_to_json(self, file_path: str) -> int:
        """Dump memory cache to a JSON file."""
        with self._lock:
            entries = [e.to_dict() for e in self._cache.values()]
        try:
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
        except Exception as e:
            logger.error(f"JSON export failed: {e}")
            return 0

    def import_from_json(self, file_path: str) -> int:
        """Populate memory cache from a previously exported JSON file."""
        if not os.path.exists(file_path):
            logger.warning(f"JSON file does not exist: {file_path}")
            return 0
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            entries = data.get("entries", [])
            count = 0
            with self._lock:
                for item in entries:
                    constraint_hash = item.get("constraint_hash", "")
                    if constraint_hash and constraint_hash not in self._cache:
                        entry = CachedConstraint(
                            constraint_hash=constraint_hash,
                            original_constraint=item.get("original_constraint", ""),
                            normalized_constraint=item.get("normalized_constraint", ""),
                            solution=item.get("solution"),
                            solver_name=item.get("solver_name", "unknown"),
                            solve_time_ms=item.get("solve_time_ms", 0.0),
                            timestamp=item.get("timestamp", time.time()),
                            hit_count=item.get("hit_count", 0),
                        )
                        self._cache[constraint_hash] = entry
                        count += 1
            self._stats.total_entries = len(self._cache)
            logger.info(f"Imported {count} constraint caches from JSON")
            return count
        except Exception as e:
            logger.error(f"JSON import failed: {e}")
            return 0

    def cache_statistics(self) -> Dict[str, Any]:
        """Return current cache performance metrics."""
        with self._lock:
            self._stats.total_entries = len(self._cache)
            self._stats.memory_usage_estimate = len(self._cache) * 2048
        return {
            "total_entries": self._stats.total_entries,
            "hit_rate": round(self._stats.hit_rate, 4),
            "hit_count": self._stats.hit_count,
            "miss_count": self._stats.miss_count,
            "eviction_count": self._stats.eviction_count,
            "total_queries": self._stats.total_queries,
            "memory_estimate_bytes": self._stats.memory_usage_estimate,
            "max_entries": self._stats.max_entries,
            "disk_entries": self._get_disk_entry_count(),
        }

    def _get_disk_entry_count(self) -> int:
        """Count rows in the SQLite table."""
        if self._db_connection is None:
            return 0
        try:
            cursor = self._db_connection.execute(
                "SELECT COUNT(*) FROM constraint_cache"
            )
            return cursor.fetchone()[0]
        except Exception:
            return 0

    def clear_cache(self) -> int:
        """Drop all in-memory entries. Returns count cleared."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._stats.total_entries = 0
            logger.info(f"Cleared {count} memory cache entries")
            return count

    def initialize(self, config: typing.Optional[Dict[str, Any]] = None) -> bool:
        """Apply config and optionally auto-load from disk."""
        if config:
            self._config.update(config)
        if config and config.get("auto_load_disk"):
            self.load_from_disk(config.get("db_path"))
        return True

    def cleanup(self) -> None:
        """Close the SQLite connection."""
        if self._db_connection:
            try:
                self._db_connection.close()
                logger.info("Database connection closed")
            except Exception as e:
                logger.warning(f"Failed to close database connection: {e}")
            self._db_connection = None

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """Dispatch cache operations by 'action' key."""
        action = kwargs.get("action", "cache")

        try:
            if action == "cache":
                constraint = kwargs.get("constraint", "")
                if not constraint:
                    return {"success": False, "error": "constraint parameter is required"}
                solution = kwargs.get("solution")
                solver = kwargs.get("solver_name", "unknown")
                solve_time = kwargs.get("solve_time_ms", 0.0)
                constraint_hash = self.cache_constraint(constraint, solution, solver, solve_time)
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

            else:
                return {"success": False, "error": f"Unknown operation: {action}"}

        except Exception as e:
            logger.error(f"Constraint cache operation failed: {e}", exc_info=True)
            return {"success": False, "error": str(e)}


def manage_constraint_cache(**kwargs) -> Dict[str, Any]:
    """Instantiate a ConstraintCachePersistence and run the requested action."""
    cache = ConstraintCachePersistence()
    return cache.analyze(**kwargs)


__all__ = ["ConstraintCachePersistence", "manage_constraint_cache"]
