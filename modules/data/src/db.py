# DataDB —— signature storage backed by SQLite
# 设计原则: 所有写操作走单线程锁, 读操作利用 WAL 模式并发
# 了 sqlite-utils 的 schema migration 思路, 但去掉了 ORM 层
#
# PRAGMA 优化:
#   mmap_size: 将 DB 文件映射到进程地址空间, 大 DB 下可将只读查询
#     延迟降低 30-50% (SQLite 官方白皮书). 默认映射 256MB,
#     超过 DB 实际大小时会静默钳制。
#   wal_autocheckpoint: WAL 文件超过阈值 (默认 1000 页) 时
#     自动执行被动 checkpoint, 防止 WAL 无限制增长拖慢恢复。
#   optimize: 定期运行 PRAGMA optimize (每 N 次写入触发一次),
#     让 SQLite 自动更新统计信息以优化查询计划。

import json
import os
import sqlite3
import threading
import time
from typing import Optional, List, Dict, Any, Tuple
from .config import DataConfig


def _connect_db(db_path: str, wal: bool = True, timeout_ms: int = 5000,
                mmap_mb: int = 256) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=timeout_ms / 1000.0)
    conn.row_factory = sqlite3.Row
    if wal:
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    # mmap_size: 默认 0 (不映射), 设为正数后 SQLite 将文件映射到内存
    # 对只读查询有显著加速, 对写入也有一定改善 (减少 syscall)
    if mmap_mb > 0:
        conn.execute(f"PRAGMA mmap_size={mmap_mb * 1024 * 1024}")
    # WAL 自动 checkpoint: 超过 2000 页时触发, 避免 WAL 无限增长
    conn.execute("PRAGMA wal_autocheckpoint=2000")
    return conn


_SCHEMA_VERSION = 3


class DataDB:
    """核心签名数据库 —— 管理 binary signature、chunk、analysis 结果、去重映射。"""

    def __init__(self, config: DataConfig):
        self._cfg = config
        db_dir = os.path.dirname(config.db.path)
        if db_dir and not os.path.isdir(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        self._conn = _connect_db(
            config.db.path, wal=config.db.wal, timeout_ms=config.db.timeout_ms,
        )
        self._lock = threading.Lock()
        self._last_checkpoint = time.time()
        self._write_count = 0

    def init_schema(self):
        with self._lock:
            self._conn.executescript(_DDL)
            cur = self._conn.execute("PRAGMA user_version")
            ver = cur.fetchone()[0]
            if ver < _SCHEMA_VERSION:
                self._migrate(ver)

    def _migrate(self, from_version: int):
        if from_version < 2:
            self._conn.execute("ALTER TABLE signatures ADD COLUMN stage TEXT DEFAULT 'raw'")
            self._conn.execute("ALTER TABLE signatures ADD COLUMN compressed_size INTEGER DEFAULT 0")
        if from_version < 3:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS simhash_index (
                    sig_id INTEGER NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
                    fingerprint INTEGER NOT NULL,
                    band_keys TEXT NOT NULL,
                    PRIMARY KEY (sig_id)
                );
                CREATE INDEX IF NOT EXISTS idx_simhash_band ON simhash_index(band_keys);
            """)
        self._conn.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    def get_connection(self) -> sqlite3.Connection:
        return self._conn

# signatures

    def add_signature(self, file_path: str, sha256: str, file_size: int = 0,
                      mtime: float = 0.0, tags: List[str] = None,
                      metadata: Dict[str, Any] = None, stage: str = "raw",
                      parent_sha256: str = "") -> int:
        tags_json = json.dumps(tags or [], ensure_ascii=False)
        meta_json = json.dumps(metadata or {}, ensure_ascii=False)
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO signatures
                   (sha256, file_path, file_size, mtime, registered_at, updated_at,
                    tags, metadata, stage, parent_sha256)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(sha256) DO UPDATE SET
                     file_path=excluded.file_path, file_size=excluded.file_size,
                     mtime=excluded.mtime, updated_at=excluded.updated_at,
                     tags=excluded.tags, metadata=excluded.metadata,
                     stage=excluded.stage""",
                (sha256, file_path, file_size, mtime, now, now,
                 tags_json, meta_json, stage, parent_sha256),
            )
            self._conn.commit()
            self._maybe_optimize()
            return cur.lastrowid

    def add_signatures_batch(self, records: List[Dict[str, Any]]) -> int:
        """批量插入, 返回实际写入数量。每条 record 需含 file_path 和 sha256。"""
        now = time.time()
        count = 0
        with self._lock:
            for r in records:
                self._conn.execute(
                    """INSERT INTO signatures
                       (sha256, file_path, file_size, mtime, registered_at, updated_at,
                        tags, metadata, stage)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(sha256) DO UPDATE SET
                         file_path=excluded.file_path, file_size=excluded.file_size,
                         mtime=excluded.mtime, updated_at=excluded.updated_at,
                         tags=excluded.tags, metadata=excluded.metadata,
                         stage=excluded.stage""",
                    (r["sha256"], r["file_path"], r.get("file_size", 0),
                     r.get("mtime", 0.0), now, now,
                     json.dumps(r.get("tags", [])),
                     json.dumps(r.get("metadata", {})),
                     r.get("stage", "raw")),
                )
                count += 1
            self._conn.commit()
            self._write_count += count
            self._maybe_optimize()
        return count

    def get_signature(self, sha256: str) -> Optional[Dict]:
        self._maybe_checkpoint()
        row = self._conn.execute(
            "SELECT * FROM signatures WHERE sha256=?", (sha256,)
        ).fetchone()
        return dict(row) if row else None

    def get_signature_by_id(self, sid: int) -> Optional[Dict]:
        row = self._conn.execute(
            "SELECT * FROM signatures WHERE id=?", (sid,)
        ).fetchone()
        return dict(row) if row else None

    def find_by_path(self, path: str, exact: bool = False) -> List[Dict]:
        if exact:
            rows = self._conn.execute(
                "SELECT * FROM signatures WHERE file_path=?", (path,)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM signatures WHERE file_path LIKE ?",
                (f"%{path}%",)
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_signature(self, sha256: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM signatures WHERE sha256=?", (sha256,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def count(self, stage: str = "") -> int:
        if stage:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM signatures WHERE stage=?", (stage,)
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) FROM signatures").fetchone()
        return row[0] if row else 0

    def list_signatures(self, limit: int = 0, offset: int = 0,
                        stage: str = "", since: str = "") -> List[Dict]:
        sql = "SELECT * FROM signatures WHERE 1=1"
        params: list = []
        if stage:
            sql += " AND stage=?"
            params.append(stage)
        if since:
            sql += " AND updated_at >= ?"
            params.append(since)
        sql += " ORDER BY id DESC"
        if limit > 0:
            sql += f" LIMIT {limit}"
            if offset:
                sql += f" OFFSET {offset}"
        self._maybe_checkpoint()
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def update_signature_meta(self, sid: int, updates: Dict[str, Any]) -> bool:
        sig = self.get_signature_by_id(sid)
        if sig is None:
            return False
        raw = sig.get("metadata", "{}")
        if isinstance(raw, str):
            try:
                meta = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                meta = {}
        else:
            meta = dict(raw or {})
        meta.update(updates)
        with self._lock:
            self._conn.execute(
                "UPDATE signatures SET metadata=?, updated_at=? WHERE id=?",
                (json.dumps(meta), time.time(), sid),
            )
            self._conn.commit()
        return True

    # ---- search (LIKE fallback when FTS not configured) ----

    def search(self, query: str, limit: int = 50) -> List[Dict]:
        pattern = f"%{query}%"
        rows = self._conn.execute(
            """SELECT * FROM signatures
               WHERE file_path LIKE ? OR tags LIKE ? OR metadata LIKE ?
               LIMIT ?""",
            (pattern, pattern, pattern, limit),
        ).fetchall()
        return [dict(r) for r in rows]

# analysis results

    def save_analysis(self, sig_id: int, tool_name: str, tool_version: str = "",
                      duration_ms: float = 0.0, findings: List[Dict] = None,
                      status: str = "completed") -> int:
        findings_json = json.dumps(findings or [], ensure_ascii=False)
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO analysis_results
                   (sig_id, tool_name, tool_version, duration_ms, findings, status, analyzed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (sig_id, tool_name, tool_version, duration_ms, findings_json,
                 status, time.time()),
            )
            self._conn.commit()
            return cur.lastrowid

    def get_analyses(self, sig_id: int) -> List[Dict]:
        rows = self._conn.execute(
            "SELECT * FROM analysis_results WHERE sig_id=? ORDER BY analyzed_at DESC",
            (sig_id,),
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            findings_raw = d.get("findings", "[]")
            if isinstance(findings_raw, str):
                try:
                    d["findings"] = json.loads(findings_raw)
                except json.JSONDecodeError:
                    d["findings"] = []
            results.append(d)
        return results

# chunk storage

    def store_chunk(self, chunk_hash: str, data: bytes) -> int:
        """存一个 chunk 并返回内部 id。chunk_hash 用于去重查找。"""
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO chunks (chunk_hash, data, stored_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(chunk_hash) DO UPDATE SET
                     data=excluded.data, stored_at=excluded.stored_at""",
                (chunk_hash, data, time.time()),
            )
            self._conn.commit()
            return cur.lastrowid

    def get_chunk(self, chunk_hash: str) -> Optional[bytes]:
        row = self._conn.execute(
            "SELECT data FROM chunks WHERE chunk_hash=?", (chunk_hash,)
        ).fetchone()
        return row["data"] if row else None

    def get_chunk_ids_by_hashes(self, hashes: List[str]) -> Dict[str, int]:
        """批量查 chunk, 返回 {chunk_hash: rowid}。快速判断哪些 chunk 已存在。"""
        if not hashes:
            return {}
        placeholders = ",".join("?" * len(hashes))
        rows = self._conn.execute(
            f"SELECT rowid, chunk_hash FROM chunks WHERE chunk_hash IN ({placeholders})",
            hashes,
        ).fetchall()
        return {r["chunk_hash"]: r["rowid"] for r in rows}

# dedup map

    def mark_duplicate(self, canonical_sha: str, dup_sha: str, algorithm: str = "sha256"):
        with self._lock:
            self._conn.execute(
                """INSERT INTO dedup_map (canonical_sha, dup_sha, algorithm, detected_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(dup_sha) DO UPDATE SET
                     canonical_sha=excluded.canonical_sha, detected_at=excluded.detected_at""",
                (canonical_sha, dup_sha, algorithm, time.time()),
            )
            self._conn.commit()

    def get_canonical(self, dup_sha: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT canonical_sha FROM dedup_map WHERE dup_sha=?", (dup_sha,)
        ).fetchone()
        return row["canonical_sha"] if row else None

    def get_duplicates(self, canonical_sha: str) -> List[str]:
        rows = self._conn.execute(
            "SELECT dup_sha FROM dedup_map WHERE canonical_sha=?", (canonical_sha,)
        ).fetchall()
        return [r["dup_sha"] for r in rows]

# lifecycle

    def update_stage(self, sid: int, new_stage: str, reason: str = "") -> bool:
        with self._lock:
            self._conn.execute(
                "UPDATE signatures SET stage=?, updated_at=? WHERE id=?",
                (new_stage, time.time(), sid),
            )
            self._conn.execute(
                """INSERT INTO lifecycle_log (sig_id, from_stage, to_stage, transition_at, reason)
                   VALUES (?, (SELECT stage FROM signatures WHERE id=?), ?, ?, ?)""",
                (sid, sid, new_stage, time.time(), reason),
            )
            self._conn.commit()
            return True

# simhash index

    def store_simhash_fingerprint(self, sig_id: int, fingerprint: int,
                                   band_keys: List[int]):
        keys_json = json.dumps(band_keys)
        with self._lock:
            self._conn.execute(
                """INSERT INTO simhash_index (sig_id, fingerprint, band_keys)
                   VALUES (?, ?, ?)
                   ON CONFLICT(sig_id) DO UPDATE SET
                     fingerprint=excluded.fingerprint, band_keys=excluded.band_keys""",
                (sig_id, fingerprint, keys_json),
            )
            self._conn.commit()

    def query_simhash_candidates(self, band_keys: List[int], limit: int = 50) -> List[Dict]:
        """用 LIKE 匹配任意 band key → 返回候选 sig_id。
        离线 LSH 查询的简单实现: 一个或多个 band 命中即候选。"""
        if not band_keys:
            return []
        conditions = " OR ".join(["band_keys LIKE ?"] * len(band_keys))
        params = [f"%{bk}%" for bk in band_keys]
        rows = self._conn.execute(
            f"SELECT sig_id, fingerprint FROM simhash_index WHERE {conditions} LIMIT ?",
            params + [limit],
        ).fetchall()
        return [dict(r) for r in rows]

# stats

    def db_stats(self) -> Dict[str, Any]:
        total = self._conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
        by_stage_rows = self._conn.execute(
            "SELECT stage, COUNT(*) as cnt FROM signatures GROUP BY stage"
        ).fetchall()
        by_stage = {r["stage"]: r["cnt"] for r in by_stage_rows}
        chunk_count = self._conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        analysis_count = self._conn.execute(
            "SELECT COUNT(*) FROM analysis_results"
        ).fetchone()[0]
        dup_count = self._conn.execute("SELECT COUNT(*) FROM dedup_map").fetchone()[0]
        db_size_mb = 0
        wal_size_mb = 0
        try:
            db_size_mb = round(os.path.getsize(self._cfg.db.path) / (1024 * 1024), 2)
            wal_path = self._cfg.db.path + "-wal"
            if os.path.exists(wal_path):
                wal_size_mb = round(os.path.getsize(wal_path) / (1024 * 1024), 2)
        except OSError:
            pass
        return {
            "total_signatures": total,
            "by_stage": by_stage,
            "total_chunks": chunk_count,
            "total_analyses": analysis_count,
            "total_duplicates": dup_count,
            "db_size_mb": db_size_mb,
            "wal_size_mb": wal_size_mb,
        }

    def _maybe_checkpoint(self):
        """每 60 秒做一次被动 WAL checkpoint —— 防止 WAL 过大。"""
        now = time.time()
        if now - self._last_checkpoint < 60:
            return
        self._last_checkpoint = now
        try:
            self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        except sqlite3.Error:
            pass

    def _maybe_optimize(self):
        """每 ~1000 次写入后运行一次 PRAGMA optimize。
        让 SQLite 更新分析统计以优化后续查询计划。"""
        self._write_count += 1
        if self._write_count % 1000 == 0:
            try:
                self._conn.execute("PRAGMA optimize")
            except sqlite3.Error:
                pass

    def explain_query(self, sql: str, *params) -> List[Dict]:
        """返回 EXPLAIN QUERY PLAN 结果 —— 用于性能诊断。

        每个结果行包含: selectid, order, from, detail。
        detail 列指示是否使用了索引、是否需要临时表等。
        """
        rows = self._conn.execute(
            f"EXPLAIN QUERY PLAN {sql}", params
        ).fetchall()
        return [dict(r) for r in rows]

    def vacuum(self):
        """手动回收空间 —— 清理碎片和已删除记录占用的空间。"""
        with self._lock:
            self._conn.execute("VACUUM")

    def table_sizes(self) -> Dict[str, Dict[str, int]]:
        """返回各表的行数和估计大小 —— 用于存储监控与容量规划。

        每张表返回 {rows, pages}; pages * page_size 约等于磁盘占用。
        """
        result = {}
        tables = ["signatures", "chunks", "analysis_results",
                  "dedup_map", "lifecycle_log", "simhash_index"]
        for tbl in tables:
            try:
                cnt = self._conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
            except sqlite3.OperationalError:
                cnt = 0
            try:
                pg = self._conn.execute(
                    "SELECT pageno FROM dbstat WHERE name=?", (tbl,)
                ).fetchone()
                pages = pg[0] if pg else 0
            except sqlite3.OperationalError:
                pages = 0
            result[tbl] = {"rows": cnt, "pages": pages}
        return result

    def export_schema(self) -> str:
        """导出当前数据库的完整 DDL (CREATE TABLE + INDEX)。

        用于备份数据库结构、版本控制 schema、或创建空副本。
        返回 SQL 字符串, 可直接执行重建相同结构的数据库。
        """
        rows = self._conn.execute(
            "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name"
        ).fetchall()
        return ";\n".join(r["sql"] + ";" for r in rows if r["sql"]) + ";\n"

    def integrity_check(self) -> List[str]:
        """运行 PRAGMA integrity_check, 返回错误行 (空列表=正常)。"""
        rows = self._conn.execute("PRAGMA integrity_check").fetchall()
        return [r[0] for r in rows if r[0] != "ok"]

    def backup(self, target_path: str) -> bool:
        """在线热备份 —— 使用 SQLite backup API 将当前 DB 复制到新文件。

        备份过程中不阻塞读操作 (利用 WAL), 写入会短暂排队。
        返回 True 表示备份成功。
        """
        try:
            dst = sqlite3.connect(target_path)
            self._conn.backup(dst)
            dst.close()
            return True
        except sqlite3.Error as e:
            _log_error = __import__('logging').getLogger(__name__)
            _log_error.error("Backup to %s failed: %s", target_path, e)
            return False

    def close(self):
        try:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        self._conn.close()


# schema

_DDL = """
CREATE TABLE IF NOT EXISTS signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL UNIQUE,
    file_path TEXT NOT NULL,
    file_size INTEGER DEFAULT 0,
    mtime REAL DEFAULT 0.0,
    registered_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    tags TEXT DEFAULT '[]',
    metadata TEXT DEFAULT '{}',
    stage TEXT DEFAULT 'raw',
    parent_sha256 TEXT DEFAULT '',
    compressed_size INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chunk_hash TEXT NOT NULL UNIQUE,
    data BLOB,
    stored_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sig_id INTEGER NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    tool_version TEXT DEFAULT '',
    duration_ms REAL DEFAULT 0.0,
    findings TEXT DEFAULT '[]',
    status TEXT DEFAULT 'completed',
    analyzed_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS dedup_map (
    canonical_sha TEXT NOT NULL,
    dup_sha TEXT NOT NULL UNIQUE,
    algorithm TEXT DEFAULT 'sha256',
    detected_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS lifecycle_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sig_id INTEGER NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    from_stage TEXT NOT NULL,
    to_stage TEXT NOT NULL,
    transition_at REAL NOT NULL,
    reason TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS simhash_index (
    sig_id INTEGER NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    fingerprint INTEGER NOT NULL,
    band_keys TEXT NOT NULL,
    PRIMARY KEY (sig_id)
);

CREATE INDEX IF NOT EXISTS idx_sig_sha256 ON signatures(sha256);
CREATE INDEX IF NOT EXISTS idx_sig_stage ON signatures(stage);
CREATE INDEX IF NOT EXISTS idx_analysis_sig ON analysis_results(sig_id);
CREATE INDEX IF NOT EXISTS idx_dedup_canonical ON dedup_map(canonical_sha);
CREATE INDEX IF NOT EXISTS idx_dedup_dup ON dedup_map(dup_sha);
CREATE INDEX IF NOT EXISTS idx_lifecycle_sig ON lifecycle_log(sig_id);
CREATE INDEX IF NOT EXISTS idx_simhash_band ON simhash_index(band_keys);

PRAGMA user_version=3;
"""

_INSTANCE: Optional[DataDB] = None


def get_db(path: Optional[str] = None) -> DataDB:
    global _INSTANCE
    if _INSTANCE is not None:
        return _INSTANCE
    from .config import DataConfig
    cfg = DataConfig()
    if path:
        cfg.db.path = path
    _INSTANCE = DataDB(cfg)
    _INSTANCE.init_schema()
    return _INSTANCE
