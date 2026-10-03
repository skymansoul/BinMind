import os, json, time, sqlite3, gzip, hashlib, logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class BackupManager:
    """SQLite 补丁备份 — 先记录原状态再修改 (WAL 思路)。

    选型:
      SQLite 优于文件系统目录: 原子事务, 避免部分写入损坏备份。
      gzip level 6: 二进制补丁压缩甜点, 更高压缩率 CPU 翻倍而收益递减。
    """

    def __init__(self, db_path: str = ".patch_backups/backup.db"):
        _dir = os.path.dirname(db_path)
        if _dir:
            os.makedirs(_dir, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

# 建表: WAL 模式下先建表再考虑后续优化
    def _ensure_schema(self):
        _sql = """
        CREATE TABLE IF NOT EXISTS patches (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            filepath        TEXT NOT NULL,
            original_sha256 TEXT NOT NULL,
            patch_sha256    TEXT,
            offset          INTEGER NOT NULL,
            original_bytes  BLOB,
            patch_bytes     BLOB,
            created_at      TEXT DEFAULT (datetime('now')),
            verified        INTEGER DEFAULT 0,
            rolled_back     INTEGER DEFAULT 0
        )
        """
        self._conn.execute(_sql)
        # filepath 查询频率最高, 建索引
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_patches_filepath ON patches(filepath)")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_patches_created ON patches(created_at)")
        self._conn.commit()

# 静态工具
    @staticmethod
    def _compress(data: bytes) -> bytes:
        return gzip.compress(data, compresslevel=6)

    @staticmethod
    def _decompress(data: bytes) -> bytes:
        return gzip.decompress(data)

    @staticmethod
    def _sha256_file(filepath: str) -> str:
        _h = hashlib.sha256()
        with open(filepath, "rb") as _fh:
            while True:
                _chunk = _fh.read(65536)
                if not _chunk:
                    break
                _h.update(_chunk)
        return _h.hexdigest()

    @staticmethod
    def _sha256_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    # 备份: 哈希确认文件状态 → 压缩原始字节 → INSERT
    # 只存被补丁偏移处的原始字节, 回滚精确不波及文件其他位置
    def create_backup(self, filepath: str, offset: int, original_bytes: bytes) -> int:
        """记录补丁前状态。返回 patch_id 供 apply/rollback。"""
        _filehash = self._sha256_file(filepath)
        _compressed = self._compress(original_bytes)
        with self._conn:
            _cur = self._conn.execute(
                "INSERT INTO patches (filepath, original_sha256, offset, original_bytes) VALUES (?, ?, ?, ?)",
                (filepath, _filehash, offset, _compressed))
            _id = _cur.lastrowid
        logger.info("backup #%d created for %s @ offset %d", _id, filepath, offset)
        return _id

# 应用: 在文件 offset 处写入 patch_bytes, 同步更新 DB
    def apply_patch(self, patch_id: int, patch_bytes: bytes) -> bool:
        _row = self._conn.execute(
            "SELECT filepath, offset, original_bytes FROM patches WHERE id = ?",
            (patch_id,)).fetchone()
        if _row is None:
            logger.error("apply_patch: patch #%d not found", patch_id)
            return False
        _filepath = _row["filepath"]
        _offset = _row["offset"]
        try:
            with open(_filepath, "r+b") as _fh:
                _fh.seek(_offset)
                _fh.write(patch_bytes)
            _patch_hash = self._sha256_bytes(patch_bytes)
            with self._conn:
                self._conn.execute(
                    "UPDATE patches SET patch_bytes = ?, patch_sha256 = ? WHERE id = ?",
                    (self._compress(patch_bytes), _patch_hash, patch_id))
            logger.info("patch #%d applied to %s", patch_id, _filepath)
            return True
        except Exception as e:
            logger.error("apply_patch #%d failed: %s", patch_id, e)
            return False

# 验证: 读文件当前内容与期望 patch_bytes 比对
    def verify_patch(self, patch_id: int) -> bool:
        _row = self._conn.execute(
            "SELECT filepath, offset, patch_bytes FROM patches WHERE id = ?",
            (patch_id,)).fetchone()
        if _row is None:
            return False
        _filepath = _row["filepath"]
        _offset = _row["offset"]
        _expected = self._decompress(_row["patch_bytes"]) if _row["patch_bytes"] else b''
        try:
            with open(_filepath, "rb") as _fh:
                _fh.seek(_offset)
                _actual = _fh.read(len(_expected))
            _ok = (_actual == _expected)
            with self._conn:
                self._conn.execute(
                    "UPDATE patches SET verified = ? WHERE id = ?",
                    (1 if _ok else 0, patch_id))
            if _ok:
                logger.info("patch #%d verified", patch_id)
            else:
                logger.warning("patch #%d verification FAILED", patch_id)
            return _ok
        except Exception as e:
            logger.error("verify_patch #%d error: %s", patch_id, e)
            return False

    # 回滚: DB 读压缩原字节 → 解压 → 写回文件
    # 最后安全网, 极简实现, 不做额外验证链
    def rollback(self, patch_id: int) -> bool:
        _row = self._conn.execute(
            "SELECT filepath, offset, original_bytes FROM patches WHERE id = ?",
            (patch_id,)).fetchone()
        if _row is None:
            logger.error("rollback: patch #%d not found", patch_id)
            return False
        _filepath = _row["filepath"]
        _offset = _row["offset"]
        try:
            _orig = self._decompress(_row["original_bytes"])
            with open(_filepath, "r+b") as _fh:
                _fh.seek(_offset)
                _fh.write(_orig)
            with self._conn:
                self._conn.execute(
                    "UPDATE patches SET rolled_back = 1 WHERE id = ?",
                    (patch_id,))
            logger.info("patch #%d rolled back", patch_id)
            return True
        except Exception as e:
            logger.error("rollback #%d failed: %s", patch_id, e)
            return False

# 列表: 按 filepath 过滤, 时间倒序
    def list_patches(self, filepath: Optional[str] = None) -> List[Dict]:
        if filepath:
            _rows = self._conn.execute(
                "SELECT * FROM patches WHERE filepath = ? ORDER BY created_at DESC",
                (filepath,))
        else:
            _rows = self._conn.execute(
                "SELECT * FROM patches ORDER BY created_at DESC")
        return [dict(r) for r in _rows]

# 清理: 仅删除已验证且超过保留期的旧记录
    def auto_expire(self, days: int = 30) -> int:
        _sql = (
            "DELETE FROM patches WHERE verified = 1 "
            "AND created_at < datetime('now', '-' || ? || ' days')"
        )
        _cur = self._conn.execute(_sql, (str(days),))
        self._conn.commit()
        _count = _cur.rowcount
        logger.info("auto_expire: removed %d old verified patches (>=%d days)", _count, days)
        return _count

    def get_patch_info(self, patch_id: int) -> Optional[Dict]:
        _row = self._conn.execute(
            "SELECT * FROM patches WHERE id = ?", (patch_id,)).fetchone()
        return dict(_row) if _row else None

    def close(self):
        self._conn.commit()
        self._conn.close()
        logger.debug("BackupManager connection closed")

# def _legacy_handler(data):
#     """旧版处理器"""
#     if data is None:
#         return {}
#     return dict(data)
