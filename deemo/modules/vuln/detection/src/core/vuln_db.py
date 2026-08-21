# SQLite漏洞存储层——WAL模式+全文搜索+统计聚合+导入导出
# 边界条件: db_path为None时推导默认路径~/.binmind/vulns.db

import sqlite3
import os
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

from deemo.modules.vuln.detection.src.logger import get_logger

_log = get_logger("vuln_detection.vuln_db")
_DEBUG = False

_STRFTIME_FMT = "%Y-%m-%d %H:%M:%S"
_DEFAULT_DB = os.path.join(os.path.expanduser("~"), ".binmind", "vulns.db")


def _fetch_default_path() -> str:
    return os.environ.get("VULN_DB_PATH", _DEFAULT_DB)


@dataclass
class FindingRecord:
    id: int = 0
    run_ts: str = ""
    binary_path: str = ""
    binary_hash: str = ""
    function_name: str = ""
    vuln_type: str = ""
    severity: str = ""
    cwe: str = ""
    description: str = ""
    evidence: str = ""
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "run_ts": self.run_ts,
            "binary_path": self.binary_path, "binary_hash": self.binary_hash,
            "function_name": self.function_name, "vuln_type": self.vuln_type,
            "severity": self.severity, "cwe": self.cwe,
            "description": self.description, "evidence": self.evidence,
            "created_at": self.created_at,
        }

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "FindingRecord":
        return cls(
            id=row["id"], run_ts=row["run_ts"] or "",
            binary_path=row["binary_path"] or "",
            binary_hash=row["binary_hash"] or "",
            function_name=row["function_name"] or "",
            vuln_type=row["vuln_type"] or "", severity=row["severity"] or "",
            cwe=row["cwe"] or "", description=row["description"] or "",
            evidence=row["evidence"] or "", created_at=row["created_at"] or "",
        )


class VulnDB:
    """SQLite漏洞持久化存储。

    支持CRUD+全文搜索+按severity/type/function聚合。
    WAL模式启用并发读——写入不阻塞读取。
    """

    VALID_SOURCES = {"vuldb", "nvd", "ghadvisory", "all"}

    def __init__(self, db_path: str = ""):
        self.db_path = db_path or _fetch_default_path()
        self.connection: Optional[sqlite3.Connection] = None

    connected = property(lambda self: self.connection is not None)

    def _connect(self) -> sqlite3.Connection:
        if self.connection is None:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA journal_mode=WAL")
            self._ensure_schema()
        return self.connection

    def _ensure_schema(self) -> None:
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_ts TEXT NOT NULL DEFAULT (datetime('now')),
                binary_path TEXT NOT NULL,
                binary_hash TEXT,
                function_name TEXT,
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                cwe TEXT,
                description TEXT,
                evidence TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(vuln_type);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_func ON findings(function_name);
        """)
        self.connection.commit()

    def close(self) -> None:
        if self.connection:
            self.connection.close()
            self.connection = None

    def __enter__(self):
        self._connect()
        return self

    def __exit__(self, *args):
        self.close()

# CRUD

    def insert(self, **kwargs) -> int:
        try:
            conn = self._connect()
            now = datetime.now().strftime(_STRFTIME_FMT)
            cursor = conn.execute(
                "INSERT INTO findings (binary_path, function_name, vuln_type, "
                "severity, cwe, description, evidence, binary_hash, run_ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (kwargs.get("binary_path", ""),
                 kwargs.get("function_name", ""),
                 kwargs.get("vuln_type", ""),
                 kwargs.get("severity", "Medium"),
                 kwargs.get("cwe", ""),
                 kwargs.get("description", ""),
                 kwargs.get("evidence", ""),
                 kwargs.get("binary_hash", ""),
                 now))
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            _log.warning("insert failed: %s", e)
            return -1

    def get_all(self, limit: int = 100) -> List[Dict[str, Any]]:
        try:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM findings ORDER BY created_at DESC LIMIT ?",
                (max(1, limit),)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def get_by_id(self, vuln_id: int) -> Optional[Dict[str, Any]]:
        try:
            conn = self._connect()
            row = conn.execute(
                "SELECT * FROM findings WHERE id = ?", (vuln_id,)).fetchone()
            return dict(row) if row else None
        except Exception:
            return None

    def update(self, vuln_id: int, **kwargs) -> bool:
        allowed = {"vuln_type", "severity", "cwe", "description",
                   "function_name", "evidence", "binary_hash"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        try:
            conn = self._connect()
            set_clause = ", ".join(f"{k} = ?" for k in updates)
            values = list(updates.values()) + [vuln_id]
            conn.execute(
                f"UPDATE findings SET {set_clause} WHERE id = ?", values)
            conn.commit()
            return True
        except Exception as e:
            _log.warning("update(%d) failed: %s", vuln_id, e)
            return False

    def delete(self, vuln_id: int) -> bool:
        try:
            conn = self._connect()
            conn.execute("DELETE FROM findings WHERE id = ?", (vuln_id,))
            conn.commit()
            return True
        except Exception:
            return False

# 搜索

    def search_by_function(self, function_name: str) -> List[Dict[str, Any]]:
        try:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM findings WHERE function_name LIKE ?",
                (f"%{function_name}%",)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def search_by_type(self, vuln_type: str) -> List[Dict[str, Any]]:
        try:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM findings WHERE vuln_type LIKE ?",
                (f"%{vuln_type}%",)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def search_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        try:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM findings WHERE severity = ?",
                (severity,)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def fulltext_search(self, query: str) -> List[Dict[str, Any]]:
        q = f"%{query}%"
        try:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM findings WHERE function_name LIKE ? "
                "OR vuln_type LIKE ? OR description LIKE ? OR cwe LIKE ?",
                (q, q, q, q)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

# 统计

    def statistics(self) -> Dict[str, Any]:
        try:
            conn = self._connect()
            total = conn.execute(
                "SELECT COUNT(*) as c FROM findings").fetchone()["c"]
            by_sev = {r["severity"]: r["c"] for r in conn.execute(
                "SELECT severity, COUNT(*) as c FROM findings GROUP BY severity")}
            by_type = {r["vuln_type"]: r["c"] for r in conn.execute(
                "SELECT vuln_type, COUNT(*) as c FROM findings GROUP BY vuln_type")}
            return {"total": total, "by_severity": by_sev, "by_type": by_type}
        except Exception:
            return {"total": 0, "by_severity": {}, "by_type": {}}

    def count(self) -> int:
        try:
            conn = self._connect()
            return conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        except Exception:
            return 0

# 导入导出

    def export_to(self, export_path: str) -> bool:
        try:
            import shutil
            self.close()
            shutil.copy2(self.db_path, export_path)
            return True
        except Exception:
            return False

    def import_from(self, import_path: str) -> int:
        try:
            import shutil
            self.close()
            shutil.copy2(import_path, self.db_path)
            return self.count() if self._connect() else 0
        except Exception:
            return 0

    @staticmethod
    def _hash_pseudocode(pseudocode: str) -> str:
        return hashlib.sha256(str(pseudocode).encode()).hexdigest()

    def _resolve_external_cache(self, source: str) -> Optional[Any]:
        return None

    def _save_external_cache(self, source: str, data: Any,
                             ttl_seconds: int = 3600) -> bool:
        return True

    def _process_vuldb_entry(self, entry: Dict) -> Optional[Dict]:
        return None

    def _process_github_advisory_graphql(self, advisory: Dict) -> Optional[Dict]:
        return None

    def _extract_github_advisories_from_graphql(self, data: Dict) -> List[Dict]:
        return []

    def _build_github_advisory_query(self, **kwargs) -> str:
        return ""

    def _validate_external_query_params(self, **kwargs) -> Dict:
        return {"valid": True, "sanitized": kwargs, "errors": []}


def get_vuln_db(db_path: str = "") -> VulnDB:
    """获取VulnDB实例——便捷工厂函数"""
    return VulnDB(db_path=db_path)
