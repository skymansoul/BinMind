# 策略: SQLite而非JSON - CVE数据量大（10万+条），全量加载内存爆炸
# SQLite FTS5全文搜索比手写倒排索引可靠，且支持并发读

from __future__ import annotations

import sqlite3
import json
import logging
from typing import Any, Optional
from dataclasses import dataclass, field

_log = logging.getLogger(__name__)


@dataclass
class CVEEntry:
    cve_id: str
    description: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    affected_vendors: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    published_date: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_ids": self.cwe_ids,
            "affected_vendors": self.affected_vendors,
            "affected_products": self.affected_products,
            "published_date": self.published_date,
            "references": self.references,
        }


class VulnKB:
    def __init__(self, db_path: str = ":memory:"):
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_entries (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL DEFAULT 0.0,
                cvss_vector TEXT DEFAULT '',
                cwe_ids TEXT DEFAULT '[]',
                affected_vendors TEXT DEFAULT '[]',
                affected_products TEXT DEFAULT '[]',
                published_date TEXT DEFAULT '',
                "references" TEXT DEFAULT '[]'
            )
        """)
        conn.commit()
        self._conn = conn

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def add(self, entry: CVEEntry) -> None:
        if not self._conn:
            raise RuntimeError("database connection closed")
        self._conn.execute(
            "INSERT OR REPLACE INTO cve_entries VALUES (?,?,?,?,?,?,?,?,?,?)",
            (entry.cve_id, entry.description, entry.severity,
             entry.cvss_score, entry.cvss_vector,
             json.dumps(entry.cwe_ids), json.dumps(entry.affected_vendors),
             json.dumps(entry.affected_products),
             entry.published_date, json.dumps(entry.references)),
        )
        self._conn.commit()

    def insert(self, entry: CVEEntry) -> None:
        self.add(entry)

    def import_json(self, payload: dict) -> int:
        """从 NVD JSON 结构导入 CVE 条目，返回导入数量。

        payload 为 {cve_id: {...}} 或包含 'vulnerabilities' 键的 NVD 2.0 结构。
        """
        count = 0
        entries = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
        for item in entries:
            cve = item.get("cve", item) if isinstance(item, dict) else {}
            cve_id = cve.get("id", "") if isinstance(cve, dict) else ""
            if not cve_id:
                continue
            desc = ""
            if isinstance(cve, dict) and cve.get("descriptions"):
                for d in cve["descriptions"]:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
            self.add(CVEEntry(cve_id=cve_id, description=desc))
            count += 1
        return count

    def sync_nvd(self, url: str = "") -> int:
        """从 NVD 拉取并入库（网络依赖）。离线时返回 0。"""
        if not url:
            return 0
        try:
            import urllib.request
            import json as _json
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = _json.loads(resp.read().decode("utf-8", errors="replace"))
            return self.import_json(data)
        except Exception:
            return 0

    def get(self, cve_id: str) -> Optional[CVEEntry]:
        if not self._conn:
            return None
        row = self._conn.execute(
            "SELECT * FROM cve_entries WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_entry(row)

    def count(self) -> int:
        if not self._conn:
            return 0
        return self._conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]

    def _row_to_entry(self, row: tuple) -> CVEEntry:
        return CVEEntry(
            cve_id=row[0], description=row[1] or "", severity=row[2] or "",
            cvss_score=row[3] or 0.0, cvss_vector=row[4] or "",
            cwe_ids=self._safe_json(row[5], []),
            affected_vendors=self._safe_json(row[6], []),
            affected_products=self._safe_json(row[7], []),
            published_date=row[8] or "",
            references=self._safe_json(row[9], []),
        )

    @staticmethod
    def _safe_json(val: Any, default: Any) -> Any:
        try:
            return json.loads(val) if val else default
        except (json.JSONDecodeError, TypeError):
            return default

    def search_by_keyword(self, keyword: str, limit: int = 50) -> list[CVEEntry]:
        if not self._conn:
            return []
        rows = self._conn.execute(
            "SELECT * FROM cve_entries WHERE description LIKE ? LIMIT ?",
            (f"%{keyword}%", limit),
        ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_critical(self, limit: int = 100) -> list[CVEEntry]:
        if not self._conn:
            return []
        rows = self._conn.execute(
            "SELECT * FROM cve_entries WHERE severity=? ORDER BY cvss_score DESC LIMIT ?",
            ("CRITICAL", limit),
        ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def severity_distribution(self) -> dict:
        if not self._conn:
            return {}
        rows = self._conn.execute(
            "SELECT severity, COUNT(*) FROM cve_entries GROUP BY severity"
        ).fetchall()
        return {r[0]: r[1] for r in rows}
