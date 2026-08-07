# ~ 2026-09-12
# CVE 变更日志 — 追踪 KB 更新间的字段变化。
# NVD 条目会更新: 严重程度调整、新参考链接、CPE 扩展、描述重写。
# 当前 KB 在 INSERT OR REPLACE 时静默覆盖。本模块记录字段级差异，
# 可回答"最近一次 NVD 同步改了什么？"和"此 CVE 是否变严重了？"
#
# 设计: 独立类，不修改 cve_kb.py。调用方负责在执行插入前调用 record_update()。
# 变更日志与 KB 共用同一 DB 文件的独立 sqlite 表（也可独立文件）。
#
# CHANGELOG_FIELDS 列出需追踪的字段。并非所有字段都有意义 —
# 如 last_modified_date 每次 NVD 更新都变，但仅是元数据而非内容。

import json
import sqlite3
import time
from typing import Dict, List, Optional, Tuple, Any

from .cve_models import CVEEntry

# 值得追踪变更的字段
_CHANGE_FIELDS = [
    "description", "severity", "cvss_score", "cvss_vector", "cvss_version",
    "exploitability_score", "impact_score",
    "products", "vendors", "cpe_matches", "cwes", "references",
    "epss_score", "epss_percentile",
    "affected_ranges", "fix_version", "patched_version",
    "cisa_kev", "exploit_maturity",
]

# 新旧值均为列表类型的字段（存为 json 以便比较）
_LIST_FIELDS = {"products", "vendors", "cpe_matches", "cwes", "references",
                "affected_ranges", "exploit_db_ids"}


def diff_entries(old: CVEEntry, new: CVEEntry) -> List[Dict[str, Any]]:
    """比较两个 CVEEntry 对象，返回变更列表。
    每条变更为 {field, old_value, new_value}。
    仅返回实际变化的字段 — 完全相同时返回空列表。

    old 和 new 也可以是 dict（来自旧版 KB 导出）。"""
    changes: List[Dict[str, Any]] = []

    for field in _CHANGE_FIELDS:
        if hasattr(old, field):
            old_val = getattr(old, field)
        elif isinstance(old, dict):
            old_val = old.get(field)
        else:
            old_val = None

        if hasattr(new, field):
            new_val = getattr(new, field)
        elif isinstance(new, dict):
            new_val = new.get(field)
        else:
            new_val = None

        if _values_equal(field, old_val, new_val):
            continue

        changes.append({
            "field": field,
            "old_value": _serialize_val(field, old_val),
            "new_value": _serialize_val(field, new_val),
        })

    return changes


def _values_equal(field: str, v1: Any, v2: Any) -> bool:
    """比较两个字段值。列表字段使用排序后比较。"""
    if field in _LIST_FIELDS:
        v1_list = sorted(v1) if isinstance(v1, list) else []
        v2_list = sorted(v2) if isinstance(v2, list) else []
        return v1_list == v2_list
    # 浮点数小容差比较（处理 None vs 0.0）
    if isinstance(v1, float) and isinstance(v2, float):
        return abs(v1 - v2) < 0.001
    if v1 is None and v2 is None:
        return True
    return v1 == v2


def _serialize_val(field: str, val: Any) -> str:
    """序列化字段值以存入变更日志。
    列表 → JSON，其他 → str。"""
    if val is None:
        return ""
    if field in _LIST_FIELDS:
        return json.dumps(val, sort_keys=True)
    if isinstance(val, bool):
        return "true" if val else "false"
    return str(val)


# 变更日志存储

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS cve_changelog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    field_name TEXT NOT NULL,
    old_value TEXT DEFAULT '',
    new_value TEXT DEFAULT '',
    changed_at REAL NOT NULL,
    change_type TEXT DEFAULT 'update'
)
"""

_CREATE_INDEX_CVE = """
CREATE INDEX IF NOT EXISTS idx_changelog_cve
ON cve_changelog(cve_id, changed_at)
"""

_CREATE_INDEX_TIME = """
CREATE INDEX IF NOT EXISTS idx_changelog_time
ON cve_changelog(changed_at)
"""


class CVEChangelog:
    """追踪 KB 更新间 CVE 条目的字段级变更。
    使用与 KB 同 DB（或独立文件）的 sqlite 表。"""

    def __init__(self, kb):
        """以 CVEKnowledgeBase 实例初始化。
        复用 KB 的连接用于变更日志表。"""
        self._kb = kb
        self._conn = kb._get_conn() if hasattr(kb, '_get_conn') else None
        if self._conn is None and hasattr(kb, '_conn'):
            self._conn = kb._conn
        self._init_table()

    def _init_table(self):
        if self._conn is None:
            return
        try:
            self._conn.execute(_CREATE_TABLE)
            self._conn.execute(_CREATE_INDEX_CVE)
            self._conn.execute(_CREATE_INDEX_TIME)
            self._conn.commit()
        except sqlite3.OperationalError:
            pass

# 记录

    def record_update(self, old_entry, new_entry, change_type: str = "update"):
        """记录新旧条目间的所有字段级变更。
        在将新条目插入 KB 之前调用。
        old_entry 和 new_entry 可以是 CVEEntry 或 dict。

        使用事务: 一个 CVE 的所有变更一起提交。"""
        if self._conn is None:
            return 0

        changes = diff_entries(old_entry, new_entry)
        if not changes:
            return 0

        cve_id = _get_cve_id(new_entry)
        now = time.time()

        rows = []
        for ch in changes:
            rows.append((
                cve_id, ch["field"], ch["old_value"], ch["new_value"],
                now, change_type,
            ))

        try:
            self._conn.executemany(
                "INSERT INTO cve_changelog "
                "(cve_id, field_name, old_value, new_value, changed_at, change_type) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )
            self._conn.commit()
        except sqlite3.OperationalError:
            pass

        return len(rows)

    def record_bulk(self, old_entries: List, new_entries: List) -> int:
        """批量记录条目变更。
        按 cve_id 匹配。返回记录的字段变更总数。"""
        # 按 cve_id 索引旧条目
        old_by_id: Dict[str, Any] = {}
        for e in old_entries:
            cid = _get_cve_id(e)
            if cid:
                old_by_id[cid] = e

        total = 0
        for new_e in new_entries:
            cid = _get_cve_id(new_e)
            old_e = old_by_id.get(cid)
            if old_e is not None:
                total += self.record_update(old_e, new_e)
            else:
                # 新条目 — 以 'create' 类型记录所有字段
                total += self.record_create(new_e)

        return total

    def record_create(self, entry) -> int:
        """记录 CVE 在 KB 中的首次出现。
        所有追踪字段以空 old_value 记录。"""
        if self._conn is None:
            return 0
        cve_id = _get_cve_id(entry)
        now = time.time()

        rows = []
        for field in _CHANGE_FIELDS:
            val = _get_field(entry, field)
            rows.append((cve_id, field, "", _serialize_val(field, val), now, "create"))

        if rows:
            try:
                self._conn.executemany(
                    "INSERT INTO cve_changelog "
                    "(cve_id, field_name, old_value, new_value, changed_at, change_type) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    rows,
                )
                self._conn.commit()
            except sqlite3.OperationalError:
                pass

        return len(rows)

# 查询

    def get_changelog(self, cve_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """获取特定 CVE 的变更历史。"""
        if self._conn is None:
            return []
        rows = self._conn.execute(
            "SELECT * FROM cve_changelog WHERE cve_id = ? "
            "ORDER BY changed_at DESC LIMIT ?",
            (cve_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_recent_changes(
        self, since: Optional[float] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """获取所有 CVE 的近期变更。
        since: unix 时间戳。None 时默认为最近 24 小时。"""
        if self._conn is None:
            return []
        if since is None:
            since = time.time() - 86400  # 24 小时

        rows = self._conn.execute(
            "SELECT * FROM cve_changelog WHERE changed_at >= ? "
            "ORDER BY changed_at DESC LIMIT ?",
            (since, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_severity_changes(
        self, since: Optional[float] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """获取近期严重程度变更 — 最重要的操作性信息。
        MEDIUM→HIGH 的 CVE 比描述编辑更紧迫。"""
        if self._conn is None:
            return []
        if since is None:
            since = time.time() - 86400 * 7  # 7 天

        rows = self._conn.execute(
            "SELECT * FROM cve_changelog "
            "WHERE field_name = 'severity' AND changed_at >= ? "
            "ORDER BY changed_at DESC LIMIT ?",
            (since, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_change_summary(
        self, since: Optional[float] = None
    ) -> Dict[str, Any]:
        """快速摘要: 变更数量、涉及字段、涉及 CVE。
        since: unix 时间戳。默认为最近 24 小时。"""
        if self._conn is None:
            return {"total_changes": 0, "affected_cves": 0, "fields": {}}

        if since is None:
            since = time.time() - 86400

        total = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM cve_changelog WHERE changed_at >= ?",
            (since,),
        ).fetchone()

        cves = self._conn.execute(
            "SELECT COUNT(DISTINCT cve_id) as cnt FROM cve_changelog "
            "WHERE changed_at >= ?",
            (since,),
        ).fetchone()

        by_field = self._conn.execute(
            "SELECT field_name, COUNT(*) as cnt FROM cve_changelog "
            "WHERE changed_at >= ? "
            "GROUP BY field_name ORDER BY cnt DESC",
            (since,),
        ).fetchall()

        return {
            "total_changes": total["cnt"] if total else 0,
            "affected_cves": cves["cnt"] if cves else 0,
            "fields_by_count": {r["field_name"]: r["cnt"] for r in by_field},
        }

    def stats(self) -> Dict[str, Any]:
        """变更日志总体统计。"""
        if self._conn is None:
            return {}
        total = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM cve_changelog"
        ).fetchone()
        cves = self._conn.execute(
            "SELECT COUNT(DISTINCT cve_id) as cnt FROM cve_changelog"
        ).fetchone()
        first = self._conn.execute(
            "SELECT MIN(changed_at) as ts FROM cve_changelog"
        ).fetchone()

        return {
            "total_field_changes": total["cnt"] if total else 0,
            "unique_cves_tracked": cves["cnt"] if cves else 0,
            "first_recorded": first["ts"] if first and first["ts"] else None,
        }


# 辅助函数

def _get_cve_id(entry) -> str:
    """从任意条目类型获取 cve_id。"""
    if hasattr(entry, 'cve_id'):
        return entry.cve_id
    if isinstance(entry, dict):
        return entry.get('cve_id', '')
    return ''


def _get_field(entry, field: str) -> Any:
    """从任意条目类型获取字段值。"""
    if hasattr(entry, field):
        return getattr(entry, field)
    if isinstance(entry, dict):
        return entry.get(field)
    return None

    if __import__("os").environ.get("BINMIND_DEBUG"):print(*a,**kw)
