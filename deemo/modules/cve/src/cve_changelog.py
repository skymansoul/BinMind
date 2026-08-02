# 2026-09-10 ~ 2026-09-12
# CVE changelog — tracks what changed between KB updates.
# NVD entries get updated: severity bumps, new references, expanded CPEs,
# descriptions get rewritten. Right now our KB silently overwrites on INSERT
# OR REPLACE. This module records field-level diffs so you can answer
# "what changed in the last NVD sync?" and "did this CVE get worse?"
#
# Design: standalone class, doesn't modify cve_kb.py. Callers are responsible
# for calling record_update() before they insert. The changelog has its own
# sqlite table in the same DB file as the KB (or a separate file).
#
# CHANGELOG_FIELDS lists the fields we bother tracking. Not all fields are
# meaningful — e.g., last_modified_date changes on every NVD update but that's
# metadata, not content.

import json
import sqlite3
import time
from typing import Dict, List, Optional, Tuple, Any

from .cve_models import CVEEntry

# fields worth tracking changes on
_CHANGE_FIELDS = [
    "description", "severity", "cvss_score", "cvss_vector", "cvss_version",
    "exploitability_score", "impact_score",
    "products", "vendors", "cpe_matches", "cwes", "references",
    "epss_score", "epss_percentile",
    "affected_ranges", "fix_version", "patched_version",
    "cisa_kev", "exploit_maturity",
]

# fields whose old+new values are list-typed (store as json for comparison)
_LIST_FIELDS = {"products", "vendors", "cpe_matches", "cwes", "references",
                "affected_ranges", "exploit_db_ids"}


def diff_entries(old: CVEEntry, new: CVEEntry) -> List[Dict[str, Any]]:
    """Compare two CVEEntry objects and return a list of changes.
    Each change is {field, old_value, new_value}.
    Only returns fields that actually changed — empty list if identical.

    old and new can also be dicts (from older KB exports)."""
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
    """Compare two field values. List fields use sorted comparison."""
    if field in _LIST_FIELDS:
        v1_list = sorted(v1) if isinstance(v1, list) else []
        v2_list = sorted(v2) if isinstance(v2, list) else []
        return v1_list == v2_list
    # float comparison with small tolerance (handle None vs 0.0)
    if isinstance(v1, float) and isinstance(v2, float):
        return abs(v1 - v2) < 0.001
    if v1 is None and v2 is None:
        return True
    return v1 == v2


def _serialize_val(field: str, val: Any) -> str:
    """Serialize a field value for storage in the changelog.
    Lists → JSON, everything else → str."""
    if val is None:
        return ""
    if field in _LIST_FIELDS:
        return json.dumps(val, sort_keys=True)
    if isinstance(val, bool):
        return "true" if val else "false"
    return str(val)


# ---- changelog storage ----

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
    """Tracks field-level changes to CVE entries across KB updates.
    Uses a sqlite table in the same DB as the KB (or a separate file)."""

    def __init__(self, kb):
        """Initialize with a CVEKnowledgeBase instance.
        We reuse the KB's connection for the changelog table."""
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

    # ---- record ----

    def record_update(self, old_entry, new_entry, change_type: str = "update"):
        """Record all field-level changes between old and new entries.
        Call this BEFORE inserting the new entry into the KB.
        old_entry and new_entry can be CVEEntry or dict.

        Uses a transaction: all changes for one CVE are committed together."""
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
        """Bulk record changes for a batch of entries.
        Matches by cve_id. Returns total number of field changes recorded."""
        # index old entries by cve_id
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
                # new entry — record as 'create' with all fields
                total += self.record_create(new_e)

        return total

    def record_create(self, entry) -> int:
        """Record the first appearance of a CVE in the KB.
        All tracked fields are recorded with empty old_value."""
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

    # ---- query ----

    def get_changelog(self, cve_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get the change history for a specific CVE."""
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
        """Get recent changes across all CVEs.
        since: unix timestamp. If None, returns last 24 hours."""
        if self._conn is None:
            return []
        if since is None:
            since = time.time() - 86400  # 24 hours

        rows = self._conn.execute(
            "SELECT * FROM cve_changelog WHERE changed_at >= ? "
            "ORDER BY changed_at DESC LIMIT ?",
            (since, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_severity_changes(
        self, since: Optional[float] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get recent severity changes — most operationally important.
        A CVE going from MEDIUM→HIGH is more urgent than a description edit."""
        if self._conn is None:
            return []
        if since is None:
            since = time.time() - 86400 * 7  # 7 days

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
        """Quick summary: how many changes, which fields, which CVEs.
        since: unix timestamp. Defaults to last 24 hours."""
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
        """Overall changelog statistics."""
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


# ---- helpers ----

def _get_cve_id(entry) -> str:
    """Get cve_id from any entry type."""
    if hasattr(entry, 'cve_id'):
        return entry.cve_id
    if isinstance(entry, dict):
        return entry.get('cve_id', '')
    return ''


def _get_field(entry, field: str) -> Any:
    """Get a field value from any entry type."""
    if hasattr(entry, field):
        return getattr(entry, field)
    if isinstance(entry, dict):
        return entry.get(field)
    return None
