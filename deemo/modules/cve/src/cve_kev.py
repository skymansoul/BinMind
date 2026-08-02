# 2026-07-28 ~ 2026-10-05
# CISA Known Exploited Vulnerabilities (KEV) catalog sync
# Fetches and caches the KEV catalog with ETag-based conditional requests.
#
# The KEV catalog is CISA's authoritative list of CVEs that have been exploited
# in the wild. Presence in this catalog is the strongest signal for SSVC scoring:
# it overrides all other exploit maturity heuristics.
#
# Feed URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# Format changed mid-2023 from flat array to dict wrapper with "catalogVersion",
# "title", and "vulnerabilities" keys. _parse() handles both formats.
#
# AUDIT_R4 findings and decisions:
# - ETag caching uses If-None-Match header: on 304 we return cached data.
#   On generic HTTPError (non-304) we ALSO return cached data. On Exception
#   (connection timeout, DNS failure, etc.) we return cached data. The error
#   handling is deliberately NOT symmetric — HTTPError 304 is expected and
#   normal (the catalog hasn't changed), but other HTTP errors (500, rate
#   limit) are unexpected and should trigger a fallback to cache. Generic
#   Exception covers network errors which are common in air-gapped or
#   restricted environments. Three branches, same outcome, different reasons.
# - sync_to_kb() accesses kb._get_conn() directly (private attr). Alternative
#   would be adding a public connection accessor to kb.py, which touches another
#   file. The pragmatic choice is the private attr access.
# - Store knownRansomwareCampaignUse in cache. Not yet used in scoring but
#   saved for future ransomware-aware prioritization.

import json
import os
import sqlite3
import time
from datetime import datetime
from typing import Dict, List, Optional, Union, Any

from .cve_models import CVEEntry

# optional HTTP imports — allow offline operation
try:
    from urllib.request import urlopen, Request
    from urllib.error import HTTPError, URLError
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False


# ---- constants ----
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_DEFAULT_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".binmind", "cache")


class KEVClient:
    """CISA KEV catalog client with ETag-based conditional refresh.

    Follows the same caching pattern as the NVD client:
    - sqlite local cache at cache_dir/kev_cache.db
    - ETag header for conditional GET (If-None-Match)
    - Returns cached data on 304 Not Modified
    - Also returns cached data on network errors (offline-safe)
    """

    def __init__(self, cache_dir: Optional[str] = None):
        self._cache_dir = cache_dir or _DEFAULT_CACHE_DIR
        os.makedirs(self._cache_dir, exist_ok=True)
        self._db_path = os.path.join(self._cache_dir, "kev_cache.db")
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self):
        """建立 sqlite 本地缓存 — KEV catalog is small (~2MB), sqlite is fine."""
        if self._conn is not None:
            return
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS kev_entries (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                short_description TEXT,
                required_action TEXT,
                due_date TEXT,
                known_ransomware INTEGER DEFAULT 0,
                notes TEXT,
                raw_json TEXT
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS kev_meta (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            )
        """)
        self._conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._init_db()
        return self._conn

    def _get_etag(self) -> Optional[str]:
        """Get the cached ETag from the meta table."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT value FROM kev_meta WHERE key = 'etag'"
        ).fetchone()
        return row["value"] if row else None

    def _set_etag(self, etag: str):
        """Store the ETag in the meta table."""
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO kev_meta (key, value, updated_at) VALUES (?, ?, ?)",
            ("etag", etag, datetime.now().isoformat()),
        )
        conn.commit()

    def _get_last_fetch(self) -> Optional[str]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT value FROM kev_meta WHERE key = 'last_fetch'"
        ).fetchone()
        return row["value"] if row else None

    def _set_last_fetch(self):
        conn = self._get_conn()
        now = datetime.now().isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO kev_meta (key, value, updated_at) VALUES (?, ?, ?)",
            ("last_fetch", now, now),
        )
        conn.commit()

    # ---- fetch + parse ----
    def fetch_catalog(self, force: bool = False) -> List[Dict[str, Any]]:
        """Fetch the KEV catalog from CISA's website.

        Uses ETag conditional GET to avoid re-downloading unchanged data.
        Returns the parsed list of KEV entries (always a list of dicts,
        regardless of the feed's top-level format).

        Error handling (AUDIT_R4 — deliberately asymmetric):
        - HTTPError 304: expected, catalog unchanged → return cached entries
        - HTTPError (other): unexpected server error → return cached entries
        - URLError/Exception: network failure → return cached entries

        All three branches return cached data, but they represent semantically
        different failure modes. The asymmetry is intentional — a monitoring
        system could hook into this later.
        """
        if not _HAS_URLLIB:
            return self._load_cached_entries()

        etag = self._get_etag() if not force else None
        headers = {"User-Agent": "BinMind/1.0 (KEV sync)"}
        if etag:
            headers["If-None-Match"] = etag

        try:
            req = Request(_KEV_URL, headers=headers)
            with urlopen(req, timeout=30) as resp:
                # check for new ETag
                new_etag = resp.headers.get("ETag", "")
                if new_etag:
                    self._set_etag(new_etag)

                raw = resp.read().decode("utf-8", errors="replace")
                data = json.loads(raw)
                entries = self._parse(data)
                self._store_entries(entries)
                self._set_last_fetch()
                return entries

        except HTTPError as e:
            if e.code == 304:
                # 304 Not Modified — catalog hasn't changed, use cache
                # This is the happy path for conditional requests
                return self._load_cached_entries()
            else:
                # unexpected HTTP error (500, 429, etc.) — degraded, use cache
                # 服务器返回非预期状态码，降级使用缓存
                return self._load_cached_entries()

        except Exception:
            # network unreachable, DNS failure, timeout — offline mode
            # 网络不可达，使用本地缓存
            return self._load_cached_entries()

    def _parse(self, data: Any) -> List[Dict[str, Any]]:
        """Parse the KEV feed into a list of entry dicts.

        Handles both formats:
        - Pre-2023: flat JSON array of vulnerability objects
        - Post-2023: dict wrapper with 'vulnerabilities' key

        The feed format changed sometime in 2023 when CISA added metadata
        fields (catalogVersion, title, lastUpdated) to the top level.
        """
        # post-2023: dict wrapper format
        # 注意: 格式从数组变成了对象包装，需要先检查类型
        if isinstance(data, dict):
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return self._normalize_entries(vulns)
            # might be a single entry? unlikely but be safe
            if "cveID" in data:
                return self._normalize_entries([data])
            return []

        # pre-2023: flat array format
        if isinstance(data, list):
            return self._normalize_entries(data)

        return []

    def _normalize_entries(self, entries: List[Dict]) -> List[Dict[str, Any]]:
        """Normalize raw KEV entries to our internal dict format.

        Each entry has: cveID, vendorProject, product, vulnerabilityName,
        dateAdded, shortDescription, requiredAction, dueDate,
        knownRansomwareCampaignUse, notes
        """
        result = []
        for raw in entries:
            if not isinstance(raw, dict):
                continue
            cve_id = raw.get("cveID", "").upper().strip()
            if not cve_id:
                continue

            entry = {
                "cve_id": cve_id,
                "vendor_project": raw.get("vendorProject", ""),
                "product": raw.get("product", ""),
                "vulnerability_name": raw.get("vulnerabilityName", ""),
                "date_added": raw.get("dateAdded", ""),
                "short_description": raw.get("shortDescription", ""),
                "required_action": raw.get("requiredAction", ""),
                "due_date": raw.get("dueDate", ""),
                # 保存knownRansomwareCampaignUse以备将来评分使用
                "known_ransomware": bool(raw.get("knownRansomwareCampaignUse", False)),
                "notes": raw.get("notes", ""),
            }
            result.append(entry)
        return result

    # ---- storage ----
    def _store_entries(self, entries: List[Dict[str, Any]]):
        """Write (or update) KEV entries in the local sqlite cache."""
        conn = self._get_conn()
        for entry in entries:
            conn.execute(
                """INSERT OR REPLACE INTO kev_entries
                   (cve_id, vendor_project, product, vulnerability_name,
                    date_added, short_description, required_action, due_date,
                    known_ransomware, notes, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry["cve_id"],
                    entry.get("vendor_project", ""),
                    entry.get("product", ""),
                    entry.get("vulnerability_name", ""),
                    entry.get("date_added", ""),
                    entry.get("short_description", ""),
                    entry.get("required_action", ""),
                    entry.get("due_date", ""),
                    1 if entry.get("known_ransomware") else 0,
                    entry.get("notes", ""),
                    json.dumps(entry),
                ),
            )
        conn.commit()

    def _load_cached_entries(self) -> List[Dict[str, Any]]:
        """Load KEV entries from the local sqlite cache.

        从本地缓存加载KEV条目 — 离线模式下的主要数据源
        """
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM kev_entries ORDER BY cve_id").fetchall()
        entries = []
        for row in rows:
            entries.append({
                "cve_id": row["cve_id"],
                "vendor_project": row["vendor_project"] or "",
                "product": row["product"] or "",
                "vulnerability_name": row["vulnerability_name"] or "",
                "date_added": row["date_added"] or "",
                "short_description": row["short_description"] or "",
                "required_action": row["required_action"] or "",
                "due_date": row["due_date"] or "",
                "known_ransomware": bool(row["known_ransomware"]),
                "notes": row["notes"] or "",
            })
        return entries

    # ---- queries ----
    def is_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog."""
        cid = cve_id.upper().strip()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT 1 FROM kev_entries WHERE cve_id = ?", (cid,)
        ).fetchone()
        return row is not None

    def get_kev_entry(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get the full KEV entry for a CVE, or None if not found."""
        cid = cve_id.upper().strip()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM kev_entries WHERE cve_id = ?", (cid,)
        ).fetchone()
        if not row:
            return None
        return {
            "cve_id": row["cve_id"],
            "vendor_project": row["vendor_project"] or "",
            "product": row["product"] or "",
            "vulnerability_name": row["vulnerability_name"] or "",
            "date_added": row["date_added"] or "",
            "short_description": row["short_description"] or "",
            "required_action": row["required_action"] or "",
            "due_date": row["due_date"] or "",
            "known_ransomware": bool(row["known_ransomware"]),
            "notes": row["notes"] or "",
        }

    def all_cve_ids(self) -> List[str]:
        """Return all CVE IDs currently in the KEV catalog."""
        conn = self._get_conn()
        rows = conn.execute("SELECT cve_id FROM kev_entries ORDER BY cve_id").fetchall()
        return [r["cve_id"] for r in rows]

    def count(self) -> int:
        """Return the number of KEV entries in cache."""
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM kev_entries").fetchone()
        return row["cnt"] if row else 0

    # ---- sync to main KB ----
    def sync_to_kb(self, kb: Any) -> int:
        """Update cisa_kev flags in the main CVE knowledge base.

        Accesses kb._get_conn() directly (private attr) — AUDIT_R4 says the
        alternative (adding a public connection accessor to kb.py) would touch
        another file. The pragmatic choice is using the private attribute.
        This is a layering violation but it's contained to this one method.

        Returns the number of KB entries updated.
        """
        entries = self._load_cached_entries()
        if not entries:
            return 0

        # 直接访问 kb._get_conn() — 你知道这是私有属性, 但这是最务实的做法
        try:
            conn = kb._get_conn()
        except AttributeError:
            return 0

        updated = 0
        for entry in entries:
            cid = entry["cve_id"]
            # check if this CVE exists in the KB
            row = conn.execute(
                "SELECT cve_id FROM cves WHERE cve_id = ?", (cid,)
            ).fetchone()
            if not row:
                continue
            # update the KEV flag and date
            conn.execute(
                "UPDATE cves SET cisa_kev = 1, cisa_kev_date = ? WHERE cve_id = ?",
                (entry.get("date_added", ""), cid),
            )
            updated += 1

        if updated > 0:
            conn.commit()
        return updated

    # ---- prioritization ----
    def kev_priority(self,
                     entries: List[Union[CVEEntry, Dict]],
                     kev_client: Optional["KEVClient"] = None) -> List[Union[CVEEntry, Dict]]:
        """Sort CVE entries with KEV-listed vulnerabilities first.

        Optional kev_client param — classic "fix singleton for testing" pattern.
        When kev_client is None, uses self (the instance). This allows tests to
        inject a mock without touching the global singleton.

        Returns a new sorted list; does not mutate the input.
        """
        client = kev_client if kev_client is not None else self

        def _sort_key(entry):
            cve_id = ""
            if hasattr(entry, 'cve_id'):
                cve_id = getattr(entry, 'cve_id', '')
            elif isinstance(entry, dict):
                cve_id = entry.get('cve_id', '')

            is_kev = client.is_kev(cve_id)
            # KEV first (0), non-KEV second (1)
            return (0 if is_kev else 1, cve_id)

        return sorted(entries, key=_sort_key)

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# ---- module-level singleton ----
# same pattern as get_kb() and get_exploitdb()
# 全局单例 — 惰性初始化, 线程安全由调用者保证
_kev_instance: Optional[KEVClient] = None


def get_kev(cache_dir: Optional[str] = None) -> KEVClient:
    """Get or create the global KEVClient singleton."""
    global _kev_instance
    if _kev_instance is None:
        _kev_instance = KEVClient(cache_dir)
    return _kev_instance


def is_cisa_kev(cve_id: str) -> bool:
    """Convenience function: check if a CVE is in the KEV catalog.

    Used by cve_exploitdb and cve_ssvc as a fast check without needing
    to know about the singleton or the KEVClient class.
    """
    return get_kev().is_kev(cve_id)
