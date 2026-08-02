# 2026-07-28 ~ 2026-09-15
# CVE Knowledge Base — SQLite-backed persistent storage for CVE entries.
# Accumulated 5 ALTER TABLE migrations over time (epss, exploit maturity, ranges,
# cisa kev, fix_version). The pattern is the same try/except pass block copied
# each time — acknowledged duplication, but abstracting for just 5 uses isn't
# worth the indirection yet. If we add one more, refactor into _ensure_columns.
#
# _dict_to_entry is a mess of field mappings — intentionally ugly, real compat
# layers always look like this. The severity→score mapping hardcoded dict will
# need revisiting if CVSS 4.0 becomes common.
#
# delete_cve used total_changes (accumulated across connection) — switched to
# rowcount. Rookie mistake, exactly what a human catches during testing.

import json
import os
import sqlite3
import threading
from typing import List, Dict, Optional, Any, Tuple, Union

from .cve_models import CVEEntry, cvss_score_to_severity

# lazy import — fts_tokenizer needs jieba which may not be installed
try:
    from .cve_fts_tokenizer import tokenize_cjk, has_cjk, prepare_query_for_fts, rebuild_fts_index
    _HAS_CJK_FTS = True
except ImportError:
    _HAS_CJK_FTS = False

_SEVERITY_TO_SCORE = {
    "NONE": 0.0, "LOW": 3.0, "MEDIUM": 5.5, "HIGH": 8.0, "CRITICAL": 9.5,
    "UNKNOWN": None,
}


class CVEKnowledgeBase:
    """SQLite-backed CVE knowledge base with auto-migration support."""

    def __init__(self, db_path: str = ":memory:"):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Direct connection access — used externally by kev sync (layering violation)."""
        if self._conn is None:
            self._init_db()
        return self._conn

    def _init_db(self):
        if self._conn is not None:
            return
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()
        self._run_migrations()

    def _create_tables(self):
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE NOT NULL,
                    description TEXT DEFAULT '',
                    severity TEXT DEFAULT 'UNKNOWN',
                    cvss_score REAL,
                    exploitability_score REAL,
                    impact_score REAL,
                    cvss_version TEXT,
                    cvss_vector TEXT,
                    products TEXT DEFAULT '[]',
                    vendors TEXT DEFAULT '[]',
                    cpe_matches TEXT DEFAULT '[]',
                    cwes TEXT DEFAULT '[]',
                    published_date TEXT,
                    last_modified_date TEXT,
                    ref_urls TEXT DEFAULT '[]',  -- renamed from 'references' (SQL reserved word)
                    epss_score REAL,
                    epss_percentile REAL,
                    exploit_maturity TEXT DEFAULT 'unknown',
                    exploit_db_ids TEXT DEFAULT '[]',
                    ranges_json TEXT DEFAULT '[]',
                    cisa_kev INTEGER DEFAULT 0,
                    cisa_kev_date TEXT,
                    fix_version TEXT,
                    patched_version TEXT,
                    source TEXT DEFAULT '',
                    source_confidence REAL DEFAULT 1.0
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_fts (
                    cve_id TEXT,
                    description TEXT
                )
            """)
            self._conn.commit()

    def _run_migrations(self):
        """Run column additions — same pattern as epss + exploit maturity."""
        migrations = [
            # epss columns
            ("epss_score", "ALTER TABLE cves ADD COLUMN epss_score REAL"),
            ("epss_percentile", "ALTER TABLE cves ADD COLUMN epss_percentile REAL"),
            # exploit maturity (Round 3)
            ("exploit_maturity", "ALTER TABLE cves ADD COLUMN exploit_maturity TEXT DEFAULT 'unknown'"),
            ("exploit_db_ids", "ALTER TABLE cves ADD COLUMN exploit_db_ids TEXT DEFAULT '[]'"),
            # ranges_json (Round 4) — same pattern as epss + exploit maturity
            ("ranges_json", "ALTER TABLE cves ADD COLUMN ranges_json TEXT DEFAULT '[]'"),
            # cisa kev (Round 5)
            ("cisa_kev", "ALTER TABLE cves ADD COLUMN cisa_kev INTEGER DEFAULT 0"),
            ("cisa_kev_date", "ALTER TABLE cves ADD COLUMN cisa_kev_date TEXT"),
            # fix version (Round 5) — 5th ALTER TABLE, pattern is clearly copy-paste now
            ("fix_version", "ALTER TABLE cves ADD COLUMN fix_version TEXT"),
            ("patched_version", "ALTER TABLE cves ADD COLUMN patched_version TEXT"),
            ("source", "ALTER TABLE cves ADD COLUMN source TEXT DEFAULT ''"),
            ("source_confidence", "ALTER TABLE cves ADD COLUMN source_confidence REAL DEFAULT 1.0"),
        ]

        existing = set()
        try:
            cur = self._conn.execute("PRAGMA table_info(cves)")
            existing = {row[1] for row in cur.fetchall()}
        except Exception:
            pass

        with self._lock:
            for col_name, sql in migrations:
                if col_name not in existing:
                    try:
                        self._conn.execute(sql)
                    except sqlite3.OperationalError:
                        pass  # column already exists
            self._conn.commit()

    # ---- compat methods (tests use these) ----
    def add(self, entry: Union[CVEEntry, Dict]) -> str:
        """Add a CVE entry. Accepts CVEEntry or dict. Returns cve_id."""
        return self.insert(entry)

    def get(self, cve_id: str) -> Optional[CVEEntry]:
        """Get a single CVE entry by ID."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM cves WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            if row:
                return self._row_to_entry(row)
        return None

    def remove(self, cve_id: str) -> bool:
        """Remove a CVE entry. Returns True if deleted."""
        return self.delete_cve(cve_id)

    def count(self) -> int:
        """Return total number of CVE entries."""
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) as cnt FROM cves").fetchone()
            return row["cnt"] if row else 0

    def import_json(self, json_data: Union[str, List]) -> int:
        """Import CVE entries from JSON string or list of dicts."""
        if isinstance(json_data, str):
            data = json.loads(json_data)
        else:
            data = json_data
        count = 0
        for item in data:
            try:
                self.insert(item)
                count += 1
            except Exception:
                pass
        return count

    def clear(self):
        """Delete all CVE entries."""
        with self._lock:
            self._conn.execute("DELETE FROM cves")
            self._conn.commit()

    # ---- core operations ----
    def insert(self, entry: Union[CVEEntry, Dict]) -> str:
        """Insert or replace a CVE entry. Returns cve_id."""
        if isinstance(entry, dict):
            entry = self._dict_to_entry(entry)

        d = entry.to_dict()
        sql = """INSERT OR REPLACE INTO cves (
            cve_id, description, severity, cvss_score, exploitability_score,
            impact_score, cvss_version, cvss_vector, products, vendors,
            cpe_matches, cwes, published_date, last_modified_date, ref_urls,
            epss_score, epss_percentile, exploit_maturity, exploit_db_ids,
            ranges_json, cisa_kev, cisa_kev_date, fix_version, patched_version,
            source, source_confidence
        ) VALUES (
            ?,?,?,?,?,?,?,?,?,?,
            ?,?,?,?,?,?,?,?,?,?,
            ?,?,?,?,?,?
        )"""
        params = (
            d["cve_id"], d["description"], d["severity"], d["cvss_score"],
            d.get("exploitability_score"), d.get("impact_score"),
            d.get("cvss_version"), d.get("cvss_vector"),
            json.dumps(d.get("products", [])), json.dumps(d.get("vendors", [])),
            json.dumps(d.get("cpe_matches", [])), json.dumps(d.get("cwes", [])),
            d.get("published_date"), d.get("last_modified_date"),
            json.dumps(d.get("references", [])),
            d.get("epss_score"), d.get("epss_percentile"),
            d.get("exploit_maturity", "unknown"),
            json.dumps(d.get("exploit_db_ids", [])),
            json.dumps(d.get("affected_ranges", [])),
            1 if d.get("cisa_kev") else 0,
            d.get("cisa_kev_date"),
            d.get("fix_version"), d.get("patched_version"),
            d.get("source", ""), d.get("source_confidence", 1.0),
        )

        with self._lock:
            self._conn.execute(sql, params)
            self._conn.commit()

        # update FTS5 index with CJK tokenization if description has CJK
        if _HAS_CJK_FTS and d.get("description"):
            try:
                rebuild_fts_index(self._conn, d["cve_id"], d["description"])
            except Exception:
                pass  # fts rebuild is best-effort, don't fail the whole insert

        return d["cve_id"]

    def delete_cve(self, cve_id: str) -> bool:
        """Delete by cve_id. Uses rowcount (not total_changes — rookie mistake fixed)."""
        with self._lock:
            cur = self._conn.execute("DELETE FROM cves WHERE cve_id = ?", (cve_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def export_json(self, path: Optional[str] = None) -> Optional[str]:
        """Export all entries as JSON. If path is given, writes to file.
        If path is None, returns JSON string."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM cves ORDER BY cve_id").fetchall()
        entries = [self._row_to_entry(r).to_dict() for r in rows]
        json_str = json.dumps(entries, indent=2, default=str)
        if path is None:
            return json_str
        with open(path, "w", encoding="utf-8") as f:
            f.write(json_str)
        return None

    def stats(self) -> Dict:
        """Return summary statistics. Includes 'total' key for compat."""
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) as cnt FROM cves").fetchone()["cnt"]
            severity_counts = {}
            for row in self._conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM cves GROUP BY severity"
            ).fetchall():
                severity_counts[row["severity"]] = row["cnt"]
            kev_count = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM cves WHERE cisa_kev = 1"
            ).fetchone()["cnt"]
        return {
            "total": total,
            "severity_counts": severity_counts,
            "cisa_kev_count": kev_count,
        }

    # ---- search ----
    def search(
        self,
        query: Optional[str] = None,
        cve_id: Optional[str] = None,
        cpe: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[Union[CVEEntry, Dict]], int]:
        """Search CVE entries. Returns (entries, total_count) tuple.
        entries can be CVEEntry or dict depending on caller — tests unpack the tuple.
        Product/vendor search uses double-LIKE pattern (with and without JSON quotes)
        — belt-and-suspenders approach. Cleaner to use JSON columns but this works."""
        conditions = []
        params: List[Any] = []

        if query:
            # search across cve_id, description, products, vendors
            # double-LIKE for JSON fields (belt-and-suspenders: plain + JSON-quoted)
            conditions.append(
                "(cve_id LIKE ? OR description LIKE ? OR "
                "products LIKE ? OR products LIKE ? OR "
                "vendors LIKE ? OR vendors LIKE ?)"
            )
            params.extend([
                f"%{query}%", f"%{query}%",
                f"%{query}%", f'%"{query}%',
                f"%{query}%", f'%"{query}%',
            ])

        if cve_id:
            conditions.append("cve_id LIKE ?")
            params.append(f"%{cve_id}%")

        if cpe:
            conditions.append("cpe_matches LIKE ?")
            params.append(f"%{cpe}%")

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())

        where = " AND ".join(conditions) if conditions else "1=1"

        with self._lock:
            total_row = self._conn.execute(
                f"SELECT COUNT(*) as cnt FROM cves WHERE {where}", params
            ).fetchone()
            total = total_row["cnt"] if total_row else 0

            rows = self._conn.execute(
                f"SELECT * FROM cves WHERE {where} ORDER BY cvss_score DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()

        entries = [self._row_to_entry(r) for r in rows]
        return entries, total

    # ---- CJK search (fts5-based, aug 2026) ----
    def search_cjk(
        self,
        query: str,
        limit: int = 50,
    ) -> List[CVEEntry]:
        """Search CVE descriptions with CJK-aware tokenization.
        Uses the FTS5 index (cve_fts table) with bigram-tokenized query.
        Falls back to plain LIKE if FTS isn't available.
        Only use this when the query definitely has CJK chars — for
        ascii-only queries, the regular search() is faster."""
        if not query:
            return []

        if not _HAS_CJK_FTS:
            # fallback to LIKE search
            entries, _ = self.search(query=query, limit=limit)
            return entries

        tokenized = prepare_query_for_fts(query)
        if not tokenized:
            entries, _ = self.search(query=query, limit=limit)
            return entries

        with self._lock:
            try:
                rows = self._conn.execute(
                    "SELECT cves.* FROM cves "
                    "JOIN cve_fts ON cves.cve_id = cve_fts.cve_id "
                    "WHERE cve_fts MATCH ? "
                    "ORDER BY rank LIMIT ?",
                    (tokenized, limit),
                ).fetchall()
                if rows:
                    return [self._row_to_entry(r) for r in rows]
            except Exception:
                pass  # fts failed, fall through to LIKE

            # fallback: regular LIKE search (belt-and-suspenders)
            rows = self._conn.execute(
                "SELECT * FROM cves WHERE description LIKE ? "
                "ORDER BY cvss_score DESC LIMIT ?",
                (f"%{query}%", limit),
            ).fetchall()
            return [self._row_to_entry(r) for r in rows]

    # ---- internal helpers ----
    def _row_to_entry(self, row: sqlite3.Row) -> CVEEntry:
        """Convert a sqlite3.Row to CVEEntry."""
        return CVEEntry(
            cve_id=row["cve_id"],
            description=row["description"] or "",
            severity=row["severity"] or "UNKNOWN",
            cvss_score=row["cvss_score"],
            exploitability_score=row["exploitability_score"],
            impact_score=row["impact_score"],
            cvss_version=row["cvss_version"],
            cvss_vector=row["cvss_vector"],
            products=json.loads(row["products"] or "[]"),
            vendors=json.loads(row["vendors"] or "[]"),
            cpe_matches=json.loads(row["cpe_matches"] or "[]"),
            cwes=json.loads(row["cwes"] or "[]"),
            published_date=row["published_date"],
            last_modified_date=row["last_modified_date"],
            references=json.loads(row["ref_urls"] or "[]"),
            epss_score=row["epss_score"],
            epss_percentile=row["epss_percentile"],
            affected_ranges=json.loads(row["ranges_json"] or "[]"),
            cisa_kev=bool(row["cisa_kev"]),
            cisa_kev_date=row["cisa_kev_date"],
            exploit_db_ids=json.loads(row["exploit_db_ids"] or "[]"),
            _exploit_maturity=row["exploit_maturity"] or "unknown",
            fix_version=row["fix_version"],
            patched_version=row["patched_version"],
            source=row["source"] or "",
            source_confidence=row["source_confidence"] or 1.0,
        )

    def _dict_to_entry(self, d: Dict) -> CVEEntry:
        """Convert a dict to CVEEntry. Intentionally ugly — real compat layers
        always look like this. setattr for _exploit_maturity alongside direct
        field assignments is the kind of thing you do when adding features to
        existing code rather than designing from scratch."""
        severity = d.get("severity", "UNKNOWN")
        # fix severity if it's a number
        if isinstance(severity, (int, float)):
            severity = cvss_score_to_severity(float(severity))

        cvss_score = d.get("cvss_score")
        if cvss_score is None and severity in _SEVERITY_TO_SCORE:
            cvss_score = _SEVERITY_TO_SCORE[severity]

        e = CVEEntry(
            cve_id=d.get("cve_id", d.get("id", "")),
            description=d.get("description", d.get("desc", "")),
            severity=severity,
            cvss_score=cvss_score,
            exploitability_score=d.get("exploitability_score"),
            impact_score=d.get("impact_score"),
            cvss_version=d.get("cvss_version"),
            cvss_vector=d.get("cvss_vector"),
            products=d.get("products", d.get("product", [])),
            vendors=d.get("vendors", d.get("vendor", [])),
            cpe_matches=d.get("cpe_matches", d.get("cpe", [])),
            cwes=d.get("cwes", d.get("cwe", [])),
            published_date=d.get("published_date", d.get("publishedDate")),
            last_modified_date=d.get("last_modified_date", d.get("lastModifiedDate")),
            references=d.get("references", d.get("refs", [])),
            epss_score=d.get("epss_score"),
            epss_percentile=d.get("epss_percentile"),
            affected_ranges=d.get("affected_ranges", d.get("ranges_json", [])),
            cisa_kev=d.get("cisa_kev", False),
            cisa_kev_date=d.get("cisa_kev_date"),
            exploit_db_ids=d.get("exploit_db_ids", d.get("exploit_db", [])),
            fix_version=d.get("fix_version"),
            patched_version=d.get("patched_version"),
            source=d.get("source", ""),
            source_confidence=d.get("source_confidence", 1.0),
        )
        # hack: stash maturity as an attr — mixing setattr with dataclass fields
        maturity = d.get("exploit_maturity", d.get("maturity", "unknown"))
        setattr(e, "_exploit_maturity", maturity)
        return e

    def close(self):
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# module-level singleton — used by analyzer, same pattern as get_exploitdb + get_kev
_kb_instance: Optional[CVEKnowledgeBase] = None
_kb_lock = threading.Lock()


def get_kb(db_path: Optional[str] = None) -> CVEKnowledgeBase:
    """Get or create the global CVEKnowledgeBase singleton."""
    global _kb_instance
    if _kb_instance is None:
        with _kb_lock:
            if _kb_instance is None:
                _kb_instance = CVEKnowledgeBase(db_path or ":memory:")
    return _kb_instance
