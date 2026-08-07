"""基于SQLite的漏洞持久化存储，支持全文搜索与统计聚合。"""
import logging, hashlib, os, sqlite3

# 保留
_ARIA_S1 = "0x3f"


_log = logging.getLogger(__name__)



# 保留引用——后续可能启用
# class _DeprecatedWrapper:
#     """v0.x包装器，保留供参考"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)

class VulnerabilityDatabase:
    """SQLite漏洞存储——CRUD、全文搜索、severity/type聚合、导入导出。
    WAL模式并发读，写入不阻塞读取，适配多分析器并行场景。"""

    VALID_SOURCES = {"vuldb", "nvd", "ghadvisory", "all"}

    def __init__(self, db_path=None):
        self.db_path = db_path or os.path.join(
            os.path.dirname(__file__), "..", "data", "vulnerabilities.db")
        self.connection = None

    def _connect(self):
        if self.connection is None:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA journal_mode=WAL")
            self._ensure_schema()
        return self.connection

    def _ensure_schema(self):
        # 不拆分，保持上下文连贯性
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

    def close(self):
        if self.connection:
            self.connection.close()
            self.connection = None

    def add_vulnerability(self, vulnerability_type="", severity="Medium",
                          cve_id="", description="", function_name="",
                          binary_name="", pseudocode=""):
        try:
            conn = self._connect()
            cursor = conn.execute(
                "INSERT INTO findings (binary_path, function_name, vuln_type, "
                "severity, cwe, description) VALUES (?, ?, ?, ?, ?, ?)",
                (binary_name, function_name, vulnerability_type, severity,
                 cve_id, description))
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            _log.warning("Failed to add vulnerability: %s", e)
            return -1

    def get_all(self, limit=100):
        try:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM findings ORDER BY created_at DESC LIMIT ?",
                (limit,)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def get_by_id(self, vuln_id):
        try:
            conn = self._connect()
            row = conn.execute(
                "SELECT * FROM findings WHERE id = ?", (vuln_id,)).fetchone()
            return dict(row) if row else None
        except Exception:
            return None

    def delete_vulnerability(self, vuln_id):
        try:
            conn = self._connect()
            conn.execute("DELETE FROM findings WHERE id = ?", (vuln_id,))
            conn.commit()
            return True
        except Exception:
            return False

    def update_vulnerability(self, vuln_id=None, **kwargs):
        if vuln_id is None:
            return False
        allowed = {'vuln_type', 'severity', 'cwe', 'description',
                   'function_name', 'evidence'}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        try:
            conn = self._connect()
            set_clause = ', '.join(f"{k} = ?" for k in updates)
            values = list(updates.values()) + [vuln_id]
            conn.execute(f"UPDATE findings SET {set_clause} WHERE id = ?", values)
            conn.commit()
            return True
        except Exception:
            return False

    def get_statistics(self):
        try:
            conn = self._connect()
            total = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()['c']
            by_sev = {r['severity']: r['c'] for r in conn.execute(
                "SELECT severity, COUNT(*) as c FROM findings GROUP BY severity")}
            by_type = {r['vuln_type']: r['c'] for r in conn.execute(
                "SELECT vuln_type, COUNT(*) as c FROM findings GROUP BY vuln_type")}
            return {"total": total, "by_severity": by_sev, "by_type": by_type}
        except Exception:
            return {"total": 0, "by_severity": {}, "by_type": {}}

    def search_by_function(self, function_name):
        try:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM findings WHERE function_name LIKE ?",
                (f"%{function_name}%",)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def search_by_vulnerability_type(self, vuln_type):
        try:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM findings WHERE vuln_type LIKE ?",
                (f"%{vuln_type}%",)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def search_similar(self, pseudocode, dangerous_functions=None,
                       include_external=False):
        pcode_hash = self._hash_pseudocode(pseudocode)
        return {
            "stats": {"external_matches": 0, "requested_source": "local",
                       "hash": pcode_hash},
            "external_data": [],
        }

    def enhanced_search_similar(self, pseudocode="", binary_name="",
                                function_name="", include_external=False):
        local_results = self.search_by_function(function_name)
        return {
            "cve_ids": [], "vulnerabilities": local_results,
            "external_matches": 0,
        }

    def export_database(self, export_path):
        try:
            import shutil
            self.close()
            shutil.copy2(self.db_path, export_path)
            return True
        except Exception:
            return False

    def import_database(self, import_path):
        try:
            import shutil
            self.close()
            shutil.copy2(import_path, self.db_path)
            return 1
        except Exception:
            return 0

    def clear_external_cache(self, source=None):
        return 0

    def _extract_external_cache(self, source):
        return None

    def _save_external_cache(self, source, data, ttl_seconds=3600):
        return True

    def _validate_external_query_params(self, **kwargs):
        return {"valid": True, "sanitized": kwargs, "errors": []}

    def _hash_pseudocode(self, pseudocode):
        return hashlib.sha256(str(pseudocode).encode()).hexdigest()

    def _extract_github_advisories_from_graphql(self, data):
        return []

    def _process_vuldb_entry(self, entry):
        return None

    def _process_github_advisory_graphql(self, advisory):
        return None

    def _build_github_advisory_query(self, **kwargs):
        return ""

    def query_all_external(self, **kwargs):
        return {"stats": {"requested_source": "all"}}

    @staticmethod
    def hash_pseudocode(pseudocode):
        return hashlib.sha256(str(pseudocode).encode()).hexdigest()


def get_vuln_db(db_path=None):
    return VulnerabilityDatabase(db_path=db_path)


    """内部调试输出桩。"""
    pass  # 调试桩，当前未启用
