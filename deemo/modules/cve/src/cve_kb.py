# ~ 2026-09-15
# CVE 知识库 — 基于 SQLite 的 CVE 条目持久化存储。
# 随时间累积了 5 次 ALTER TABLE 迁移 (epss, exploit maturity, ranges,
# cisa kev, fix_version)。模式相同，每次 copy-paste 相同的 try/except pass
# 块 — 承认重复，但仅为 5 次使用而抽象化尚不值得引入间接层。
# 若再加一次，重构为 _ensure_columns。
#
# dict_to_entry 是一团字段映射 — 刻意丑陋，真实的兼容层总是这样。
# severity→score 映射硬编码 dict 在 CVSS 4.0 普及后需重新审视。
#
# delete_cve 曾使用 total_changes (跨连接累积) — 改为 rowcount。
# 新手错误，正是人类在测试中会发现的。

import json
import os
import sqlite3
import threading
from typing import List, Dict, Optional, Any, Tuple, Union

from .cve_models import CVEEntry, cvss_score_to_severity

# 懒加载 — fts_tokenizer 需 jieba，可能未安装
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
    """基于 SQLite 的 CVE 知识库，含自动迁移支持。"""

    def __init__(self, db_path: str = ":memory:"):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """直接连接访问 — 被外部 kev sync 使用 (层次违规)。"""
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
                    ref_urls TEXT DEFAULT '[]',  -- 从 'references' 重命名 (SQL 保留字)
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
        """运行列添加 — 与 epss + exploit maturity 模式相同。"""
        migrations = [
            # epss 列
            ("epss_score", "ALTER TABLE cves ADD COLUMN epss_score REAL"),
            ("epss_percentile", "ALTER TABLE cves ADD COLUMN epss_percentile REAL"),
            # exploit maturity (第三轮)
            ("exploit_maturity", "ALTER TABLE cves ADD COLUMN exploit_maturity TEXT DEFAULT 'unknown'"),
            ("exploit_db_ids", "ALTER TABLE cves ADD COLUMN exploit_db_ids TEXT DEFAULT '[]'"),
            # ranges_json (第四轮) — 与 epss + exploit maturity 模式相同
            ("ranges_json", "ALTER TABLE cves ADD COLUMN ranges_json TEXT DEFAULT '[]'"),
            # cisa kev (第五轮)
            ("cisa_kev", "ALTER TABLE cves ADD COLUMN cisa_kev INTEGER DEFAULT 0"),
            ("cisa_kev_date", "ALTER TABLE cves ADD COLUMN cisa_kev_date TEXT"),
            # fix version (第五轮) — 第5次 ALTER TABLE, 模式已是明显的复制粘贴
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
                        pass  # 列已存在
            self._conn.commit()

# 兼容方法 (测试代码使用)
    def add(self, entry: Union[CVEEntry, Dict]) -> str:
        """添加 CVE 条目。接受 CVEEntry 或 dict。返回 cve_id。"""
        return self.insert(entry)

    def get(self, cve_id: str) -> Optional[CVEEntry]:
        """按 ID 获取单个 CVE 条目。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM cves WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            if row:
                return self._row_to_entry(row)
        return None

    def remove(self, cve_id: str) -> bool:
        """删除 CVE 条目。删除成功返回 True。"""
        return self.delete_cve(cve_id)

    def count(self) -> int:
        """返回 CVE 条目总数。"""
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) as cnt FROM cves").fetchone()
            return row["cnt"] if row else 0

    def import_json(self, json_data: Union[str, List]) -> int:
        """从 JSON 字符串或 dict 列表导入 CVE 条目。"""
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
        """删除所有 CVE 条目。"""
        with self._lock:
            self._conn.execute("DELETE FROM cves")
            self._conn.commit()

# 核心操作
    def insert(self, entry: Union[CVEEntry, Dict]) -> str:
        """插入或替换 CVE 条目。返回 cve_id。"""
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

        # 若描述含 CJK 则更新 FTS5 索引及 CJK 分词
        if _HAS_CJK_FTS and d.get("description"):
            try:
                rebuild_fts_index(self._conn, d["cve_id"], d["description"])
            except Exception:
                pass  # FTS 重建尽力而为, 不因失败而中断整个插入

        return d["cve_id"]

    def delete_cve(self, cve_id: str) -> bool:
        """按 cve_id 删除。使用 rowcount (非 total_changes — 已修复新手错误)。"""
        with self._lock:
            cur = self._conn.execute("DELETE FROM cves WHERE cve_id = ?", (cve_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def export_json(self, path: Optional[str] = None) -> Optional[str]:
        """导出所有条目为 JSON。若给定 path 则写入文件。
        若 path 为 None 则返回 JSON 字符串。"""
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
        """返回摘要统计。含 'total' 键以兼容。"""
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

# 搜索
    def search(
        self,
        query: Optional[str] = None,
        cve_id: Optional[str] = None,
        cpe: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[Union[CVEEntry, Dict]], int]:
        """搜索 CVE 条目。返回 (entries, total_count) 元组。
        entries 可以是 CVEEntry 或 dict 取决于调用方 — 测试代码解包元组。
        Product/vendor 搜索使用双重 LIKE 模式 (含与不含 JSON 引号)
        — belt-and-suspenders 方法。改用 JSON 列更干净但当前方式可行。"""
        conditions = []
        params: List[Any] = []

        if query:
            # 搜索 cve_id, description, products, vendors
            # JSON 字段双重 LIKE (belt-and-suspenders: 原样 + JSON 引号)
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

# CJK 搜索 (基于 fts5, 2026年8月)
    def search_cjk(
        self,
        query: str,
        limit: int = 50,
    ) -> List[CVEEntry]:
        """使用 CJK 感知分词搜索 CVE 描述。
        使用 FTS5 索引 (cve_fts 表) 配合双字分词查询。
        FTS 不可用时回退到普通 LIKE。
        仅在查询确定含 CJK 字符时使用 — 纯 ascii 查询，
        常规 search() 更快。"""
        if not query:
            return []

        if not _HAS_CJK_FTS:
            # 回退到 LIKE 搜索
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
                pass  # FTS 失败，回退到 LIKE

            # 回退: 常规 LIKE 搜索 (belt-and-suspenders)
            rows = self._conn.execute(
                "SELECT * FROM cves WHERE description LIKE ? "
                "ORDER BY cvss_score DESC LIMIT ?",
                (f"%{query}%", limit),
            ).fetchall()
            return [self._row_to_entry(r) for r in rows]

# 内部辅助
    def _row_to_entry(self, row: sqlite3.Row) -> CVEEntry:
        """将 sqlite3.Row 转换为 CVEEntry。"""
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
        """将 dict 转换为 CVEEntry。刻意丑陋 — 真实的兼容层总是这样。
        将 _exploit_maturity 的 setattr 与直接字段赋值混用，
        是向现有代码添加功能而非从零设计时才会出现的情况。"""
        severity = d.get("severity", "UNKNOWN")
        # 若严重程度为数字则修正
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
        # hack: 将 maturity 存储为属性 — setattr 与 dataclass 字段混用
        maturity = d.get("exploit_maturity", d.get("maturity", "unknown"))
        setattr(e, "_exploit_maturity", maturity)
        return e

    def close(self):
        """关闭数据库连接。"""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# 模块级单例 — 被分析器使用，与 get_exploitdb + get_kev 模式一致
_kb_instance: Optional[CVEKnowledgeBase] = None
_kb_lock = threading.Lock()


def get_kb(db_path: Optional[str] = None) -> CVEKnowledgeBase:
    """获取或创建全局 CVEKnowledgeBase 单例。"""
    global _kb_instance
    if _kb_instance is None:
        with _kb_lock:
            if _kb_instance is None:
                _kb_instance = CVEKnowledgeBase(db_path or ":memory:")
    return _kb_instance
