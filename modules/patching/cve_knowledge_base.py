"""CVE 知识库 — CVE-Genie 启发的结构化存储。

CVE-Genie 通过多代理流水线将 CVE 描述、补丁 diff 和安全公告转化为
结构化知识。本模块实现其 Processor 阶段的核心数据结构：
从 NVD JSON / 本地 JSON 加载 CVE 信息，构建可查询的因果图。

不做 CVE 复现（CVE-Genie Builder 的职责），仅元数据管理。
"""

import os, json, re, logging, hashlib, sqlite3
import datetime as _dt
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict

_lgr = logging.getLogger(__name__)


@dataclass
class CVEEntry:
    """CVE 条目 — Processor 阶段提取的结构化字段。"""
    cve_id: str
    description: str = ""
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_vector: str = ""
    affected_products: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)
    patch_links: List[str] = field(default_factory=list)
    published_date: str = ""
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    # CVE-Genie 风格: 补丁 diff 摘要
    patch_summary: str = ""
    root_cause_hypothesis: str = ""

    def to_dict(self) -> Dict:
        return {
            'cve_id': self.cve_id,
            'description': self.description[:200],
            'cwe_ids': self.cwe_ids,
            'cvss_score': self.cvss_score,
            'exploitability_score': self.exploitability_score,
            'impact_score': self.impact_score,
            'affected_products': self.affected_products[:10],
            'affected_functions': self.affected_functions[:10],
            'patch_links': self.patch_links[:5],
            'published_date': self.published_date,
            'tags': self.tags,
        }


@dataclass
class CVEQueryResult:
    """CVE 查询结果集。"""
    query: str = ""
    matches: List[CVEEntry] = field(default_factory=list)
    total_matches: int = 0
    search_time_ms: float = 0.0
    cwe_distribution: Dict[str, int] = field(default_factory=dict)
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    # CVE-Genie 风格: 因果边
    causal_links: List[Tuple[str, str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'query': self.query,
            'total_matches': self.total_matches,
            'cwe_distribution': self.cwe_distribution,
            'severity_distribution': self.severity_distribution,
            'matches': [_m.to_dict() for _m in self.matches[:50]],
        }


# NVD JSON 解析
# NVD API 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0

class NVDParser:
    """NVD CVE JSON 解析器 — 抽取 Processor 所需的结构化字段。"""

    # CWE 提取 — 从 NVD weaknesses 字段匹配
    _CWE_PATTERN = re.compile(r'CWE-(\d+)')

    # 产品/厂商 — 从 CPE 字符串剥离
    _CPE_PATTERN = re.compile(r'cpe:2\.3:[aho*\-]:([^:]+):([^:]+):')

    @classmethod
    def parse_nvd_json(cls, nvd_data: Dict) -> List[CVEEntry]:
        """解析 NVD API 2.0 响应，返回 CVE 条目列表。"""
        _entries = []
        _vulns = nvd_data.get('vulnerabilities', [])
        for _item in _vulns:
            _cve = _item.get('cve', {})
            if not _cve:
                continue

            _cve_id = _cve.get('id', '')
            _desc = cls._extract_description(_cve)
            _cwes = cls._extract_cwes(_cve)
            _metrics = cls._extract_metrics(_item)
            _products = cls._extract_products(_cve)
            _refs = cls._extract_references(_cve)
            _published = _cve.get('published', '')

            _entry = CVEEntry(
                cve_id=_cve_id,
                description=_desc,
                cwe_ids=_cwes,
                cvss_score=_metrics.get('baseScore', 0.0),
                cvss_vector=_metrics.get('vectorString', ''),
                exploitability_score=_metrics.get('exploitabilityScore', 0.0),
                impact_score=_metrics.get('impactScore', 0.0),
                affected_products=_products,
                references=_refs,
                published_date=_published,
            )
            _entries.append(_entry)
        return _entries

    @classmethod
    def _extract_description(cls, cve_data: Dict) -> str:
        _descs = cve_data.get('descriptions', [])
        for _d in _descs:
            if _d.get('lang', '') == 'en':
                return _d.get('value', '')
        if _descs:
            return _descs[0].get('value', '')
        return ""

    @classmethod
    def _extract_cwes(cls, cve_data: Dict) -> List[str]:
        _cwes = []
        _weaknesses = cve_data.get('weaknesses', [])
        for _w in _weaknesses:
            for _d in _w.get('description', []):
                _val = _d.get('value', '')
                _m = cls._CWE_PATTERN.search(_val)
                if _m:
                    _cwe = 'CWE-' + _m.group(1)
                    if _cwe not in _cwes:
                        _cwes.append(_cwe)
        return _cwes

    @classmethod
    def _extract_metrics(cls, item: Dict) -> Dict:
        """提取 CVSS v3.1 评分，回退到 v2.0。"""
        _metrics = item.get('metrics', {})
        # CVSS v3.1
        _cvss31 = _metrics.get('cvssMetricV31', [])
        if _cvss31:
            return _cvss31[0].get('cvssData', {})
        # CVSS v3.0
        _cvss30 = _metrics.get('cvssMetricV30', [])
        if _cvss30:
            return _cvss30[0].get('cvssData', {})
        # CVSS v2.0
        _cvss2 = _metrics.get('cvssMetricV2', [])
        if _cvss2:
            return _cvss2[0].get('cvssData', {})
        return {}

    @classmethod
    def _extract_products(cls, cve_data: Dict) -> List[str]:
        _prods = set()
        _configs = cve_data.get('configurations', [])
        for _cfg in _configs:
            _nodes = _cfg.get('nodes', [])
            for _node in _nodes:
                for _match in _node.get('cpeMatch', []):
                    _criteria = _match.get('criteria', '')
                    if _criteria:
                        _prods.add(_criteria)
        return sorted(_prods)[:50]

    @classmethod
    def _extract_references(cls, cve_data: Dict) -> List[str]:
        _refs = []
        for _r in cve_data.get('references', []):
            _url = _r.get('url', '')
            if _url:
                _refs.append(_url)
        return _refs[:20]


# 本地简化 JSON 解析
# 格式: [{"id": "CVE-...", "desc": "...", ...}]

class SimpleCVEParser:
    """本地简化 CVE JSON 的解析适配。"""

    @classmethod
    def parse(cls, data: List[Dict]) -> List[CVEEntry]:
        _entries = []
        for _item in data:
            _entry = CVEEntry(
                cve_id=_item.get('id', _item.get('cve_id', '')),
                description=_item.get('desc', _item.get('description', '')),
                cwe_ids=_item.get('cwes', _item.get('cwe_ids', [])),
                cvss_score=_item.get('cvss', _item.get('cvss_score', 0.0)),
                affected_products=_item.get('products', _item.get('affected_products', [])),
                affected_functions=_item.get('functions', _item.get('affected_functions', [])),
                patch_links=_item.get('patches', _item.get('patch_links', [])),
                published_date=_item.get('date', _item.get('published_date', '')),
                tags=_item.get('tags', []),
                references=_item.get('refs', _item.get('references', [])),
                patch_summary=_item.get('patch_summary', ''),
                root_cause_hypothesis=_item.get('root_cause', ''),
            )
            _entries.append(_entry)
        return _entries


# CVE 知识库

class CVEKnowledgeBase:
    """CVE-Genie 风格知识库 — 导入、查询、因果分析。

    存储后端: SQLite（与 BackupManager 一致）。
    Processor 阶段产物：从 NVD + 安全公告 + patch diff
    中提取 CWE → 受影响函数 → 补丁链接的因果图。
    """

    def __init__(self, db_path: str = ".cve_kb/cve_kb.db"):
        _dir = os.path.dirname(db_path)
        if _dir:
            os.makedirs(_dir, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()
        self._entries: Dict[str, CVEEntry] = {}

    def _ensure_schema(self):
        _sql = """
        CREATE TABLE IF NOT EXISTS cve_entries (
            cve_id          TEXT PRIMARY KEY,
            description     TEXT,
            cwe_ids         TEXT,       -- JSON array
            cvss_score      REAL,
            exploitability  REAL,
            impact_score    REAL,
            products        TEXT,       -- JSON array
            functions       TEXT,       -- JSON array
            patch_links     TEXT,       -- JSON array
            published_date  TEXT,
            tags            TEXT,       -- JSON array
            patch_summary   TEXT,
            root_cause      TEXT,
            imported_at     TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS causal_links (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_cve      TEXT NOT NULL,
            target_cve      TEXT,
            relation        TEXT NOT NULL,  -- same_cwe, same_product, same_function, affects
            description     TEXT
        );
        """
        self._conn.executescript(_sql)
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cve_cwe ON cve_entries(cwe_ids)")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cve_score ON cve_entries(cvss_score)")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_causal_src ON causal_links(source_cve)")
        self._conn.commit()

    # 批量导入
    def import_entries(self, entries: List[CVEEntry]) -> int:
        _count = 0
        for _e in entries:
            try:
                self._conn.execute(
                    """INSERT OR REPLACE INTO cve_entries
                    (cve_id, description, cwe_ids, cvss_score,
                     exploitability, impact_score, products, functions,
                     patch_links, published_date, tags, patch_summary, root_cause)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        _e.cve_id,
                        _e.description,
                        json.dumps(_e.cwe_ids),
                        _e.cvss_score,
                        _e.exploitability_score,
                        _e.impact_score,
                        json.dumps(_e.affected_products),
                        json.dumps(_e.affected_functions),
                        json.dumps(_e.patch_links),
                        _e.published_date,
                        json.dumps(_e.tags),
                        _e.patch_summary,
                        _e.root_cause_hypothesis,
                    ))
                self._entries[_e.cve_id] = _e
                _count += 1
            except Exception as e:
                _lgr.warning("import %s failed: %s", _e.cve_id, e)
        self._conn.commit()
        self._build_causal_links()
        _lgr.info("imported %d CVE entries", _count)
        return _count

    def import_from_nvd_json(self, nvd_json_path: str) -> int:
        """从 NVD API JSON 文件批量导入。"""
        with open(nvd_json_path, 'r', encoding='utf-8') as _fh:
            _data = json.load(_fh)
        _entries = NVDParser.parse_nvd_json(_data)
        return self.import_entries(_entries)

    def import_from_simple_json(self, json_path: str) -> int:
        """从本地简化 JSON 格式导入。"""
        with open(json_path, 'r', encoding='utf-8') as _fh:
            _data = json.load(_fh)
        _entries = SimpleCVEParser.parse(_data)
        return self.import_entries(_entries)

# 查询

    def query_by_cwe(self, cwe_id: str) -> CVEQueryResult:
        """按 CWE ID 检索相关 CVE，按 CVSS 降序。"""
        _rows = self._conn.execute(
            "SELECT * FROM cve_entries WHERE cwe_ids LIKE ? ORDER BY cvss_score DESC",
            ('%"' + cwe_id + '"%',)).fetchall()
        _result = CVEQueryResult(query="cwe:" + cwe_id, total_matches=len(_rows))
        for _r in _rows:
            _result.matches.append(self._row_to_entry(_r))
        _result.cwe_distribution = self._compute_distribution(_rows, 'cwe_ids')
        _result.severity_distribution = self._compute_severity_dist(_rows)
        return _result

    def query_by_product(self, product: str) -> CVEQueryResult:
        """按产品名模糊检索。"""
        _rows = self._conn.execute(
            "SELECT * FROM cve_entries WHERE products LIKE ? ORDER BY cvss_score DESC",
            ('%' + product + '%',)).fetchall()
        _result = CVEQueryResult(query="product:" + product, total_matches=len(_rows))
        for _r in _rows:
            _result.matches.append(self._row_to_entry(_r))
        _result.severity_distribution = self._compute_severity_dist(_rows)
        return _result

    def query_by_function(self, func_name: str) -> CVEQueryResult:
        """按受影响函数名检索 — 可直接关联补丁建议。"""
        _rows = self._conn.execute(
            "SELECT * FROM cve_entries WHERE functions LIKE ?",
            ('%' + func_name + '%',)).fetchall()
        _result = CVEQueryResult(query="function:" + func_name, total_matches=len(_rows))
        for _r in _rows:
            _result.matches.append(self._row_to_entry(_r))
        return _result

    def query_high_severity(self, min_score: float = 7.0) -> CVEQueryResult:
        """列出高于阈值的严重漏洞。"""
        _rows = self._conn.execute(
            "SELECT * FROM cve_entries WHERE cvss_score >= ? ORDER BY cvss_score DESC",
            (min_score,)).fetchall()
        _result = CVEQueryResult(
            query="severity>=" + str(min_score), total_matches=len(_rows))
        for _r in _rows:
            _result.matches.append(self._row_to_entry(_r))
        _result.cwe_distribution = self._compute_distribution(_rows, 'cwe_ids')
        _result.severity_distribution = self._compute_severity_dist(_rows)
        return _result

# CVE-Genie 风格因果图

    def _build_causal_links(self):
        """构建 CVE 间因果边：同 CWE → same_cwe，同产品 → same_product。"""
        self._conn.execute("DELETE FROM causal_links")  # 全量重建
        _rows = self._conn.execute("SELECT cve_id, cwe_ids, products, functions FROM cve_entries").fetchall()

        _by_cwe = defaultdict(list)
        _by_product = defaultdict(list)
        for _r in _rows:
            try:
                _cwes = json.loads(_r['cwe_ids'])
            except (json.JSONDecodeError, TypeError):
                _cwes = []
            for _c in _cwes:
                _by_cwe[_c].append(_r['cve_id'])
            try:
                _prods = json.loads(_r['products'])
            except (json.JSONDecodeError, TypeError):
                _prods = []
            for _p in _prods[:5]:
                _by_product[_p].append(_r['cve_id'])

        # 同 CWE 链接
        for _cwe, _cve_list in _by_cwe.items():
            _n = len(_cve_list)
            _i = 0
            while _i < _n:
                _j = _i + 1
                while _j < _n and _j - _i < 5:
                    self._conn.execute(
                        "INSERT INTO causal_links (source_cve, target_cve, relation, description) VALUES (?, ?, 'same_cwe', ?)",
                        (_cve_list[_i], _cve_list[_j], _cwe))
                    _j += 1
                _i += 1

        self._conn.commit()

    def get_causal_links(self, cve_id: str) -> List[Dict]:
        """获取与指定 CVE 关联的因果边列表。"""
        _rows = self._conn.execute(
            """SELECT * FROM causal_links
            WHERE source_cve = ? OR target_cve = ?
            ORDER BY relation""",
            (cve_id, cve_id)).fetchall()
        return [dict(_r) for _r in _rows]

# 统计

    def statistics(self) -> Dict:
        _total = self._conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]
        _avg_score = self._conn.execute(
            "SELECT AVG(cvss_score) FROM cve_entries WHERE cvss_score > 0").fetchone()[0]
        _cwes = self._conn.execute(
            "SELECT cwe_ids FROM cve_entries WHERE cwe_ids != '[]'").fetchall()
        _all_cwes = []
        for _r in _cwes:
            try:
                _all_cwes.extend(json.loads(_r[0]))
            except (json.JSONDecodeError, TypeError):
                pass
        _cwe_dist = defaultdict(int)
        for _c in _all_cwes:
            _cwe_dist[_c] += 1
        return {
            'total_cves': _total,
            'avg_cvss_score': round(_avg_score or 0.0, 2),
            'top_cwes': sorted(_cwe_dist.items(), key=lambda x: x[1], reverse=True)[:10],
            'causal_links': self._conn.execute(
                "SELECT COUNT(*) FROM causal_links").fetchone()[0],
        }

# 辅助

    def _row_to_entry(self, row: sqlite3.Row) -> CVEEntry:
        try:
            _cwes = json.loads(row['cwe_ids'])
        except (json.JSONDecodeError, TypeError):
            _cwes = []
        try:
            _prods = json.loads(row['products'])
        except (json.JSONDecodeError, TypeError):
            _prods = []
        try:
            _funcs = json.loads(row['functions'])
        except (json.JSONDecodeError, TypeError):
            _funcs = []
        return CVEEntry(
            cve_id=row['cve_id'],
            description=row['description'] or '',
            cwe_ids=_cwes,
            cvss_score=row['cvss_score'] or 0.0,
            exploitability_score=row['exploitability'] or 0.0,
            impact_score=row['impact_score'] or 0.0,
            affected_products=_prods,
            affected_functions=_funcs,
            patch_links=[],
            published_date=row['published_date'] or '',
            patch_summary=row['patch_summary'] or '',
            root_cause_hypothesis=row['root_cause'] or '',
        )

    def _compute_distribution(self, rows, field) -> Dict[str, int]:
        _dist = defaultdict(int)
        for _r in rows[:500]:
            try:
                _items = json.loads(_r[field])
            except (json.JSONDecodeError, TypeError, KeyError):
                _items = []
            for _item in _items:
                _dist[_item] += 1
        return dict(sorted(_dist.items(), key=lambda x: x[1], reverse=True)[:20])

    def _compute_severity_dist(self, rows) -> Dict[str, int]:
        _dist = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for _r in rows[:500]:
            _s = _r['cvss_score'] or 0.0
            if _s >= 9.0:
                _dist['critical'] += 1
            elif _s >= 7.0:
                _dist['high'] += 1
            elif _s >= 4.0:
                _dist['medium'] += 1
            else:
                _dist['low'] += 1
        return _dist

    def close(self):
        self._conn.commit()
        self._conn.close()


# 快捷入口

def create_cve_kb(db_path: str = ".cve_kb/cve_kb.db") -> CVEKnowledgeBase:
    return CVEKnowledgeBase(db_path)


def import_nvd_to_kb(kb: CVEKnowledgeBase, nvd_json_path: str) -> int:
    return kb.import_from_nvd_json(nvd_json_path)
