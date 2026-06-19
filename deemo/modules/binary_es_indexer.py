"""
大规模二进制索引与实时搜索 (Elasticsearch 集成) 模块

功能:
    1. 建立全项目函数级索引: 反编译文本/字符串/常量/导入导出/漏洞标签
    2. 提供秒级搜索 API
    3. 支持正则 + 语义向量混合查询
    4. 跨项目快速关联分析

核心技术:
    - ES 索引 mapping 模板
    - 批量索引 (helpers.bulk)
    - 混合查询 (bool + knn)
    - 离线降级 (无 ES 时使用 sqlite FTS5)
"""

import logging
import os
import json
import time
import hashlib
import re
import threading
from typing import Dict, Any, List, Optional, Tuple, Iterable
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False

try:
    import sqlite3
    SQLITE_FTS_AVAILABLE = True
except ImportError:
    SQLITE_FTS_AVAILABLE = False


class IndexField(Enum):
    FUNC_NAME = "func_name"
    BINARY_ID = "binary_id"
    PROJECT = "project"
    DECOMP_TEXT = "decomp_text"
    ASM_TEXT = "asm_text"
    STRINGS = "strings"
    CONSTANTS = "constants"
    IMPORTS = "imports"
    EXPORTS = "exports"
    VULN_TAGS = "vuln_tags"
    CWE = "cwe"
    ARCH = "arch"
    FILE_PATH = "file_path"
    FUNC_OFFSET = "func_offset"
    EMBEDDING = "embedding"
    TIMESTAMP = "@timestamp"


@dataclass
class FunctionDoc:
    """函数索引文档"""
    func_name: str
    binary_id: str
    project: str
    decomp_text: str = ""
    asm_text: str = ""
    strings: List[str] = field(default_factory=list)
    constants: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    vuln_tags: List[str] = field(default_factory=list)
    cwe: List[str] = field(default_factory=list)
    arch: str = ""
    file_path: str = ""
    func_offset: int = 0
    embedding: Optional[List[float]] = None
    timestamp: float = field(default_factory=time.time)

    def doc_id(self) -> str:
        h = hashlib.sha256()
        h.update(self.binary_id.encode("utf-8"))
        h.update(b"\x00")
        h.update(self.func_name.encode("utf-8"))
        h.update(b"\x00")
        h.update(str(self.func_offset).encode("utf-8"))
        return h.hexdigest([:32])


class ESBackend:
    """Elasticsearch 后端"""

    INDEX = "binmind-functions"

    MAPPING = {
        "properties": {
            "func_name": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
            "binary_id": {"type": "keyword"},
            "project": {"type": "keyword"},
            "decomp_text": {"type": "text"},
            "asm_text": {"type": "text"},
            "strings": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
            "constants": {"type": "keyword"},
            "imports": {"type": "keyword"},
            "exports": {"type": "keyword"},
            "vuln_tags": {"type": "keyword"},
            "cwe": {"type": "keyword"},
            "arch": {"type": "keyword"},
            "file_path": {"type": "keyword"},
            "func_offset": {"type": "long"},
            "embedding": {
                "type": "dense_vector",
                "dims": 384,
                "index": True,
                "similarity": "cosine"
            },
            "@timestamp": {"type": "date"}
        }
    }

    def __init__(self, hosts: List[str] = None, **kwargs):
        if not ES_AVAILABLE:
            raise RuntimeError("elasticsearch 未安装, pip install elasticsearch")
        self.client = Elasticsearch(hosts=hosts or ["http://localhost:9200"], **kwargs)
        if not self.client.indices.exists(index=self.INDEX):
            self.client.indices.create(index=self.INDEX, mappings=self.MAPPING)

    def bulk_index(self, docs: List[FunctionDoc]) -> Tuple[int, List[Any]]:
        actions = []
        for d in docs:
            actions.append({
                "_index": self.INDEX,
                "_id": d.doc_id(),
                "_source": asdict(d)
            })
        return bulk(self.client, actions)

    def search(self, query: str, project: Optional[str] = None,
               regex: bool = False, knn: bool = False,
               limit: int = 20) -> List[Dict[str, Any]]:
        must = []
        if project:
            must.append({"term": {"project": project}})
        if query:
            if regex:
                must.append({
                    "regexp": {
                        "decomp_text": {
                            "value": query,
                            "flags": "ALL"
                        }
                    }
                })
            else:
                must.append({"match": {"decomp_text": query}})
        body = {"size": limit, "query": {"bool": {"must": must}}}
        # KNN 向量混合查询
        if knn:
            # 占位: 实际应基于 query embedding
            body["knn"] = {
                "field": "embedding",
                "query_vector": [0.0] * 384,
                "k": limit,
                "num_candidates": 100
            }
        res = self.client.search(index=self.INDEX, body=body)
        return [hit["_source"] for hit in res["hits"]["hits"]]


class SQLiteBackend:
    """SQLite FTS5 后端 (离线降级)"""

    def __init__(self, db_path: Optional[str] = None):
        if not SQLITE_FTS_AVAILABLE:
            raise RuntimeError("sqlite3 不可用")
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(__file__), '..', 'data',
                'binary_index.sqlite3'
            )
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()
        self._lock = threading.Lock()

    def _conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS functions (
                    doc_id TEXT PRIMARY KEY,
                    func_name TEXT,
                    binary_id TEXT,
                    project TEXT,
                    decomp_text TEXT,
                    asm_text TEXT,
                    strings TEXT,
                    constants TEXT,
                    imports TEXT,
                    exports TEXT,
                    vuln_tags TEXT,
                    cwe TEXT,
                    arch TEXT,
                    file_path TEXT,
                    func_offset INTEGER,
                    timestamp REAL
                )
            """)
            c.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS functions_fts USING fts5(
                    func_name, decomp_text, asm_text, strings,
                    content='functions', content_rowid='rowid'
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_project ON functions(project)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_binary ON functions(binary_id)")

    def bulk_index(self, docs: List[FunctionDoc]) -> Tuple[int, List[Any]]:
        inserted = 0
        errors = []
        with self._lock, self._conn() as c:
            for d in docs:
                try:
                    c.execute("""
                        INSERT OR REPLACE INTO functions VALUES (
                            ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
                        )
                    """, (
                        d.doc_id(), d.func_name, d.binary_id, d.project,
                        d.decomp_text, d.asm_text,
                        json.dumps(d.strings), json.dumps(d.constants),
                        json.dumps(d.imports), json.dumps(d.exports),
                        json.dumps(d.vuln_tags), json.dumps(d.cwe),
                        d.arch, d.file_path, d.func_offset, d.timestamp
                    ))
                    c.execute("""
                        INSERT OR REPLACE INTO functions_fts(func_name, decomp_text, asm_text, strings)
                        VALUES (?,?,?,?)
                    """, (d.func_name, d.decomp_text, d.asm_text, " ".join(d.strings)))
                    inserted += 1
                except Exception as e:
                    errors.append((d.doc_id(), str(e)))
        return inserted, errors

    def search(self, query: str, project: Optional[str] = None,
               regex: bool = False, knn: bool = False,
               limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock, self._conn() as c:
            if regex:
                # FTS5 不支持正则, 用 LIKE 兜底
                sql = "SELECT * FROM functions WHERE decomp_text LIKE ?"
                params: Tuple = (f"%{query}%")
            else:
                sql = """
                    SELECT f.* FROM functions f
                    JOIN functions_fts fts ON fts.rowid = f.rowid
                    WHERE functions_fts MATCH ?
                """
                params = (query)
            if project:
                sql += " AND project = ?"
                params = params + (project)
            sql += " LIMIT ?"
            params = params + (limit)
            try:
                cur = c.execute(sql, params)
            except sqlite3.OperationalError:
                # FTS5 解析失败, 降级 LIKE
                cur = c.execute(
                    "SELECT * FROM functions WHERE decomp_text LIKE ? LIMIT ?",
                    (f"%{query}%", limit)
                )
            rows = cur.fetchall()
        results = []
        for r in rows:
            results.append({
                'doc_id': r[0], 'func_name': r[1], 'binary_id': r[2],
                'project': r[3], 'decomp_text': r[4], 'asm_text': r[5],
                'strings': json.loads(r[6] or '[]'),
                'constants': json.loads(r[7] or '[]'),
                'imports': json.loads(r[8] or '[]'),
                'exports': json.loads(r[9] or '[]'),
                'vuln_tags': json.loads(r[10] or '[]'),
                'cwe': json.loads(r[11] or '[]'),
                'arch': r[12], 'file_path': r[13], 'func_offset': r[14]
            })
        return results


class BinaryIndexer:
    """
    二进制索引器统一入口
    - 默认使用 SQLite 降级; 检测到 ES 自动切换
    """

    def __init__(self, es_hosts: Optional[List[str]] = None,
                 db_path: Optional[str] = None,
                 prefer: str = "auto"):
        self.backend: Any = None
        if prefer in ("auto", "es") and ES_AVAILABLE and es_hosts:
            try:
                self.backend = ESBackend(hosts=es_hosts)
                self.kind = "elasticsearch"
                logger.info("[indexer] 使用 Elasticsearch 后端")
            except Exception as e:
                logger.warning(f"ES 初始化失败: {e}, 切换 SQLite")
                self.backend = None
        if self.backend is None:
            try:
                self.backend = SQLiteBackend(db_path)
                self.kind = "sqlite"
                logger.info("[indexer] 使用 SQLite FTS5 后端")
            except Exception as e:
                logger.error(f"SQLite 初始化失败: {e}")
                self.backend = None
                self.kind = "none"

    def index_function(self, doc: FunctionDoc) -> bool:
        if not self.backend:
            return False
        n, errs = self.backend.bulk_index([doc])
        return n == 1 and not errs

    def index_functions(self, docs: List[FunctionDoc]) -> Dict[str, int]:
        if not self.backend:
            return {'inserted': 0, 'errors': 0}
        n, errs = self.backend.bulk_index(docs)
        return {'inserted': n, 'errors': len(errs)}

    def search(self, query: str, **kwargs) -> List[Dict[str, Any]]:
        if not self.backend:
            return []
        try:
            return self.backend.search(query, **kwargs)
        except Exception as e:
            logger.warning(f"搜索失败: {e}")
            return []

    def cross_project_search(self, query: str, limit: int = 20) -> Dict[str, List[Dict[str, Any]]]:
        """跨项目搜索, 按项目分组"""
        results = self.search(query, limit=limit * 4)
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for r in results:
            project = r.get('project', 'unknown')
            grouped.setdefault(project, []).append(r)
        return grouped


def build_function_doc(
    func_name: str,
    binary_id: str,
    project: str,
    decomp_text: str = "",
    asm_text: str = "",
    strings: Optional[List[str]] = None,
    imports: Optional[List[str]] = None,
    exports: Optional[List[str]] = None,
    vuln_tags: Optional[List[str]] = None,
    cwe: Optional[List[str]] = None,
    arch: str = "",
    file_path: str = "",
    func_offset: int = 0,
    constants: Optional[List[str]] = None) -> FunctionDoc:
    return FunctionDoc(
        func_name=func_name,
        binary_id=binary_id,
        project=project,
        decomp_text=decomp_text,
        asm_text=asm_text,
        strings=strings or [],
        constants=constants or [],
        imports=imports or [],
        exports=exports or [],
        vuln_tags=vuln_tags or [],
        cwe=cwe or [],
        arch=arch,
        file_path=file_path,
        func_offset=func_offset
    )
