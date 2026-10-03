from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Union

import logging
import json
import time
import re
from enum import Enum

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class IndexStatus(str, Enum):
    ACTIVE = "active"
    UNUSED = "unused"
    REDUNDANT = "redundant"
    PROPOSED = "proposed"

class QueryType(str, Enum):
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    JOIN = "JOIN"
    AGGREGATE = "AGGREGATE"
    FULL_SCAN = "FULL_SCAN"


@dataclass
class QueryLogEntry:
    query_id: str
    query_type: QueryType
    table: str
    columns: List[str]
    where_columns: List[str]
    elapsed_ms: float
    rows_scanned: int = 0
    using_index: bool = False
    index_used: str = ""
    full_table_scan: bool = False
    sql_text: str = ""
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


@dataclass
class IndexSuggestion:
    suggestion_id: str
    table: str
    columns: List[str]
    reason: str
    estimated_improvement_pct: float
    status: IndexStatus = IndexStatus.PROPOSED
    create_sql: str = ""
    priority: int = 5


@dataclass
class IndexBenchmark:
    table: str
    columns: List[str]
    before_ms: float
    after_ms: float
    improvement_pct: float
    query_type: QueryType
    sample_size: int
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


@dataclass
class OptimizationReport:
    tables_analyzed: int
    queries_analyzed: int
    slow_queries: int
    full_scans: int
    suggestions: List[IndexSuggestion]
    unused_indexes: List[str]
    benchmarks: List[IndexBenchmark]
    overall_recommendation: str


class DatabaseIndexOptimizer(BaseAnalyzer):

    SLOW_QUERY_THRESHOLD_MS = 200
    FULL_SCAN_THRESHOLD_ROWS = 1000

    def __init__(self):
        super().__init__()
        self._query_log: List[QueryLogEntry] = []
        self._existing_indexes: Dict[str, List[Dict[str, Any]]] = {}
        self._suggestions: List[IndexSuggestion] = []
        self._benchmarks: List[IndexBenchmark] = []

    def log_query(self, query_type: Union[str, QueryType], table: str,
                  elapsed_ms: float, **kwargs) -> QueryLogEntry:
        if isinstance(query_type, str):
            try:
                query_type = QueryType(query_type.upper())
            except ValueError:
                query_type = QueryType.SELECT

        entry = QueryLogEntry(
            query_id=f"q{len(self._query_log):06d}",
            query_type=query_type,
            table=table,
            columns=kwargs.get("columns", []),
            where_columns=kwargs.get("where_columns", []),
            elapsed_ms=elapsed_ms,
            rows_scanned=kwargs.get("rows_scanned", 0),
            using_index=kwargs.get("using_index", False),
            index_used=kwargs.get("index_used", ""),
            full_table_scan=kwargs.get("full_table_scan",
                                        elapsed_ms > self.SLOW_QUERY_THRESHOLD_MS),
            sql_text=kwargs.get("sql_text", "")
        )
        self._query_log.append(entry)
        if len(self._query_log) > 10000:
            self._query_log = self._query_log[-10000:]

        if elapsed_ms > self.SLOW_QUERY_THRESHOLD_MS:
            logger.warning("Slow query: table=%s, elapsed=%.1fms, type=%s",
                           table, elapsed_ms, query_type.value)
        return entry

    def analyze_query_patterns(self) -> Dict[str, Any]:
        if not self._query_log:
            return {"total_queries": 0, "message": "No query log data"}

        total = len(self._query_log)
        slow = [q for q in self._query_log
                if q.elapsed_ms > self.SLOW_QUERY_THRESHOLD_MS]
        full_scans = [q for q in self._query_log if q.full_table_scan]
        using_index = [q for q in self._query_log if q.using_index]

        by_table: Dict[str, Dict[str, Any]] = {}
        for q in self._query_log:
            if q.table not in by_table:
                by_table[q.table] = {
                    "count": 0, "total_time_ms": 0,
                    "avg_time_ms": 0, "max_time_ms": 0,
                    "full_scans": 0, "columns_queried": set()
                }
            stats = by_table[q.table]
            stats["count"] += 1
            stats["total_time_ms"] += q.elapsed_ms
            stats["max_time_ms"] = max(stats["max_time_ms"], q.elapsed_ms)
            if q.full_table_scan:
                stats["full_scans"] += 1
            stats["columns_queried"].update(
                q.where_columns + q.columns
            )

        for table, stats in by_table.items():
            stats["avg_time_ms"] = round(stats["total_time_ms"] / stats["count"], 2)
            stats["columns_queried"] = list(stats["columns_queried"])
            stats["full_scan_ratio"] = round(
                stats["full_scans"] / stats["count"] * 100, 1
            )

        where_freq: Dict[str, Dict[str, int]] = {}
        for q in self._query_log:
            if q.table not in where_freq:
                where_freq[q.table] = {}
            for col in q.where_columns:
                where_freq[q.table][col] = where_freq[q.table].get(col, 0) + 1

        return {
            "total_queries": total,
            "slow_queries": len(slow),
            "slow_query_ratio": round(len(slow) / total * 100, 1),
            "full_table_scans": len(full_scans),
            "queries_using_index": len(using_index),
            "index_usage_ratio": round(len(using_index) / total * 100, 1),
            "avg_query_time_ms": round(
                sum(q.elapsed_ms for q in self._query_log) / total, 2
            ),
            "slowest_query_ms": max((q.elapsed_ms for q in self._query_log),
                                     default=0),
            "by_table": by_table,
            "where_column_frequency": {
                table: dict(sorted(cols.items(), key=lambda x: x[1], reverse=True))
                for table, cols in where_freq.items()
            }
        }

    def recommend_indexes(self) -> List[IndexSuggestion]:
        if not self._query_log:
            return []

        analysis = self.analyze_query_patterns()
        where_freq = analysis.get("where_column_frequency", {})
        suggestions: List[IndexSuggestion] = []

        for table, stats in analysis.get("by_table", {}).items():
            if stats["full_scan_ratio"] > 30:
                freq_cols = where_freq.get(table, {})
                top_cols = sorted(freq_cols.items(), key=lambda x: x[1],
                                  reverse=True)

                if top_cols:
                    for col, freq in top_cols[:3]:
                        if freq >= 3:
                            est_improvement = min(90, freq * 8)
                            sid = f"idx_{table}_{col}"
                            suggestions.append(IndexSuggestion(
                                suggestion_id=sid,
                                table=table,
                                columns=[col],
                                reason=f"Full scan ratio {stats['full_scan_ratio']}%, "
                                       f"column '{col}' used in WHERE {freq} times",
                                estimated_improvement_pct=est_improvement,
                                create_sql=self._gen_create_index_sql(
                                    sid, table, [col]
                                ),
                                priority=min(10, 4 + freq)
                            ))

                    if len(top_cols) >= 2:
                        comp_cols = [top_cols[0][0], top_cols[1][0]]
                        sid = f"idx_{table}_{'_'.join(comp_cols)}"
                        suggestions.append(IndexSuggestion(
                            suggestion_id=sid,
                            table=table,
                            columns=comp_cols,
                            reason=f"Composite index covering high-frequency WHERE columns: {comp_cols}",
                            estimated_improvement_pct=min(95, top_cols[0][1] * 10),
                            create_sql=self._gen_create_index_sql(
                                sid, table, comp_cols
                            ),
                            priority=min(10, 5 + top_cols[0][1])
                        ))

            joins_on_table = [
                q for q in self._query_log
                if q.table == table and q.query_type == QueryType.JOIN
            ]
            if joins_on_table:
                for q in joins_on_table:
                    for col in q.where_columns:
                        sid = f"idx_{table}_join_{col}"
                        if not any(s.suggestion_id == sid for s in suggestions):
                            suggestions.append(IndexSuggestion(
                                suggestion_id=sid,
                                table=table,
                                columns=[col],
                                reason=f"JOIN query frequently uses column '{col}'",
                                estimated_improvement_pct=75,
                                create_sql=self._gen_create_index_sql(
                                    sid, table, [col]
                                ),
                                priority=8
                            ))

        redundant = self._detect_redundant_indexes()
        for idx_name in redundant:
            for s in suggestions:
                if s.suggestion_id == idx_name:
                    s.status = IndexStatus.REDUNDANT
                    s.reason += " (Redundant: covered by a wider index)"
                    s.priority = max(1, s.priority - 3)

        suggestions.sort(key=lambda s: s.priority, reverse=True)
        self._suggestions = suggestions
        return suggestions

    @staticmethod
    def _gen_create_index_sql(index_name: str, table: str,
                               columns: List[str]) -> str:
        col_str = ", ".join(columns)
        return f"CREATE INDEX {index_name} ON {table}({col_str});"

    def _detect_redundant_indexes(self) -> List[str]:
        redundant = []
        for table, indexes in self._existing_indexes.items():
            for i, idx1 in enumerate(indexes):
                cols1 = set(idx1.get("columns", []))
                for j, idx2 in enumerate(indexes):
                    if i >= j:
                        continue
                    cols2 = set(idx2.get("columns", []))
                    if cols1.issubset(cols2):
                        redundant.append(idx1.get("name", f"idx_{table}_{i}"))
                        break
        return redundant

    def benchmark_index(self, table: str, columns: List[str],
                        query_type: QueryType = QueryType.SELECT,
                        sample_size: int = 100,
                        simulate_fn=None) -> Optional[IndexBenchmark]:
        matching_queries = [
            q for q in self._query_log
            if q.table == table and q.query_type == query_type
               and any(c in q.where_columns for c in columns)
        ]

        if not matching_queries:
            before_ms = 500.0
        else:
            before_ms = sum(q.elapsed_ms for q in matching_queries[
                -sample_size:
            ]) / min(sample_size, len(matching_queries))

        if before_ms == 0:
            before_ms = 50.0

        est_factor = min(0.8, 0.1 * len(columns) + 0.3)
        after_ms = before_ms * est_factor

        if simulate_fn:
            try:
                after_ms = simulate_fn(table, columns)
            except Exception as e:
                logger.warning("Simulated benchmark failed: %s", e)

        improvement = ((before_ms - after_ms) / max(1, before_ms)) * 100
        benchmark = IndexBenchmark(
            table=table,
            columns=columns,
            before_ms=round(before_ms, 2),
            after_ms=round(after_ms, 2),
            improvement_pct=round(improvement, 1),
            query_type=query_type,
            sample_size=min(sample_size, len(matching_queries))
        )
        self._benchmarks.append(benchmark)
        logger.info("Index benchmark: table=%s, columns=%s, improvement=%.1f%%",
                    table, columns, improvement)
        return benchmark

    def drop_unused_indexes(self) -> List[str]:
        used_indexes = set()
        for q in self._query_log:
            if q.index_used:
                used_indexes.add(q.index_used)

        unused = []
        for table, indexes in self._existing_indexes.items():
            for idx in indexes:
                idx_name = idx.get("name", "")
                if idx_name and idx_name not in used_indexes:
                    unused.append(idx_name)
                    logger.info("Detected unused index: %s (table=%s)", idx_name, table)

        return unused

    def get_drop_sql(self, index_names: List[str]) -> List[str]:
        return [f"DROP INDEX IF EXISTS {name};" for name in index_names]

    @staticmethod
    def _parse_explain_output(explain_data: Any) -> Dict[str, Any]:
        if isinstance(explain_data, dict):
            return {
                "selectid": explain_data.get("selectid", 0),
                "order": explain_data.get("order", 0),
                "from": explain_data.get("from", 0),
                "detail": explain_data.get("detail", ""),
                "using_index": "USING INDEX" in explain_data.get("detail", ""),
                "full_scan": "SCAN TABLE" in explain_data.get("detail", "")
            }
        return {"detail": str(explain_data), "using_index": False,
                "full_scan": False}

    def explain_query(self, sql: str,
                      table: Optional[str] = None) -> Dict[str, Any]:
        sql_upper = sql.upper().strip()

        has_where = "WHERE" in sql_upper
        has_indexed = bool(re.search(r'\b(WHERE|ON)\s+\w+\.(\w+)\s*=', sql_upper))

        cols = re.findall(r'\b(\w+)\s*[=<>]', sql_upper)
        cols = [c for c in cols if c not in
                ("SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "IN",
                 "NULL", "TABLE", "INDEX")]

        likely_full_scan = not has_where or not has_indexed

        return {
            "sql": sql[:200],
            "table": table or "unknown",
            "has_where": has_where,
            "has_indexed_condition": has_indexed,
            "columns_referenced": list(set(cols)),
            "likely_full_scan": likely_full_scan,
            "recommendation": ("Consider creating index on WHERE condition columns"
                               if likely_full_scan else "Query may already be using an index")
        }

    def register_existing_index(self, table: str, index_name: str,
                                columns: List[str], is_unique: bool = False) -> None:
        if table not in self._existing_indexes:
            self._existing_indexes[table] = []
        self._existing_indexes[table].append({
            "name": index_name,
            "columns": columns,
            "is_unique": is_unique
        })

    def get_tables_without_indexes(self) -> List[str]:
        indexed_tables = set(self._existing_indexes.keys())
        queried_tables = set(q.table for q in self._query_log)
        return list(queried_tables - indexed_tables)

    def analyze(self, **kwargs) -> Dict[str, Any]:
        action = kwargs.get("action", "analyze")

        try:
            if action == "log":
                queries = kwargs.get("queries", [])
                if queries:
                    entries = []
                    for q in queries:
                        entry = self.log_query(
                            query_type=q.get("type", "SELECT"),
                            table=q.get("table", ""),
                            elapsed_ms=q.get("elapsed_ms", 0),
                            columns=q.get("columns", []),
                            where_columns=q.get("where_columns", []),
                            rows_scanned=q.get("rows_scanned", 0),
                            using_index=q.get("using_index", False),
                            index_used=q.get("index_used", ""),
                            sql_text=q.get("sql", "")
                        )
                        entries.append(entry.query_id)
                    return {"success": True, "logged": len(entries)}
                else:
                    entry = self.log_query(
                        query_type=kwargs.get("query_type", "SELECT"),
                        table=kwargs.get("table", ""),
                        elapsed_ms=kwargs.get("elapsed_ms", 0),
                        columns=kwargs.get("columns", []),
                        where_columns=kwargs.get("where_columns", []),
                        sql_text=kwargs.get("sql", "")
                    )
                    return {"success": True, "query_id": entry.query_id}

            elif action == "analyze":
                patterns = self.analyze_query_patterns()
                return {"success": True, **patterns}

            elif action == "recommend":
                suggestions = self.recommend_indexes()
                return {
                    "success": True,
                    "suggestions": [
                        {"id": s.suggestion_id, "table": s.table,
                         "columns": s.columns,
                         "reason": s.reason,
                         "estimated_improvement_pct": s.estimated_improvement_pct,
                         "create_sql": s.create_sql,
                         "priority": s.priority,
                         "status": s.status.value}
                        for s in suggestions
                    ],
                    "count": len(suggestions)
                }

            elif action == "benchmark":
                table = kwargs.get("table", "")
                columns = kwargs.get("columns", [])
                if not table or not columns:
                    return {"success": False,
                            "error": "table and columns are required parameters"}
                qt_str = kwargs.get("query_type", "SELECT")
                try:
                    qt = QueryType(qt_str.upper())
                except ValueError:
                    qt = QueryType.SELECT
                bm = self.benchmark_index(
                    table, columns, qt,
                    sample_size=kwargs.get("sample_size", 100)
                )
                if bm:
                    return {
                        "success": True,
                        "benchmark": {
                            "table": bm.table, "columns": bm.columns,
                            "before_ms": bm.before_ms,
                            "after_ms": bm.after_ms,
                            "improvement_pct": bm.improvement_pct,
                            "sample_size": bm.sample_size
                        }
                    }
                return {"success": False,
                        "error": "Cannot execute benchmark, no matching queries"}

            elif action == "explain":
                sql = kwargs.get("sql", "")
                if not sql:
                    return {"success": False, "error": "sql is a required parameter"}
                result = self.explain_query(sql, kwargs.get("table"))
                return {"success": True, **result}

            elif action == "unused":
                unused = self.drop_unused_indexes()
                drop_sqls = self.get_drop_sql(unused)
                return {
                    "success": True,
                    "unused_indexes": unused,
                    "drop_sql": drop_sqls,
                    "count": len(unused)
                }

            elif action == "register_index":
                table = kwargs.get("table", "")
                idx_name = kwargs.get("index_name", "")
                columns = kwargs.get("index_columns", [])
                if not table or not idx_name or not columns:
                    return {"success": False,
                            "error": "table, index_name, index_columns are required parameters"}
                self.register_existing_index(
                    table, idx_name, columns,
                    is_unique=kwargs.get("is_unique", False)
                )
                return {"success": True}

            elif action == "report":
                patterns = self.analyze_query_patterns()
                suggestions = self.recommend_indexes()
                unused = self.drop_unused_indexes()
                tables_no_idx = self.get_tables_without_indexes()

                report = {
                    "tables_analyzed": len(patterns.get("by_table", {})),
                    "queries_analyzed": patterns.get("total_queries", 0),
                    "slow_queries": patterns.get("slow_queries", 0),
                    "full_scans": patterns.get("full_table_scans", 0),
                    "index_usage_ratio": patterns.get("index_usage_ratio", 0),
                    "avg_query_ms": patterns.get("avg_query_time_ms", 0),
                    "suggestions_count": len(suggestions),
                    "top_suggestions": [
                        {"id": s.suggestion_id, "table": s.table,
                         "columns": s.columns,
                         "improvement_pct": s.estimated_improvement_pct,
                         "sql": s.create_sql}
                        for s in suggestions[:5]
                    ],
                    "unused_indexes": unused,
                    "tables_without_indexes": tables_no_idx
                }
                return {"success": True, "report": report}

            else:
                return {"success": False,
                        "error": f"Unsupported action: {action}"}

        except Exception as e:
            logger.error("Index optimization operation failed: %s", e, exc_info=True)
            return {"success": False, "error": str(e)}

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="DatabaseIndexOptimizer",
            type=AnalyzerType.UTILITY,
            version="1.0.0",
            description="Database index optimizer: analyze query patterns, recommend optimal indexes, benchmark improvements, clean up redundant indexes",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["any"]
        )


