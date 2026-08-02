# 参数化 SQL 查询构造器 — 不是 ORM，就是个 safe SQL builder
# 不用字符串拼接，所有值通过 ? 占位符传参
# keyset 分页参考 Instagram engineering blog：WHERE id > last_id 走索引
#
# 新增 Mutation 构造器：INSERT / UPDATE / DELETE 的参数化构建，
# 避免手写 SQL 字符串拼接的安全隐患。
#
# GROUP BY + HAVING: 聚合查询的参数化构建。

from typing import List, Tuple, Any, Optional, Dict


class Query:
    """参数化 SELECT 构造器。"""

    def __init__(self, table: str, alias: str = ""):
        self._table = table
        self._alias = alias
        self._select_cols = ["*"]
        self._wheres: List[str] = []
        self._params: List[Any] = []
        self._order: List[str] = []
        self._limit_val: int = 0
        self._offset_val: int = 0
        self._joins: List[Tuple[str, str, str]] = []
        self._group_cols: List[str] = []
        self._having_clauses: List[str] = []
        self._having_params: List[Any] = []

    def select(self, *cols: str) -> "Query":
        self._select_cols = list(cols) if cols else ["*"]
        return self

    def where(self, clause: str, *params: Any) -> "Query":
        self._wheres.append(clause)
        self._params.extend(params)
        return self

    def subquery(self, inner_sql: str, *params: Any, alias: str = "sub") -> "Query":
        """将子查询作为 FROM 源 —— `SELECT * FROM (inner_sql) AS alias`。

        参数化传递：inner_sql 中的 ? 占位符由 params 绑定。
        用于自关联、窗口函数等复杂查询场景。
        """
        self._table = f"({inner_sql})"
        self._alias = alias
        self._params = list(params)
        return self

    def where_in(self, col: str, values: List[Any]) -> "Query":
        if not values:
            self._wheres.append("1=0")
            return self
        placeholders = ", ".join("?" * len(values))
        self._wheres.append(f"{col} IN ({placeholders})")
        self._params.extend(values)
        return self

    def join(self, table: str, on_clause: str, alias: str = "") -> "Query":
        self._joins.append((table, alias, on_clause))
        return self

    def group_by(self, *cols: str) -> "Query":
        self._group_cols.extend(cols)
        return self

    def having(self, clause: str, *params: Any) -> "Query":
        self._having_clauses.append(clause)
        self._having_params.extend(params)
        return self

    def order_by(self, *clauses: str) -> "Query":
        self._order.extend(clauses)
        return self

    def limit(self, n: int) -> "Query":
        self._limit_val = n
        return self

    def offset(self, n: int) -> "Query":
        self._offset_val = n
        return self

    def build(self) -> Tuple[str, List[Any]]:
        parts = [f"SELECT {', '.join(self._select_cols)} FROM {self._table}"]
        if self._alias:
            parts[-1] += f" AS {self._alias}"
        for tbl, als, on_clause in self._joins:
            j = f"JOIN {tbl}"
            if als:
                j += f" AS {als}"
            j += f" ON {on_clause}"
            parts.append(j)
        if self._wheres:
            parts.append("WHERE " + " AND ".join(f"({w})" for w in self._wheres))
        if self._group_cols:
            parts.append("GROUP BY " + ", ".join(self._group_cols))
        if self._having_clauses:
            parts.append("HAVING " + " AND ".join(f"({h})" for h in self._having_clauses))
        if self._order:
            parts.append("ORDER BY " + ", ".join(self._order))
        if self._limit_val > 0:
            parts.append(f"LIMIT {self._limit_val}")
            if self._offset_val > 0:
                parts.append(f"OFFSET {self._offset_val}")
        all_params = list(self._params) + list(self._having_params)
        return " ".join(parts), all_params

    def keyset_paginate(self, key_col: str, last_val: Any, page_size: int = 50) -> "Query":
        """Keyset 分页：用 WHERE key_col > last_val 替换 OFFSET。
        OFFSET 大偏移量性能差，走索引快很多。"""
        self._offset_val = 0
        self._limit_val = 0
        if last_val is not None:
            self._wheres.append(f"{key_col} > ?")
            self._params.append(last_val)
        self._order.insert(0, f"{key_col} ASC")
        self._limit_val = page_size
        return self


class Mutation:
    """参数化 INSERT / UPDATE / DELETE 构造器。"""
    def __init__(self, table: str):
        self._table = table
        self._type = ""
        self._cols: List[str] = []
        self._vals: List[Any] = []
        self._wheres: List[str] = []
        self._wparams: List[Any] = []

    def insert(self, **kwargs) -> "Mutation":
        self._type = "INSERT"
        self._cols = list(kwargs.keys())
        self._vals = list(kwargs.values())
        return self

    def update(self, where_clause: str, *params: Any, **setvals) -> "Mutation":
        self._type = "UPDATE"
        self._cols = list(setvals.keys())
        self._vals = list(setvals.values())
        self._wheres = [where_clause]
        self._wparams = list(params)
        return self

    def delete(self, where_clause: str, *params: Any) -> "Mutation":
        self._type = "DELETE"
        self._wheres = [where_clause]
        self._wparams = list(params)
        return self

    def build(self) -> Tuple[str, List[Any]]:
        if self._type == "INSERT":
            ph = ", ".join("?" * len(self._cols))
            cols = ", ".join(self._cols)
            return f"INSERT INTO {self._table} ({cols}) VALUES ({ph})", list(self._vals)
        elif self._type == "UPDATE":
            sets = ", ".join(f"{c}=?" for c in self._cols)
            where = " AND ".join(f"({w})" for w in self._wheres)
            return f"UPDATE {self._table} SET {sets} WHERE {where}", self._vals + self._wparams
        elif self._type == "DELETE":
            where = " AND ".join(f"({w})" for w in self._wheres)
            return f"DELETE FROM {self._table} WHERE {where}", list(self._wparams)
        raise ValueError("No mutation type set — call insert/update/delete first")


class SignatureQuery(Query):
    """签名表专用的构造器。"""

    def __init__(self):
        super().__init__("signatures")

    def by_stage(self, stage: str) -> "SignatureQuery":
        return self.where("stage = ?", stage)

    def by_tags(self, tags: List[str]) -> "SignatureQuery":
        for tag in tags:
            self.where("tags LIKE ?", f"%{tag}%")
        return self

    def by_date_range(self, start_ts: float, end_ts: float) -> "SignatureQuery":
        return self.where("registered_at BETWEEN ? AND ?", start_ts, end_ts)
