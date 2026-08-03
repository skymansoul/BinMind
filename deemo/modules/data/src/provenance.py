# 数据溯源追踪 — W3C PROV 模型 + lineage DAG
# 审计二进制签名完整溯源链: 谁、何时、通过何种工具处理数据。
# W3C PROV-DM [Moreau et al. 2013] 核心三元组:
#   Entity → Activity → Agent, 含 attribution/derivation/generation 关系。
# 补充文献:
#   Vestige — 二进制代码来源识别系统，与本模块 provenance chain 对应:
#     从编译工具链/源码库/第三方组件的 provenance 追溯漏洞源头。
#   CBTracer [Kim et al., ASIA CCS 2018] — 持续数据集构建
#     中的 data lineage 追踪。
#   Arbiter — 静态/动态分析的混合 provenance。
#
# 存储模型: SQLite 中 prov_nodes + prov_edges 两张表，
# 节点类型: entity | activity | agent，边类型: used | wasGeneratedBy |
#   wasAttributedTo | wasDerivedFrom | wasInformedBy。
# 查询接口支持 DAG 遍历: 上游溯源 (回溯至最早输入) 和
#   下游影响分析 (前向追踪某 entity 影响到的后续产物)。
#
# 冷存储溯源视角 [AVS, arXiv:2511.19453 [待验证]]: 数据从热层迁至冷层时，
# provenance 记录迁移操作 + 压缩策略，使下游可还原数据处理链。

import time
from typing import Dict, List, Optional, Any, Set


class ProvNode:
    """PROV 图节点 —— Entity / Activity / Agent 统一表示。"""
    __slots__ = ("node_id", "node_type", "name", "attrs")

    def __init__(self, node_id: str, ntype: str, name: str = "",
                 attrs: dict = None):
        self.node_id = node_id
        self.node_type = ntype    # 'entity', 'activity', 'agent'
        self.name = name
        self.attrs = attrs or {}

    def to_dict(self):
        return {"id": self.node_id, "type": self.node_type,
                "name": self.name, "attrs": self.attrs}


class ProvEdge:
    """PROV 图有向边 —— 关系类型固定为 W3C PROV-DM 标准。"""
    __slots__ = ("src", "tgt", "rel_type", "timestamp", "meta")

    def __init__(self, src: str, tgt: str, rel_type: str,
                 timestamp: float = 0.0, meta: dict = None):
        self.src = src
        self.tgt = tgt
        self.rel_type = rel_type
        self.timestamp = timestamp or time.time()
        self.meta = meta or {}

    def to_dict(self):
        return {"src": self.src, "tgt": self.tgt, "type": self.rel_type,
                "ts": self.timestamp, "meta": self.meta}


class ProvenanceGraph:
    """有向无环图 (DAG) 表达 provenance。

    不去重接受所有节点/边，遍历基于邻接表 BFS/DFS。
    图本身不持久化 —— 由 ProvenanceTracker 负责 DB 存储。
    """

    def __init__(self):
        self._nodes: Dict[str, ProvNode] = {}
        self._edges: List[ProvEdge] = []
        self._adj_out: Dict[str, List[ProvEdge]] = {}   # src → edges
        self._adj_in: Dict[str, List[ProvEdge]] = {}    # tgt → edges

    def add_node(self, node: ProvNode):
        self._nodes[node.node_id] = node
        self._adj_out.setdefault(node.node_id, [])
        self._adj_in.setdefault(node.node_id, [])

    def add_edge(self, edge: ProvEdge):
        self._edges.append(edge)
        self._adj_out.setdefault(edge.src, []).append(edge)
        self._adj_in.setdefault(edge.tgt, []).append(edge)

    def node(self, nid: str) -> Optional[ProvNode]:
        return self._nodes.get(nid)

    def trace_upstream(self, start_id: str, max_depth: int = 20) -> List[ProvNode]:
        """BFS 上游溯源 —— 从 start_id 沿 used / wasDerivedFrom
        回溯所有 input entity 和 activity 节点 (逆拓扑序)。"""
        seen: Set[str] = set()
        result: List[ProvNode] = []
        queue = [(start_id, 0)]
        while queue:
            cur, depth = queue.pop(0)
            if depth > max_depth or cur in seen:
                continue
            seen.add(cur)
            node = self._nodes.get(cur)
            if node is not None:
                result.append(node)
            for e in self._adj_in.get(cur, []):
                if e.src not in seen:
                    queue.append((e.src, depth + 1))
        return result

    def trace_downstream(self, start_id: str, max_depth: int = 20) -> List[ProvNode]:
        """BFS 下游影响追踪 —— 从 start_id 沿 wasGeneratedBy /
        wasDerivedFrom 找所有受影响产物。"""
        seen: Set[str] = set()
        result: List[ProvNode] = []
        q = [(start_id, 0)]
        while q:
            cur, depth = q.pop(0)
            if depth > max_depth or cur in seen:
                continue
            seen.add(cur)
            node = self._nodes.get(cur)
            if node is not None:
                result.append(node)
            for e in self._adj_out.get(cur, []):
                if e.tgt not in seen:
                    q.append((e.tgt, depth + 1))
        return result

    def to_prov_json(self) -> dict:
        """导出为 W3C PROV-JSON 格式。"""
        return {
            "prefix": {"prov": "http://www.w3.org/ns/prov#",
                       "bm": "http://binmind.local/prov#"},
            "entity": {n.node_id: {"prov:label": n.name, **n.attrs}
                       for n in self._nodes.values() if n.node_type == "entity"},
            "activity": {n.node_id: {"prov:label": n.name, **n.attrs}
                         for n in self._nodes.values() if n.node_type == "activity"},
            "agent": {n.node_id: {"prov:label": n.name, **n.attrs}
                      for n in self._nodes.values() if n.node_type == "agent"},
            "wasGeneratedBy": _prov_edges_to_json(self._edges, "wasGeneratedBy"),
            "used": _prov_edges_to_json(self._edges, "used"),
            "wasDerivedFrom": _prov_edges_to_json(self._edges, "wasDerivedFrom"),
            "wasAttributedTo": _prov_edges_to_json(self._edges, "wasAttributedTo"),
        }

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)


def _prov_edges_to_json(edges: List[ProvEdge], rel: str) -> dict:
    result = {}
    for i, e in enumerate(edges):
        if e.rel_type == rel:
            result[f"_{i}"] = {
                "prov:entity": e.tgt if rel == "wasGeneratedBy" else e.src,
                "prov:activity": e.src if rel in ("wasGeneratedBy", "used") else "",
                "prov:time": e.timestamp,
            }
    return result


# ---------------------------------------------------------------------------
# ProvenanceTracker — 与 DataDB 集成
# ---------------------------------------------------------------------------

class ProvenanceTracker:
    """DB-backed provenance 追踪器 —— 数据进出各处理步骤时记录 provenance 关系。

    用法:
      tracker = ProvenanceTracker(db)
      tracker.record_import(sig_id, file_path, agent="cli_import")
      tracker.record_analysis(sig_id, tool_name, findings_count)
      tracker.record_transition(sig_id, "raw", "analysis")
      chain = tracker.get_provenance_chain(sig_id)
    """

    def __init__(self, db):
        self._db = db
        self._init_tables()

    def _init_tables(self):
        conn = self._db.get_connection()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS prov_nodes (
                node_id TEXT PRIMARY KEY,
                node_type TEXT NOT NULL,
                name TEXT DEFAULT '',
                attrs TEXT DEFAULT '{}',
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS prov_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_id TEXT NOT NULL,
                tgt_id TEXT NOT NULL,
                rel_type TEXT NOT NULL,
                timestamp REAL NOT NULL,
                meta TEXT DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_prov_edges_src ON prov_edges(src_id);
            CREATE INDEX IF NOT EXISTS idx_prov_edges_tgt ON prov_edges(tgt_id);
        """)
        conn.commit()

    def record_import(self, sig_id: int, file_path: str,
                      agent: str = "cli_import", metadata: dict = None) -> str:
        """导入文件时的 provenance 记录。

        构建路径: Entity(sig) ← wasGeneratedBy ← Activity(import_file) ← used ← Entity(file)
        """
        import json
        now = time.time()
        conn = self._db.get_connection()

        fe_id = f"file:{_hash_str(file_path)}"
        sig_eid = f"sig:{sig_id}"
        act_id = f"act:import_{sig_id}_{int(now)}"
        ag_id = f"agent:{agent}"

        conn.execute(
            "INSERT OR IGNORE INTO prov_nodes VALUES(?,?,?,?,?)",
            (fe_id, "entity", file_path, json.dumps({"path": file_path}), now))
        conn.execute(
            "INSERT OR IGNORE INTO prov_nodes VALUES(?,?,?,?,?)",
            (sig_eid, "entity", f"signature_{sig_id}",
             json.dumps(metadata or {}), now))
        conn.execute(
            "INSERT OR IGNORE INTO prov_nodes VALUES(?,?,?,?,?)",
            (act_id, "activity", f"import_file",
             json.dumps({"sig_id": sig_id}), now))
        conn.execute(
            "INSERT OR IGNORE INTO prov_nodes VALUES(?,?,?,?,?)",
            (ag_id, "agent", agent, "{}", now))

        conn.execute(
            "INSERT INTO prov_edges VALUES(NULL,?,?,?,?,?)",
            (act_id, sig_eid, "wasGeneratedBy", now, "{}"))
        conn.execute(
            "INSERT INTO prov_edges VALUES(NULL,?,?,?,?,?)",
            (act_id, fe_id, "used", now, "{}"))
        conn.execute(
            "INSERT INTO prov_edges VALUES(NULL,?,?,?,?,?)",
            (act_id, ag_id, "wasAttributedTo", now, "{}"))
        conn.commit()
        return sig_eid

    def record_analysis(self, sig_id: int, tool_name: str,
                        findings_count: int = 0,
                        agent: str = "binmind_scanner") -> str:
        """记录分析结果 —— analysis activity 产出 findings entity。"""
        import json
        now = time.time()
        conn = self._db.get_connection()
        sig_eid = f"sig:{sig_id}"
        fnd_id = f"findings:{sig_id}_{int(now)}"
        act_id = f"act:analyze_{sig_id}_{int(now)}"
        ag_id = f"agent:{agent}"

        conn.execute("INSERT OR IGNORE INTO prov_nodes VALUES(?,?,?,?,?)",
                     (fnd_id, "entity", f"findings_{tool_name}",
                      json.dumps({"tool": tool_name, "count": findings_count}), now))
        conn.execute("INSERT OR IGNORE INTO prov_nodes VALUES(?,?,?,?,?)",
                     (act_id, "activity", f"analyze",
                      json.dumps({"tool": tool_name}), now))
        conn.execute("INSERT OR IGNORE INTO prov_nodes VALUES(?,?,?,?,?)",
                     (ag_id, "agent", agent, "{}", now))
        conn.execute("INSERT INTO prov_edges VALUES(NULL,?,?,?,?,?)",
                     (act_id, fnd_id, "wasGeneratedBy", now, "{}"))
        conn.execute("INSERT INTO prov_edges VALUES(NULL,?,?,?,?,?)",
                     (act_id, sig_eid, "used", now, "{}"))
        conn.execute("INSERT INTO prov_edges VALUES(NULL,?,?,?,?,?)",
                     (act_id, ag_id, "wasAttributedTo", now, "{}"))
        conn.commit()
        return fnd_id

    def record_transition(self, sig_id: int, from_stage: str,
                          to_stage: str):
        """生命周期迁移的 provenance 记录。"""
        import json
        now = time.time()
        conn = self._db.get_connection()
        act_id = f"act:transition_{sig_id}_{int(now)}"
        conn.execute(
            "INSERT OR IGNORE INTO prov_nodes VALUES(?,?,?,?,?)",
            (act_id, "activity",
             f"stage_transition_{from_stage}_to_{to_stage}",
             json.dumps({"from": from_stage, "to": to_stage}), now))
        conn.execute(
            "INSERT INTO prov_edges VALUES(NULL,?,?,?,?,?)",
            (act_id, f"sig:{sig_id}", "wasGeneratedBy", now, "{}"))
        conn.commit()

    def get_chain(self, sig_id: int) -> ProvenanceGraph:
        """返回包含该签名完整 provenance 链的 DAG。"""
        import json
        conn = self._db.get_connection()
        graph = ProvenanceGraph()
        start = f"sig:{sig_id}"
        # 向上游 BFS
        visited = set()
        queue = [start]
        while queue:
            cur = queue.pop(0)
            if cur in visited:
                continue
            visited.add(cur)
            row = conn.execute(
                "SELECT node_type,name,attrs FROM prov_nodes WHERE node_id=?",
                (cur,)).fetchone()
            if row is not None:
                try:
                    attrs = json.loads(row["attrs"]) if isinstance(row["attrs"], str) else {}
                except Exception:
                    attrs = {}
                graph.add_node(ProvNode(cur, row["node_type"], row["name"], attrs))
            for e_row in conn.execute(
                "SELECT * FROM prov_edges WHERE tgt_id=? OR src_id=?",
                (cur, cur)).fetchall():
                e = ProvEdge(e_row["src_id"], e_row["tgt_id"],
                             e_row["rel_type"], e_row["timestamp"])
                graph.add_edge(e)
                if e_row["src_id"] not in visited:
                    queue.append(e_row["src_id"])
                if e_row["tgt_id"] not in visited:
                    queue.append(e_row["tgt_id"])
        return graph

    def search_by_agent(self, agent: str, limit: int = 100) -> List[dict]:
        """按 agent 反查该操作者处理过的全部产物。"""
        conn = self._db.get_connection()
        rows = conn.execute("""
            SELECT pn.node_id, pn.name, pe.timestamp FROM prov_nodes pn
            JOIN prov_edges pe ON pe.tgt_id = pn.node_id
            WHERE pe.src_id IN (
                SELECT e.src_id FROM prov_edges e
                WHERE e.tgt_id = ? AND e.rel_type = 'wasAttributedTo'
            )
            AND pn.node_type = 'entity'
            ORDER BY pe.timestamp DESC LIMIT ?
        """, (f"agent:{agent}", limit)).fetchall()
        return [dict(r) for r in rows]

    def recent_activities(self, limit: int = 50) -> List[dict]:
        """最近 N 条 activity —— 供 dashboard 和审计使用。"""
        conn = self._db.get_connection()
        rows = conn.execute(
            "SELECT * FROM prov_nodes WHERE node_type='activity' "
            "ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def export_graph(self, sig_ids: List[int] = None) -> ProvenanceGraph:
        """导出指定签名 ID 列表的完整 provenance 子图。"""
        if sig_ids is None:
            # 默认导出全部
            return self._full_graph()
        graph = ProvenanceGraph()
        for sid in sig_ids:
            sub = self.get_chain(sid)
            for n in sub._nodes.values():
                graph.add_node(n)
            for e in sub._edges:
                graph.add_edge(e)
        return graph

    def _full_graph(self) -> ProvenanceGraph:
        import json
        conn = self._db.get_connection()
        graph = ProvenanceGraph()
        for row in conn.execute("SELECT * FROM prov_nodes").fetchall():
            try:
                attrs = json.loads(row["attrs"]) if isinstance(row["attrs"], str) else {}
            except Exception:
                attrs = {}
            graph.add_node(ProvNode(row["node_id"], row["node_type"],
                                     row["name"], attrs))
        for row in conn.execute("SELECT * FROM prov_edges").fetchall():
            graph.add_edge(ProvEdge(row["src_id"], row["tgt_id"],
                                     row["rel_type"], row["timestamp"]))
        return graph


def _hash_str(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()[:16]
