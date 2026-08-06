# GRL-Sched 第一层: 任务依赖图建模 (TaskDependencyGraph)
#
# 将通用分布式任务表示为有向无环图:
#   节点 = 任务/流水线阶段
#   边 = 数据依赖/控制依赖
#   边权 = 预估通信代价 (跨机器传输)
#   节点属性 exec_time = 预估执行时间
#
# 设计意图:
#   - 从 Task 列表 (src/models.py) 或 Pipeline (src/pipeline.py) 无侵入抽取依赖
#   - 提供拓扑序/层级/关键路径等图结构原语，供划分器与调度器共用
#   - 提供固定维度节点特征矩阵，供 GNN 编码器 (grl_scheduler.GNNEncoder) 聚合
#   - 全部纯标准库实现，无 numpy/torch 依赖
#   - DAG 调度是组合优化中的经典问题 (P|prec|Cmax 的 NP-hardness 见
#     Ullman 1975; 列表调度与 HEFT 见 Topcuoglu et al. 2002, IEEE TPDS)
#
# 边界条件:
#   - 重复节点/自环/双向边会破坏 DAG 不变量，构造时显式防护
#   - 环检测委托给 topological_sort，出现环抛 ValueError

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple

# 节点特征固定维度 — 顺序与 GNNEncoder 的输入投影对齐
_FEATURE_KEYS = (
    "exec_time", "priority", "comm_in", "comm_out",
    "out_degree", "in_degree", "level", "is_fanout",
)


@dataclass
class TaskNode:
    """依赖图节点 — 对应一个任务或流水线阶段。

    exec_time:  预估执行时间 (调度/关键路径的权重)
    comm_weight: 节点自身的通信量 (与边权 comm_cost 语义区分，保留扩展位)
    features:    缓存的特征向量 (由 node_features_matrix 填充)
    """
    node_id: str
    label: str = ""
    exec_time: float = 1.0
    comm_weight: float = 1.0
    priority: float = 0.0
    kind: str = "task"          # task | stage
    features: List[float] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DependencyEdge:
    """依赖边 — src 完成后 dst 方可就绪。

    comm_cost: 预估通信代价 (跨分区传输耗时，同分区忽略)
    kind:      data=数据依赖 / control=控制依赖
    """
    src: str
    dst: str
    comm_cost: float = 1.0
    kind: str = "data"


class TaskDependencyGraph:
    """有向无环任务依赖图。

    对外原语:
      add_node / add_edge / successors / predecessors / edge_weight
      topological_sort / levels / critical_path / ancestors / descendants
      node_features_matrix / adjacency_list   (供 GNN 与划分器)
      from_tasks / from_pipeline / to_dict / from_dict
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, TaskNode] = {}
        self._out: Dict[str, List[DependencyEdge]] = {}
        self._in: Dict[str, List[DependencyEdge]] = {}
        self._order: List[str] = []   # 插入顺序，保证稳定迭代

    # ---- 构建 ----

    def add_node(self, node: TaskNode) -> "TaskDependencyGraph":
        if node.node_id in self._nodes:
            raise ValueError(f"duplicate node id: {node.node_id}")
        self._nodes[node.node_id] = node
        self._out[node.node_id] = []
        self._in[node.node_id] = []
        self._order.append(node.node_id)
        return self

    def add_edge(self, src: str, dst: str, comm_cost: float = 1.0,
                 kind: str = "data") -> "TaskDependencyGraph":
        if src not in self._nodes or dst not in self._nodes:
            raise KeyError(f"edge endpoints must exist: {src!r}->{dst!r}")
        if src == dst:
            raise ValueError(f"self-loop edge is forbidden: {src!r}")
        # 重复边按覆盖语义更新权值，避免累计权重偏差
        for e in self._out[src]:
            if e.dst == dst:
                e.comm_cost = comm_cost
                e.kind = kind
                return self
        edge = DependencyEdge(src, dst, comm_cost, kind)
        self._out[src].append(edge)
        self._in[dst].append(edge)
        return self

    # ---- 查询 ----

    @property
    def node_ids(self) -> List[str]:
        return list(self._order)

    @property
    def nodes(self) -> List[TaskNode]:
        return [self._nodes[n] for n in self._order]

    @property
    def edge_count(self) -> int:
        return sum(len(v) for v in self._out.values())

    def node(self, node_id: str) -> Optional[TaskNode]:
        return self._nodes.get(node_id)

    def successors(self, node_id: str) -> List[str]:
        return [e.dst for e in self._out.get(node_id, [])]

    def predecessors(self, node_id: str) -> List[str]:
        return [e.src for e in self._in.get(node_id, [])]

    def edge_weight(self, src: str, dst: str) -> float:
        for e in self._out.get(src, []):
            if e.dst == dst:
                return e.comm_cost
        return 0.0

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, node_id: str) -> bool:
        return node_id in self._nodes

    # ---- 图原语 ----

    def topological_sort(self) -> List[str]:
        """Kahn 算法求拓扑序 — 就绪队列按插入序，保证确定性。

        若图含环则 len(result) < 节点数，抛 ValueError。
        """
        in_deg = {n: len(self._in[n]) for n in self._order}
        ready = deque(n for n in self._order if in_deg[n] == 0)
        result: List[str] = []
        while ready:
            nid = ready.popleft()
            result.append(nid)
            for e in self._out[nid]:
                in_deg[e.dst] -= 1
                if in_deg[e.dst] == 0:
                    ready.append(e.dst)
        if len(result) != len(self._order):
            raise ValueError("task dependency graph contains a cycle")
        return result

    def is_acyclic(self) -> bool:
        try:
            self.topological_sort()
            return True
        except ValueError:
            return False

    def levels(self) -> Dict[str, int]:
        """节点层级: level(v) = max(level(pred))+1, 根节点为 0。

        分层是动态图划分的基础 — 同层节点理论上可并行，
        跨层边构成候选割边 (对应 GraphEdge 中跨设备张量通信)。
        """
        topo = self.topological_sort()
        level = {n: 0 for n in self._order}
        for nid in topo:
            for e in self._out[nid]:
                if level[nid] + 1 > level[e.dst]:
                    level[e.dst] = level[nid] + 1
        return level

    def critical_path(self) -> float:
        """关键路径长度 — 最长 源→汇 的加权和 (exec_time)。

        作为 makespan 的理论下界，也是 HEFT 排级与 RL 奖励基准。
        """
        topo = self.topological_sort()
        dist = {n: self._nodes[n].exec_time for n in self._order}
        for nid in topo:
            base = dist[nid]
            for e in self._out[nid]:
                cand = base + self._nodes[e.dst].exec_time
                if cand > dist[e.dst]:
                    dist[e.dst] = cand
        return max(dist.values()) if dist else 0.0

    def ancestors(self, node_id: str) -> set:
        """沿反向边回溯全部祖先 — 供 SA 邻域合法性判断。"""
        seen = set()
        stack = [e.src for e in self._in.get(node_id, [])]
        while stack:
            nid = stack.pop()
            if nid in seen:
                continue
            seen.add(nid)
            stack.extend(e.src for e in self._in.get(nid, []))
        return seen

    def descendants(self, node_id: str) -> set:
        """沿正向边遍历全部后代 — 供局部重划分圈定影响域。"""
        seen = set()
        stack = [e.dst for e in self._out.get(node_id, [])]
        while stack:
            nid = stack.pop()
            if nid in seen:
                continue
            seen.add(nid)
            stack.extend(e.dst for e in self._out.get(nid, []))
        return seen

    # ---- 特征矩阵 (GNN 编码输入) ----

    def node_features_matrix(self) -> Tuple[List[List[float]], List[str]]:
        """构造 (n, d=8) 特征矩阵，d 与 _FEATURE_KEYS 对齐。

        各维先做图内归一化，避免执行时间/通信量级差异淹没特征信号；
        level 与 fanout 提供结构与并行性先验。
        每次调用重算 (拓扑序+统计) — 图规模通常 < 1e3，开销可接受。
        """
        ids = self._order
        n = len(ids)
        level = self.levels()
        comm_in = [0.0] * n
        comm_out = [0.0] * n
        for i, nid in enumerate(ids):
            comm_in[i] = sum(e.comm_cost for e in self._in[nid])
            comm_out[i] = sum(e.comm_cost for e in self._out[nid])

        exec_max = max((self._nodes[x].exec_time for x in ids), default=1.0) or 1.0
        comm_max = max(comm_in + comm_out, default=1.0) or 1.0
        prio_max = max((abs(self._nodes[x].priority) for x in ids), default=1.0) or 1.0
        max_level = max(level.values(), default=1) or 1

        feats: List[List[float]] = []
        for i, nid in enumerate(ids):
            nd = self._nodes[nid]
            feats.append([
                nd.exec_time / exec_max,
                (nd.priority / prio_max + 1.0) / 2.0,   # 归一化到 [0,1]
                comm_in[i] / comm_max,
                comm_out[i] / comm_max,
                len(self._out[nid]) / max(n, 1),
                len(self._in[nid]) / max(n, 1),
                level[nid] / max_level,
                1.0 if nd.metadata.get("is_fanout") else 0.0,
            ])
        return feats, ids

    def adjacency_list(self) -> List[Tuple[int, int, float]]:
        """边表 [(src_idx, dst_idx, comm_cost)] — 供划分器/编码器索引。"""
        idx = {nid: i for i, nid in enumerate(self._order)}
        edges = []
        for nid in self._order:
            for e in self._out[nid]:
                edges.append((idx[nid], idx[e.dst], e.comm_cost))
        return edges

    # ---- 构造器 ----

    @classmethod
    def from_tasks(cls, tasks: List[Any], default_exec: float = 1.0) -> "TaskDependencyGraph":
        """从 Task 列表构建 DAG。

        依赖来源:
          - Task.parent_id        → data 边 (数据依赖)
          - payload.depends_on    → control 边 (显式声明)
        权重估计:
          - exec_time: payload.exec_time 或 default_exec
          - comm_cost: payload.comm_cost 或 1.0
        Task 同时兼容 dict 与 dataclass (见 _task_* 帮助函数)。
        """
        g = cls()
        for t in tasks:
            tid = _task_id(t)
            payload = _task_payload(t)
            g.add_node(TaskNode(
                node_id=tid,
                label=str(tid),
                exec_time=float(payload.get("exec_time", default_exec)),
                comm_weight=float(payload.get("comm_cost", 1.0)),
                priority=_task_priority(t),
                kind="task",
                metadata={
                    "is_fanout": bool(payload.get("fan_out_n", 1) or 1) and bool(
                        payload.get("fan_out_n", 1) or 1) > 1,
                },
            ))
        for t in tasks:
            tid = _task_id(t)
            parent = _task_parent(t)
            if parent and str(parent) in g._nodes:
                g.add_edge(str(parent), tid, comm_cost=1.0, kind="data")
            payload = _task_payload(t)
            for dep in (payload.get("depends_on") or []):
                if str(dep) in g._nodes:
                    g.add_edge(str(dep), tid, comm_cost=1.0, kind="control")
        return g

    @classmethod
    def from_pipeline(cls, pipeline, default_exec: float = 1.0) -> "TaskDependencyGraph":
        """从 src.pipeline.Pipeline 构建 DAG。

        - Stage.depends_on → control 边
        - Stage.fan_out_n > 1 → 展开为 N 个并行子节点 (后缀 #i)，标记 is_fanout
        - exec_time: Stage.timeout (或 default_exec)
        fan-out 依赖展开: 前置 fan-out 源的每个分片都连到目标节点。
        """
        g = cls()
        stages = list(pipeline.stages)
        # 第一遍注册节点 (含 fan-out 展开)
        for s in stages:
            n = s.fan_out_n or 1
            if n > 1:
                for i in range(n):
                    nid = f"{s.name}#{i}"
                    g.add_node(TaskNode(
                        nid, label=s.name, exec_time=float(s.timeout or default_exec),
                        kind="stage", metadata={"is_fanout": True},
                    ))
            else:
                g.add_node(TaskNode(
                    s.name, label=s.name, exec_time=float(s.timeout or default_exec),
                    kind="stage",
                ))
        # 第二遍建边 — 解析 depends_on 到展开后的节点
        name_to_nodes: Dict[str, List[str]] = {}
        for s in stages:
            n = s.fan_out_n or 1
            name_to_nodes[s.name] = (
                [f"{s.name}#{i}" for i in range(n)] if n > 1 else [s.name]
            )
        for s in stages:
            targets = name_to_nodes[s.name]
            for dep in s.depends_on:
                for dt in name_to_nodes.get(dep, []):
                    for tt in targets:
                        if dt != tt:
                            g.add_edge(dt, tt, comm_cost=1.0, kind="control")
        return g

    # ---- 序列化 ----

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {"node_id": nd.node_id, "label": nd.label,
                 "exec_time": nd.exec_time, "comm_weight": nd.comm_weight,
                 "priority": nd.priority, "kind": nd.kind,
                 "metadata": dict(nd.metadata)}
                for nd in self.nodes
            ],
            "edges": [
                {"src": e.src, "dst": e.dst, "comm_cost": e.comm_cost, "kind": e.kind}
                for nid in self._order for e in self._out[nid]
            ],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TaskDependencyGraph":
        g = cls()
        for nd in d.get("nodes", []):
            g.add_node(TaskNode(
                node_id=nd["node_id"],
                label=nd.get("label", nd["node_id"]),
                exec_time=float(nd.get("exec_time", 1.0)),
                comm_weight=float(nd.get("comm_weight", 1.0)),
                priority=float(nd.get("priority", 0.0)),
                kind=nd.get("kind", "task"),
                metadata=dict(nd.get("metadata", {})),
            ))
        for e in d.get("edges", []):
            g.add_edge(e["src"], e["dst"], float(e.get("comm_cost", 1.0)),
                       e.get("kind", "data"))
        return g

    def __repr__(self) -> str:
        return f"TaskDependencyGraph(nodes={len(self._nodes)}, edges={self.edge_count})"


# ---- Task 访问帮助函数 (兼容 dict 与 dataclass 两种任务表示) ----

def _task_id(t: Any) -> str:
    if isinstance(t, dict):
        return str(t.get("id", ""))
    return str(getattr(t, "id", ""))


def _task_parent(t: Any) -> Optional[str]:
    if isinstance(t, dict):
        return t.get("parent_id")
    return getattr(t, "parent_id", None)


def _task_payload(t: Any) -> dict:
    if isinstance(t, dict):
        return t.get("payload", {}) or {}
    return getattr(t, "payload", None) or {}


def _task_priority(t: Any) -> float:
    if isinstance(t, dict):
        return float(t.get("priority", 0) or 0)
    return float(getattr(t, "priority", 0) or 0)


def _task_exec(t: Any, default: float = 1.0) -> float:
    return float(_task_payload(t).get("exec_time", default))


def _task_comm(t: Any, default: float = 1.0) -> float:
    return float(_task_payload(t).get("comm_cost", default))
