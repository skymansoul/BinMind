# 数据血缘追踪: W3C PROV兼容/有向无环图/增量更新/溯源查询
# 参考: Li et al. "Survey of Binary Code Toolchain Provenance Recovery" (CNSSE 2026)
#       PMC-SBOM "Runtime SBOM Verification Using Hardware Performance Counters" (CERIAS 2026)
#       UniBOM "A Unified SBOM Analysis and Visualisation Tool" (arXiv:2511.22359, 2025)
#       Herschel et al. "Provenance for Data: A Survey" (ACM CSUR 2017)
import json, logging, time, hashlib, uuid as _uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any, Iterator
from collections import defaultdict, deque
from pathlib import Path

log = logging.getLogger(__name__)

# W3C PROV兼容数据模型 [PROV-DM 2013]

class ProvType:
    ENTITY     = "entity"       # 数据实体
    ACTIVITY   = "activity"     # 处理活动
    AGENT      = "agent"        # 执行主体 (用户/工具/进程)
    GENERATION = "wasGeneratedBy"     # entity ← activity
    USAGE      = "used"               # activity → entity
    DERIVATION = "wasDerivedFrom"     # entity → entity
    ATTRIBUTION = "wasAttributedTo"   # entity → agent
    ASSOCIATION = "wasAssociatedWith" # activity → agent

@dataclass
class ProvNode:
    node_id: str
    node_type: str  # entity | activity | agent
    label: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

@dataclass
class ProvEdge:
    edge_id: str
    edge_type: str  # wasGeneratedBy | used | wasDerivedFrom | wasAttributedTo | wasAssociatedWith
    source_id: str
    target_id: str
    properties: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

@dataclass
class ProvGraph:
    nodes: Dict[str, ProvNode] = field(default_factory=dict)
    edges: List[ProvEdge] = field(default_factory=list)
    adj: Dict[str, Dict[str, List[ProvEdge]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(list)))


# 血缘追踪器

class DataLineageTracker:
    # W3C PROV兼容: entity/activity/agent + wasGeneratedBy/used/wasDerivedFrom
    # 查询: upstream(溯源)/downstream(影响分析)/impact_analysis
    def __init__(self, storage_path: str = ".binmind_lineage/lineage.json"):
        self.graph = ProvGraph()
        self._storage = Path(storage_path)
        self._storage.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    # 记录方法
    def record_entity(self, entity_id: str, label: str = "",
                      agent_id: str = None, **properties) -> ProvNode:
        node = ProvNode(entity_id, ProvType.ENTITY, label=label,
                        properties=properties)
        self.graph.nodes[entity_id] = node
        if agent_id:
            self._edge(ProvType.ATTRIBUTION, entity_id, agent_id)
        self._save(); return node

    def record_activity(self, activity_id: str, label: str = "",
                        inputs: List[str] = None, outputs: List[str] = None,
                        agent_id: str = None, **properties) -> ProvNode:
        node = ProvNode(activity_id, ProvType.ACTIVITY, label=label,
                        properties=properties)
        self.graph.nodes[activity_id] = node
        for inp in (inputs or []):
            if inp in self.graph.nodes:
                self._edge(ProvType.USAGE, activity_id, inp)
        for out in (outputs or []):
            self._edge(ProvType.GENERATION, out, activity_id)
        if agent_id:
            self._edge(ProvType.ASSOCIATION, activity_id, agent_id)
        self._save(); return node

    def record_agent(self, agent_id: str, label: str = "",
                     agent_type: str = "tool", **properties) -> ProvNode:
        node = ProvNode(agent_id, ProvType.AGENT, label=label,
                        properties={**properties, 'agent_type': agent_type})
        self.graph.nodes[agent_id] = node
        self._save(); return node

    def record_derivation(self, derived_id: str, source_id: str, **properties):
        """实体派生关系: derived ← source."""
        if derived_id in self.graph.nodes and source_id in self.graph.nodes:
            self._edge(ProvType.DERIVATION, derived_id, source_id,
                       properties=properties)
            self._save()

    def _edge(self, etype: str, source: str, target: str, **kw):
        eid = hashlib.sha256(f"{etype}:{source}:{target}:{time.time()}".encode()).hexdigest()[:16]
        edge = ProvEdge(eid, etype, source, target, properties=kw.get('properties', {}))
        self.graph.edges.append(edge)
        self.graph.adj[source][etype].append(edge)

    # 查询方法
    def upstream(self, entity_id: str, max_depth: int = 10) -> List[Dict]:
        """向前追溯: BFS over reversed edges."""
        visited = set(); result = []
        q = deque([(entity_id, 0)])
        while q:
            nid, depth = q.popleft()
            if nid in visited or depth > max_depth:
                continue
            visited.add(nid)
            node = self.graph.nodes.get(nid)
            if node:
                result.append({'node_id': nid, 'type': node.node_type,
                               'label': node.label, 'depth': depth})

            # 反向边: 谁生成了它? 谁使用了它?
            for e in self.graph.edges:
                if e.source_id == nid and e.target_id not in visited:
                    q.append((e.target_id, depth + 1))
                elif e.edge_type == ProvType.GENERATION and e.target_id == nid:
                    if e.source_id not in visited:
                        q.append((e.source_id, depth + 1))
        return result

    def downstream(self, entity_id: str, max_depth: int = 10) -> List[Dict]:
        """向后追溯: 下游产物."""
        visited = set(); result = []
        q = deque([(entity_id, 0)])
        while q:
            nid, depth = q.popleft()
            if nid in visited or depth > max_depth:
                continue
            visited.add(nid)
            node = self.graph.nodes.get(nid)
            if node:
                result.append({'node_id': nid, 'type': node.node_type,
                               'label': node.label, 'depth': depth})
            # 正向边
            for e in self.graph.adj.get(nid, {}).get(ProvType.GENERATION, []):
                if e.source_id not in visited and e.source_id != nid:
                    q.append((e.source_id, depth + 1))
            for e in self.graph.adj.get(nid, {}).get(ProvType.USAGE, []):
                if e.target_id not in visited:
                    q.append((e.target_id, depth + 1))
        return result

    def impact_analysis(self, changed_entity_id: str) -> Dict:
        """影响分析: 实体变更后列出需重新生成的产物."""
        downstream_all = self.downstream(changed_entity_id, max_depth=20)
        impacted_entities = [d for d in downstream_all
                             if d['type'] == ProvType.ENTITY and d['node_id'] != changed_entity_id]
        impacted_activities = [d for d in downstream_all if d['type'] == ProvType.ACTIVITY]
        return {
            'changed_entity': changed_entity_id,
            'impacted_entities': impacted_entities,
            'impacted_activities': impacted_activities,
            'total_impacted': len(impacted_entities) + len(impacted_activities)
        }

    def export_prov_json(self) -> Dict:
        """W3C PROV-JSON格式导出."""
        entities = {}
        activities = {}
        agents = {}

        for nid, node in self.graph.nodes.items():
            obj = {f"prov:{nid}": {"prov:label": node.label, **node.properties}}
            if node.node_type == ProvType.ENTITY:
                entities.update(obj)
            elif node.node_type == ProvType.ACTIVITY:
                activities.update(obj)
            elif node.node_type == ProvType.AGENT:
                agents.update(obj)

        relations = []
        for e in self.graph.edges:
            rel = {f"prov:{e.edge_type}": {"prov:entity": f"prov:{e.source_id}",
                                            "prov:activity": f"prov:{e.target_id}"}}
            relations.append(rel)

        return {
            "prefix": {"prov": "http://www.w3.org/ns/prov#", "ex": "http://example.org/"},
            "entity": entities, "activity": activities, "agent": agents,
            "wasGeneratedBy": {}, "used": {},
            "wasDerivedFrom": {},
            "wasAttributedTo": {}, "wasAssociatedWith": {}
        }

    def get_lineage_graph(self) -> Dict:
        """简单图结构，适合前端可视化."""
        graph_nodes = []
        for nid, node in self.graph.nodes.items():
            graph_nodes.append({
                'id': nid, 'type': node.node_type,
                'label': node.label or nid, 'properties': node.properties})
        graph_edges = []
        for e in self.graph.edges:
            graph_edges.append({
                'id': e.edge_id, 'source': e.source_id, 'target': e.target_id,
                'type': e.edge_type, 'timestamp': e.timestamp})
        return {'nodes': graph_nodes, 'edges': graph_edges}

    def _save(self):
        try:
            data = {
                'nodes': {nid: {'node_type': n.node_type, 'label': n.label,
                                 'properties': n.properties, 'created_at': n.created_at}
                          for nid, n in self.graph.nodes.items()},
                'edges': [{'edge_id': e.edge_id, 'edge_type': e.edge_type,
                           'source': e.source_id, 'target': e.target_id,
                           'properties': e.properties, 'timestamp': e.timestamp}
                          for e in self.graph.edges]
            }
            with open(self._storage, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except (OSError, TypeError) as e:
            log.debug("血缘保存失败: %s", e)

    def _load(self):
        if not self._storage.exists():
            return
        try:
            with open(self._storage, encoding='utf-8') as f:
                data = json.load(f)
            for nid, nd in data.get('nodes', {}).items():
                self.graph.nodes[nid] = ProvNode(
                    nid, nd['node_type'], nd.get('label', ''),
                    nd.get('properties', {}), nd.get('created_at', 0))
            for ed in data.get('edges', []):
                e = ProvEdge(ed['edge_id'], ed['edge_type'],
                             ed['source'], ed['target'],
                             ed.get('properties', {}), ed.get('timestamp', 0))
                self.graph.edges.append(e)
                self.graph.adj[e.source_id][e.edge_type].append(e)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            log.debug("血缘加载异常: %s", e)

    def clear(self):
        self.graph = ProvGraph()
        log.info("血缘已清空")


# 与分析管道集成

class PipelineLineageHook:
    """血缘钩子: 管道每阶段自动记录数据流动.

    用法:
      hook = PipelineLineageHook(tracker)
      with hook.stage('disassembly', inputs=['binary.elf'], outputs=['functions.json']):
          disassemble('binary.elf', 'functions.json')
    """

    def __init__(self, tracker: DataLineageTracker = None, agent_name: str = "binmind"):
        self.tracker = tracker or DataLineageTracker()
        self.agent_name = agent_name
        if agent_name not in self.tracker.graph.nodes:
            self.tracker.record_agent(agent_name, label="BinMind Analysis Engine",
                                       agent_type="tool", version="1.7")

    def stage(self, stage_name: str, inputs: List[str] = None,
              outputs: List[str] = None):
        """上下文管理器: 自动记录活动和I/O关系."""
        return _StageContext(self.tracker, stage_name, inputs or [],
                             outputs or [], self.agent_name)


class _StageContext:
    def __init__(self, tracker, name, inputs, outputs, agent):
        self.tracker = tracker; self.name = name
        self.inputs = inputs; self.outputs = outputs; self.agent = agent

    def __enter__(self):
        # 确保输入实体已注册
        for inp in self.inputs:
            if inp not in self.tracker.graph.nodes:
                self.tracker.record_entity(inp, label=inp, agent_id=self.agent)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        activity_id = f"activity:{self.name}:{time.time()}"
        self.tracker.record_activity(
            activity_id, label=self.name,
            inputs=self.inputs, outputs=self.outputs,
            agent_id=self.agent
        )
        # 派生关系: output ← input
        for out in self.outputs:
            if out not in self.tracker.graph.nodes:
                self.tracker.record_entity(out, label=out, agent_id=self.agent)
            for inp in self.inputs:
                self.tracker.record_derivation(out, inp)
        return False


# 全局单例
_lineage_tracker: DataLineageTracker = None

def get_lineage_tracker() -> DataLineageTracker:
    global _lineage_tracker
    if _lineage_tracker is None:
        _lineage_tracker = DataLineageTracker()
    return _lineage_tracker
