# GraphRAG知识检索 — 基于知识图谱的检索增强生成 (适用于威胁情报)
# 依据: KGV 的LLM+KG CTI可信度评估
# GraphRAG Under Fire 的图谱检索安全分析
# Cyber Knowledge Completion
# 核心: 构建CTI知识图谱 → 多跳关系检索 → 上下文增强LLM分析

from __future__ import annotations
import math
import hashlib
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# 数据结构

@dataclass
class KGEntity:
    entity_id: str
    entity_type: str  # vulnerability, threat_actor, malware, campaign, indicator, cve, cwe, attack_pattern
    properties: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[List[float]] = None

@dataclass
class KGRelation:
    source_id: str
    target_id: str
    relation_type: str  # exploits, targets, mitigates, indicates, uses, attributed_to, similar_to
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RetrievalResult:
    query: str
    entities: List[KGEntity]
    paths: List[List[Tuple[KGEntity, KGRelation, KGEntity]]]
    context_text: str
    confidence: float
    source_count: int


# 图索引

class GraphRAGIndex:
    """面向RAG的知识图谱索引

    支持:
      - 基于嵌入的实体检索 (语义搜索)
      - 基于关系链的多跳遍历 (结构化推理)
      - 子图上下文提取 (GraphRAG风格的社区摘要)
    """

    def __init__(self, embed_dim: int = 128):
        self.dim = embed_dim
        self.entities: Dict[str, KGEntity] = {}
        self.relations: List[KGRelation] = []
        # 邻接索引
        self._outgoing: Dict[str, List[int]] = defaultdict(list)  # entity_id -> [relation_idx]
        self._incoming: Dict[str, List[int]] = defaultdict(list)

# CRUD

    def add_entity(self, entity: KGEntity):
        self.entities[entity.entity_id] = entity

    def add_entities_batch(self, entities: List[KGEntity]):
        for e in entities:
            self.add_entity(e)

    def add_relation(self, rel: KGRelation):
        idx = len(self.relations)
        self.relations.append(rel)
        self._outgoing[rel.source_id].append(idx)
        self._incoming[rel.target_id].append(idx)

    def add_relations_batch(self, relations: List[KGRelation]):
        for r in relations:
            self.add_relation(r)

# 检索

    def search_entities(self, query_text: str, top_k: int = 10,
                        entity_type: Optional[str] = None) -> List[Tuple[KGEntity, float]]:
        """基于文本匹配的实体检索 (简化BM25)"""
        query_tokens = set(query_text.lower().split())

        scored = []
        for eid, entity in self.entities.items():
            if entity_type and entity.entity_type != entity_type:
                continue

            # 构建搜索文本
            search_text = f"{entity.entity_type} {' '.join(f'{k}={v}' for k, v in entity.properties.items())}"
            entity_tokens = set(search_text.lower().split())

            if not query_tokens:
                scored.append((entity, 0.0))
                continue

            # Jaccard + 属性精确匹配 bonus
            intersection = query_tokens & entity_tokens
            union = query_tokens | entity_tokens
            jaccard = len(intersection) / max(len(union), 1)

            # 精确匹配bonus
            exact_bonus = 0.0
            for tok in query_tokens:
                if tok in search_text.lower():
                    exact_bonus += 0.05
            exact_bonus = min(exact_bonus, 0.30)

            score = jaccard + exact_bonus
            scored.append((entity, min(score, 1.0)))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def traverse_paths(self, start_entity_id: str,
                       max_hops: int = 3,
                       relation_filter: Optional[List[str]] = None,
                       max_paths: int = 20) -> List[List[Tuple[KGEntity, KGRelation, KGEntity]]]:
        """从起始实体出发的多跳路径遍历 (BFS)"""
        if start_entity_id not in self.entities:
            return []

        paths = []
        # BFS: 每层存储 (entity_id, path_so_far)
        queue = deque()
        queue.append((start_entity_id, []))

        visited_paths = set()

        while queue and len(paths) < max_paths:
            current_id, path = queue.popleft()

            if len(path) >= max_hops:
                if path:  # 记录完整路径
                    paths.append(path)
                continue

            # 从当前节点出发的所有关系
            for rel_idx in self._outgoing.get(current_id, []):
                rel = self.relations[rel_idx]
                next_id = rel.target_id

                if next_id not in self.entities:
                    continue

                # 关系过滤器
                if relation_filter and rel.relation_type not in relation_filter:
                    continue

                # 避免环
                path_ids = tuple(e.entity_id for e, _, _ in path)
                if next_id in path_ids:
                    continue

                new_segment = (self.entities[current_id], rel, self.entities[next_id])
                new_path = path + [new_segment]

                # 去重
                path_key = tuple(e.entity_id for e, _, _ in new_path)
                if path_key not in visited_paths:
                    visited_paths.add(path_key)
                    queue.append((next_id, new_path))

        # 收集剩余的完整路径
        if len(paths) < max_paths and queue:
            remaining = [(p, len(p)) for _, p in queue if p]
            remaining.sort(key=lambda x: x[1], reverse=True)
            for p, _ in remaining[:max_paths - len(paths)]:
                paths.append(p)

        return paths[:max_paths]

    def extract_subgraph_context(self, entity_ids: List[str],
                                  radius: int = 2) -> Tuple[List[KGEntity], List[KGRelation]]:
        """提取给定实体的邻域子图上下文 (GraphRAG社区摘要)"""
        visited_entities: Set[str] = set(entity_ids)
        frontier = set(entity_ids)

        for _ in range(radius):
            next_frontier = set()
            for eid in frontier:
                for rel_idx in self._outgoing.get(eid, []):
                    neighbor = self.relations[rel_idx].target_id
                    if neighbor not in visited_entities:
                        next_frontier.add(neighbor)
                for rel_idx in self._incoming.get(eid, []):
                    neighbor = self.relations[rel_idx].source_id
                    if neighbor not in visited_entities:
                        next_frontier.add(neighbor)
            visited_entities.update(next_frontier)
            frontier = next_frontier

        # 收集实体和关系
        sub_entities = [self.entities[eid] for eid in visited_entities if eid in self.entities]
        sub_relations = [
            r for r in self.relations
            if r.source_id in visited_entities and r.target_id in visited_entities
        ]

        return sub_entities, sub_relations

    def retrieve(self, query: str, top_k: int = 10,
                 max_hops: int = 2, max_paths: int = 15) -> RetrievalResult:
        """完整的GraphRAG检索流程:
          1. 语义搜索匹配初始实体
          2. 从匹配实体出发多跳遍历
          3. 提取子图上下文
          4. 构建上下文文本
        """
        # 实体搜索
        matched = self.search_entities(query, top_k=top_k)

        if not matched:
            return RetrievalResult(
                query=query, entities=[], paths=[],
                context_text='', confidence=0.0, source_count=0,
            )

        entities = [e for e, _ in matched]
        top_scores = [s for _, s in matched]

        # 多跳遍历
        all_paths = []
        for entity in entities[:3]:  # 从top-3出发
            paths = self.traverse_paths(entity.entity_id, max_hops=max_hops,
                                        max_paths=max_paths // 3)
            all_paths.extend(paths)

        # 子图上下文
        top_ids = [e.entity_id for e in entities[:5]]
        sub_entities, sub_relations = self.extract_subgraph_context(top_ids)

        # 构建上下文文本
        context = self._build_context_text(entities, all_paths, sub_entities, sub_relations)

        # 置信度评估
        avg_score = sum(top_scores) / max(len(top_scores), 1) if top_scores else 0.0
        path_bonus = min(len(all_paths) * 0.02, 0.20)
        source_diversity = len(set(e.entity_type for e in entities)) / max(len(entities), 1)
        confidence = avg_score * 0.6 + source_diversity * 0.25 + path_bonus

        return RetrievalResult(
            query=query,
            entities=entities,
            paths=all_paths,
            context_text=context,
            confidence=min(confidence, 1.0),
            source_count=len(sub_entities),
        )

    def _build_context_text(self, entities, paths, sub_entities, sub_relations) -> str:
        parts = []

        # 实体列表
        parts.append("### Matched Entities")
        for e in entities[:10]:
            props = ', '.join(f'{k}={v}' for k, v in list(e.properties.items())[:3])
            parts.append(f"- [{e.entity_type}] {e.entity_id}: {props}")

        # 关系路径
        if paths:
            parts.append("\n### Discovered Paths")
            for pi, path in enumerate(paths[:5]):
                path_str = " -> ".join(
                    f"[{e.entity_type}]{e.entity_id} --({r.relation_type})--> [{n.entity_type}]{n.entity_id}"
                    for e, r, n in path
                )
                parts.append(f"{pi + 1}. {path_str}")

        # 子图统计
        parts.append(f"\n### Subgraph: {len(sub_entities)} entities, {len(sub_relations)} relations")

        return '\n'.join(parts)


# CTI知识图谱种子

def seed_cti_knowledge_graph(index: GraphRAGIndex) -> GraphRAGIndex:
    """预置CTI知识图谱的种子数据 (常见CVE/CWE/攻击模式)"""

    # CWE实体
    cwes = [
        ('CWE-119', 'cwe', {'name': 'Buffer Overflow', 'likelihood': 'high'}),
        ('CWE-416', 'cwe', {'name': 'Use After Free', 'likelihood': 'medium'}),
        ('CWE-20', 'cwe', {'name': 'Improper Input Validation', 'likelihood': 'high'}),
        ('CWE-78', 'cwe', {'name': 'OS Command Injection', 'likelihood': 'medium'}),
        ('CWE-89', 'cwe', {'name': 'SQL Injection', 'likelihood': 'high'}),
        ('CWE-787', 'cwe', {'name': 'Out-of-bounds Write', 'likelihood': 'high'}),
        ('CWE-476', 'cwe', {'name': 'NULL Pointer Dereference', 'likelihood': 'medium'}),
        ('CWE-798', 'cwe', {'name': 'Hardcoded Credentials', 'likelihood': 'medium'}),
    ]
    for eid, etype, props in cwes:
        index.add_entity(KGEntity(entity_id=eid, entity_type=etype, properties=props))

    # 攻击模式 (CAPEC)
    capecs = [
        ('CAPEC-100', 'attack_pattern', {'name': 'Buffer Overflow via Environment Variables', 'severity': 'high'}),
        ('CAPEC-14', 'attack_pattern', {'name': 'Client-side Injection-induced Buffer Overflow', 'severity': 'high'}),
        ('CAPEC-242', 'attack_pattern', {'name': 'Code Injection', 'severity': 'critical'}),
    ]
    for eid, etype, props in capecs:
        index.add_entity(KGEntity(entity_id=eid, entity_type=etype, properties=props))

    # 威胁行为体
    actors = [
        ('APT29', 'threat_actor', {'origin': 'Russia', 'motivation': 'espionage'}),
        ('APT41', 'threat_actor', {'origin': 'China', 'motivation': 'espionage+financial'}),
        ('Lazarus', 'threat_actor', {'origin': 'North Korea', 'motivation': 'financial'}),
    ]
    for eid, etype, props in actors:
        index.add_entity(KGEntity(entity_id=eid, entity_type=etype, properties=props))

    # 关系
    relations = [
        KGRelation('CAPEC-100', 'CWE-119', 'exploits', weight=0.9),
        KGRelation('CAPEC-14', 'CWE-119', 'exploits', weight=0.85),
        KGRelation('CAPEC-242', 'CWE-78', 'exploits', weight=0.95),
        KGRelation('CAPEC-242', 'CWE-89', 'exploits', weight=0.90),
        KGRelation('APT29', 'CWE-119', 'uses', weight=0.70),
        KGRelation('APT41', 'CWE-78', 'uses', weight=0.65),
        KGRelation('Lazarus', 'CWE-787', 'uses', weight=0.75),
        KGRelation('Lazarus', 'CWE-119', 'uses', weight=0.80),
    ]
    for r in relations:
        index.add_relation(r)

    return index


def create_graphrag_index(embed_dim=128) -> GraphRAGIndex:
    return GraphRAGIndex(embed_dim=embed_dim)


def create_cti_graphrag() -> GraphRAGIndex:
    idx = GraphRAGIndex()
    return seed_cti_knowledge_graph(idx)
