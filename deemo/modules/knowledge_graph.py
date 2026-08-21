# 漏洞知识图谱 - 实体/关系存储与图谱导出。
# 实体为二进制、函数、CVE 等节点；关系描述节点间的语义连接。
# 支持 JSON 导出，供下游关联分析与报告使用。

import json
import os
import uuid


class KnowledgeGraphEntity:
    """知识图谱实体节点。"""

    def __init__(self, entity_id: str, entity_type: str, name: str,
                 properties: dict = None):
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.name = name
        self.properties = dict(properties or {})

    def to_dict(self) -> dict:
        return {
            'entity_id': self.entity_id,
            'entity_type': self.entity_type,
            'name': self.name,
            'properties': self.properties,
        }


class KnowledgeGraphRelation:
    """实体间的语义关系边。"""

    def __init__(self, source_id: str, target_id: str, relation_type: str,
                 properties: dict = None):
        self.source_id = source_id
        self.target_id = target_id
        self.relation_type = relation_type
        self.properties = dict(properties or {})

    def to_dict(self) -> dict:
        return {
            'source_id': self.source_id,
            'target_id': self.target_id,
            'relation_type': self.relation_type,
            'properties': self.properties,
        }


class VulnKnowledgeGraph:
    """漏洞知识图谱 - 实体与关系的增删查与导出。"""

    def __init__(self, storage_path: str = None):
        self.storage_path = storage_path
        if self.storage_path:
            os.makedirs(self.storage_path, exist_ok=True)
        self.entities: dict = {}
        self.relations: list = []

    def add_entity(self, entity_type: str, name: str,
                   properties: dict = None) -> str:
        """新增实体节点，返回自动生成的实体 ID。"""
        entity_id = uuid.uuid4().hex[:12]
        entity = KnowledgeGraphEntity(entity_id, entity_type, name, properties)
        self.entities[entity_id] = entity
        return entity_id

    def add_relation(self, source_id: str, target_id: str,
                     relation_type: str, properties: dict = None) -> None:
        """新增关系边。"""
        relation = KnowledgeGraphRelation(
            source_id, target_id, relation_type, properties)
        self.relations.append(relation)

    def export_graph(self, fmt: str = 'json', path: str = None) -> str:
        """导出图谱到文件，返回写入路径。"""
        if path is None:
            path = os.path.join(self.storage_path or '.', 'graph.json')
        payload = {
            'entities': [e.to_dict() for e in self.entities.values()],
            'relations': [r.to_dict() for r in self.relations],
        }
        if fmt == 'json':
            with open(path, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
        return path
