import logging
import os
import json
import pickle
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime
from pathlib import Path

from config import Config, mask_sensitive_data

logger = logging.getLogger(__name__)

NETWORKX_AVAILABLE = False
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    logger.warning("networkx 未安装，知识图谱功能将使用简化实现")

GRAPHVIZ_AVAILABLE = False
try:
    import graphviz
    GRAPHVIZ_AVAILABLE = True
except ImportError:
    logger.warning("graphviz 未安装，图谱可视化功能不可用")


ENTITY_TYPES = [
    'Binary', 'Function', 'Vulnerability', 'CVE', 'CWE', 
    'Exploit', 'Malware', 'ThreatActor', 'TTP', 'Patch'
]

RELATION_TYPES = [
    'HAS_FUNCTION', 'CONTAINS_VULN', 'REFERENCES_CVE', 
    'EXPLOITED_BY', 'ATTRIBUTED_TO', 'IMPLEMENTS_TTP',
    'FIXED_BY', 'RELATED_TO', 'DERIVED_FROM'
]


class KnowledgeGraphEntity:
    """知识图谱实体类"""
    
    def __init__(
        self,
        entity_id: str,
        entity_type: str,
        name: str,
        properties: Optional[Dict[str, Any]] = None
    ):
        if entity_type not in ENTITY_TYPES:
            raise ValueError(f"无效的实体类型: {entity_type}")
        
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.name = name
        self.properties = properties or {}
        self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'entity_id': self.entity_id,
            'entity_type': self.entity_type,
            'name': self.name,
            'properties': self.properties,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
    
    def update_properties(self, new_properties: Dict[str, Any]):
        """更新属性"""
        self.properties.update(new_properties)
        self.updated_at = datetime.now().isoformat()


class KnowledgeGraphRelation:
    """知识图谱关系类"""
    
    def __init__(
        self,
        source_id: str,
        target_id: str,
        relation_type: str,
        properties: Optional[Dict[str, Any]] = None
    ):
        if relation_type not in RELATION_TYPES:
            raise ValueError(f"无效的关系类型: {relation_type}")
        
        self.source_id = source_id
        self.target_id = target_id
        self.relation_type = relation_type
        self.properties = properties or {}
        self.created_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'source_id': self.source_id,
            'target_id': self.target_id,
            'relation_type': self.relation_type,
            'properties': self.properties,
            'created_at': self.created_at
        }


class VulnKnowledgeGraph:
    """
    漏洞知识图谱构建与可视化类
    
    功能:
        1. 从分析结果、漏洞数据库和威胁情报中提取实体和关系
        2. 构建知识图谱并持久化存储
        3. 支持类Cypher查询
        4. 生成可视化图谱
    """
    
    def __init__(self, storage_path: str = None):
        """
        初始化知识图谱
        
        Args:
            storage_path: 图谱数据存储路径
        """
        self.storage_path = storage_path or os.path.join(Config.DATA_DIR, 'knowledge_graph')
        os.makedirs(self.storage_path, exist_ok=True)
        
        self.entities: Dict[str, KnowledgeGraphEntity] = {}
        self.relations: List[KnowledgeGraphRelation] = []
        
        self.graph = None
        if NETWORKX_AVAILABLE:
            self.graph = nx.DiGraph()
        
        self._load_graph()
    
    def _generate_entity_id(self, entity_type: str, name: str) -> str:
        """生成唯一的实体ID"""
        import hashlib
        unique_str = f"{entity_type}_{name}_{datetime.now().timestamp()}"
        return hashlib.md5(unique_str.encode()).hexdigest()[:16]
    
    def add_entity(
        self,
        entity_type: str,
        name: str,
        properties: Optional[Dict[str, Any]] = None,
        entity_id: str = None
    ) -> str:
        """
        添加实体到图谱
        
        Args:
            entity_type: 实体类型
            name: 实体名称
            properties: 实体属性
            entity_id: 可选的实体ID，不提供则自动生成
        
        Returns:
            实体ID
        """
        if entity_type not in ENTITY_TYPES:
            raise ValueError(f"无效的实体类型: {entity_type}")
        
        if entity_id and entity_id in self.entities:
            logger.warning(f"实体已存在，将更新属性: {entity_id}")
            self.entities[entity_id].update_properties(properties or {})
            return entity_id
        
        entity_id = entity_id or self._generate_entity_id(entity_type, name)
        
        entity = KnowledgeGraphEntity(
            entity_id=entity_id,
            entity_type=entity_type,
            name=name,
            properties=properties
        )
        
        self.entities[entity_id] = entity
        
        if self.graph:
            self.graph.add_node(
                entity_id,
                label=name,
                type=entity_type,
                **(properties or {})
            )
        
        logger.debug(f"添加实体: {entity_type} - {name} ({entity_id})")
        return entity_id
    
    def add_relation(
        self,
        source_id: str,
        target_id: str,
        relation_type: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        添加关系到图谱
        
        Args:
            source_id: 源实体ID
            target_id: 目标实体ID
            relation_type: 关系类型
            properties: 关系属性
        """
        if source_id not in self.entities:
            raise ValueError(f"源实体不存在: {source_id}")
        
        if target_id not in self.entities:
            raise ValueError(f"目标实体不存在: {target_id}")
        
        if relation_type not in RELATION_TYPES:
            raise ValueError(f"无效的关系类型: {relation_type}")
        
        relation = KnowledgeGraphRelation(
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            properties=properties
        )
        
        self.relations.append(relation)
        
        if self.graph:
            self.graph.add_edge(
                source_id,
                target_id,
                label=relation_type,
                **(properties or {})
            )
        
        logger.debug(f"添加关系: {source_id} -{relation_type}-> {target_id}")
    
    def get_entity(self, entity_id: str) -> Optional[KnowledgeGraphEntity]:
        """获取实体"""
        return self.entities.get(entity_id)
    
    def get_entities_by_type(self, entity_type: str) -> List[KnowledgeGraphEntity]:
        """按类型获取实体"""
        return [e for e in self.entities.values() if e.entity_type == entity_type]
    
    def get_entity_by_name(self, name: str) -> List[KnowledgeGraphEntity]:
        """按名称搜索实体"""
        return [e for e in self.entities.values() if name.lower() in e.name.lower()]
    
    def get_relations_by_type(self, relation_type: str) -> List[KnowledgeGraphRelation]:
        """按类型获取关系"""
        return [r for r in self.relations if r.relation_type == relation_type]
    
    def get_relations_for_entity(self, entity_id: str) -> List[KnowledgeGraphRelation]:
        """获取实体相关的所有关系"""
        return [
            r for r in self.relations 
            if r.source_id == entity_id or r.target_id == entity_id
        ]
    
    def query(self, query_str: str) -> List[Dict[str, Any]]:
        """
        执行类Cypher查询
        
        支持的查询语法:
        - MATCH (b:Binary)-[:CONTAINS_VULN]->(v:Vulnerability) RETURN b.name, v.type
        - MATCH (v:Vulnerability)-[:REFERENCES_CVE]->(c:CVE) RETURN v.name, c.name
        
        Args:
            query_str: 查询字符串
        
        Returns:
            查询结果列表
        """
        try:
            return self._parse_and_execute_query(query_str)
        except Exception as e:
            logger.error(f"查询执行失败: {e}")
            return []
    
    def _parse_and_execute_query(self, query_str: str) -> List[Dict[str, Any]]:
        """解析并执行查询"""
        query_str = query_str.strip()
        
        if not query_str.upper().startswith('MATCH'):
            return []
        
        import re
        
        match_pattern = r'MATCH\s+(.+?)\s+RETURN\s+(.+)$'
        match = re.match(match_pattern, query_str, re.DOTALL | re.IGNORECASE)
        
        if not match:
            return []
        
        pattern_part = match.group(1).strip()
        return_part = match.group(2).strip()
        
        return self._execute_match(pattern_part, return_part)
    
    def _execute_match(self, pattern: str, return_clause: str) -> List[Dict[str, Any]]:
        """执行 MATCH 模式匹配"""
        pattern = pattern.replace('(', ' (').replace(')', ') ').strip()
        
        tokens = pattern.split()
        
        nodes = []
        edges = []
        
        i = 0
        while i < len(tokens):
            if tokens[i].startswith('('):
                node_str = tokens[i].strip('()')
                parts = node_str.split(':')
                alias = parts[0]
                node_type = parts[1] if len(parts) > 1 else None
                nodes.append({'alias': alias, 'type': node_type})
                i += 1
            elif tokens[i].startswith('-'):
                edge_str = tokens[i].strip('-[]')
                parts = edge_str.split(':')
                edge_type = parts[1] if len(parts) > 1 else None
                edges.append({'type': edge_type})
                i += 2
            else:
                i += 1
        
        return_fields = [f.strip() for f in return_clause.split(',')]
        
        results = []
        
        if len(nodes) == 2 and len(edges) == 1:
            source_type = nodes[0]['type']
            target_type = nodes[1]['type']
            edge_type = edges[0]['type']
            
            for relation in self.relations:
                source_entity = self.entities.get(relation.source_id)
                target_entity = self.entities.get(relation.target_id)
                
                if not source_entity or not target_entity:
                    continue
                
                if source_type and source_entity.entity_type != source_type:
                    continue
                
                if target_type and target_entity.entity_type != target_type:
                    continue
                
                if edge_type and relation.relation_type != edge_type:
                    continue
                
                result = {}
                for field in return_fields:
                    parts = field.split('.')
                    if len(parts) == 2:
                        alias, prop = parts
                        for node in nodes:
                            if node['alias'] == alias:
                                entity = source_entity if node['alias'] == nodes[0]['alias'] else target_entity
                                result[field] = getattr(entity, prop, None) or entity.properties.get(prop)
                                break
                
                if result:
                    results.append(result)
        
        return results
    
    def _build_from_vuln_db(self, vuln_db) -> None:
        """从漏洞数据库构建图谱"""
        if not vuln_db:
            return
        
        try:
            vulns = vuln_db.get_all(limit=100)
            
            for vuln in vulns:
                binary_name = vuln.get('binary_name', '')
                function_name = vuln.get('function_name', '')
                vuln_type = vuln.get('vulnerability_type', '')
                severity = vuln.get('severity', '')
                
                binary_id = self.add_entity('Binary', binary_name, {
                    'format': vuln.get('binary_format'),
                    'architecture': vuln.get('architecture'),
                    'bits': vuln.get('bits')
                })
                
                func_id = self.add_entity('Function', function_name, {
                    'binary_name': binary_name,
                    'severity': severity
                })
                
                vuln_id = self.add_entity('Vulnerability', vuln_type, {
                    'severity': severity,
                    'description': vuln.get('description'),
                    'function_name': function_name
                })
                
                self.add_relation(binary_id, func_id, 'HAS_FUNCTION')
                self.add_relation(binary_id, vuln_id, 'CONTAINS_VULN')
                
                if 'CVE-' in vuln_type:
                    cve_id = self.add_entity('CVE', vuln_type, {'source': 'NVD'})
                    self.add_relation(vuln_id, cve_id, 'REFERENCES_CVE')
        
        except Exception as e:
            logger.error(f"从漏洞数据库构建图谱失败: {e}")
    
    def _build_from_analysis_result(self, analysis_result: Dict[str, Any]) -> None:
        """从分析结果构建图谱"""
        try:
            binary_info = analysis_result.get('binary_info', {})
            binary_name = binary_info.get('binary_name', 'unknown')
            
            binary_id = self.add_entity('Binary', binary_name, {
                'format': binary_info.get('binary_format'),
                'architecture': binary_info.get('arch'),
                'bits': binary_info.get('bits'),
                'size': binary_info.get('size')
            })
            
            decomp_results = analysis_result.get('decomp_results', [])
            for result in decomp_results:
                func_name = result.get('function_name', '')
                analysis = result.get('analysis', {})
                vulns = analysis.get('vulnerabilities', [])
                
                func_id = self.add_entity('Function', func_name, {
                    'risk_level': analysis.get('risk_level'),
                    'summary': analysis.get('summary')
                })
                
                self.add_relation(binary_id, func_id, 'HAS_FUNCTION')
                
                for vuln in vulns:
                    vuln_type = vuln.get('type', 'Unknown')
                    vuln_severity = vuln.get('severity', 'Medium')
                    
                    vuln_id = self.add_entity('Vulnerability', vuln_type, {
                        'severity': vuln_severity,
                        'location': vuln.get('location'),
                        'description': vuln.get('description')
                    })
                    
                    self.add_relation(binary_id, vuln_id, 'CONTAINS_VULN')
        
        except Exception as e:
            logger.error(f"从分析结果构建图谱失败: {e}")
    
    def build_graph(self, analysis_result: Dict[str, Any] = None, vuln_db = None) -> None:
        """
        构建/更新知识图谱
        
        Args:
            analysis_result: 分析结果字典
            vuln_db: 漏洞数据库实例
        """
        logger.info("开始构建知识图谱...")
        
        if vuln_db:
            self._build_from_vuln_db(vuln_db)
        
        if analysis_result:
            self._build_from_analysis_result(analysis_result)
        
        self._save_graph()
        logger.info(f"知识图谱构建完成，实体数: {len(self.entities)}, 关系数: {len(self.relations)}")
    
    def export_graph(self, format: str = 'json', output_path: str = None) -> Optional[str]:
        """
        导出图谱数据
        
        Args:
            format: 导出格式 (json, pickle, gexf)
            output_path: 输出路径
        
        Returns:
            导出文件路径
        """
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.storage_path, f'graph_{timestamp}.{format}')
        
        try:
            if format == 'json':
                data = {
                    'metadata': {
                        'export_time': datetime.now().isoformat(),
                        'entity_count': len(self.entities),
                        'relation_count': len(self.relations)
                    },
                    'entities': [e.to_dict() for e in self.entities.values()],
                    'relations': [r.to_dict() for r in self.relations]
                }
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            
            elif format == 'pickle':
                data = {
                    'entities': self.entities,
                    'relations': self.relations
                }
                
                with open(output_path, 'wb') as f:
                    pickle.dump(data, f)
            
            elif format == 'gexf' and NETWORKX_AVAILABLE:
                if self.graph:
                    nx.write_gexf(self.graph, output_path)
            
            logger.info(f"图谱已导出: {output_path}")
            return output_path
        
        except Exception as e:
            logger.error(f"导出图谱失败: {e}")
            return None
    
    def visualize(self, output_path: str = None, format: str = 'png') -> Optional[str]:
        """
        生成可视化图谱
        
        Args:
            output_path: 输出路径
            format: 输出格式 (png, svg)
        
        Returns:
            输出文件路径
        """
        if not GRAPHVIZ_AVAILABLE:
            logger.warning("graphviz 未安装，无法生成可视化图谱")
            return None
        
        if not self.graph or len(self.entities) == 0:
            logger.warning("图谱为空，无法生成可视化")
            return None
        
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.storage_path, f'graph_{timestamp}.{format}')
        
        try:
            dot = graphviz.Digraph(comment='Vulnerability Knowledge Graph', format=format)
            
            color_map = {
                'Binary': '#1f78b4',
                'Function': '#33a02c',
                'Vulnerability': '#e31a1c',
                'CVE': '#ff7f00',
                'CWE': '#6a3d9a',
                'Exploit': '#b15928',
                'Malware': '#fb9a99',
                'ThreatActor': '#fdbf6f',
                'TTP': '#cab2d6',
                'Patch': '#ffff99'
            }
            
            for entity_id, entity in self.entities.items():
                color = color_map.get(entity.entity_type, '#808080')
                label = f"{entity.name}\\n({entity.entity_type})"
                dot.node(entity_id, label, style='filled', fillcolor=color, fontcolor='white')
            
            for relation in self.relations:
                dot.edge(relation.source_id, relation.target_id, label=relation.relation_type)
            
            dot.render(output_path.replace(f'.{format}', ''), format=format, cleanup=True)
            
            logger.info(f"图谱可视化已生成: {output_path}")
            return output_path
        
        except Exception as e:
            logger.error(f"生成可视化图谱失败: {e}")
            return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取图谱统计信息"""
        type_counts = {}
        for entity in self.entities.values():
            type_counts[entity.entity_type] = type_counts.get(entity.entity_type, 0) + 1
        
        relation_type_counts = {}
        for relation in self.relations:
            relation_type_counts[relation.relation_type] = relation_type_counts.get(relation.relation_type, 0) + 1
        
        return {
            'total_entities': len(self.entities),
            'total_relations': len(self.relations),
            'entities_by_type': type_counts,
            'relations_by_type': relation_type_counts
        }
    
    def _save_graph(self):
        """保存图谱到磁盘"""
        try:
            data = {
                'entities': {k: v.to_dict() for k, v in self.entities.items()},
                'relations': [r.to_dict() for r in self.relations],
                'saved_at': datetime.now().isoformat()
            }
            
            save_path = os.path.join(self.storage_path, 'graph_data.json')
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            logger.debug(f"图谱数据已保存: {save_path}")
        
        except Exception as e:
            logger.error(f"保存图谱失败: {e}")
    
    def _load_graph(self):
        """从磁盘加载图谱"""
        try:
            load_path = os.path.join(self.storage_path, 'graph_data.json')
            if os.path.exists(load_path):
                with open(load_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                for entity_id, entity_dict in data.get('entities', {}).items():
                    entity = KnowledgeGraphEntity(
                        entity_id=entity_dict['entity_id'],
                        entity_type=entity_dict['entity_type'],
                        name=entity_dict['name'],
                        properties=entity_dict.get('properties', {})
                    )
                    entity.created_at = entity_dict.get('created_at', entity.created_at)
                    entity.updated_at = entity_dict.get('updated_at', entity.updated_at)
                    self.entities[entity_id] = entity
                
                for relation_dict in data.get('relations', []):
                    relation = KnowledgeGraphRelation(
                        source_id=relation_dict['source_id'],
                        target_id=relation_dict['target_id'],
                        relation_type=relation_dict['relation_type'],
                        properties=relation_dict.get('properties', {})
                    )
                    relation.created_at = relation_dict.get('created_at', relation.created_at)
                    self.relations.append(relation)
                
                if self.graph:
                    for entity_id, entity in self.entities.items():
                        self.graph.add_node(
                            entity_id,
                            label=entity.name,
                            type=entity.entity_type,
                            **entity.properties
                        )
                    
                    for relation in self.relations:
                        self.graph.add_edge(
                            relation.source_id,
                            relation.target_id,
                            label=relation.relation_type,
                            **relation.properties
                        )
                
                logger.info(f"已加载图谱: {len(self.entities)} 实体, {len(self.relations)} 关系")
        
        except Exception as e:
            logger.debug(f"加载图谱失败（首次运行）: {e}")
    
    def clear(self):
        """清空图谱"""
        self.entities = {}
        self.relations = []
        
        if self.graph:
            self.graph.clear()
        
        self._save_graph()
        logger.info("图谱已清空")
