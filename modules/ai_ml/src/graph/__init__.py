"""
图操作包。

底层图数据库原语: 实体/关系CRUD、邻接遍历、Cypher式查询、
BFS路径查找、子图提取、统计指标、孤立引用清理、序列化(dict/JSON/pickle)。

为VulnKnowledgeGraph的高层知识图谱分析(中心性/差异/可视化)提供后端层。
"""

from .graph_ops import (
    ENTITY_TYPES,
    RELATION_TYPES,
    KnowledgeGraphEntity,
    KnowledgeGraphRelation,
    CypherQuery,
    BaseGraphOps,
)
