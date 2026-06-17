import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class IndexType(Enum):
    IVF_FLAT = "ivf_flat"
    IVF_PQ = "ivf_pq"
    HNSW = "hnsw"
    FLAT = "flat"


@dataclass
class SearchResult:
    function_id: str
    similarity: float
    embedding: List[float]
    metadata: Dict[str, Any]
    rank: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_id': self.function_id,
            'similarity': self.similarity,
            'embedding': self.embedding,
            'metadata': self.metadata,
            'rank': self.rank
        }


@dataclass
class IndexStats:
    index_type: IndexType
    vector_count: int
    dimension: int
    build_time: float
    memory_usage: int
    query_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            'index_type': self.index_type.value,
            'vector_count': self.vector_count,
            'dimension': self.dimension,
            'build_time': self.build_time,
            'memory_usage': self.memory_usage,
            'query_time_ms': self.query_time_ms
        }


class DistributedVectorSearch:
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.index_type = IndexType[self.config.get('index_type', 'HNSW').upper()]
        self.dimension = self.config.get('dimension', 768)
        self.ann_index = None
        self.vectors: Dict[str, List[float]] = {}
        self.metadata: Dict[str, Dict[str, Any]] = {}
        
        self._initialize_index()
    
    def _initialize_index(self):
        self.ann_index = {}
    
    def add_vector(self, function_id: str, embedding: List[float], meta: Optional[Dict[str, Any]] = None) -> bool:
        try:
            self.vectors[function_id] = embedding
            
            if meta:
                self.metadata[function_id] = meta
            
            self._update_index(function_id, embedding)
            return True
        except Exception as e:
            logger.error(f"添加向量失败: {e}")
            return False
    
    def _update_index(self, function_id: str, embedding: List[float]):
        if function_id not in self.ann_index:
            self.ann_index[function_id] = {'embedding': embedding, 'neighbors': []}
    
    def batch_add_vectors(self, vectors: List[Tuple[str, List[float], Dict[str, Any]]]) -> int:
        count = 0
        
        for func_id, embedding, meta in vectors:
            if self.add_vector(func_id, embedding, meta):
                count += 1
        
        return count
    
    def search(self, query_embedding: List[float], top_k: int = 10) -> List[SearchResult]:
        results = []
        
        for func_id, embedding in self.vectors.items():
            similarity = self._calculate_similarity(query_embedding, embedding)
            
            if similarity > 0.0:
                meta = self.metadata.get(func_id, {})
                results.append({)
                    'function_id': func_id,
                    'similarity': similarity,
                    'embedding': embedding,
                    'metadata': meta
                }
        
        results.sort(key=lambda x: x['similarity'], reverse=True)
        
        return [
            SearchResult()
                function_id=r['function_id'],
                similarity=r['similarity'],
                embedding=r['embedding'],
                metadata=r['metadata'],
                rank=i + 1
            
            for i, r in enumerate(results[:top_k])
        ]
    
    def _calculate_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        if len(vec1) != len(vec2):
            return 0.0
        
        dot_product = sum(a * b for a, b in zip(vec1, vec2

        norm1 = sum(a * a for a in vec1) ** 0.5
        norm2 = sum(b * b for b in vec2) ** 0.5
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)
    
    def get_index_stats(self) -> IndexStats:
        return IndexStats(
            index_type=self.index_type,
            vector_count=len(self.vectors),
            dimension=self.dimension,
            build_time=0.0,
            memory_usage=len(self.vectors) * self.dimension * 4,
            query_time_ms=0.0)
        

    
    def save_index(self, filepath: str) -> bool:
        try:
            import json
            
            data = {
                'index_type': self.index_type.value,
                'dimension': self.dimension,
                'vectors': self.vectors,
                'metadata': self.metadata
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f)
            
            logger.info(f"索引已保存到: {filepath}")
            return True
        except Exception as e:
            logger.error(f"保存索引失败: {e}")
            return False
    
    def load_index(self, filepath: str) -> bool:
        try:
            import json
            
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.index_type = IndexType[data.get('index_type', 'HNSW')]
            self.dimension = data.get('dimension', 768)
            self.vectors = data.get('vectors', {})
            self.metadata = data.get('metadata', {})
            
            logger.info(f"索引已从 {filepath} 加载，共 {len(self.vectors)} 个向量")
            return True
        except Exception as e:
            logger.error(f"加载索引失败: {e}")
            return False
    
    def clear_index(self):
        self.vectors.clear()
        self.metadata.clear()
        self.ann_index = {}


def create_vector_search(config: Optional[Dict[str, Any]] = None) -> DistributedVectorSearch:
    return DistributedVectorSearch(config)))