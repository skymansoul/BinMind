"""
二进制基因片段提取模块

功能：
1. 提取可序列化的二进制片段
2. 存入知识库
3. 支持相似度匹配

核心组件：
- BinaryGene: 二进制基因
- GeneExtractor: 基因提取器
- GeneRepository: 基因仓库
"""

import os
import hashlib
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class GeneType(Enum):
    CODE = "code"
    DATA = "data"
    STRING = "string"
    HEADER = "header"
    SIGNATURE = "signature"


@dataclass
class BinaryGene:
    id: str
    data: bytes
    gene_type: GeneType
    offset: int
    metadata: Dict[str, Any] = field(default_factory=dict)


class GeneExtractor:

    def __init__(self):
        self._min_length = 16
        self._max_length = 4096

    def extract_genes(self, binary_data: bytes) -> List[BinaryGene]:
        genes = []
        
        genes.extend(self._extract_code_genes(binary_data))
        genes.extend(self._extract_string_genes(binary_data))
        genes.extend(self._extract_signature_genes(binary_data))
        
        return genes

    def _extract_code_genes(self, data: bytes) -> List[BinaryGene]:
        genes = []
        offset = 0
        
        while offset < len(data):
            if self._is_code_region(data, offset):
                end = self._find_code_end(data, offset)
                if end - offset >= self._min_length:
                    gene_data = data[offset:end]
                    genes.append(BinaryGene(
                        id=self._generate_id(gene_data),
                        data=gene_data,
                        gene_type=GeneType.CODE,
                        offset=offset,
                        metadata={"length": end - offset}
                    ))
                offset = end
            else:
                offset += 1
        
        return genes

    def _is_code_region(self, data: bytes, offset: int) -> bool:
        if offset + 2 > len(data):
            return False
        return data[offset] in [0x55, 0x89, 0x48, 0x49, 0x4c, 0x50, 0x51, 0x52]

    def _find_code_end(self, data: bytes, offset: int) -> int:
        max_end = min(offset + self._max_length, len(data))
        return max_end

    def _extract_string_genes(self, data: bytes) -> List[BinaryGene]:
        genes = []
        i = 0
        
        while i < len(data):
            if data[i] == 0:
                i += 1
                continue
            
            if data[i] >= 0x20 and data[i] <= 0x7E:
                start = i
                while i < len(data) and data[i] >= 0x20 and data[i] <= 0x7E:
                    i += 1
                
                if i - start >= self._min_length:
                    gene_data = data[start:i]
                    genes.append(BinaryGene(
                        id=self._generate_id(gene_data),
                        data=gene_data,
                        gene_type=GeneType.STRING,
                        offset=start,
                        metadata={"encoding": "ascii"}
                    ))
            i += 1
        
        return genes

    def _extract_signature_genes(self, data: bytes) -> List[BinaryGene]:
        genes = []
        signatures = [b"PE\x00\x00", b"MZ", b"\x7fELF"]
        
        for sig in signatures:
            offset = data.find(sig)
            if offset != -1:
                genes.append(BinaryGene(
                    id=self._generate_id(sig),
                    data=sig,
                    gene_type=GeneType.SIGNATURE,
                    offset=offset,
                    metadata={"signature": sig.hex()}
                ))
        
        return genes

    def _generate_id(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


class GeneRepository:

    def __init__(self):
        self._genes: Dict[str, BinaryGene] = {}
        self._index: Dict[str, List[str]] = {}

    def add_gene(self, gene: BinaryGene):
        self._genes[gene.id] = gene
        
        gene_type = gene.gene_type.value
        if gene_type not in self._index:
            self._index[gene_type] = []
        self._index[gene_type].append(gene.id)

    def get_gene(self, gene_id: str) -> Optional[BinaryGene]:
        return self._genes.get(gene_id)

    def search_by_type(self, gene_type: GeneType) -> List[BinaryGene]:
        gene_ids = self._index.get(gene_type.value, [])
        return [self._genes[gid] for gid in gene_ids if gid in self._genes]

    def find_similar(self, data: bytes, threshold: float = 0.8) -> List[Tuple[BinaryGene, float]]:
        results = []
        target_hash = hashlib.sha256(data).digest()
        
        for gene in self._genes.values():
            gene_hash = hashlib.sha256(gene.data).digest()
            similarity = self._calculate_similarity(target_hash, gene_hash)
            if similarity >= threshold:
                results.append((gene, similarity))
        
        return sorted(results, key=lambda x: x[1], reverse=True)

    def _calculate_similarity(self, hash1: bytes, hash2: bytes) -> float:
        matches = sum(1 for a, b in zip(hash1, hash2) if a == b)
        return matches / len(hash1)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_genes": len(self._genes),
            "by_type": {gene_type: len(ids) for gene_type, ids in self._index.items()}
        }


def extract_and_store_genes(binary_data: bytes, repository: GeneRepository) -> List[BinaryGene]:
    extractor = GeneExtractor()
    genes = extractor.extract_genes(binary_data)
    
    for gene in genes:
        repository.add_gene(gene)
    
    return genes