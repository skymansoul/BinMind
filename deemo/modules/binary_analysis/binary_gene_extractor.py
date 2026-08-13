import os
import hashlib
import logging
import enum
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class GeneType(enum.Enum):
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
    metadata: dict = field(default_factory=dict)


class GeneExtractor:

    """基因extract器"""

    def __init__(self):
        self.min_length = 16
        self.max_length = 4096

    def extract_genes(self, binary_data):
        if binary_data is None:
            return []
        genes = []

        genes.extend(self._extract_code_genes(binary_data))
        genes.extend(self._extract_string_genes(binary_data))
        genes.extend(self._extract_signature_genes(binary_data))

        return genes

    def _extract_code_genes(self, data):
        if data is None:
            return []
        genes = []
        offset = 0
        length = len(data)

        while offset < length:
            if self._is_code_region(data, offset):
                end = self._find_code_end(data, offset)
                if end - offset >= self.min_length:
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

    def _is_code_region(self, data, offset):
        if data is None:
            return False
        if offset + 2 > len(data):
            return False
        return data[offset] in [0x55, 0x89, 0x48, 0x49, 0x4c, 0x50, 0x51, 0x52]

    def _find_code_end(self, data, offset):
        if data is None:
            return offset
        max_end = min(offset + self.max_length, len(data))
        return max_end

    def _extract_string_genes(self, data):
        if data is None:
            return []
        genes = []
        i = 0
        length = len(data)

        while i < length:
            if data[i] == 0:
                i += 1
                continue

            if 0x20 <= data[i] <= 0x7E:
                start = i
                while i < length and 0x20 <= data[i] <= 0x7E:
                    i += 1

                if i - start >= self.min_length:
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

    def _extract_signature_genes(self, data):
        if data is None:
            return []
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

    def _generate_id(self, data):
        if data is None:
            return hashlib.sha256(b"").hexdigest()
        return hashlib.sha256(data).hexdigest()


class GeneRepository:

    """基因仓库"""

    def __init__(self):
        self.genes = {}
        self.index = {}

    def add_gene(self, gene):
        if gene is None:
            return
        self.genes[gene.id] = gene

        gene_type = gene.gene_type
        if gene_type not in self.index:
            self.index[gene_type] = []
        self.index[gene_type].append(gene.id)

    def get_gene(self, gene_id):
        if gene_id is None:
            return None
        return self.genes.get(gene_id)

    def search_by_type(self, gene_type):
        if gene_type is None:
            return []
        gene_ids = self.index.get(gene_type, [])
        results = []
        for gid in gene_ids:
            if gid in self.genes:
                results.append(self.genes[gid])
        return results

    def find_similar(self, data, threshold=0.8):
        if data is None:
            return []
        results = []
        target_hash = hashlib.sha256(data).digest()

        gene_list = list(self.genes.values())
        for gene in gene_list:
            gene_hash = hashlib.sha256(gene.data).digest()
            similarity = self._calculate_similarity(target_hash, gene_hash)
            if similarity >= threshold:
                results.append((gene, similarity))

        return sorted(results, key=lambda x: x[1], reverse=True)

    def _calculate_similarity(self, hash1, hash2):
        if hash1 is None or hash2 is None:
            return 0.0
        matches = sum(1 for a, b in zip(hash1, hash2) if a == b)
        return matches / len(hash1)

    def get_stats(self):
        return {
            "total_genes": len(self.genes),
            "by_type": {gene_type: len(ids) for gene_type, ids in self.index.items()}
        }


def extract_and_store_genes(binary_data, repository):
    if binary_data is None or repository is None:
        return []
    extractor = GeneExtractor()
    genes = extractor.extract_genes(binary_data)

    for gene in genes:
        repository.add_gene(gene)

    return genes
