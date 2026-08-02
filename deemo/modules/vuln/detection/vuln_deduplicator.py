# 漏洞去重引擎——基于数据流哈希+语法哈希+语义特征的加权混合聚类。
# 数据流哈希精确匹配权重最高(0.4)，语法和语义各占0.3——数据流拓扑是漏洞指纹的最强判别特征。
# 参考VUDDY(vuln dedup via function-level fingerprints, S&P'17)和
# CENTRIS(vuln clone detection, USENIX Security'21)的混合哈希策略。

import logging, hashlib
from typing import Dict, List, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class DeduplicationStrategy:
    DATAFLOW = "dataflow"
    SYNTAX = "syntax"
    SEMANTIC = "semantic"
    HYBRID = "hybrid"

    def __init__(self, value=None): pass


class ClusterSimilarity:
    EXACT = "exact"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    def __init__(self, v=None): pass


class VulnerabilitySignature:
    __slots__ = ('vulnerability_type', 'function_name', 'dataflow_hash',
                 'syntax_hash', 'semantic_features', 'address', 'severity')

    def __init__(self, vulnerability_type, function_name, dataflow_hash,
                 syntax_hash, semantic_features, address=0, severity="unknown"):
        self.vulnerability_type = vulnerability_type
        self.function_name = function_name
        self.dataflow_hash = dataflow_hash
        self.syntax_hash = syntax_hash
        self.semantic_features = semantic_features
        self.address = address
        self.severity = severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            'vulnerability_type': self.vulnerability_type,
            'function_name': self.function_name,
            'dataflow_hash': self.dataflow_hash,
            'syntax_hash': self.syntax_hash,
            'semantic_features': self.semantic_features,
            'address': hex(self.address),
            'severity': self.severity}


class VulnerabilityCluster:
    __slots__ = ('cluster_id', 'representative', 'members', 'similarity', 'nCount')

    def __init__(self, cluster_id, representative, members=None,
                 similarity="medium", nCount=0):
        self.cluster_id = cluster_id
        self.representative = representative
        self.members = members if members is not None else []
        self.similarity = similarity
        self.nCount = nCount

    def to_dict(self) -> Dict[str, Any]:
        return {
            'cluster_id': self.cluster_id,
            'representative': self.representative.to_dict(),
            'members': [m.to_dict() for m in self.members],
            'similarity': self.similarity,
            'nCount': self.nCount}


class DeduplicationResult:
    __slots__ = ('clusters', 'unique_count', 'total_count',
                 'deduplicated_count', 'strategy')

    def __init__(self, clusters, unique_count, total_count,
                 deduplicated_count, strategy):
        self.clusters = clusters
        self.unique_count = unique_count
        self.total_count = total_count
        self.deduplicated_count = deduplicated_count
        self.strategy = strategy

    def to_dict(self) -> Dict[str, Any]:
        return {
            'clusters': [c.to_dict() for c in self.clusters],
            'unique_count': self.unique_count,
            'total_count': self.total_count,
            'deduplicated_count': self.deduplicated_count,
            'strategy': self.strategy if isinstance(self.strategy, str) else str(self.strategy)}


class VulnDeduplicator:
    """混合去重器——三路哈希+Jaccard语义相似度+加权评分。
    阈值按策略分级：dataflow(0.85)要求最高——精确匹配；
    semantic(0.70)最低——语义特征稀疏，允许较宽的近似匹配。"""

    def __init__(self, strategy: str = "hybrid"):
        self.strategy = strategy
        self.similarity_thresholds = {
            "dataflow": 0.85, "syntax": 0.80,
            "semantic": 0.70, "hybrid": 0.75}

    def deduplicate(self, vulnerabilities: List[Dict[str, Any]]) -> DeduplicationResult:
        signatures = self._create_signatures(vulnerabilities)
        if self.strategy == "dataflow":
            clusters = self._cluster_by_dataflow(signatures)
        elif self.strategy == "syntax":
            clusters = self._cluster_by_syntax(signatures)
        elif self.strategy == "semantic":
            clusters = self._cluster_by_semantic(signatures)
        else:
            clusters = self._cluster_hybrid(signatures)
        return DeduplicationResult(
            clusters=clusters, unique_count=len(clusters),
            total_count=len(vulnerabilities),
            deduplicated_count=len(vulnerabilities) - len(clusters),
            strategy=self.strategy)

    def _create_signatures(self, vulnerabilities: List[Dict[str, Any]]
                            ) -> List[VulnerabilitySignature]:
        signatures = []
        for vuln in vulnerabilities:
            df_hash = self._compute_dataflow_hash(vuln)
            syn_hash = self._compute_syntax_hash(vuln)
            sem_feats = self._extract_semantic_features(vuln)
            signatures.append(VulnerabilitySignature(
                vulnerability_type=vuln.get('vulnerability_type', 'unknown'),
                function_name=vuln.get('function_name', ''),
                dataflow_hash=df_hash, syntax_hash=syn_hash,
                semantic_features=sem_feats,
                address=vuln.get('address', 0),
                severity=vuln.get('severity', 'unknown')))
        return signatures

    def _compute_dataflow_hash(self, vuln: Dict[str, Any]) -> str:
        elements = []
        for key in ('source', 'sink', 'path', 'taint_flow'):
            if key in vuln:
                elements.append(str(vuln[key]))
        return hashlib.md5('|'.join(elements).encode()).hexdigest()

    def _compute_syntax_hash(self, vuln: Dict[str, Any]) -> str:
        elements = []
        for key in ('pseudocode', 'function_name', 'vulnerability_type'):
            if key in vuln:
                elements.append(str(vuln[key]))
        return hashlib.md5('|'.join(elements).encode()).hexdigest()

    def _extract_semantic_features(self, vuln: Dict[str, Any]) -> List[str]:
        features = []
        if vuln.get('vulnerability_type'):
            features.append(f"type:{vuln['vulnerability_type']}")
        if vuln.get('severity'):
            features.append(f"severity:{vuln['severity']}")
        if vuln.get('function_name'):
            features.append(f"func:{vuln['function_name']}")
        if vuln.get('requires_user_interaction'):
            features.append(f"interaction:{vuln['requires_user_interaction']}")
        if vuln.get('network_accessible'):
            features.append(f"network:{vuln['network_accessible']}")
        return features

    def _cluster_by_dataflow(self, signatures: List[VulnerabilitySignature]
                              ) -> List[VulnerabilityCluster]:
        clusters = []
        seen_hashes = set()
        for sig in signatures:
            if sig.dataflow_hash not in seen_hashes:
                clusters.append(VulnerabilityCluster(
                    cluster_id=f"df_{sig.dataflow_hash[:8]}",
                    representative=sig, members=[sig],
                    similarity=ClusterSimilarity.EXACT, nCount=1))
                seen_hashes.add(sig.dataflow_hash)
            else:
                for cluster in clusters:
                    if cluster.representative.dataflow_hash == sig.dataflow_hash:
                        cluster.members.append(sig)
                        cluster.nCount += 1
                        break
        return clusters

    def _cluster_by_syntax(self, signatures: List[VulnerabilitySignature]
                            ) -> List[VulnerabilityCluster]:
        clusters = []
        for sig in signatures:
            matched = False
            for cluster in clusters:
                sim = self._calculate_syntax_similarity(sig, cluster.representative)
                if sim >= self.similarity_thresholds["syntax"]:
                    cluster.members.append(sig)
                    cluster.nCount += 1
                    if sim >= 0.95:
                        cluster.similarity = ClusterSimilarity.EXACT
                    elif sim >= 0.85 and cluster.similarity != ClusterSimilarity.EXACT:
                        cluster.similarity = ClusterSimilarity.HIGH
                    matched = True
                    break
            if not matched:
                clusters.append(VulnerabilityCluster(
                    cluster_id=f"syn_{hash(sig.syntax_hash) % 10000}",
                    representative=sig, members=[sig],
                    similarity=ClusterSimilarity.EXACT, nCount=1))
        return clusters

    def _calculate_syntax_similarity(self, sig1: VulnerabilitySignature,
                                       sig2: VulnerabilitySignature) -> float:
        if sig1.syntax_hash == sig2.syntax_hash:
            return 1.0
        score = 0.0
        if sig1.vulnerability_type == sig2.vulnerability_type:
            score += 0.5
        if sig1.function_name == sig2.function_name:
            score += 0.5
        return score

    def _cluster_by_semantic(self, signatures: List[VulnerabilitySignature]
                              ) -> List[VulnerabilityCluster]:
        clusters = []
        for sig in signatures:
            matched = False
            for cluster in clusters:
                sim = self._calculate_semantic_similarity(sig, cluster.representative)
                if sim >= self.similarity_thresholds["semantic"]:
                    cluster.members.append(sig)
                    cluster.nCount += 1
                    if sim >= 0.9:
                        cluster.similarity = ClusterSimilarity.HIGH
                    matched = True
                    break
            if not matched:
                clusters.append(VulnerabilityCluster(
                    cluster_id=f"sem_{hash(tuple(sig.semantic_features)) % 10000}",
                    representative=sig, members=[sig],
                    similarity=ClusterSimilarity.EXACT, nCount=1))
        return clusters

    def _calculate_semantic_similarity(self, sig1: VulnerabilitySignature,
                                         sig2: VulnerabilitySignature) -> float:
        f1 = set(sig1.semantic_features)
        f2 = set(sig2.semantic_features)
        union = f1 | f2
        if not union:
            return 0.0
        return len(f1 & f2) / len(union)

    def _cluster_hybrid(self, signatures: List[VulnerabilitySignature]
                         ) -> List[VulnerabilityCluster]:
        """加权混合聚类——dataflow(0.4) + syntax(0.3) + semantic(0.3)。"""
        clusters = []
        for sig in signatures:
            matched = False
            for cluster in clusters:
                df_sim = 1.0 if sig.dataflow_hash == cluster.representative.dataflow_hash else 0.0
                syn_sim = self._calculate_syntax_similarity(sig, cluster.representative)
                sem_sim = self._calculate_semantic_similarity(sig, cluster.representative)
                weighted = (df_sim * 0.4) + (syn_sim * 0.3) + (sem_sim * 0.3)
                if weighted >= self.similarity_thresholds["hybrid"]:
                    cluster.members.append(sig)
                    cluster.nCount += 1
                    if weighted >= 0.95:
                        cluster.similarity = ClusterSimilarity.EXACT
                    elif weighted >= 0.85 and cluster.similarity != ClusterSimilarity.EXACT:
                        cluster.similarity = ClusterSimilarity.HIGH
                    elif weighted >= 0.75 and cluster.similarity not in (
                            ClusterSimilarity.EXACT, ClusterSimilarity.HIGH):
                        cluster.similarity = ClusterSimilarity.MEDIUM
                    matched = True
                    break
            if not matched:
                clusters.append(VulnerabilityCluster(
                    cluster_id=f"hyb_{hash(sig.dataflow_hash + sig.syntax_hash) % 10000}",
                    representative=sig, members=[sig],
                    similarity=ClusterSimilarity.EXACT, nCount=1))
        return clusters


def deduplicate_vulnerabilities(vulnerabilities: List[Dict[str, Any]],
                                  strategy: str = 'hybrid') -> DeduplicationResult:
    deduplicator = VulnDeduplicator(strategy)
    return deduplicator.deduplicate(vulnerabilities)
