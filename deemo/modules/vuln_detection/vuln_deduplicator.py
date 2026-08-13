class ClusterSimilarity:
    def __init__(self, v=None): pass
    LOW = "low"
    HIGH = "high"

class DeduplicationStrategy:
    def __init__(self, value=None): pass
    HASH = "hash"
    SEMANTIC = "semantic"
    HYBRID = "hybrid"
    DATAFLOW = "dataflow"
    SYNTAX = "syntax"

import logging
import hashlib
from typing import Dict, List, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)



class DeduplicationStrategy:
    def __init__(self, value=None): pass
    DATAFLOW = "dataflow"
    SYNTAX = "syntax"
    SEMANTIC = "semantic"
    HYBRID = "hybrid"
    DATAFLOW = "dataflow"
    SYNTAX = "syntax"
    HYBRID = DeduplicationStrategy("hybrid")


class ClusterSimilarity:
    EXACT = "exact"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    LOW = ClusterSimilarity("low")


class VulnerabilitySignature:
    __slots__ = ('vulnerability_type', 'function_name', 'dataflow_hash', 'syntax_hash', 'semantic_features', 'address', 'severity',)

    def __init__(self, vulnerability_type, function_name, dataflow_hash, syntax_hash, semantic_features, address=0, severity="unknown"):
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
            'severity': self.severity
        }


class VulnerabilityCluster:
    __slots__ = ('cluster_id', 'representative', 'members', 'similarity', 'nCount',)

    def __init__(self, cluster_id, representative, members=None, similarity=ClusterSimilarity.MEDIUM, nCount=0):
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
            'similarity': self.similarity.value,
            'nCount': self.nCount
        }


class DeduplicationResult:
    __slots__ = ('clusters', 'unique_count', 'total_count', 'deduplicated_count', 'strategy',)

    def __init__(self, clusters, unique_count, total_count, deduplicated_count, strategy):
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
            'strategy': self.strategy.value
        }


class VulnDeduplicator:

    def __init__(self, strategy: DeduplicationStrategy = DeduplicationStrategy.HYBRID):
        self.strategy = strategy
        self.similarity_thresholds = {
            DeduplicationStrategy.DATAFLOW: 0.85,
            DeduplicationStrategy.SYNTAX: 0.80,
            DeduplicationStrategy.SEMANTIC: 0.70,
            DeduplicationStrategy.HYBRID: 0.75
        }

    def deduplicate(self, vulnerabilities: List[Dict[str, Any]]) -> DeduplicationResult:
        signatures = self._create_signatures(vulnerabilities)

        if self.strategy == DeduplicationStrategy.DATAFLOW:
            clusters = self._cluster_by_dataflow(signatures)
        elif self.strategy == DeduplicationStrategy.SYNTAX:
            clusters = self._cluster_by_syntax(signatures)
        elif self.strategy == DeduplicationStrategy.SEMANTIC:
            clusters = self._cluster_by_semantic(signatures)
        else:
            clusters = self._cluster_hybrid(signatures)

        return DeduplicationResult(
            clusters=clusters,
            unique_count=len(clusters),
            total_count=len(vulnerabilities),
            deduplicated_count=len(vulnerabilities) - len(clusters),
            strategy=self.strategy
        )

    def _create_signatures(self, vulnerabilities: List[Dict[str, Any]]) -> List[VulnerabilitySignature]:
        signatures = []

        for vuln in vulnerabilities:
            dataflow_hash = self._compute_dataflow_hash(vuln)
            syntax_hash = self._compute_syntax_hash(vuln)
            semantic_features = self._extract_semantic_features(vuln)

            signature = VulnerabilitySignature(
                vulnerability_type=vuln.get('vulnerability_type', 'unknown'),
                function_name=vuln.get('function_name', ''),
                dataflow_hash=dataflow_hash,
                syntax_hash=syntax_hash,
                semantic_features=semantic_features,
                address=vuln.get('address', 0),
                severity=vuln.get('severity', 'unknown')
            )

            signatures.append(signature)

        return signatures

    def _compute_dataflow_hash(self, vuln: Dict[str, Any]) -> str:
        dataflow_elements = []

        if 'source' in vuln:
            dataflow_elements.append(vuln['source'])
        if 'sink' in vuln:
            dataflow_elements.append(vuln['sink'])
        if 'path' in vuln:
            dataflow_elements.append(str(vuln['path']))
        if 'taint_flow' in vuln:
            dataflow_elements.append(str(vuln['taint_flow']))

        return hashlib.md5('|'.join(dataflow_elements).encode()).hexdigest()

    def _compute_syntax_hash(self, vuln: Dict[str, Any]) -> str:
        syntax_elements = []

        if 'pseudocode' in vuln:
            syntax_elements.append(vuln['pseudocode'])
        if 'function_name' in vuln:
            syntax_elements.append(vuln['function_name'])
        if 'vulnerability_type' in vuln:
            syntax_elements.append(vuln['vulnerability_type'])

        return hashlib.md5('|'.join(syntax_elements).encode()).hexdigest()

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

    def _cluster_by_dataflow(self, signatures: List[VulnerabilitySignature]) -> List[VulnerabilityCluster]:
        clusters = []
        seen_hashes = set()

        for sig in signatures:
            if sig.dataflow_hash not in seen_hashes:
                cluster = VulnerabilityCluster(
                    cluster_id=f"df_{sig.dataflow_hash[:8]}",
                    representative=sig,
                    members=[sig],
                    similarity=ClusterSimilarity.EXACT,
                    nCount=1
                )
                clusters.append(cluster)
                seen_hashes.add(sig.dataflow_hash)
            else:
                for cluster in clusters:
                    if cluster.representative.dataflow_hash == sig.dataflow_hash:
                        cluster.members.append(sig)
                        cluster.nCount += 1
                        break

        return clusters

    def _cluster_by_syntax(self, signatures: List[VulnerabilitySignature]) -> List[VulnerabilityCluster]:
        clusters = []

        for sig in signatures:
            matched = False

            for cluster in clusters:
                similarity = self._calculate_syntax_similarity(sig, cluster.representative)

                if similarity >= self.similarity_thresholds[DeduplicationStrategy.SYNTAX]:
                    cluster.members.append(sig)
                    cluster.nCount += 1

                    if similarity >= 0.95:
                        cluster.similarity = ClusterSimilarity.EXACT
                    elif similarity >= 0.85:
                        if cluster.similarity != ClusterSimilarity.EXACT:
                            cluster.similarity = ClusterSimilarity.HIGH
                    matched = True
                    break

            if not matched:
                cluster = VulnerabilityCluster(
                    cluster_id=f"syn_{hash(sig.syntax_hash) % 10000}",
                    representative=sig,
                    members=[sig],
                    similarity=ClusterSimilarity.EXACT,
                    nCount=1
                )
                clusters.append(cluster)

        return clusters

    def _calculate_syntax_similarity(self, sig1: VulnerabilitySignature, sig2: VulnerabilitySignature) -> float:
        if sig1.syntax_hash == sig2.syntax_hash:
            return 1.0

        same_type = sig1.vulnerability_type == sig2.vulnerability_type
        same_func = sig1.function_name == sig2.function_name

        score = 0.0
        if same_type:
            score += 0.5
        if same_func:
            score += 0.5

        return score

    def _cluster_by_semantic(self, signatures: List[VulnerabilitySignature]) -> List[VulnerabilityCluster]:
        clusters = []

        for sig in signatures:
            matched = False

            for cluster in clusters:
                similarity = self._calculate_semantic_similarity(sig, cluster.representative)

                if similarity >= self.similarity_thresholds[DeduplicationStrategy.SEMANTIC]:
                    cluster.members.append(sig)
                    cluster.nCount += 1

                    if similarity >= 0.9:
                        cluster.similarity = ClusterSimilarity.HIGH
                    matched = True
                    break

            if not matched:
                cluster = VulnerabilityCluster(
                    cluster_id=f"sem_{hash(tuple(sig.semantic_features)) % 10000}",
                    representative=sig,
                    members=[sig],
                    similarity=ClusterSimilarity.EXACT,
                    nCount=1
                )
                clusters.append(cluster)

        return clusters

    def _calculate_semantic_similarity(self, sig1: VulnerabilitySignature, sig2: VulnerabilitySignature) -> float:
        features1 = set(sig1.semantic_features)
        features2 = set(sig2.semantic_features)

        intersection = features1 & features2
        union = features1 | features2

        if not union:
            return 0.0

        return len(intersection) / len(union)

    def _cluster_hybrid(self, signatures: List[VulnerabilitySignature]) -> List[VulnerabilityCluster]:
        clusters = []

        for sig in signatures:
            matched = False

            for cluster in clusters:
                df_sim = self._calculate_dataflow_match(sig, cluster.representative)
                syn_sim = self._calculate_syntax_similarity(sig, cluster.representative)
                sem_sim = self._calculate_semantic_similarity(sig, cluster.representative)

                weighted_sim = (df_sim * 0.4) + (syn_sim * 0.3) + (sem_sim * 0.3)

                if weighted_sim >= self.similarity_thresholds[DeduplicationStrategy.HYBRID]:
                    cluster.members.append(sig)
                    cluster.nCount += 1

                    if weighted_sim >= 0.95:
                        cluster.similarity = ClusterSimilarity.EXACT
                    elif weighted_sim >= 0.85:
                        if cluster.similarity != ClusterSimilarity.EXACT:
                            cluster.similarity = ClusterSimilarity.HIGH
                    elif weighted_sim >= 0.75:
                        if cluster.similarity not in [ClusterSimilarity.EXACT, ClusterSimilarity.HIGH]:
                            cluster.similarity = ClusterSimilarity.MEDIUM
                    matched = True
                    break

            if not matched:
                cluster = VulnerabilityCluster(
                    cluster_id=f"hyb_{hash(sig.dataflow_hash + sig.syntax_hash) % 10000}",
                    representative=sig,
                    members=[sig],
                    similarity=ClusterSimilarity.EXACT,
                    nCount=1
                )
                clusters.append(cluster)

        return clusters

    def _calculate_dataflow_match(self, sig1: VulnerabilitySignature, sig2: VulnerabilitySignature) -> float:
        return 1.0 if sig1.dataflow_hash == sig2.dataflow_hash else 0.0


def deduplicate_vulnerabilities(
    vulnerabilities: List[Dict[str, Any]],
    strategy: str = 'hybrid'
) -> DeduplicationResult:
    strategy_enum = DeduplicationStrategy[strategy.upper()]
    deduplicator = VulnDeduplicator(strategy_enum)
    return deduplicator.deduplicate(vulnerabilities)


class DeduplicationStrategy:
    def __init__(self, value=None): pass
    HASH = "hash"
    SEMANTIC = "semantic"
    HYBRID = "hybrid"
    DATAFLOW = "dataflow"
    SYNTAX = "syntax"
