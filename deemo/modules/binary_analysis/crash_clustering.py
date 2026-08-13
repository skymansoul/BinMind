import os
import hashlib
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

__log = logging.getLogger(__name__)

_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class ClusterMethod(str, Enum):
    CALL_STACK_HASH = "call_stack_hash"
    CRASH_ADDRESS = "crash_address"
    COMBINED = "combined"
    DBSCAN = "dbscan"

class CrashSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self):
        """Numeric weight for severity comparison."""
        return _SEVERITY_WEIGHT.get(self.value, 1)


@dataclass
class CrashInfo:
    crash_id: str
    crash_address: int
    call_stack: List[str]
    registers: Dict[str, Any] = field(default_factory=dict)
    memory_dump: Optional[bytes] = None
    severity: CrashSeverity = CrashSeverity.MEDIUM
    timestamp: float = 0.0


@dataclass
class Cluster:
    cluster_id: str
    crashes: List[CrashInfo] = field(default_factory=list)
    representative: Optional[CrashInfo] = None
    similarity_score: float = 0.0
    size: int = 0


class StackHashGenerator:
    """Generates crash hash signatures for fast deduplication."""

    @staticmethod
    def generate_hash(call_stack: List[str]) -> str:
        stack_str = '\n'.join(call_stack)
        return hashlib.md5(stack_str.encode()).hexdigest()

    @staticmethod
    def generate_fuzzy_hash(call_stack: List[str], depth: int = 5) -> str:
        truncated = call_stack[:depth]
        normalized = [s.split('+')[0] for s in truncated]
        stack_str = '\n'.join(normalized)
        return hashlib.sha256(stack_str.encode()).hexdigest()

    @staticmethod
    def generate_signature(crash: CrashInfo) -> str:
        parts = [
            hex(crash.crash_address),
            StackHashGenerator.generate_fuzzy_hash(crash.call_stack)
        ]
        return '|'.join(parts)


class CrashClusterer:
    """Core clustering engine."""

    def __init__(self, method=None):
        self.method = method if method is not None else ClusterMethod.COMBINED
        self.clusters: Dict[str, Cluster] = {}
        self.crash_map: Dict[str, CrashInfo] = {}
        self.similarity_threshold = 0.8

    def add_crash(self, crash: CrashInfo) -> None:
        self.crash_map[crash.crash_id] = crash

        signature = self._generate_signature(crash)

        if signature in self.clusters:
            self.clusters[signature].crashes.append(crash)
            self.clusters[signature].size += 1
        else:
            cluster = Cluster(
                cluster_id=signature,
                crashes=[crash],
                representative=crash,
                size=1
            )
            self.clusters[signature] = cluster

    def _generate_signature(self, crash: CrashInfo) -> str:
        if self.method == ClusterMethod.CALL_STACK_HASH:
            return StackHashGenerator.generate_hash(crash.call_stack)
        elif self.method == ClusterMethod.CRASH_ADDRESS:
            return hex(crash.crash_address)
        else:
            return StackHashGenerator.generate_signature(crash)

    def cluster(self) -> List[Cluster]:
        return list(self.clusters.values())

    def get_cluster_for_crash(self, crash_id: str) -> Optional[Cluster]:
        crash = self.crash_map.get(crash_id)
        if not crash:
            return None

        signature = self._generate_signature(crash)
        return self.clusters.get(signature)

    def merge_clusters(self, threshold: float = 0.8) -> None:
        signatures = list(self.clusters.keys())

        for i in range(len(signatures)):
            for j in range(i + 1, len(signatures)):
                sig1 = signatures[i]
                sig2 = signatures[j]

                if self.clusters.get(sig1) and self.clusters.get(sig2):
                    similarity = self._calculate_similarity(
                        self.clusters[sig1],
                        self.clusters[sig2]
                    )

                    if similarity >= threshold:
                        self._merge_two_clusters(sig1, sig2)

    def _calculate_similarity(self, cluster1: Cluster, cluster2: Cluster) -> float:
        stack1 = cluster1.representative.call_stack
        stack2 = cluster2.representative.call_stack

        common = set(stack1) & set(stack2)
        union = set(stack1) | set(stack2)

        return len(common) / len(union) if union else 0.0

    def _merge_two_clusters(self, sig1: str, sig2: str) -> None:
        cluster1 = self.clusters[sig1]
        cluster2 = self.clusters[sig2]

        cluster1.crashes.extend(cluster2.crashes)
        cluster1.size += cluster2.size

        if cluster2.representative.severity.weight > cluster1.representative.severity.weight:
            cluster1.representative = cluster2.representative

        del self.clusters[sig2]

    def get_top_clusters(self, count: int = 10) -> List[Cluster]:
        clusters = sorted(
            self.clusters.values(),
            key=lambda c: c.size,
            reverse=True
        )
        return clusters[:count]

    def get_total_crashes(self) -> int:
        return sum(cluster.size for cluster in self.clusters.values())

    def get_unique_clusters(self) -> int:
        return len(self.clusters)


class ClusterAnalyzer:
    """Analyzer wrapper that chains clustering, dedup, and reporting."""

    def __init__(self):
        self.clusterer = CrashClusterer()

    def analyze_crashes(self, crashes: List[CrashInfo]) -> Dict[str, Any]:
        for crash in crashes:
            self.clusterer.add_crash(crash)

        self.clusterer.merge_clusters()

        top_clusters = self.clusterer.get_top_clusters(5)

        return {
            "total_crashes": self.clusterer.get_total_crashes(),
            "unique_clusters": self.clusterer.get_unique_clusters(),
            "top_clusters": [
                {
                    "cluster_id": c.cluster_id,
                    "size": c.size,
                    "severity": c.representative.severity.value,
                    "crash_address": hex(c.representative.crash_address)
                }
                for c in top_clusters
            ]
        }

    def find_duplicates(self, crash: CrashInfo) -> List[CrashInfo]:
        cluster = self.clusterer.get_cluster_for_crash(crash.crash_id)
        if not cluster:
            return []
        return [c for c in cluster.crashes if c.crash_id != crash.crash_id]

    def generate_report(self) -> str:
        report = []
        report.append("=" * 60)
        report.append("Crash Clustering Report")
        report.append("=" * 60)
        report.append(f"Total crashes: {self.clusterer.get_total_crashes()}")
        report.append(f"Unique clusters: {self.clusterer.get_unique_clusters()}")
        report.append("")

        for cluster in self.clusterer.get_top_clusters(10):
            report.append(f"Cluster: {cluster.cluster_id[:16]}...")
            report.append(f"  Size: {cluster.size}")
            report.append(f"  Severity: {cluster.representative.severity.value}")
            report.append(f"  Address: {hex(cluster.representative.crash_address)}")
            report.append("")

        return '\n'.join(report)


def create_crash_info(crash_id: str, crash_address: int,
                      call_stack: List[str]) -> CrashInfo:
    """Convenience factory function."""
    return CrashInfo(
        crash_id=crash_id,
        crash_address=crash_address,
        call_stack=call_stack,
        severity=CrashSeverity.HIGH if crash_address == 0 else CrashSeverity.MEDIUM
    )


def cluster_crashes(crashes: List[CrashInfo]) -> List[Cluster]:
    """Convenience entry point for external scripts."""
    clusterer = CrashClusterer()
    for crash in crashes:
        clusterer.add_crash(crash)
    return clusterer.cluster()
