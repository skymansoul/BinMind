
import pytest
import time
_MOD_DEBUG = False
from modules.vuln_deduplicator import (
    VulnDeduplicator,
    VulnerabilitySignature,
    VulnerabilityCluster,
    DeduplicationResult,
    DeduplicationStrategy,
    ClusterSimilarity,
    deduplicate_vulnerabilities,
)


class TestDeduplicationStrategy:
    """Test deduplication strategy enum"""

    def test_strategy_values(self):
        assert DeduplicationStrategy.DATAFLOW.value == "dataflow"
        assert DeduplicationStrategy.SYNTAX.value == "syntax"
        assert DeduplicationStrategy.SEMANTIC.value == "semantic"
        assert DeduplicationStrategy.HYBRID.value == "hybrid"


class TestClusterSimilarity:
    """Test cluster similarity enum"""

    def test_similarity_values(self):
        assert ClusterSimilarity.EXACT.value == "exact"
        assert ClusterSimilarity.HIGH.value == "high"
        assert ClusterSimilarity.MEDIUM.value == "medium"
        assert ClusterSimilarity.LOW.value == "low"


class TestVulnerabilitySignature:
    """Test vulnerability signature dataclass"""

    def test_signature_creation(self):
        sig = VulnerabilitySignature(
            vulnerability_type="buffer_overflow",
            function_name="process_input",
            dataflow_hash="abc123def456",
            syntax_hash="xyz789ghi012",
            semantic_features=["type:buffer_overflow", "severity:HIGH"],
            address=0x401000,
            severity="HIGH",
        )
        assert sig.vulnerability_type == "buffer_overflow"
        assert sig.function_name == "process_input"
        assert sig.dataflow_hash == "abc123def456"
        assert sig.address == 0x401000
        assert sig.severity == "HIGH"

    def test_signature_to_dict(self):
        sig = VulnerabilitySignature(
            vulnerability_type="buffer_overflow",
            function_name="process_input",
            dataflow_hash="abc123",
            syntax_hash="def456",
            semantic_features=["type:buffer_overflow"],
            address=0x401000,
            severity="HIGH",
        )
        d = sig.to_dict()
        assert d["vulnerability_type"] == "buffer_overflow"
        assert d["function_name"] == "process_input"
        assert d["severity"] == "HIGH"


class TestVulnerabilityCluster:
    """Test vulnerability cluster dataclass"""

    def test_cluster_creation(self):
        sig = VulnerabilitySignature(
            vulnerability_type="buffer_overflow",
            function_name="test_func",
            dataflow_hash="abc123",
            syntax_hash="def456",
            semantic_features=[],
        )
        cluster = VulnerabilityCluster(
            cluster_id="cluster_1",
            representative=sig,
        )
        assert cluster.cluster_id == "cluster_1"
        assert cluster.representative == sig
        assert len(cluster.members) == 0
        assert cluster.count == 0

    def test_cluster_to_dict(self):
        sig = VulnerabilitySignature(
            vulnerability_type="buffer_overflow",
            function_name="test_func",
            dataflow_hash="abc123",
            syntax_hash="def456",
            semantic_features=[],
        )
        cluster = VulnerabilityCluster(
            cluster_id="cluster_1",
            representative=sig,
            members=[sig],
            similarity=ClusterSimilarity.EXACT,
            count=1,
        )
        d = cluster.to_dict()
        assert d["cluster_id"] == "cluster_1"
        assert d["count"] == 1
        assert d["similarity"] == "exact"


class TestDeduplicationResult:
    """Test deduplication result dataclass"""

    def test_result_creation(self):
                sig = VulnerabilitySignature(
            vulnerability_type="buffer_overflow",
            function_name="test_func",
            dataflow_hash="abc123",
            syntax_hash="def456",
            semantic_features=[],
        )
        cluster = VulnerabilityCluster(
            cluster_id="cluster_1",
            representative=sig,
        )
        result = DeduplicationResult(
            clusters=[cluster],
            unique_count=1,
            total_count=3,
            deduplicated_count=2,
            strategy=DeduplicationStrategy.HYBRID,
        )
lass字段完整性$/d
        assert result.unique_count == 1
        assert result.total_count == 3
        assert result.deduplicated_count == 2

    def test_result_to_dict(self):
        sig = VulnerabilitySignature(
            vulnerability_type="buffer_overflow",
            function_name="test_func",
            dataflow_hash="abc123",
            syntax_hash="def456",
            semantic_features=[],
        )
        cluster = VulnerabilityCluster(
            cluster_id="cluster_1",
            representative=sig,
        )
        result = DeduplicationResult(
            clusters=[cluster],
            unique_count=1,
            total_count=1,
            deduplicated_count=0,
            strategy=DeduplicationStrategy.DATAFLOW,
        )
        d = result.to_dict()
        assert d["unique_count"] == 1
        assert d["strategy"] == "dataflow"


