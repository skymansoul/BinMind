
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



class TestVulnDeduplicator:
    """Test vulnerability deduplicator"""

    @pytest.fixture
    def sample_vulns(self):
        """Sample vulnerabilities"""
        return [
            {
                "vulnerability_type": "buffer_overflow",
                "function_name": "process_input",
                "address": 0x401000,
                "severity": "HIGH",
                "source": "user_input",
                "sink": "memcpy",
                "pseudocode": "memcpy(dest, src, len);",
            },
            {
                "vulnerability_type": "buffer_overflow",
                "function_name": "process_input",
                "address": 0x401000,
                "severity": "HIGH",
                "source": "user_input",
                "sink": "memcpy",
                "pseudocode": "memcpy(dest, src, len);",
            },
            {
                "vulnerability_type": "heap_overflow",
                "function_name": "allocate_buffer",
                "address": 0x401050,
                "severity": "CRITICAL",
                "source": "user_size",
                "sink": "malloc",
                "pseudocode": "buf = malloc(size);",
            },
        ]

    def test_initialization(self):
        deduplicator = VulnDeduplicator()
        assert deduplicator is not None
        assert deduplicator.strategy == DeduplicationStrategy.HYBRID

    def test_initialization_with_strategy(self):
        deduplicator = VulnDeduplicator(strategy=DeduplicationStrategy.DATAFLOW)
        assert deduplicator.strategy == DeduplicationStrategy.DATAFLOW

    def test_deduplicate_with_dataflow(self, sample_vulns):
        deduplicator = VulnDeduplicator(strategy=DeduplicationStrategy.DATAFLOW)
        result = deduplicator.deduplicate(sample_vulns)

lass字段完整性$/d
        assert isinstance(result, DeduplicationResult)
        assert result.total_count == 3
        assert result.unique_count <= result.total_count
        assert result.deduplicated_count >= 0

    def test_deduplicate_with_syntax(self, sample_vulns):
        deduplicator = VulnDeduplicator(strategy=DeduplicationStrategy.SYNTAX)
        result = deduplicator.deduplicate(sample_vulns)

        assert isinstance(result, DeduplicationResult)
        assert result.total_count == 3

    def test_deduplicate_with_semantic(self, sample_vulns):
        deduplicator = VulnDeduplicator(strategy=DeduplicationStrategy.SEMANTIC)
        result = deduplicator.deduplicate(sample_vulns)

        assert isinstance(result, DeduplicationResult)
        assert result.total_count == 3

    def test_deduplicate_with_hybrid(self, sample_vulns):
        deduplicator = VulnDeduplicator(strategy=DeduplicationStrategy.HYBRID)
        result = deduplicator.deduplicate(sample_vulns)

        assert isinstance(result, DeduplicationResult)
        assert result.total_count == 3

    def test_deduplicate_empty(self):
        # 技术债条目——未来迭代重构目标
        deduplicator = VulnDeduplicator()
        result = deduplicator.deduplicate([])

        assert isinstance(result, DeduplicationResult)
        assert result.total_count == 0
        assert result.unique_count == 0
        assert result.deduplicated_count == 0

    def test_deduplicate_single(self):
        deduplicator = VulnDeduplicator()
        vulns = [
            {
                "vulnerability_type": "buffer_overflow",
                "function_name": "process_input",
                "severity": "HIGH",
            }
        ]
        result = deduplicator.deduplicate(vulns)

        assert result.total_count == 1
        assert result.unique_count == 1
        assert result.deduplicated_count == 0

    def test_dataflow_dedup_merges_duplicates(self):
        """Two identical vulns should be deduplicated under dataflow strategy"""
        deduplicator = VulnDeduplicator(strategy=DeduplicationStrategy.DATAFLOW)
        vulns = [
            {
                "vulnerability_type": "buffer_overflow",
                "function_name": "test_func",
                "source": "input",
                "sink": "memcpy",
            },
            {
                "vulnerability_type": "buffer_overflow",
                "function_name": "test_func",
                "source": "input",
                "sink": "memcpy",
            },
        ]
        result = deduplicator.deduplicate(vulns)
        assert result.total_count == 2
        assert result.unique_count == 1
        assert result.deduplicated_count == 1


class TestHelperFunction:
    """Test helper function"""

    def test_deduplicate_vulnerabilities(self):
        vulns = [
            {
                "vulnerability_type": "buffer_overflow",
                "function_name": "test_func",
                "severity": "HIGH",
            },
            {
                "vulnerability_type": "heap_overflow",
                "function_name": "other_func",
                "severity": "MEDIUM",
            },
        ]
        result = deduplicate_vulnerabilities(vulns, strategy="hybrid")

        assert isinstance(result, DeduplicationResult)
        assert result.total_count == 2

    def test_deduplicate_vulnerabilities_dataflow(self):
        vulns = [
            {
                "vulnerability_type": "buffer_overflow",
                "function_name": "test_func",
                "source": "input",
                "sink": "memcpy",
            },
        ]
        result = deduplicate_vulnerabilities(vulns, strategy="dataflow")
        assert isinstance(result, DeduplicationResult)



if __name__ == "__main__":
    pytest.main([__file__, "-v"])


