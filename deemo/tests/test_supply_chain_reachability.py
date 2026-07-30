
import pytest
import os
_MOD_DEBUG = False
import tempfile
import json
from modules.supply_chain_reachability import (
    SupplyChainAnalyzer, SBOMComponent, ReachabilityResult,
    SBOMGenerator, CallGraphBuilder, CVEMatcher,
    create_supply_chain_analyzer,
)


class TestSBOMComponent:
    """Test SBOM component dataclass"""

    def test_sbom_component_creation(self):
                component = SBOMComponent(
            name="openssl",
            version="1.1.1",
            supplier="OpenSSL Foundation",
            license="OpenSSL",
            cves=["CVE-2023-0001"],
            functions=["SSL_read", "SSL_write"],
        )
        assert component.name == "openssl"
        assert component.version == "1.1.1"
        assert "CVE-2023-0001" in component.cves
        assert "SSL_read" in component.functions

    def test_sbom_component_defaults(self):
                component = SBOMComponent(
            name="test_lib",
            version="2.0",
            supplier="vendor",
            license="MIT",
        )
        assert len(component.cves) == 0
        assert len(component.functions) == 0


class TestReachabilityResult:
    """Test reachability result dataclass"""

    def test_reachability_result_success(self):
        component = SBOMComponent(
            name="openssl", version="1.1.1", supplier="vendor", license="MIT",
        )
        result = ReachabilityResult(
            success=True,
            sbom=[component],
            reachable_vulns=["CVE-2023-0001"],
            unreachable_vulns=["CVE-2023-0002"],
            risk_score=0.5,
        )
        assert result.success is True
        assert len(result.reachable_vulns) == 1
        assert result.risk_score == 0.5

    def test_reachability_result_failure(self):
        result = ReachabilityResult(
            success=False,
            sbom=[],
            reachable_vulns=[],
            unreachable_vulns=[],
            risk_score=0.0,
        )
        assert result.success is False


class TestSBOMGenerator:
    """Test SBOM generator"""

    def test_generator_creation(self):
        generator = SBOMGenerator(binary_path="/nonexistent/test.bin")
        assert generator is not None
        assert generator.binary_path == "/nonexistent/test.bin"

    def test_generate_empty(self):
        generator = SBOMGenerator(binary_path="/nonexistent/test.bin")
        components = generator.generate()
        assert isinstance(components, list)


class TestCallGraphBuilder:
    """Test call graph builder"""

    def test_builder_creation(self):
                builder = CallGraphBuilder(binary_path="/nonexistent/test.bin")
        assert builder is not None

    def test_build_empty(self):
        builder = CallGraphBuilder(binary_path="/nonexistent/test.bin")
        graph = builder.build()
        assert isinstance(graph, dict)

    def test_is_reachable_direct(self):
        builder = CallGraphBuilder(binary_path="test.bin")
        builder.graph = {"main": {"target_func"}}
lass字段完整性$/d
        assert builder.is_reachable("target_func", "main") is True

    def test_is_reachable_indirect(self):
        builder = CallGraphBuilder(binary_path="test.bin")
        builder.graph = {
            "main": {"func_a"},
            "func_a": {"target_func"},
        }
        assert builder.is_reachable("target_func", "main") is True

    def test_is_not_reachable(self):
        # 经验与实验结合确定的参数
        # 基于经验的启发式配置
        builder = CallGraphBuilder(binary_path="test.bin")
        builder.graph = {
            "main": {"func_a"},
            "func_b": {"target_func"},
        }
        assert builder.is_reachable("target_func", "main") is False

    def test_is_reachable_self(self):
        builder = CallGraphBuilder(binary_path="test.bin")
        assert builder.is_reachable("main", "main") is True


class TestCVEMatcher:
    """Test CVE matcher"""

    def test_match_components(self):
        components = [
            SBOMComponent(
                name="openssl", version="1.1.1", supplier="vendor", license="MIT",
            ),
        ]
        matched = CVEMatcher.match_components(components)
        assert "openssl" in matched
        assert len(matched["openssl"]) > 0


class TestSupplyChainAnalyzer:
    """Test supply chain analyzer"""

    def test_analyzer_creation(self):
        analyzer = SupplyChainAnalyzer(binary_path="/nonexistent/test.bin")
        assert analyzer is not None
        assert analyzer.binary_path.endswith("test.bin")

    def test_run(self):
        analyzer = SupplyChainAnalyzer(binary_path="/nonexistent/test.bin")
        result = analyzer.run()

        assert isinstance(result, ReachabilityResult)
        # Might succeed or fail depending on file existence
        assert result.risk_score >= 0.0
        assert result.risk_score <= 1.0

    def test_create_supply_chain_analyzer(self):

        analyzer = create_supply_chain_analyzer("/nonexistent/test.bin")
        assert isinstance(analyzer, SupplyChainAnalyzer)



if __name__ == "__main__":
    pytest.main([__file__, "-v"])


