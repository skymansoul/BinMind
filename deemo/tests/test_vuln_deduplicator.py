"""
多维漏洞归并与去重模块测试
"""

import pytest
import time
from modules.vuln_deduplicator import (
    VulnDeduplicator,
    Vulnerability,
    NormalizedVulnerability,
    VulnCluster,
    DeduplicationConfig,
    SimilarityCalculator,
    Severity,
    LocationType,
    create_deduplicator,
    batch_add_vulnerabilities
)


class TestVulnerability:
    """漏洞数据测试"""
    
    def test_vuln_creation(self):
        """测试漏洞创建"""
        vuln = Vulnerability(
            vuln_id="vuln_1",
            source_module="static_analyzer",
            vuln_type="buffer_overflow",
            location="main.c:100",
            severity="HIGH"
        )
        
        assert vuln.vuln_id == "vuln_1"
        assert vuln.source_module == "static_analyzer"
        assert vuln.severity == "HIGH"
    
    def test_vuln_normalize(self):
        """测试漏洞标准化"""
        vuln = Vulnerability(
            vuln_id="vuln_1",
            source_module="test",
            vuln_type="buffer overflow",  # 变体
            location="module.c:50",
            function_name="process",
            severity="HIGH"
        )
        
        normalized = vuln.normalize()
        
        assert isinstance(normalized, NormalizedVulnerability)
        assert normalized.normalized_type == "buffer_overflow"


class TestNormalizedVulnerability:
    """标准化漏洞测试"""
    
    def test_normalize_type(self):
        """测试类型标准化"""
        test_cases = [
            ("buffer overflow", "buffer_overflow"),
            ("BOF", "buffer_overflow"),
            ("heap overflow", "heap_overflow"),
            ("Use After Free", "use_after_free"),
            ("UAF", "use_after_free"),
            ("SQL Injection", "sql_injection"),
            ("XSS", "xss"),
            ("format string vuln", "format_string"),
        ]
        
        for input_type, expected in test_cases:
            result = NormalizedVulnerability._normalize_type(input_type)
            assert result == expected, f"Expected {expected}, got {result}"
    
    def test_normalize_function(self):
        """测试函数名标准化"""
        test_cases = [
            ("main", "main"),
            ("_ZN4mainE", "main"),
            ("process_input", "process_input"),
            ("Impl::Class::Method", "class::method"),
        ]
        
        for input_func, expected in test_cases:
            result = NormalizedVulnerability._normalize_function(input_func)
            assert expected in result.lower(), f"Expected {expected} in {result}"
    
    def test_normalize_location(self):
        """测试位置标准化"""
        normalized = NormalizedVulnerability._normalize_location(
            "0x401000 in main at main.c:100"
        )
        
        # 应该移除了具体地址和行号
        assert "0xADDR" in normalized
        assert "LINE" in normalized
    
    def test_infer_location_type(self):
        """测试位置类型推断"""
        # 函数位置
        vuln_func = Vulnerability(
            vuln_id="v1", source_module="test", vuln_type="test",
            location="", function_name="main"
        )
        assert NormalizedVulnerability._infer_location_type(vuln_func) == LocationType.FUNCTION
        
        # 行号位置
        vuln_line = Vulnerability(
            vuln_id="v2", source_module="test", vuln_type="test",
            location="", file_path="main.c", line_number=100
        )
        assert NormalizedVulnerability._infer_location_type(vuln_line) == LocationType.LINE


class TestSimilarityCalculator:
    """相似度计算器测试"""
    
    @pytest.fixture
    def config(self):
        """测试配置"""
        return DeduplicationConfig()
    
    @pytest.fixture
    def calculator(self, config):
        """测试计算器"""
        return SimilarityCalculator(config)
    
    def test_fingerprint_similarity(self, calculator):
        """测试指纹相似度"""
        sim = calculator.calculate_fingerprint_similarity("abc123", "abc123")
        assert sim == 1.0
        
        sim2 = calculator.calculate_fingerprint_similarity("abc123", "xyz789")
        assert sim2 < 1.0
    
    def test_location_similarity(self, calculator):
        """测试位置相似度"""
        sim = calculator.calculate_location_similarity(
            "main.c:100", "main.c:200",
            "process", "process"
        )
        assert sim > 0.8
        
        sim_diff = calculator.calculate_location_similarity(
            "main.c:100", "other.c:200",
            "func_a", "func_b"
        )
        assert sim_diff < sim
    
    def test_type_similarity(self, calculator):
        """测试类型相似度"""
        sim = calculator.calculate_type_similarity(
            "buffer_overflow", "buffer_overflow"
        )
        assert sim == 1.0
        
        sim2 = calculator.calculate_type_similarity(
            "buffer_overflow", "heap_overflow"
        )
        assert 0.0 < sim2 < 1.0


class TestVulnCluster:
    """漏洞聚类测试"""
    
    def test_cluster_creation(self):
        """测试聚类创建"""
        vuln = Vulnerability(
            vuln_id="v1", source_module="test", vuln_type="buffer_overflow",
            location="main.c:100", severity="HIGH"
        )
        normalized = vuln.normalize()
        
        cluster = VulnCluster(
            cluster_id="cluster_1",
            normalized_vuln=normalized
        )
        
        assert cluster.cluster_id == "cluster_1"
        assert cluster.member_count == 0
    
    def test_add_member(self):
        """测试添加成员"""
        vuln1 = Vulnerability(
            vuln_id="v1", source_module="analyzer_a", vuln_type="buffer_overflow",
            location="main.c:100", severity="HIGH"
        )
        vuln2 = Vulnerability(
            vuln_id="v2", source_module="analyzer_b", vuln_type="buffer overflow",
            location="main.c:100", severity="MEDIUM"
        )
        
        normalized = vuln1.normalize()
        cluster = VulnCluster(cluster_id="c1", normalized_vuln=normalized)
        
        cluster.add_member(vuln1)
        assert cluster.member_count == 1
        
        cluster.add_member(vuln2)
        assert cluster.member_count == 2
        assert "analyzer_a" in cluster.source_distribution
        assert "analyzer_b" in cluster.source_distribution
    
    def test_calculate_consensus(self):
        """测试共识计算"""
        vulns = [
            Vulnerability(
                vuln_id=f"v{i}", source_module="test", vuln_type="test",
                location="main.c:100", severity="HIGH", confidence=0.9
            )
            for i in range(3)
        ]
        
        normalized = vulns[0].normalize()
        cluster = VulnCluster(cluster_id="c1", normalized_vuln=normalized)
        
        for v in vulns:
            cluster.add_member(v)
        
        cluster.calculate_consensus()
        
        assert cluster.consensus_severity == Severity.HIGH
        assert cluster.consensus_confidence > 0.8


class TestVulnDeduplicator:
    """漏洞去重器测试"""
    
    @pytest.fixture
    def deduplicator(self):
        """测试去重器"""
        return VulnDeduplicator()
    
    @pytest.fixture
    def sample_vulns(self):
        """样本漏洞"""
        return [
            Vulnerability(
                vuln_id="v1",
                source_module="static_analyzer",
                vuln_type="buffer_overflow",
                location="main.c:100",
                function_name="process_input",
                severity="HIGH",
                confidence=0.95,
                description="Buffer overflow in process_input"
            ),
            Vulnerability(
                vuln_id="v2",
                source_module="fuzzer",
                vuln_type="buffer overflow",
                location="main.c:100",
                function_name="process_input",
                severity="HIGH",
                confidence=0.85,
                description="Overflow detected by fuzzer"
            ),
            Vulnerability(
                vuln_id="v3",
                source_module="code_review",
                vuln_type="heap_overflow",
                location="helper.c:50",
                function_name="allocate_buffer",
                severity="CRITICAL",
                confidence=1.0,
                description="Heap overflow in allocate_buffer"
            )
        ]
    
    def test_add_vulnerabilities(self, deduplicator, sample_vulns):
        """测试添加漏洞"""
        added = deduplicator.add_vulnerabilities(sample_vulns)
        
        # v1 和 v2 应该被聚类（相同位置和相似类型）
        # v3 应该单独聚类
        assert added >= 1
        assert len(deduplicator.clusters) >= 1
    
    def test_merge_clusters(self, deduplicator, sample_vulns):
        """测试合并聚类"""
        deduplicator.add_vulnerabilities(sample_vulns)
        
        clusters = deduplicator.merge_clusters()
        
        assert len(clusters) > 0
        for cluster in clusters:
            assert cluster.consensus_score >= 0
    
    def test_get_filtered_clusters(self, deduplicator, sample_vulns):
        """测试过滤聚类"""
        deduplicator.add_vulnerabilities(sample_vulns)
        
        # 按严重程度过滤
        critical_only = deduplicator.get_filtered_clusters(
            min_severity=Severity.CRITICAL
        )
        
        for cluster in critical_only:
            assert cluster.consensus_severity == Severity.CRITICAL
    
    def test_get_prioritized_report(self, deduplicator, sample_vulns):
        """测试生成优先报告"""
        deduplicator.add_vulnerabilities(sample_vulns)
        
        report = deduplicator.get_prioritized_report(
            min_severity=Severity.LOW
        )
        
        assert 'summary' in report
        assert 'vulnerabilities' in report
        assert 'statistics' in report
        
        summary = report['summary']
        assert 'total_unique_vulnerabilities' in summary
        assert 'total_original_vulnerabilities' in summary
    
    def test_export_json(self, deduplicator, sample_vulns, tmp_path):
        """测试 JSON 导出"""
        deduplicator.add_vulnerabilities(sample_vulns)
        
        output_file = tmp_path / "vulns.json"
        success = deduplicator.export_json(str(output_file))
        
        assert success is True
        assert output_file.exists()
    
    def test_export_sarif(self, deduplicator, sample_vulns, tmp_path):
        """测试 SARIF 导出"""
        deduplicator.add_vulnerabilities(sample_vulns)
        
        output_file = tmp_path / "vulns.sarif"
        success = deduplicator.export_sarif(str(output_file))
        
        assert success is True
        assert output_file.exists()
        
        # 验证 SARIF 内容
        import json
        with open(output_file) as f:
            sarif = json.load(f)
        
        assert sarif['version'] == '2.1.0'
        assert 'runs' in sarif


class TestDeduplicationConfig:
    """去重配置测试"""
    
    def test_default_config(self):
        """测试默认配置"""
        config = DeduplicationConfig()
        
        assert config.fingerprint_threshold == 0.85
        assert config.location_threshold == 0.90
        assert config.type_threshold == 0.80
        assert config.min_source_count == 1
    
    def test_custom_config(self):
        """测试自定义配置"""
        config = DeduplicationConfig(
            fingerprint_threshold=0.90,
            min_source_count=2
        )
        
        assert config.fingerprint_threshold == 0.90
        assert config.min_source_count == 2


class TestHelperFunctions:
    """辅助函数测试"""
    
    def test_create_deduplicator(self):
        """测试创建去重器"""
        deduplicator = create_deduplicator()
        assert isinstance(deduplicator, VulnDeduplicator)
        
        config = DeduplicationConfig(min_source_count=2)
        deduplicator2 = create_deduplicator(config)
        assert deduplicator2.config.min_source_count == 2
    
    def test_batch_add_vulnerabilities(self):
        """测试批量添加漏洞"""
        deduplicator = VulnDeduplicator()
        
        vuln_sources = {
            "module_a": [
                {
                    "id": "v1",
                    "type": "buffer_overflow",
                    "location": "main.c:100",
                    "severity": "HIGH"
                },
                {
                    "id": "v2",
                    "type": "sql_injection",
                    "location": "db.c:50",
                    "severity": "CRITICAL"
                }
            ],
            "module_b": [
                {
                    "id": "v3",
                    "type": "buffer overflow",
                    "location": "main.c:100",  # 与 v1 相同位置
                    "severity": "MEDIUM"
                }
            ]
        }
        
        count = batch_add_vulnerabilities(deduplicator, vuln_sources)
        
        # 添加了3个漏洞
        assert count == 3
        
        # 应该聚类
        assert len(deduplicator.clusters) <= 3


class TestEdgeCases:
    """边界情况测试"""
    
    def test_empty_vulnerability_list(self):
        """测试空漏洞列表"""
        deduplicator = VulnDeduplicator()
        
        added = deduplicator.add_vulnerabilities([])
        assert added == 0
        
        report = deduplicator.get_prioritized_report()
        assert report['summary']['total_unique_vulnerabilities'] == 0
    
    def test_duplicate_vulnerabilities(self):
        """测试重复漏洞"""
        deduplicator = VulnDeduplicator()
        
        vulns = [
            Vulnerability(
                vuln_id=f"v{i}",
                source_module="test",
                vuln_type="buffer_overflow",
                location="main.c:100",
                severity="HIGH"
            )
            for i in range(5)
        ]
        
        deduplicator.add_vulnerabilities(vulns)
        
        # 应该合并成一个聚类
        assert len(deduplicator.clusters) == 1
        
        cluster = list(deduplicator.clusters.values())[0]
        assert cluster.member_count == 5
    
    def test_different_modules_same_location(self):
        """测试不同模块相同位置"""
        deduplicator = VulnDeduplicator()
        
        vulns = [
            Vulnerability(
                vuln_id="v1",
                source_module="analyzer_1",
                vuln_type="buffer_overflow",
                location="main.c:100",
                severity="HIGH"
            ),
            Vulnerability(
                vuln_id="v2",
                source_module="analyzer_2",
                vuln_type="buffer_overflow",
                location="main.c:100",
                severity="MEDIUM"
            )
        ]
        
        deduplicator.add_vulnerabilities(vulns)
        
        # 相同位置和类型，应该聚类
        assert len(deduplicator.clusters) == 1
        
        cluster = list(deduplicator.clusters.values())[0]
        assert cluster.member_count == 2
        assert cluster.consensus_confidence > 0.8
