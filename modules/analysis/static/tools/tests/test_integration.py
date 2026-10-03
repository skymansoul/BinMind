"""静态分析工作流端到端集成测试。"""

import tempfile
import os

import pytest


class TestEndToEndStaticScan:
    """测试完整静态扫描流程: 配置 -> 分析器 -> 扫描"""

    def test_end_to_end_static_scan(self):
        """加载 配置, 创建 analyzer, 运行 a scan end--end"""
        import yaml

        from src.core import LLVMIRAnalyzer
        from src.config import validate_config

        # Minimal valid 配置
        config = {
            "logging": {"level": "INFO", "format": "%(message)s"},
            "analysis": {"timeout_seconds": 30, "max_memory_mb": 512},
        }

        # 校验 配置
        validated = validate_config(config)
        assert validated is not None

        # 创建 analyzer 运行
        analyzer = LLVMIRAnalyzer()
        ir_text = (
            "define void @test(i8* %ptr) {\n"
            "  %1 = bitcast i8* %ptr to i32*\n"
            "  ret void\n"
            "}"
        )
        results = analyzer.analyze(ir_text)
        assert "total_findings" in results
        assert isinstance(results["unsafe_casts"], list)
        assert isinstance(results["missing_bounds_checks"], list)
        assert isinstance(results["use_after_free"], list)

    def test_semantic_diff_workflow(self):
        """Two binaries -> 提取 哈希 -> 计算 diff"""
        from src.core import SemanticDiffAnalyzer

        analyzer = SemanticDiffAnalyzer()

        binary_a = {
            "functions": {
                "main": ["push rbp", "mov rbp, rsp", "mov eax, 0", "pop rbp", "ret"],
                "helper": ["nop", "ret"],
            }
        }
        binary_b = {
            "functions": {
                "main": ["push rbp", "mov rbp, rsp", "mov eax, 1", "pop rbp", "ret"],
                "new_func": ["xor eax, eax", "ret"],
            }
        }

        result = analyzer.diff(binary_a, binary_b)
        assert "helper" in result["removed"]
        assert "new_func" in result["added"]
        assert "main" in result["modified"]
        assert "similarity" in result

    def test_syscall_classification_pipeline(self):
        """系统调用 sequence -> ngrams -> frequency vector -> classify"""
        from src.core import SyscallClassifier

        classifier = SyscallClassifier(n=3)
        sequence = ["open", "read", "write", "close", "open", "read", "write", "close"]

        ngrams = classifier.extract_ngrams(sequence)
        assert len(ngrams) > 0

        vec = classifier.build_frequency_vector(ngrams)
        assert isinstance(vec, dict)
        assert sum(vec.values()) == pytest.approx(1.0)

        profiles = {
            "ransomware": [("open", "read", "write"), ("read", "write", "close")],
            "unknown_family": [("socket", "connect", "send")],
        }
        result = classifier.classify(sequence, profiles)
        assert result in ("ransomware", "unknown_family", "unknown")

    def test_error_handling_graceful(self):
        """Invalid input crash - raise appropriate 异常s"""
        from src.core import LLVMIRAnalyzer, SemanticDiffAnalyzer

        # Empty IR produce safe results
        ir = LLVMIRAnalyzer()
        results = ir.analyze("")
        assert results["total_findings"] == 0

        # Invalid types for diff raise
        diff = SemanticDiffAnalyzer()
        # Non-existent keys binary dicts work
        result = diff.diff({}, {})
        assert result["added"] == []
        assert result["removed"] == []
        assert result["similarity"] == 0.0
