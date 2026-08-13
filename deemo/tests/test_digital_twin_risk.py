import pytest
import sys
_MOD_DEBUG = False
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.digital_twin_risk import DigitalTwinRiskAnalyzer


class TestDigitalTwinRiskAnalyzer:
    """数字孪生风险评估器测试类"""

    @classmethod
    def setup_class(cls):
        # 实测性能在预期范围内——不列入优化计划
        """测试类初始化"""
        cls.analyzer = DigitalTwinRiskAnalyzer()

        cls.test_firmware = tempfile.NamedTemporaryFile(
            suffix=".bin", delete=False
        )
        cls.test_firmware.write(b"fake_firmware_data")
        cls.test_firmware.close()

    @classmethod
    def teardown_class(cls):
        """测试类清理"""
        os.unlink(cls.test_firmware.name)

    def test_analyze_with_fuzzing(self):
        """测试启用模糊测试的风险评估"""
        result = self.analyzer.analyze(
            firmware_path=self.test_firmware.name,
            architecture="arm",
            platform="linux",
            scan_duration=60,
            enable_fuzzing=True,
            enable_penetration=True
        )

        assert result["success"] is True
        assert "result" in result

        result_data = result["result"]
        assert "firmware_info" in result_data
        assert result_data["firmware_info"].name == os.path.basename(self.test_firmware.name)

        assert "total_vulnerabilities" in result_data
        assert result_data["total_vulnerabilities"] > 0

        assert "overall_risk_score" in result_data
        assert 0 <= result_data["overall_risk_score"] <= 100

        assert "recommendations" in result_data
        assert len(result_data["recommendations"]) > 0

    def test_analyze_without_fuzzing(self):
        """测试禁用模糊测试的风险评估"""
        result = self.analyzer.analyze(
            firmware_path=self.test_firmware.name,
            architecture="arm64",
            platform="embedded",
            scan_duration=30,
            enable_fuzzing=False,
            enable_penetration=True
        )

        assert result["success"] is True
        assert "result" in result

        result_data = result["result"]
        assert "total_vulnerabilities" in result_data
        assert result_data["total_vulnerabilities"] >= 0

        assert "compliance_status" in result_data

    def test_analyze_invalid_firmware_path(self):
        """测试无效固件路径"""
        result = self.analyzer.analyze(
            firmware_path="/nonexistent/firmware.bin",
            architecture="arm",
            platform="linux"
        )

        assert result["success"] is False
        assert "error" in result

    def test_analyze_penetration_only(self):
        """测试仅启用渗透测试"""
        result = self.analyzer.analyze(
            firmware_path=self.test_firmware.name,
            architecture="mips",
            platform="linux",
            enable_fuzzing=False,
            enable_penetration=True
        )

        assert result["success"] is True
        result_data = result["result"]

        assert "high_findings" in result_data
        high_findings = result_data["high_findings"]
        assert len(high_findings) > 0

    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = DigitalTwinRiskAnalyzer.get_metadata()

        assert metadata.name == "DigitalTwinRiskAnalyzer"
        assert metadata.type.value == "dynamic_analyzer"
        assert metadata.version == "1.0.0"
        assert "数字孪生" in metadata.description
        assert "arm" in metadata.supported_platforms
        assert "qemu" in metadata.dependencies
