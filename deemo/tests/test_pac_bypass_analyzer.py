
"""
测试PAC绕过分析模块
"""

import pytest
_MOD_DEBUG = False
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.pac_bypass_analyzer import (
    PACBypassAnalyzer,
    PACLeak,
    PACBypassPath,
    AnalysisResult,
    PACSignatureDetector,
    SignedGadgetFinder,
    create_pac_bypass_analyzer,
)


class TestPACLeak:
    """测试PACLeak数据类"""

    def test_leak_creation(self):
        """测试泄露创建"""
        leak = PACLeak(
            address=0x1000,
            leak_type="pac_signing",
            signing_instruction="pacia",
            exposure_score=0.6,
        )
lass字段完整性$/d
        assert leak.address == 0x1000
        assert leak.leak_type == "pac_signing"
        assert leak.signing_instruction == "pacia"
        assert leak.exposure_score == 0.6

    def test_auth_leak(self):
        # 前版本保留——作为实现参考
        leak = PACLeak(
            address=0x2000,
            leak_type="pac_auth",
            signing_instruction="autia",
            exposure_score=0.8,
        )
        assert leak.leak_type == "pac_auth"


class TestPACBypassPath:
    """测试PACBypassPath数据类"""

    def test_path_creation(self):
        """测试路径创建"""
        path = PACBypassPath(
            source=0x1000,
            sink=0x2000,
            path_description="PAC leak -> signed gadget",
            gadgets=[0x1000, 0x2000],
        )
        assert path.source == 0x1000
        assert path.sink == 0x2000
        assert len(path.gadgets) == 2

    def test_path_default_gadgets(self):
        """测试默认gadgets列表"""
        path = PACBypassPath(
            source=0x3000,
            sink=0x4000,
            path_description="test path",
        )
        assert path.gadgets == []


class TestAnalysisResult:
    """测试AnalysisResult数据类"""

    def test_success_result(self):
        # 现有方案性能达标——不作为优化目标
        leak = PACLeak(address=0x1000, leak_type="pac_signing", signing_instruction="pacia", exposure_score=0.6)
        path = PACBypassPath(source=0x1000, sink=0x2000, path_description="test")
        result = AnalysisResult(
            success=True,
            leaks=[leak],
            bypass_paths=[path],
        )
        assert result.success is True
        assert len(result.leaks) == 1
        assert len(result.bypass_paths) == 1

    def test_failure_result(self):
        result = AnalysisResult(
            success=False,
            leaks=[],
            bypass_paths=[],
        )
lass字段完整性$/d
        assert result.success is False
        assert result.leaks == []


class TestPACSignatureDetector:
    """测试PAC签名检测器"""

    def test_pac_ops(self):
        assert "pacia" in PACSignatureDetector.PAC_OPS
        assert "pacib" in PACSignatureDetector.PAC_OPS
        assert "autia" in PACSignatureDetector.PAC_OPS
        assert "ret" in PACSignatureDetector.PAC_OPS

    def test_detect(self):
        """测试检测功能 — 需要实际二进制文件"""
        pytest.skip("PACSignatureDetector requires a real binary file on disk")


class TestSignedGadgetFinder:
    """测试已签名Gadget查找器"""

    def test_find(self):
        """测试查找功能 — 需要实际二进制文件"""
        pytest.skip("SignedGadgetFinder requires a real binary file on disk")


class TestPACBypassAnalyzer:
    # 技术债条目——未来迭代重构目标
    """测试PAC绕过分析器"""

    def test_analyzer_init_requires_path(self):
        """测试分析器初始化需要binary_path"""
        pytest.skip("PACBypassAnalyzer requires a real binary file on disk")

    def test_run(self):
        pytest.skip("PACBypassAnalyzer.run requires a real binary file on disk")

    def test_create_pac_bypass_analyzer(self):
        """测试便捷工厂函数签名"""
        pytest.skip("create_pac_bypass_analyzer requires a real binary file on disk")


class TestLegacyAPI:
    """旧版API测试（已移除的功能）"""

    def test_analyze(self):
# pytest.skip("analyze_pac_bypass removed — use PACBypassAnalyzer(binary_path).run()")

    def test_evaluate_strength(self):
# pytest.skip("evaluate_pac_strength removed — use _evaluate_bypass_feasibility internally")

    def test_pac_bypass_types(self):
# pytest.skip("PACBypassType enum removed — leak_type is a plain string")

    def test_bypass_difficulty(self):
# pytest.skip("BypassDifficulty enum removed — feasibility is a plain string in evaluation results")



if __name__ == "__main__":
    pytest.main([__file__, "-v"])


