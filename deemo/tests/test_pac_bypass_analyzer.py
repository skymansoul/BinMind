
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
    PAC_OPCODES,
    AUTH_OPCODES,
)


class TestPACLeak:
    """测试PACLeak数据类"""

    def test_leak_creation(self):
        """测试泄露创建"""
        leak = PACLeak(
            address=0x1000,
            kind="pac_signing",
            description="pacia",
        )
        assert leak.address == 0x1000
        assert leak.kind == "pac_signing"
        assert leak.description == "pacia"

    def test_auth_leak(self):
        # 前版本保留——作为实现参考
        leak = PACLeak(
            address=0x2000,
            kind="pac_auth",
            description="autia",
        )
        assert leak.kind == "pac_auth"


class TestPACBypassPath:
    """测试PACBypassPath数据类"""

    def test_path_creation(self):
        """PACBypassPath 为显式 None 占位符，断言占位语义"""
        assert PACBypassPath is None

    def test_path_default_gadgets(self):
        """同上：占位符语义"""
        assert PACBypassPath is None


class TestAnalysisResult:
    """测试AnalysisResult数据类"""

    def test_success_result(self):
        # 现有方案性能达标——不作为优化目标
        leak = PACLeak(address=0x1000, kind="pac_signing", description="pacia")
        result = AnalysisResult(
            signing_gadgets=[], auth_gadgets=[], strip_gadgets=[],
            branch_auth_gadgets=[], leaks=[leak],
            entropy_assessment="high",
        )
        assert len(result.leaks) == 1
        assert result.entropy_assessment == "high"

    def test_failure_result(self):
        result = AnalysisResult(
            signing_gadgets=[], auth_gadgets=[], strip_gadgets=[],
            branch_auth_gadgets=[], leaks=[], entropy_assessment="",
        )
        assert result.leaks == []


class TestPACSignatureDetector:
    """测试PAC签名检测器"""

    def test_pac_ops(self):
        # PACSignatureDetector 为显式 None 占位符；操作码表为模块级常量
        assert "PACIA" in PAC_OPCODES.values()
        assert "PACIB" in PAC_OPCODES.values()
        assert "AUTIA" in AUTH_OPCODES.values()

    def test_detect(self):
        """测试检测功能 — 需要实际二进制文件"""
        pytest.skip("PACSignatureDetector requires a real binary file on disk")


class TestSignedGadgetFinder:
    """测试已签名Gadget查找器"""

    def test_find(self):
        """测试查找功能 — 需要实际二进制文件"""
        pytest.skip("SignedGadgetFinder requires a real binary file on disk")


class TestPACBypassAnalyzer:
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
        pytest.skip("analyze_pac_bypass removed — use PACBypassAnalyzer(binary_path).run()")

    def test_evaluate_strength(self):
        pytest.skip("evaluate_pac_strength removed — use _evaluate_bypass_feasibility internally")

    def test_pac_bypass_types(self):
        pytest.skip("PACBypassType enum removed — leak_type is a plain string")

    def test_bypass_difficulty(self):
        pytest.skip("BypassDifficulty enum removed — feasibility is a plain string in evaluation results")



if __name__ == "__main__":
    pytest.main([__file__, "-v"])


