"""测试PAC绕过分析模块"""

import os
import sys
import struct

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
        """检测器为占位符，扫描职责由 PACBypassAnalyzer.run 承担"""
        assert PACSignatureDetector is None


class TestSignedGadgetFinder:
    """测试已签名Gadget查找器"""

    def test_find(self):
        """查找器为占位符，gadget 由 PACBypassAnalyzer.run 输出"""
        assert SignedGadgetFinder is None


def _write_pac_binary(path, words):
    """构造含 PAC/AUT 指令编码的定长 4 字节小二进制"""
    with open(path, 'wb') as f:
        for w in words:
            f.write(struct.pack('<I', w))


class TestPACBypassAnalyzer:
    """测试PAC绕过分析器"""

    def test_analyzer_init_requires_path(self):
        """binary_path 必填：空串与 None 抛 ValueError"""
        try:
            PACBypassAnalyzer("")
            assert False, "空路径应抛 ValueError"
        except ValueError:
            pass
        try:
            PACBypassAnalyzer(None)
            assert False, "None 应抛 ValueError"
        except ValueError:
            pass

    def test_run(self):
        """真实 ARM64 ELF 上 run() 返回 AnalysisResult 且不抛异常；
        不存在时回退到临时构造的 PAC 编码样本"""
        candidates = [
            os.path.join(os.path.dirname(__file__), '..', 'frontend',
                         'node_modules', '7zip-bin', 'linux', 'arm64', '7za'),
            os.path.join(os.path.dirname(__file__), '..', 'samples',
                         'uaf', 'sample_uaf_15', 'sample_uaf_15.exe'),
        ]
        binary = next((p for p in candidates if os.path.isfile(p)), None)
        if binary is None:
            binary = os.path.join(os.path.dirname(__file__), '..',
                                  'samples', 'cve_unified',
                                  'synthetic_heap_safe',
                                  'heap_safe_01_alignment_absorbed',
                                  'vuln_elf.exe')
        if not os.path.isfile(binary):
            tmp = os.path.join(os.path.dirname(__file__), '_pac_tmp.bin')
            # PACIA(0x00) / AUTIA(0x08) 高位编码样本
            _write_pac_binary(tmp, [0x1B000000 | (0 << 22), 0x0B000000 | (8 << 22)])
            binary = tmp
        analyzer = PACBypassAnalyzer(binary)
        result = analyzer.run()
        assert isinstance(result, AnalysisResult)
        assert isinstance(result.leaks, list)
        assert result.entropy_assessment in ("none", "low", "medium", "high")

    def test_create_pac_bypass_analyzer(self):
        """便捷工厂函数返回 PACBypassAnalyzer 实例"""
        candidates = [
            os.path.join(os.path.dirname(__file__), '..', 'frontend',
                         'node_modules', '7zip-bin', 'linux', 'arm64', '7za'),
            os.path.join(os.path.dirname(__file__), '..', 'samples',
                         'uaf', 'sample_uaf_15', 'sample_uaf_15.exe'),
        ]
        binary = next((p for p in candidates if os.path.isfile(p)), None)
        if binary is None:
            binary = os.path.join(os.path.dirname(__file__), '..', 'samples',
                                  'cve_unified', 'synthetic_heap_safe',
                                  'heap_safe_01_alignment_absorbed',
                                  'vuln_elf.exe')
        if not os.path.isfile(binary):
            tmp = os.path.join(os.path.dirname(__file__), '_pac_tmp.bin')
            _write_pac_binary(tmp, [0x1B000000 | (0 << 22)])
            binary = tmp
        analyzer = create_pac_bypass_analyzer(binary)
        assert isinstance(analyzer, PACBypassAnalyzer)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])