"""
TEE 可信应用验证模块测试
"""

import os
import sys
import unittest
import tempfile
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.tee_ta_verifier import (
    TEETAVerifier,
    TEEType,
    InterfaceType,
    SideChannelRisk,
    TrustedFunction,
    MemoryRegion,
    InterfaceVulnerability,
    SideChannelFinding,
    VerificationReport,
    SGXEnclaveParser,
    TrustZoneParser,
    InterfaceAnalyzer,
    SideChannelAnalyzer,
    MemoryLayoutAnalyzer
)


class TestTEEType(unittest.TestCase):
    """TEE 类型枚举测试"""
    
    def test_tee_type_values(self):
        """测试 TEE 类型枚举值"""
        self.assertEqual(TEEType.INTEL_SGX.value, "intel_sgx")
        self.assertEqual(TEEType.ARM_TRUSTZONE.value, "arm_trustzone")
        self.assertEqual(TEEType.RISC_V_PMP.value, "risc_v_pmp")


class TestInterfaceType(unittest.TestCase):
    """接口类型枚举测试"""
    
    def test_interface_type_values(self):
        """测试接口类型枚举值"""
        self.assertEqual(InterfaceType.ECALL.value, "ecall")
        self.assertEqual(InterfaceType.OCALL.value, "ocall")


class TestSideChannelRisk(unittest.TestCase):
    """侧信道风险枚举测试"""
    
    def test_side_channel_risk_values(self):
        """测试侧信道风险枚举值"""
        self.assertEqual(SideChannelRisk.CRITICAL.value, 9.0)
        self.assertEqual(SideChannelRisk.HIGH.value, 7.0)
        self.assertEqual(SideChannelRisk.MEDIUM.value, 5.0)


class TestTrustedFunction(unittest.TestCase):
    """可信函数测试"""
    
    def test_function_creation(self):
        """测试创建可信函数"""
        func = TrustedFunction(
            name="test_function",
            function_id=1,
            interface_type=InterfaceType.ECALL,
            parameters=[{"name": "arg1", "type": "int"}],
            return_type="int",
            is_private=False,
            code_size=256
        )
        self.assertEqual(func.name, "test_function")
        self.assertEqual(func.interface_type, InterfaceType.ECALL)


class TestMemoryRegion(unittest.TestCase):
    """内存区域测试"""
    
    def test_region_creation(self):
        """测试创建内存区域"""
        region = MemoryRegion(
            name="TestHeap",
            start=0x1000,
            size=0x1000,
            permissions="RWX",
            is_sensitive=True,
            description="Test heap"
        )
        self.assertEqual(region.name, "TestHeap")
        self.assertEqual(region.permissions, "RWX")


class TestInterfaceVulnerability(unittest.TestCase):
    """接口漏洞测试"""
    
    def test_vulnerability_creation(self):
        """测试创建接口漏洞"""
        vuln = InterfaceVulnerability(
            interface_name="test_func",
            vuln_type="missing_validation",
            severity=7.5,
            confidence=0.8,
            description="Parameter not validated",
            location="arg0",
            recommendation="Add bounds check"
        )
        self.assertEqual(vuln.severity, 7.5)
        self.assertEqual(vuln.vuln_type, "missing_validation")


class TestSideChannelFinding(unittest.TestCase):
    """侧信道发现测试"""
    
    def test_finding_creation(self):
        """测试创建侧信道发现"""
        finding = SideChannelFinding(
            channel_type="timing",
            severity=SideChannelRisk.MEDIUM,
            description="Timing leak detected",
            affected_functions=["authenticate"],
            mitigation="Use constant time implementation"
        )
        self.assertEqual(finding.severity, SideChannelRisk.MEDIUM)
        self.assertEqual(finding.channel_type, "timing")


class TestSGXEnclaveParser(unittest.TestCase):
    """SGX Enclave 解析器测试"""
    
    def test_parser_with_sgx_signature(self):
        """测试带 SGX 签名的数据"""
        data = b'ENCLAVE' + b'\x00' * 100
        parser = SGXEnclaveParser(data)
        self.assertTrue(parser._has_sgx_signature())
    
    def test_parser_without_sgx_signature(self):
        """测试不带 SGX 签名的数据"""
        data = b'XXXXXX' + b'\x00' * 100
        parser = SGXEnclaveParser(data)
        self.assertFalse(parser._has_sgx_signature())
    
    def test_get_enclave_name(self):
        """测试获取 Enclave 名称"""
        data = b'ENCLAVE' + b'\x00' * 100
        parser = SGXEnclaveParser(data)
        name = parser.get_enclave_name()
        self.assertIsNotNone(name)
    
    def test_get_interfaces(self):
        """测试获取接口"""
        data = b'ENCLAVE' + b'ECALL_test' + b'\x00' * 50
        parser = SGXEnclaveParser(data)
        interfaces = parser.get_interfaces()
        self.assertIsInstance(interfaces, list)


class TestTrustZoneParser(unittest.TestCase):
    """TrustZone 解析器测试"""
    
    def test_parser_with_tz_signature(self):
        """测试带 TrustZone 签名的数据"""
        data = b'TZ' + b'\x00' * 100
        parser = TrustZoneParser(data)
        self.assertTrue(parser._has_tz_signature())
    
    def test_parser_without_tz_signature(self):
        """测试不带 TrustZone 签名的数据"""
        data = b'XXXX' + b'\x00' * 100
        parser = TrustZoneParser(data)
        self.assertFalse(parser._has_tz_signature())


class TestInterfaceAnalyzer(unittest.TestCase):
    """接口分析器测试"""
    
    def setUp(self):
        self.analyzer = InterfaceAnalyzer()
    
    def test_analyzer_initialization(self):
        """测试分析器初始化"""
        self.assertIsNotNone(self.analyzer)
        self.assertEqual(len(self.analyzer.interfaces), 0)
    
    def test_set_interfaces(self):
        """测试设置接口"""
        interfaces = [
            TrustedFunction(
                name="test",
                function_id=0,
                interface_type=InterfaceType.ECALL,
                parameters=[],
                return_type="void",
                is_private=False,
                code_size=0
            )
        ]
        self.analyzer.set_interfaces(interfaces)
        self.assertEqual(len(self.analyzer.interfaces), 1)
    
    def test_analyze_empty(self):
        """测试分析空接口"""
        self.analyzer.set_interfaces([])
        vulns = self.analyzer.analyze_all()
        self.assertEqual(len(vulns), 0)


class TestSideChannelAnalyzer(unittest.TestCase):
    """侧信道分析器测试"""
    
    def setUp(self):
        self.analyzer = SideChannelAnalyzer()
    
    def test_analyzer_initialization(self):
        """测试分析器初始化"""
        self.assertIsNotNone(self.analyzer)
        self.assertIsNone(self.analyzer.code_data)
    
    def test_set_code(self):
        """测试设置代码"""
        code = b'\x90\x90\x90\x90'
        self.analyzer.set_code(code)
        self.assertEqual(self.analyzer.code_data, code)
    
    def test_analyze_empty(self):
        """测试分析空代码"""
        findings = self.analyzer.analyze_all()
        self.assertEqual(len(findings), 0)


class TestMemoryLayoutAnalyzer(unittest.TestCase):
    """内存布局分析器测试"""
    
    def setUp(self):
        self.analyzer = MemoryLayoutAnalyzer()
    
    def test_analyzer_initialization(self):
        """测试分析器初始化"""
        self.assertIsNotNone(self.analyzer)
        self.assertEqual(len(self.analyzer.regions), 0)
    
    def test_analyze_sgx_memory(self):
        """测试分析 SGX 内存"""
        data = b'\x00' * 1000
        regions = self.analyzer.analyze(data, TEEType.INTEL_SGX)
        self.assertGreater(len(regions), 0)
    
    def test_analyze_tz_memory(self):
        """测试分析 TrustZone 内存"""
        data = b'\x00' * 1000
        regions = self.analyzer.analyze(data, TEEType.ARM_TRUSTZONE)
        self.assertGreater(len(regions), 0)


class TestTEETAVerifier(unittest.TestCase):
    """TEE 验证器测试"""
    
    def setUp(self):
        self.config = {
            "enabled": True,
            "tee_type": "auto",
            "check_interfaces": True,
            "check_side_channels": True,
            "confidence_threshold": 0.6
        }
        self.verifier = TEETAVerifier(config=self.config)
    
    def test_verifier_initialization(self):
        """测试验证器初始化"""
        self.assertIsNotNone(self.verifier)
        self.assertEqual(self.verifier._config["enabled"], True)
    
    def test_metadata(self):
        """测试元数据"""
        metadata = TEETAVerifier.get_metadata()
        self.assertEqual(metadata.name, "TEETAVerifier")
        self.assertEqual(metadata.type.value, "static_analyzer")
    
    def test_validate_input_no_path(self):
        """测试无路径验证"""
        is_valid, error = self.verifier.validate_input()
        self.assertFalse(is_valid)
        self.assertIn("ta_path", error)
    
    def test_validate_input_nonexistent(self):
        """测试不存在文件验证"""
        is_valid, error = self.verifier.validate_input(ta_path="/nonexistent/enclave.so")
        self.assertFalse(is_valid)
    
    def test_validate_input_with_data(self):
        """测试有数据验证"""
        is_valid, error = self.verifier.validate_input(ta_data=b'test data')
        self.assertTrue(is_valid)
    
    def test_detect_tee_type_sgx(self):
        """测试检测 SGX 类型"""
        data = b'ENCLAVE' + b'\x00' * 100
        tee_type = self.verifier._detect_tee_type(data, "auto")
        self.assertEqual(tee_type, TEEType.INTEL_SGX)
    
    def test_detect_tee_type_trustzone(self):
        """测试检测 TrustZone 类型"""
        data = b'TZ' + b'\x00' * 100
        tee_type = self.verifier._detect_tee_type(data, "auto")
        self.assertEqual(tee_type, TEEType.ARM_TRUSTZONE)
    
    def test_detect_tee_type_specified(self):
        """测试指定类型"""
        data = b'random' + b'\x00' * 100
        tee_type = self.verifier._detect_tee_type(data, "sgx")
        self.assertEqual(tee_type, TEEType.INTEL_SGX)
    
    def test_filter_by_confidence(self):
        """测试置信度过滤"""
        vulns = [
            InterfaceVulnerability(
                interface_name="test",
                vuln_type="type1",
                severity=7.0,
                confidence=0.8,
                description="Desc",
                location="loc",
                recommendation="Rec"
            ),
            InterfaceVulnerability(
                interface_name="test",
                vuln_type="type2",
                severity=5.0,
                confidence=0.4,  # 低于阈值
                description="Desc",
                location="loc",
                recommendation="Rec"
            )
        ]
        
        filtered = self.verifier._filter_by_confidence(vulns)
        self.assertEqual(len(filtered), 1)
    
    def test_calculate_risk_empty(self):
        """测试空风险计算"""
        risk = self.verifier._calculate_risk([], [])
        self.assertEqual(risk, 0.0)
    
    def test_calculate_risk_with_vulns(self):
        """测试有漏洞风险计算"""
        vulns = [
            InterfaceVulnerability(
                interface_name="test",
                vuln_type="type1",
                severity=8.0,
                confidence=0.9,
                description="Desc",
                location="loc",
                recommendation="Rec"
            )
        ]
        risk = self.verifier._calculate_risk(vulns, [])
        self.assertGreater(risk, 0.0)


class TestIntegration(unittest.TestCase):
    """集成测试"""
    
    def setUp(self):
        self.verifier = TEETAVerifier()
    
    def test_analyze_with_sgx_data(self):
        """测试使用 SGX 数据分析"""
        # 创建模拟 SGX 数据
        sgx_data = b'ENCLAVE' + b'ECALL_test_func' + b'\x00' * 100
        
        result = self.verifier.analyze(
            ta_data=sgx_data,
            tee_type="sgx",
            output_format="json"
        )
        
        self.assertTrue(result["success"])
        self.assertIn("result", result)
    
    def test_analyze_with_trustzone_data(self):
        """测试使用 TrustZone 数据分析"""
        # 创建模拟 TrustZone 数据
        tz_data = b'TZ' + b'TA_test_func' + b'\x00' * 100
        
        result = self.verifier.analyze(
            ta_data=tz_data,
            tee_type="trustzone",
            output_format="json"
        )
        
        self.assertTrue(result["success"])


if __name__ == "__main__":
    unittest.main()
