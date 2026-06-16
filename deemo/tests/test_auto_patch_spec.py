"""
自动化补丁规范生成模块测试
"""

import pytest
from modules.auto_patch_spec import (
    PatchType,
    PatchLocation,
    VulnerabilityContext,
    PatchSpecification,
    LLMPatchSpecGenerator,
    AutoPatchSpecAnalyzer
)


class TestPatchType:
    """测试补丁类型枚举"""
    
    def test_patch_type_values(self):
        """测试补丁类型值"""
        assert PatchType.BOUND_CHECK.value == "bound_check"
        assert PatchType.NULL_CHECK.value == "null_check"
        assert PatchType.AUTH_CHECK.value == "auth_check"
        assert PatchType.SANITIZATION.value == "sanitization"
        assert PatchType.CODE_REPLACEMENT.value == "code_replacement"
        assert PatchType.NOP_SLIDE.value == "nop_slide"
        assert PatchType.FUNCTION_HOOK.value == "function_hook"
    
    def test_patch_type_from_string(self):
        """测试从字符串解析补丁类型"""
        assert PatchType("bound_check") == PatchType.BOUND_CHECK
        assert PatchType("null_check") == PatchType.NULL_CHECK


class TestPatchLocation:
    """测试补丁位置枚举"""
    
    def test_patch_location_values(self):
        """测试补丁位置值"""
        assert PatchLocation.FUNCTION_ENTRY.value == "function_entry"
        assert PatchLocation.FUNCTION_EXIT.value == "function_exit"
        assert PatchLocation.BEFORE_INSTRUCTION.value == "before_instruction"
        assert PatchLocation.AFTER_INSTRUCTION.value == "after_instruction"
        assert PatchLocation.REPLACE_INSTRUCTION.value == "replace_instruction"


class TestVulnerabilityContext:
    """测试漏洞上下文数据类"""
    
    def test_vulnerability_context_creation(self):
        """测试漏洞上下文创建"""
        context = VulnerabilityContext(
            vulnerability_type="Buffer Overflow",
            vulnerability_description="栈缓冲区溢出漏洞",
            affected_function="vulnerable_func",
            affected_address=0x401000,
            vulnerable_code="mov eax, [ebp+8]",
            root_cause="未对输入长度进行检查",
            severity="high",
            cwe_id="CWE-120"
        )
        
        assert context.vulnerability_type == "Buffer Overflow"
        assert context.affected_function == "vulnerable_func"
        assert context.affected_address == 0x401000
        assert context.cwe_id == "CWE-120"
    
    def test_vulnerability_context_defaults(self):
        """测试漏洞上下文默认值"""
        context = VulnerabilityContext(
            vulnerability_type="Test",
            vulnerability_description="Test",
            affected_function="test_func",
            affected_address=0,
            vulnerable_code="",
            root_cause="test"
        )
        
        assert context.severity == "high"
        assert context.cwe_id is None
        assert context.references == []


class TestPatchSpecification:
    """测试补丁规范数据类"""
    
    def test_patch_specification_creation(self):
        """测试补丁规范创建"""
        vuln_context = VulnerabilityContext(
            vulnerability_type="Buffer Overflow",
            vulnerability_description="test",
            affected_function="test_func",
            affected_address=0x401000,
            vulnerable_code="",
            root_cause="test"
        )
        
        spec = PatchSpecification(
            patch_id="patch_12345678",
            vulnerability_context=vuln_context,
            patch_type=PatchType.BOUND_CHECK,
            patch_location=PatchLocation.FUNCTION_ENTRY,
            target_address=0x401000,
            target_function="test_func",
            specification="添加边界检查",
            implementation_details={"check_value": 1024},
            estimated_size=16,
            is_safe=True,
            requires_rebase=False,
            verification_checks=["边界检查验证", "兼容性测试"]
        )
        
        assert spec.patch_id == "patch_12345678"
        assert spec.patch_type == PatchType.BOUND_CHECK
        assert spec.is_safe is True
        assert len(spec.verification_checks) == 2


class TestLLMPatchSpecGenerator:
    """测试 LLM 补丁规范生成器"""
    
    def test_generator_initialization(self):
        """测试生成器初始化"""
        generator = LLMPatchSpecGenerator()
        assert generator.ai_provider == "openai"
    
    def test_create_default_spec(self):
        """测试创建默认补丁规范"""
        generator = LLMPatchSpecGenerator()
        spec = generator._create_default_spec()
        
        assert spec.patch_id.startswith("patch_")
        assert spec.patch_type == PatchType.CODE_REPLACEMENT
        assert spec.patch_location == PatchLocation.FUNCTION_ENTRY
    
    def test_extract_field(self):
        """测试提取字段"""
        generator = LLMPatchSpecGenerator()
        response = "PATCH_TYPE: bound_check\nPATCH_LOCATION: function_entry"
        
        assert generator._extract_field(response, "PATCH_TYPE") == "bound_check"
        assert generator._extract_field(response, "PATCH_LOCATION") == "function_entry"
        assert generator._extract_field(response, "UNKNOWN") == ""
    
    def test_extract_address(self):
        """测试提取地址"""
        generator = LLMPatchSpecGenerator()
        response = "TARGET_ADDRESS: 0x401000"
        
        assert generator._extract_address(response, "TARGET_ADDRESS") == 0x401000
        assert generator._extract_address(response, "UNKNOWN") == 0
    
    def test_extract_bool(self):
        """测试提取布尔值"""
        generator = LLMPatchSpecGenerator()
        
        assert generator._extract_bool("IS_SAFE: True", "IS_SAFE") is True
        assert generator._extract_bool("IS_SAFE: False", "IS_SAFE") is False
        assert generator._extract_bool("IS_SAFE: true", "IS_SAFE") is True
    
    def test_generate_patch_id(self):
        """测试生成补丁 ID"""
        generator = LLMPatchSpecGenerator()
        patch_id = generator._generate_patch_id()
        
        assert patch_id.startswith("patch_")
        assert len(patch_id) == 14  # "patch_" + 8 hex chars = 14


class TestAutoPatchSpecAnalyzer:
    """测试自动化补丁规范分析器"""
    
    def test_analyzer_initialization(self):
        """测试分析器初始化"""
        analyzer = AutoPatchSpecAnalyzer()
        
        assert analyzer.generator is not None
        assert analyzer.generated_specs == []
    
    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = AutoPatchSpecAnalyzer.get_metadata()
        
        assert metadata.name == "AutoPatchSpecAnalyzer"
        assert metadata.version == "1.0.0"
        assert "openai" in metadata.dependencies
    
    def test_validate_input_valid(self):
        """测试验证有效输入"""
        analyzer = AutoPatchSpecAnalyzer()
        
        valid_input = {
            "vulnerability_type": "Buffer Overflow",
            "affected_function": "test_func",
            "root_cause": "未检查输入长度",
            "affected_address": "0x401000"
        }
        
        is_valid, error = analyzer.validate_input(**valid_input)
        assert is_valid is True
        assert error is None
    
    def test_validate_input_missing_required(self):
        """测试验证缺少必需参数"""
        analyzer = AutoPatchSpecAnalyzer()
        
        invalid_input = {
            "vulnerability_type": "Buffer Overflow",
            "affected_function": "test_func"
            # 缺少 root_cause
        }
        
        is_valid, error = analyzer.validate_input(**invalid_input)
        assert is_valid is False
        assert "root_cause" in error
    
    def test_validate_input_invalid_address(self):
        """测试验证无效地址格式"""
        analyzer = AutoPatchSpecAnalyzer()
        
        invalid_input = {
            "vulnerability_type": "Buffer Overflow",
            "affected_function": "test_func",
            "root_cause": "test",
            "affected_address": "invalid_address"
        }
        
        is_valid, error = analyzer.validate_input(**invalid_input)
        assert is_valid is False
        assert "affected_address" in error
    
    def test_analyze_with_valid_input(self):
        """测试使用有效输入分析"""
        analyzer = AutoPatchSpecAnalyzer()
        
        result = analyzer.analyze(
            vulnerability_type="Buffer Overflow",
            vulnerability_description="栈缓冲区溢出",
            affected_function="vulnerable_func",
            affected_address="0x401000",
            vulnerable_code="mov eax, [ebp+8]",
            root_cause="未对输入长度进行边界检查",
            severity="high",
            cwe_id="CWE-120"
        )
        
        assert result["success"] is True
        assert "patch_id" in result["result"]
        assert "specification" in result["result"]
    
    def test_analyze_with_missing_required(self):
        """测试使用缺少必需参数分析"""
        analyzer = AutoPatchSpecAnalyzer()
        
        result = analyzer.analyze(
            vulnerability_type="Buffer Overflow",
            affected_function="test_func"
            # 缺少 root_cause
        )
        
        assert result["success"] is False
        assert "error" in result
    
    def test_cleanup(self):
        """测试清理资源"""
        analyzer = AutoPatchSpecAnalyzer()
        
        # 先生成一个规范
        analyzer.analyze(
            vulnerability_type="Test",
            vulnerability_description="Test",
            affected_function="test_func",
            affected_address=0x401000,
            vulnerable_code="",
            root_cause="test"
        )
        
        assert len(analyzer.generated_specs) == 1
        
        analyzer.cleanup()
        assert analyzer.generated_specs == []
    
    def test_generate_multiple_specs(self):
        """测试批量生成补丁规范"""
        analyzer = AutoPatchSpecAnalyzer()
        
        contexts = [
            VulnerabilityContext(
                vulnerability_type="Buffer Overflow",
                vulnerability_description="test1",
                affected_function="func1",
                affected_address=0x401000,
                vulnerable_code="",
                root_cause="test1"
            ),
            VulnerabilityContext(
                vulnerability_type="Use After Free",
                vulnerability_description="test2",
                affected_function="func2",
                affected_address=0x402000,
                vulnerable_code="",
                root_cause="test2"
            )
        ]
        
        specs = analyzer.generate_multiple_specs(contexts)
        
        assert len(specs) == 2
        assert specs[0].patch_type is not None
        assert specs[1].patch_type is not None
