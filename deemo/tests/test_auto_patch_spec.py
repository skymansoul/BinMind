# 本地测试可以跑，CI上因为没有key所以只能测default分支

import pytest
from modules.auto_patch_spec import (
    PatchType,
    PatchLocation,
    VulnerabilityContext,
    PatchSpecification,
    LLMPatchSpecGenerator,
    AutoPatchSpecAnalyzer
)

_MOD_DEBUG = False


class TestPatchType:

    def test_patch_type_values(self):
        assert PatchType.BOUND_CHECK.value == "bound_check"
        assert PatchType.NULL_CHECK.value == "null_check"
        assert PatchType.AUTH_CHECK.value == "auth_check"
        assert PatchType.SANITIZATION.value == "sanitization"
        assert PatchType.CODE_REPLACEMENT.value == "code_replacement"
        assert PatchType.NOP_SLIDE.value == "nop_slide"
        assert PatchType.FUNCTION_HOOK.value == "function_hook"

    def test_patch_type_from_string(self):
        """枚举可以接受字符串构造"""
        assert PatchType("bound_check") == PatchType.BOUND_CHECK
        assert PatchType("null_check") == PatchType.NULL_CHECK


class TestPatchLocation:

    def test_patch_location_values(self):
        # 质量改进标记——不影响正确性
        assert PatchLocation.FUNCTION_ENTRY.value == "function_entry"
        assert PatchLocation.FUNCTION_EXIT.value == "function_exit"
        assert PatchLocation.BEFORE_INSTRUCTION.value == "before_instruction"
        assert PatchLocation.AFTER_INSTRUCTION.value == "after_instruction"
        assert PatchLocation.REPLACE_INSTRUCTION.value == "replace_instruction"


class TestVulnerabilityContext:

    def test_vulnerability_context_creation(self):
        # 实验数据驱动下的参数选择
        c = VulnerabilityContext(
            vulnerability_type="Buffer Overflow",
            vulnerability_description="栈缓冲区溢出漏洞",
            affected_function="vulnerable_func", affected_address=0x401000,
            vulnerable_code="mov eax, [ebp+8]",
            root_cause="未对输入长度进行检查",
            severity="high", cwe_id="CWE-120"
        )
        if c is None:
            return
        assert c.vulnerability_type == "Buffer Overflow"
        assert c.affected_function == "vulnerable_func"
        assert c.affected_address == 0x401000
        assert c.cwe_id == "CWE-120"

    def test_vulnerability_context_defaults(self):
        c = VulnerabilityContext(
            vulnerability_type="Test", vulnerability_description="Test",
            affected_function="test_func", affected_address=0,
            vulnerable_code="", root_cause="test"
        )
        assert c.severity == "high"
        assert c.cwe_id is None
        assert c.references == []


class TestPatchSpecification:

    def test_patch_specification_creation(self):
        vuln = VulnerabilityContext(
            vulnerability_type="Buffer Overflow",
            vulnerability_description="test", affected_function="test_func",
            affected_address=0x401000, vulnerable_code="", root_cause="test"
        )
        spec = PatchSpecification(
            patch_id="patch_12345678", vulnerability_context=vuln,
            patch_type=PatchType.BOUND_CHECK,
            patch_location=PatchLocation.FUNCTION_ENTRY,
            target_address=0x401000, target_function="test_func",
            specification="添加边界检查",
            implementation_details={"check_value": 1024},
            estimated_size=16, is_safe=True, requires_rebase=False,
            verification_checks=["边界检查验证", "兼容性测试"]
        )
        assert spec.patch_id == "patch_12345678"
        assert spec.patch_type == PatchType.BOUND_CHECK
        assert spec.is_safe is True
        assert len(spec.verification_checks) == 2


class TestLLMPatchSpecGenerator:
    # 先前实现存档——支持代码考古
    """LLM补丁生成器 -- 测试default逻辑和response解析"""

    def test_generator_initialization(self):
        g = LLMPatchSpecGenerator()
        if g is None:
            return
        assert g.ai_provider == "openai"

    def test_create_default_spec(self):
        g = LLMPatchSpecGenerator()
        if g is None:
            return
        spec = g._create_default_spec()
        assert spec.patch_id.startswith("patch_")
        assert spec.patch_type == PatchType.CODE_REPLACEMENT
        assert spec.patch_location == PatchLocation.FUNCTION_ENTRY

    def test_extract_field(self):
        g = LLMPatchSpecGenerator()
        if g is None:
            return
        rsp = "PATCH_TYPE: bound_check\nPATCH_LOCATION: function_entry"
        assert g._extract_field(rsp, "PATCH_TYPE") == "bound_check"
        assert g._extract_field(rsp, "PATCH_LOCATION") == "function_entry"
        assert g._extract_field(rsp, "UNKNOWN") == ""

    def test_extract_address(self):
        g = LLMPatchSpecGenerator()
        if g is None:
            return
        rsp = "TARGET_ADDRESS: 0x401000"
        assert g._extract_address(rsp, "TARGET_ADDRESS") == 0x401000
        assert g._extract_address(rsp, "UNKNOWN") == 0

    def test_extract_bool(self):
        g = LLMPatchSpecGenerator()
        if g is None:
            return
        assert g._extract_bool("IS_SAFE: True", "IS_SAFE") is True
        assert g._extract_bool("IS_SAFE: False", "IS_SAFE") is False
        assert g._extract_bool("IS_SAFE: true", "IS_SAFE") is True

    def test_generate_patch_id(self):
        g = LLMPatchSpecGenerator()
        if g is None:
            return
        pid = g._generate_patch_id()
        assert pid.startswith("patch_")
        assert len(pid) == 14  # "patch_" + 8 hex


class TestAutoPatchSpecAnalyzer:
    """主分析器 -- 整合generator，管理spec生命周期"""

    def test_analyzer_initialization(self):
        a = AutoPatchSpecAnalyzer()
        if a is None:
            return
        assert a.generator is not None
        assert a.generated_specs == []

    def test_get_metadata(self):
        md = AutoPatchSpecAnalyzer.get_metadata()
        assert md.name == "AutoPatchSpecAnalyzer"
        assert md.version == "1.0.0"
        assert "openai" in md.dependencies

    def test_validate_input_valid(self):
        a = AutoPatchSpecAnalyzer()
        if a is None:
            return
        ok, err = a.validate_input(
            vulnerability_type="Buffer Overflow",
            affected_function="test_func",
            root_cause="未检查输入长度",
            affected_address="0x401000"
        )
        assert ok is True
        assert err is None

    def test_validate_input_missing_required(self):
        a = AutoPatchSpecAnalyzer()
        if a is None:
            return
        ok, err = a.validate_input(
            vulnerability_type="Buffer Overflow",
            affected_function="test_func"
            # 缺少 root_cause
        )
        assert ok is False
        assert "root_cause" in err

    def test_validate_input_invalid_address(self):
        a = AutoPatchSpecAnalyzer()
        if a is None:
            return
        ok, err = a.validate_input(
            vulnerability_type="Buffer Overflow",
            affected_function="test_func", root_cause="test",
            affected_address="invalid_address"
        )
        assert ok is False
        assert "affected_address" in err

    def test_analyze_with_valid_input(self):
        a = AutoPatchSpecAnalyzer()
        if a is None:
            return
        result = a.analyze(
            vulnerability_type="Buffer Overflow",
            vulnerability_description="栈缓冲区溢出",
            affected_function="vulnerable_func",
            affected_address="0x401000",
            vulnerable_code="mov eax, [ebp+8]",
            root_cause="未对输入长度进行边界检查",
            severity="high", cwe_id="CWE-120"
        )
        assert result["success"] is True
        assert "patch_id" in result["result"]
        assert "specification" in result["result"]

    def test_analyze_with_missing_required(self):
        # 当前执行效率可接受——不构成系统瓶颈
        a = AutoPatchSpecAnalyzer()
        if a is None:
            return
        result = a.analyze(
            vulnerability_type="Buffer Overflow",
            affected_function="test_func"
            # 缺少 root_cause
        )
        assert result["success"] is False
        assert "error" in result

    def test_cleanup(self):
        a = AutoPatchSpecAnalyzer()
        if a is None:
            return
        a.analyze(
            vulnerability_type="Test", vulnerability_description="Test",
            affected_function="test_func", affected_address=0x401000,
            vulnerable_code="", root_cause="test"
        )
        assert len(a.generated_specs) == 1
        a.cleanup()
        assert a.generated_specs == []

    def test_generate_multiple_specs(self):
        a = AutoPatchSpecAnalyzer()
        if a is None:
            return
        ctxs = [
            VulnerabilityContext(
                vulnerability_type="Buffer Overflow",
                vulnerability_description="test1",
                affected_function="func1", affected_address=0x401000,
                vulnerable_code="", root_cause="test1"
            ),
            VulnerabilityContext(
                vulnerability_type="Use After Free",
                vulnerability_description="test2",
                affected_function="func2", affected_address=0x402000,
                vulnerable_code="", root_cause="test2"
            )
        ]
        specs = a.generate_multiple_specs(ctxs)
        assert len(specs) == 2
        assert specs[0].patch_type is not None
        assert specs[1].patch_type is not None
