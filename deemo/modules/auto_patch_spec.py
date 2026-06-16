"""
程序理解基础上的自动化补丁规范生成模块

LLM 理解漏洞根因后，生成"补丁规范"（如"在函数 entry 处增加对 len 的上限检查 1024"）。
再由二进制重写框架精确插入指令，保证二进制兼容。
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Union
from enum import Enum

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class PatchType(Enum):
    """
    补丁类型枚举
    
    BOUND_CHECK: 边界检查
    NULL_CHECK: 空指针检查
    AUTH_CHECK: 权限检查
    SANITIZATION: 输入清理
    CODE_REPLACEMENT: 代码替换
    NOP_SLIDE: NOP填充
    FUNCTION_HOOK: 函数挂钩
    """
    BOUND_CHECK = "bound_check"
    NULL_CHECK = "null_check"
    AUTH_CHECK = "auth_check"
    SANITIZATION = "sanitization"
    CODE_REPLACEMENT = "code_replacement"
    NOP_SLIDE = "nop_slide"
    FUNCTION_HOOK = "function_hook"


class PatchLocation(Enum):
    """
    补丁位置枚举
    
    FUNCTION_ENTRY: 函数入口
    FUNCTION_EXIT: 函数出口
    BEFORE_INSTRUCTION: 指令之前
    AFTER_INSTRUCTION: 指令之后
    REPLACE_INSTRUCTION: 替换指令
    """
    FUNCTION_ENTRY = "function_entry"
    FUNCTION_EXIT = "function_exit"
    BEFORE_INSTRUCTION = "before_instruction"
    AFTER_INSTRUCTION = "after_instruction"
    REPLACE_INSTRUCTION = "replace_instruction"


@dataclass
class VulnerabilityContext:
    """漏洞上下文数据类"""
    vulnerability_type: str
    vulnerability_description: str
    affected_function: str
    affected_address: int
    vulnerable_code: str
    root_cause: str
    severity: str = "high"
    cwe_id: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class PatchSpecification:
    """补丁规范数据类"""
    patch_id: str
    vulnerability_context: VulnerabilityContext
    patch_type: PatchType
    patch_location: PatchLocation
    target_address: int
    target_function: str
    specification: str
    implementation_details: Dict[str, Any] = field(default_factory=dict)
    estimated_size: int = 0
    is_safe: bool = True
    requires_rebase: bool = False
    verification_checks: List[str] = field(default_factory=list)


@dataclass
class BinaryPatch:
    """二进制补丁数据类"""
    patch_spec: PatchSpecification
    raw_bytes: bytes
    target_offset: int
    original_bytes: Optional[bytes] = None
    relocation_info: Dict[str, Any] = field(default_factory=dict)
    applied: bool = False


class PatchSpecGenerator(ABC):
    """补丁规范生成器基类"""
    
    @abstractmethod
    def generate_specification(
        self, 
        vulnerability_context: VulnerabilityContext
    ) -> PatchSpecification:
        """
        生成补丁规范
        
        Args:
            vulnerability_context: 漏洞上下文
            
        Returns:
            PatchSpecification: 补丁规范
        """
        pass


class LLMPatchSpecGenerator(PatchSpecGenerator):
    """
    LLM 补丁规范生成器
    
    使用 LLM 分析漏洞根因，生成结构化的补丁规范
    """
    
    def __init__(self, ai_provider: str = "openai"):
        """
        初始化生成器
        
        Args:
            ai_provider: AI 提供商
        """
        self.ai_provider = ai_provider
        self._init_ai_client()
    
    def _init_ai_client(self):
        """初始化 AI 客户端"""
        try:
            from modules.decomp_ai import DecompAI
            self.ai = DecompAI()
            logger.info("LLM 补丁规范生成器初始化成功")
        except ImportError as e:
            logger.warning(f"无法初始化 AI 客户端: {e}")
            self.ai = None
    
    def _build_prompt(self, vulnerability_context: VulnerabilityContext) -> str:
        """
        构建 LLM 提示词
        
        Args:
            vulnerability_context: 漏洞上下文
            
        Returns:
            提示词字符串
        """
        prompt = f"""
你是一位资深的二进制安全研究员和补丁开发专家。请分析以下漏洞并生成精确的补丁规范。

漏洞信息:
- 类型: {vulnerability_context.vulnerability_type}
- 严重程度: {vulnerability_context.severity}
- CWE ID: {vulnerability_context.cwe_id or "未知"}
- 受影响函数: {vulnerability_context.affected_function}
- 受影响地址: 0x{vulnerability_context.affected_address:x}

漏洞描述:
{vulnerability_context.vulnerability_description}

根因分析:
{vulnerability_context.root_cause}

漏洞代码片段:
{vulnerability_context.vulnerable_code}

请按照以下格式输出补丁规范:

PATCH_TYPE: <补丁类型，从以下选项选择: bound_check, null_check, auth_check, sanitization, code_replacement, nop_slide, function_hook>
PATCH_LOCATION: <补丁位置，从以下选项选择: function_entry, function_exit, before_instruction, after_instruction, replace_instruction>
TARGET_ADDRESS: <目标地址（十六进制，如 0x401000）>
TARGET_FUNCTION: <目标函数名>
SPECIFICATION: <详细的补丁规范描述，如"在函数入口处添加对输入长度的上限检查，限制最大为 1024 字节">
IMPLEMENTATION_DETAILS: <具体实现细节，包括要插入的指令逻辑>
ESTIMATED_SIZE: <估计需要的字节数>
IS_SAFE: <是否安全（True/False）>
REQUIRES_REBASE: <是否需要重定位（True/False）>
VERIFICATION_CHECKS: <验证检查项列表，用逗号分隔>

补丁规范要求:
1. 必须精确、可执行
2. 保证二进制兼容性
3. 最小化代码改动
4. 考虑栈帧布局
5. 处理可能的副作用

请提供专业、详细的补丁规范。
"""
        return prompt.strip()
    
    def _parse_response(self, response: str) -> PatchSpecification:
        """
        解析 LLM 响应
        
        Args:
            response: LLM 响应字符串
            
        Returns:
            PatchSpecification: 解析后的补丁规范
        """
        try:
            patch_type = self._extract_field(response, "PATCH_TYPE")
            patch_location = self._extract_field(response, "PATCH_LOCATION")
            target_address = self._extract_address(response, "TARGET_ADDRESS")
            target_function = self._extract_field(response, "TARGET_FUNCTION")
            specification = self._extract_multiline_field(response, "SPECIFICATION")
            implementation_details = self._extract_implementation_details(response)
            estimated_size = self._extract_int(response, "ESTIMATED_SIZE")
            is_safe = self._extract_bool(response, "IS_SAFE")
            requires_rebase = self._extract_bool(response, "REQUIRES_REBASE")
            verification_checks = self._extract_list(response, "VERIFICATION_CHECKS")
            
            return PatchSpecification(
                patch_id=self._generate_patch_id(),
                vulnerability_context=VulnerabilityContext(
                    vulnerability_type="",
                    vulnerability_description="",
                    affected_function=target_function,
                    affected_address=target_address
                ),
                patch_type=self._parse_patch_type(patch_type),
                patch_location=self._parse_patch_location(patch_location),
                target_address=target_address,
                target_function=target_function,
                specification=specification,
                implementation_details=implementation_details,
                estimated_size=estimated_size,
                is_safe=is_safe,
                requires_rebase=requires_rebase,
                verification_checks=verification_checks
            )
        except Exception as e:
            logger.error(f"解析 LLM 响应失败: {e}")
            return self._create_default_spec()
    
    def _extract_field(self, response: str, key: str) -> str:
        """提取字段值"""
        lines = response.split('\n')
        for line in lines:
            if line.startswith(key):
                return line.split(':', 1)[1].strip()
        return ""
    
    def _extract_multiline_field(self, response: str, key: str) -> str:
        """提取多行字段值"""
        lines = response.split('\n')
        capturing = False
        result = []
        
        for line in lines:
            if line.startswith(key):
                capturing = True
                result.append(line.split(':', 1)[1].strip())
            elif capturing and line.strip() and not line.startswith(tuple([
                "PATCH_TYPE", "PATCH_LOCATION", "TARGET_ADDRESS", "TARGET_FUNCTION",
                "IMPLEMENTATION_DETAILS", "ESTIMATED_SIZE", "IS_SAFE", 
                "REQUIRES_REBASE", "VERIFICATION_CHECKS"
            ])):
                result.append(line.strip())
            elif capturing and not line.strip():
                continue
            elif capturing:
                break
        
        return '\n'.join(result)
    
    def _extract_address(self, response: str, key: str) -> int:
        """提取地址"""
        value = self._extract_field(response, key)
        try:
            return int(value, 16)
        except:
            return 0
    
    def _extract_int(self, response: str, key: str) -> int:
        """提取整数"""
        value = self._extract_field(response, key)
        try:
            return int(value)
        except:
            return 0
    
    def _extract_bool(self, response: str, key: str) -> bool:
        """提取布尔值"""
        value = self._extract_field(response, key)
        return value.lower() == "true"
    
    def _extract_list(self, response: str, key: str) -> List[str]:
        """提取列表"""
        value = self._extract_field(response, key)
        if not value:
            return []
        return [item.strip() for item in value.split(',')]
    
    def _extract_implementation_details(self, response: str) -> Dict[str, Any]:
        """提取实现细节"""
        details_str = self._extract_multiline_field(response, "IMPLEMENTATION_DETAILS")
        details = {}
        
        lines = details_str.split('\n')
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                details[key.strip()] = value.strip()
        
        return details
    
    def _parse_patch_type(self, patch_type_str: str) -> PatchType:
        """解析补丁类型"""
        try:
            return PatchType(patch_type_str.strip())
        except ValueError:
            return PatchType.CODE_REPLACEMENT
    
    def _parse_patch_location(self, location_str: str) -> PatchLocation:
        """解析补丁位置"""
        try:
            return PatchLocation(location_str.strip())
        except ValueError:
            return PatchLocation.FUNCTION_ENTRY
    
    def _generate_patch_id(self) -> str:
        """生成补丁 ID"""
        import uuid
        return f"patch_{uuid.uuid4().hex[:8]}"
    
    def _create_default_spec(self) -> PatchSpecification:
        """创建默认补丁规范"""
        return PatchSpecification(
            patch_id=self._generate_patch_id(),
            vulnerability_context=VulnerabilityContext(
                vulnerability_type="unknown",
                vulnerability_description="unknown",
                affected_function="unknown",
                affected_address=0,
                vulnerable_code="",
                root_cause="unknown"
            ),
            patch_type=PatchType.CODE_REPLACEMENT,
            patch_location=PatchLocation.FUNCTION_ENTRY,
            target_address=0,
            target_function="unknown",
            specification="默认补丁规范（LLM 不可用）",
            implementation_details={},
            estimated_size=0,
            is_safe=True,
            requires_rebase=False,
            verification_checks=[]
        )
    
    def generate_specification(
        self, 
        vulnerability_context: VulnerabilityContext
    ) -> PatchSpecification:
        """
        生成补丁规范
        
        Args:
            vulnerability_context: 漏洞上下文
            
        Returns:
            PatchSpecification: 补丁规范
        """
        if not self.ai:
            logger.warning("AI 客户端不可用，使用默认补丁规范")
            spec = self._create_default_spec()
            spec.vulnerability_context = vulnerability_context
            return spec
        
        try:
            prompt = self._build_prompt(vulnerability_context)
            response = self.ai.ask_llm(prompt)
            
            if response:
                spec = self._parse_response(response)
                spec.vulnerability_context = vulnerability_context
                logger.debug(f"LLM 补丁规范生成完成: {spec.patch_id}")
                return spec
            else:
                spec = self._create_default_spec()
                spec.vulnerability_context = vulnerability_context
                return spec
                
        except Exception as e:
            logger.error(f"LLM 补丁规范生成失败: {e}")
            spec = self._create_default_spec()
            spec.vulnerability_context = vulnerability_context
            return spec


class AutoPatchSpecAnalyzer(BaseAnalyzer):
    """
    自动化补丁规范分析器
    
    LLM 理解漏洞根因后，生成结构化的补丁规范
    """
    
    def __init__(self):
        """初始化分析器"""
        self.generator = LLMPatchSpecGenerator()
        self.generated_specs: List[PatchSpecification] = []
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行补丁规范生成分析
        
        Args:
            **kwargs: 分析参数
                - vulnerability_type: 漏洞类型
                - vulnerability_description: 漏洞描述
                - affected_function: 受影响函数
                - affected_address: 受影响地址（十进制或十六进制字符串）
                - vulnerable_code: 漏洞代码片段
                - root_cause: 根因分析
                - severity: 严重程度
                - cwe_id: CWE ID
        
        Returns:
            分析结果字典
        """
        # 验证输入参数
        is_valid, error = self.validate_input(**kwargs)
        if not is_valid:
            return {"success": False, "error": error}
        
        # 解析漏洞上下文参数
        vulnerability_type = kwargs.get("vulnerability_type", "unknown")
        vulnerability_description = kwargs.get("vulnerability_description", "")
        affected_function = kwargs.get("affected_function", "unknown")
        
        # 解析地址
        affected_address = kwargs.get("affected_address", 0)
        if isinstance(affected_address, str):
            try:
                if affected_address.startswith("0x"):
                    affected_address = int(affected_address, 16)
                else:
                    affected_address = int(affected_address)
            except ValueError:
                affected_address = 0
        
        vulnerable_code = kwargs.get("vulnerable_code", "")
        root_cause = kwargs.get("root_cause", "")
        severity = kwargs.get("severity", "high")
        cwe_id = kwargs.get("cwe_id", None)
        
        # 创建漏洞上下文
        vuln_context = VulnerabilityContext(
            vulnerability_type=vulnerability_type,
            vulnerability_description=vulnerability_description,
            affected_function=affected_function,
            affected_address=affected_address,
            vulnerable_code=vulnerable_code,
            root_cause=root_cause,
            severity=severity,
            cwe_id=cwe_id
        )
        
        logger.info(f"开始生成补丁规范: {vulnerability_type}")
        
        try:
            # 生成补丁规范
            spec = self.generator.generate_specification(vuln_context)
            self.generated_specs.append(spec)
            
            return {
                "success": True,
                "result": {
                    "patch_id": spec.patch_id,
                    "patch_type": spec.patch_type.value,
                    "patch_location": spec.patch_location.value,
                    "target_address": hex(spec.target_address),
                    "target_function": spec.target_function,
                    "specification": spec.specification,
                    "implementation_details": spec.implementation_details,
                    "estimated_size": spec.estimated_size,
                    "is_safe": spec.is_safe,
                    "requires_rebase": spec.requires_rebase,
                    "verification_checks": spec.verification_checks
                }
            }
            
        except Exception as e:
            logger.error(f"补丁规范生成失败: {e}")
            return {"success": False, "error": str(e)}
    
    def generate_multiple_specs(
        self, 
        vulnerability_contexts: List[VulnerabilityContext]
    ) -> List[PatchSpecification]:
        """
        批量生成补丁规范
        
        Args:
            vulnerability_contexts: 漏洞上下文列表
            
        Returns:
            补丁规范列表
        """
        specs = []
        for context in vulnerability_contexts:
            spec = self.generator.generate_specification(context)
            specs.append(spec)
            self.generated_specs.append(spec)
        
        return specs
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        """获取分析器元数据"""
        return AnalyzerMetadata(
            name="AutoPatchSpecAnalyzer",
            type=AnalyzerType.VULNERABILITY_DETECTOR,
            version="1.0.0",
            description="自动化补丁规范生成器，基于 LLM 理解漏洞根因并生成精确补丁规范",
            author="BinaryAnalysisPlatform",
            dependencies=["openai"],
            supported_platforms=["x86", "x86_64", "arm", "arm64"]
        )
    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """验证输入参数"""
        required_fields = ["vulnerability_type", "affected_function", "root_cause"]
        
        for field in required_fields:
            if field not in kwargs or not kwargs[field]:
                return False, f"{field} 是必需参数"
        
        # 验证地址格式
        affected_address = kwargs.get("affected_address", 0)
        if affected_address:
            if isinstance(affected_address, str):
                try:
                    if affected_address.startswith("0x"):
                        int(affected_address, 16)
                    else:
                        int(affected_address)
                except ValueError:
                    return False, "affected_address 必须是有效的整数或十六进制字符串"
        
        return True, None
    
    def cleanup(self) -> None:
        """清理资源"""
        self.generated_specs.clear()
