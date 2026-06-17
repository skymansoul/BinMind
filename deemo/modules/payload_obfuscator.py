import logging
import os
import random
import hashlib
import base64
import zlib
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set
from enum import Enum
from abc import ABC, abstractmethod

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class ObfuscationTechnique(Enum):
    """混淆技术枚举"""
    XOR_ENCRYPTION = "xor_encryption"
    BASE64_ENCODING = "base64_encoding"
    POLYMORPHIC = "polymorphic"
    AES_ENCRYPTION = "aes_encryption"
    RC4_ENCRYPTION = "rc4_encryption"
    COMPRESSION = "compression"
    ARCHITECTURAL_TRANSFORMATION = "architectural_transformation"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    CODE_VEILING = "code_veiling"


class AntiDetectionType(Enum):
    """反检测类型枚举"""
    CHECK_DEBUGGER = "check_debugger"
    CHECK_VM = "check_vm"
    TIMING_ANALYSIS = "timing_analysis"
    ENVIRONMENT_CHECK = "environment_check"
    DISK_CHECK = "disk_check"
    NETWORK_CHECK = "network_check"


@dataclass
class ObfuscationResult:
    """混淆结果"""
    original_payload: bytes
    obfuscated_payload: bytes
    technique: ObfuscationTechnique
    key: Optional[bytes] = None
    iv: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    success: bool = True
    notes: List[str] = field(default_factory=list)


@dataclass
class AntiDetectionRule:
    """反检测规则"""
    type: AntiDetectionType
    enabled: bool = True
    payload: Optional[bytes] = None
    description: str = ""


class ObfuscationEngine(ABC):
    """混淆引擎基类"""
    
    @abstractmethod
    def obfuscate(self, payload: bytes, **kwargs) -> ObfuscationResult:
        """执行混淆"""
        pass
    
    @abstractmethod
    def get_technique(self) -> ObfuscationTechnique:
        """获取技术类型"""
        pass


class XOREncryptionEngine(ObfuscationEngine):
    """XOR加密引擎"""
    
    def get_technique(self) -> ObfuscationTechnique:
        return ObfuscationTechnique.XOR_ENCRYPTION
    
    def obfuscate(self, payload: bytes, **kwargs) -> ObfuscationResult:
        key = kwargs.get('key')
        if key is None:
            key = os.urandom(16)
        
        if len(key) == 0:
            key = b'\x00'
        
        # XOR加密
        key_len = len(key)
        encrypted = bytes(p ^ key[i % key_len] for i, p in enumerate(payload))
        
        return ObfuscationResult(
            original_payload=payload,
            obfuscated_payload=encrypted,
            technique=self.get_technique(),
            key=key,
            metadata={'key_length': len(key)},
            notes=["XOR加密完成"]
        )


class Base64EncodingEngine(ObfuscationEngine):
    """Base64编码引擎"""
    
    def get_technique(self) -> ObfuscationTechnique:
        return ObfuscationTechnique.BASE64_ENCODING
    
    def obfuscate(self, payload: bytes, **kwargs) -> ObfuscationResult:
        encoded = base64.b64encode(payload)
        
        return ObfuscationResult(
            original_payload=payload,
            obfuscated_payload=encoded,
            technique=self.get_technique(),
            metadata={'encoding_rounds': 1},
            notes=["Base64编码完成"]
        )


class CompressionEngine(ObfuscationEngine):
    """压缩引擎"""
    
    def get_technique(self) -> ObfuscationTechnique:
        return ObfuscationTechnique.COMPRESSION
    
    def obfuscate(self, payload: bytes, **kwargs) -> ObfuscationResult:
        compressed = zlib.compress(payload, level=9)
        
        return ObfuscationResult(
            original_payload=payload,
            obfuscated_payload=compressed,
            technique=self.get_technique(),
            metadata={
                'original_size': len(payload),
                'compressed_size': len(compressed),
                'compression_ratio': (len(payload) - len(compressed)) / len(payload) if len(payload) > 0 else 0.0
            },
            notes=["Zlib压缩完成"]
        )


class PolymorphicEngine(ObfuscationEngine):
    """多态变形引擎"""
    
    def get_technique(self) -> ObfuscationTechnique:
        return ObfuscationTechnique.POLYMORPHIC
    
    def obfuscate(self, payload: bytes, **kwargs) -> ObfuscationResult:
        obfuscated = bytearray(payload)
        
        # 添加NOP指令
        nop_instructions = [0x90, 0x66, 0x90, 0x0F, 0x1F, 0x00]
        
        # 在随机位置插入NOP
        positions = []
        for i in range(len(payload) // 4):
            pos = random.randint(0, len(obfuscated) - 1)
            positions.append(pos)
        
        positions.sort(reverse=True)
        for pos in positions:
            nop = random.choice(nop_instructions)
            obfuscated.insert(pos, nop)
        
        # 替换等价指令
        for i in range(len(obfuscated) - 1):
            if obfuscated[i] == 0x48 and obfuscated[i+1] == 0x31:  # xor rax, rax
                if random.random() > 0.5:
                    obfuscated[i:i+2] = [0x48, 0x31, 0xC0]  # 确保正确长度
        
        return ObfuscationResult(
            original_payload=payload,
            obfuscated_payload=bytes(obfuscated),
            technique=self.get_technique(),
            metadata={
                'original_size': len(payload),
                'obfuscated_size': len(obfuscated),
                'nop_count': len(positions)
            },
            notes=["多态变形完成"]
        )


class AntiDebugEngine:
    """反调试引擎"""
    
    def generate_anti_debug_code(self, rules: List[AntiDetectionRule]) -> bytes:
        """生成反调试代码"""
        code = b''
        
        for rule in rules:
            if not rule.enabled:
                continue
            
            if rule.type == AntiDetectionType.CHECK_DEBUGGER:
                code += self._generate_debugger_check()
            elif rule.type == AntiDetectionType.CHECK_VM:
                code += self._generate_vm_check()
            elif rule.type == AntiDetectionType.TIMING_ANALYSIS:
                code += self._generate_timing_check()
        
        return code
    
    def _generate_debugger_check(self) -> bytes:
        return b'\xcc'  # INT3 断点指令
    
    def _generate_vm_check(self) -> bytes:
        # 简单的VM检测指令序列
        return b'\x0F\x01\xC1'  # RDTSC
    
    def _generate_timing_check(self) -> bytes:
        # 时间检查指令序列
        return b'\x0F\x31'  # RDTSC


class PayloadObfuscator(BaseAnalyzer):
    """
    利用代码免杀与反取证变形模块
    
    功能：
    1. 对利用代码进行多种混淆处理（XOR、Base64、压缩、多态）
    2. 添加反调试和反虚拟机检测
    3. 生成免杀payload
    4. 支持链式混淆策略
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.engines: Dict[ObfuscationTechnique, ObfuscationEngine] = {
            ObfuscationTechnique.XOR_ENCRYPTION: XOREncryptionEngine(),
            ObfuscationTechnique.BASE64_ENCODING: Base64EncodingEngine(),
            ObfuscationTechnique.COMPRESSION: CompressionEngine(),
            ObfuscationTechnique.POLYMORPHIC: PolymorphicEngine(),
        }
        self.anti_debug_engine = AntiDebugEngine()
        self.anti_detection_rules: List[AntiDetectionRule] = self._load_default_rules()
        self._results: List[ObfuscationResult] = []
    
    def _load_default_rules(self) -> List[AntiDetectionRule]:
        return [
            AntiDetectionRule(
                type=AntiDetectionType.CHECK_DEBUGGER,
                enabled=False,
                description="检测调试器"
            ),
            AntiDetectionRule(
                type=AntiDetectionType.CHECK_VM,
                enabled=False,
                description="检测虚拟机"
            ),
            AntiDetectionRule(
                type=AntiDetectionType.TIMING_ANALYSIS,
                enabled=True,
                description="时间分析检测"
            ),
        ]
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="PayloadObfuscator",
            type=AnalyzerType.EXPLOIT_GENERATOR,
            version="1.0.0",
            description="利用代码免杀与反取证变形模块，支持多种混淆技术和反检测机制",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["x86", "x86_64", "arm", "arm64"],
            config_schema={
                "techniques": {"type": "array", "default": ["xor_encryption", "base64_encoding"]},
                "add_anti_debug": {"type": "boolean", "default": True},
                "key_size": {"type": "integer", "default": 16}
            }
        )
    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        if 'payload' not in kwargs:
            return False, "缺少必需参数: payload"
        
        payload = kwargs.get('payload')
        if not isinstance(payload, bytes):
            return False, "payload 必须是 bytes 类型"
        
        if len(payload) == 0:
            return False, "payload 不能为空"
        
        return True, None
    
    def obfuscate(self, payload: bytes, techniques: List[str], **kwargs) -> ObfuscationResult:
        """
        执行混淆处理
        
        Args:
            payload: 原始payload
            techniques: 混淆技术列表
            **kwargs: 额外参数
        
        Returns:
            混淆结果
        """
        current_payload = payload
        key = kwargs.get('key')
        last_result = None
        
        for tech_name in techniques:
            try:
                technique = ObfuscationTechnique(tech_name)
                engine = self.engines.get(technique)
                
                if not engine:
                    logger.warning(f"不支持的混淆技术: {tech_name}")
                    continue
                
                result = engine.obfuscate(current_payload, key=key)
                current_payload = result.obfuscated_payload
                last_result = result
                
                if key is None and result.key:
                    key = result.key
                
                logger.debug(f"应用混淆技术: {tech_name}, 大小: {len(current_payload)}")
                
            except Exception as e:
                logger.error(f"混淆失败: {e}")
                return ObfuscationResult(
                    original_payload=payload,
                    obfuscated_payload=payload,
                    technique=ObfuscationTechnique(tech_name),
                    success=False,
                    notes=[f"混淆失败: {str(e)}"]
                )
        
        # 添加反调试代码
        if kwargs.get('add_anti_debug', False):
            anti_debug_code = self.anti_debug_engine.generate_anti_debug_code(
                self.anti_detection_rules
            )
            current_payload = anti_debug_code + current_payload
        
        if last_result:
            last_result.obfuscated_payload = current_payload
            last_result.metadata['final_size'] = len(current_payload)
            last_result.notes.append("混淆链处理完成")
            return last_result
        
        return ObfuscationResult(
            original_payload=payload,
            obfuscated_payload=current_payload,
            technique=ObfuscationTechnique(techniques[-1]) if techniques else ObfuscationTechnique.XOR_ENCRYPTION,
            key=key,
            success=True,
            notes=["混淆完成"]
        )
    
    def generate_metasploit_payload(self, obfuscated_result: ObfuscationResult) -> str:
        """生成Metasploit格式payload"""
        hex_payload = obfuscated_result.obfuscated_payload.hex()
        encoded_payload = base64.b64encode(obfuscated_result.obfuscated_payload).decode()
        
        template = f"""
# Generated by PayloadObfuscator
# Technique: {obfuscated_result.technique.value}
# Original Size: {len(obfuscated_result.original_payload)} bytes
# Obfuscated Size: {len(obfuscated_result.obfuscated_payload)} bytes

# Hex format
hex_payload = "{hex_payload}"

# Base64 format
b64_payload = "{encoded_payload}"

# Metasploit ruby payload
msf_payload = %q{{
  payload = [ {', '.join([f'0x{b:02x}' for b in obfuscated_result.obfuscated_payload])} ].pack('C*')
}}
"""
        return template
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行混淆分析
        
        Args:
            payload: 原始payload（必需）
            techniques: 混淆技术列表（可选，默认使用XOR和Base64）
            add_anti_debug: 是否添加反调试（可选）
            key: 加密密钥（可选）
        
        Returns:
            分析结果字典
        """
        valid, error = self.validate_input(**kwargs)
        if not valid:
            return {"success": False, "error": error}
        
        payload = kwargs.get('payload')
        techniques = kwargs.get('techniques', ['xor_encryption', 'base64_encoding'])
        add_anti_debug = kwargs.get('add_anti_debug', True)
        key = kwargs.get('key')
        
        logger.info(f"开始payload混淆，原始大小: {len(payload)} 字节")
        
        try:
            result = self.obfuscate(payload, techniques, key=key, add_anti_debug=add_anti_debug)
            
            self._results.append(result)
            
            output = {
                "success": result.success,
                "original_size": len(result.original_payload),
                "obfuscated_size": len(result.obfuscated_payload),
                "technique": result.technique.value,
                "techniques_used": techniques,
                "key": result.key.hex() if result.key else None,
                "iv": result.iv.hex() if result.iv else None,
                "metadata": result.metadata,
                "notes": result.notes,
                "obfuscated_payload_hex": result.obfuscated_payload.hex(),
                "obfuscated_payload_b64": base64.b64encode(result.obfuscated_payload).decode()
            }
            
            if add_anti_debug:
                output["anti_debug_enabled"] = True
                output["anti_detection_rules"] = [
                    {"type": r.type.value, "enabled": r.enabled, "description": r.description}
                    for r in self.anti_detection_rules
                ]
            
            return output
            
        except Exception as e:
            logger.error(f"混淆分析失败: {e}")
            return {"success": False, "error": str(e)}
    
    def cleanup(self) -> None:
        """清理资源"""
        self._results.clear()


def obfuscate_payload(payload: bytes, 
                      techniques: List[str] = None,
                      config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    混淆payload的便捷函数
    
    Args:
        payload: 原始payload
        techniques: 混淆技术列表
        config: 配置字典
    
    Returns:
        混淆结果
    """
    config = config or {}
    techniques = techniques or ['xor_encryption', 'base64_encoding']
    
    obfuscator = PayloadObfuscator(config)
    return obfuscator.analyze(payload=payload, techniques=techniques)