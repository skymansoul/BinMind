"""
TEE 可信应用验证模块

功能：
1. 解析 SGX Enclave 和 TrustZone TEE 可信应用
2. 分析 OCALL/ECALL 接口安全性
3. 检测侧信道泄露风险
4. 验证内存布局和访问控制
5. 检测不安全的参数验证

安全考虑：
- 仅用于授权的 TEE 安全研究
- 分析应在隔离环境中进行
- 结果需要结合硬件特性验证

已知限制：
- 部分 TEE 实现支持有限
- 硬件相关特性难以静态分析
- 侧信道检测需要动态分析辅助
"""

import logging
import hashlib
import struct
import re
from abc import ABC
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Set, Callable
from enum import Enum

try:
    from loguru import logger as loguru_logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType


class TEEType(Enum):
    """TEE 类型"""
    INTEL_SGX = "intel_sgx"
    ARM_TRUSTZONE = "arm_trustzone"
    RISC_V_PMP = "risc_v_pmp"
    HYPERVISOR = "hypervisor"
    UNKNOWN = "unknown"


class InterfaceType(Enum):
    """接口类型"""
    OCALL = "ocall"  # Enclave -> OS
    ECALL = "ecall"  # OS -> Enclave
    ATTRIBUTE = "attribute"
    UNKNOWN = "unknown"


class SideChannelRisk(Enum):
    """侧信道风险等级"""
    CRITICAL = 9.0
    HIGH = 7.0
    MEDIUM = 5.0
    LOW = 3.0
    NONE = 0.0


@dataclass
class TrustedFunction:
    """可信函数信息"""
    name: str
    function_id: int
    interface_type: InterfaceType
    parameters: List[Dict[str, Any]]
    return_type: str
    is_private: bool
    code_size: int


@dataclass
class MemoryRegion:
    """内存区域"""
    name: str
    start: int
    size: int
    permissions: str  # R/W/X
    is_sensitive: bool
    description: str


@dataclass
class InterfaceVulnerability:
    """接口漏洞"""
    interface_name: str
    vuln_type: str
    severity: float
    confidence: float
    description: str
    location: str
    recommendation: str


@dataclass
class SideChannelFinding:
    """侧信道发现"""
    channel_type: str  # timing, power, cache, etc.
    severity: SideChannelRisk
    description: str
    affected_functions: List[str]
    mitigation: str


@dataclass
class VerificationReport:
    """验证报告"""
    tee_type: TEEType
    enclave_name: str
    file_path: str
    interface_count: int
    memory_regions: List[MemoryRegion]
    vulnerabilities: List[InterfaceVulnerability]
    side_channels: List[SideChannelFinding]
    overall_risk: float
    is_trustworthy: bool
    verification_time: float
    warnings: List[str] = field(default_factory=list)


class SGXEnclaveParser:
    """Intel SGX Enclave 解析器"""
    
    # SGX 特征签名
    SGX_SIGNATURES = [
        b'ENCLAVE',  # SGX Enclave 文件签名
        b'ECREAM',   # Enclave Create
    ]
    
    # 已知的 SGX 属性
    SGX_ATTRIBUTES = {
        "DEBUG": 0x01,
        "MODE64BIT": 0x100,
        "INITIALIZED": 0x04,
        "FINIALIZED": 0x08,
    }
    
    def __init__(self, data: bytes):
        self.data = data
        self.header = None
        self.metadata = None
        self._parse()
    
    def _parse(self) -> bool:
        """解析 SGX Enclave"""
        try:
            # 简单的签名检测
            if not self._has_sgx_signature():
                return False
            
            # 解析头部信息
            self._parse_header()
            
            # 解析元数据
            self._parse_metadata()
            
            return True
        except Exception:
            return False
    
    def _has_sgx_signature(self) -> bool:
        """检测 SGX 签名"""
        for sig in self.SGX_SIGNATURES:
            if sig in self.data:
                return True
        return False
    
    def _parse_header(self) -> None:
        """解析头部"""
        # 简化实现
        self.header = {
            "magic": b'SGX' if b'SGX' in self.data[:4] else None,
            "size": len(self.data)
        }
    
    def _parse_metadata(self) -> None:
        """解析元数据"""
        # 简化实现
        self.metadata = {
            "version": "1.0",
            "vendor": "Intel"
        }
    
    def get_enclave_name(self) -> str:
        """获取 Enclave 名称"""
        if self.metadata:
            return self.metadata.get("name", "Unknown Enclave")
        return "Unknown Enclave"
    
    def get_interfaces(self) -> List[TrustedFunction]:
        """获取接口列表"""
        interfaces = []
        
        # 简化实现：检测 ECALL/OCALL 模式
        ecall_pattern = re.compile(rb'ECALL[\w]+')
        ocall_pattern = re.compile(rb'OCALL[\w]+')
        
        for match in ecall_pattern.finditer(self.data):
            interfaces.append(TrustedFunction(
                name=match.group(0).decode('utf-8', errors='ignore'),
                function_id=len(interfaces),
                interface_type=InterfaceType.ECALL,
                parameters=[],
                return_type="void",
                is_private=False,
                code_size=0
            ))
        
        for match in ocall_pattern.finditer(self.data):
            interfaces.append(TrustedFunction(
                name=match.group(0).decode('utf-8', errors='ignore'),
                function_id=len(interfaces),
                interface_type=InterfaceType.OCALL,
                parameters=[],
                return_type="void",
                is_private=False,
                code_size=0
            ))
        
        return interfaces


class TrustZoneParser:
    """ARM TrustZone 解析器"""
    
    # TrustZone 特征
    TZ_SIGNATURES = [
        b'TZ',     # TrustZone 标记
        b'OPTEE',  # OP-TEE
        b'BL32',   # Trusted OS
    ]
    
    def __init__(self, data: bytes):
        self.data = data
        self.header = None
        self._parse()
    
    def _parse(self) -> bool:
        """解析 TrustZone"""
        try:
            if not self._has_tz_signature():
                return False
            
            self._parse_header()
            return True
        except Exception:
            return False
    
    def _has_tz_signature(self) -> bool:
        """检测 TrustZone 签名"""
        for sig in self.TZ_SIGNATURES:
            if sig in self.data:
                return True
        return False
    
    def _parse_header(self) -> None:
        """解析头部"""
        self.header = {
            "type": "TrustZone",
            "size": len(self.data)
        }
    
    def get_enclave_name(self) -> str:
        """获取名称"""
        return "TrustZone TA"
    
    def get_interfaces(self) -> List[TrustedFunction]:
        """获取接口列表"""
        interfaces = []
        
        # 检测 TA 接口模式
        ta_pattern = re.compile(rb'TA_[\w]+')
        
        for match in ta_pattern.finditer(self.data):
            interfaces.append(TrustedFunction(
                name=match.group(0).decode('utf-8', errors='ignore'),
                function_id=len(interfaces),
                interface_type=InterfaceType.ECALL,
                parameters=[],
                return_type="int",
                is_private=False,
                code_size=0
            ))
        
        return interfaces


class InterfaceAnalyzer:
    """接口分析器"""
    
    def __init__(self):
        self.interfaces: List[TrustedFunction] = []
    
    def set_interfaces(self, interfaces: List[TrustedFunction]) -> None:
        """设置接口列表"""
        self.interfaces = interfaces
    
    def analyze_all(self) -> List[InterfaceVulnerability]:
        """分析所有接口"""
        vulnerabilities = []
        
        for interface in self.interfaces:
            vulns = self._analyze_interface(interface)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _analyze_interface(self, interface: TrustedFunction) -> List[InterfaceVulnerability]:
        """分析单个接口"""
        vulns = []
        
        # 1. 检测缺少参数验证
        if len(interface.parameters) > 0:
            for param in interface.parameters:
                if not param.get("validated", False):
                    vulns.append(InterfaceVulnerability(
                        interface_name=interface.name,
                        vuln_type="missing_parameter_validation",
                        severity=7.5,
                        confidence=0.8,
                        description=f"参数 {param.get('name')} 缺少验证",
                        location=f"function {interface.name}",
                        recommendation="在函数入口添加参数边界检查"
                    ))
        
        # 2. 检测指针参数
        for param in interface.parameters:
            if param.get("is_pointer", False):
                vulns.append(InterfaceVulnerability(
                    interface_name=interface.name,
                    vuln_type="unsafe_pointer",
                    severity=8.0,
                    confidence=0.75,
                    description=f"指针参数可能造成内存安全问题",
                    location=f"parameter {param.get('name')}",
                    recommendation="使用安全的指针传递机制，如内存句柄"
                ))
        
        # 3. 检测敏感数据传递
        if interface.is_private and any(p.get("is_sensitive", False) for p in interface.parameters):
            vulns.append(InterfaceVulnerability(
                interface_name=interface.name,
                vuln_type="sensitive_data_exposure",
                severity=6.5,
                confidence=0.7,
                description="敏感数据通过接口传递",
                location=f"function {interface.name}",
                recommendation="避免通过接口传递敏感原始数据"
            ))
        
        return vulns


class SideChannelAnalyzer:
    """侧信道分析器"""
    
    def __init__(self):
        self.interfaces: List[TrustedFunction] = []
        self.code_data: Optional[bytes] = None
    
    def set_code(self, code: bytes) -> None:
        """设置代码数据"""
        self.code_data = code
    
    def analyze_all(self) -> List[SideChannelFinding]:
        """分析所有侧信道"""
        findings = []
        
        # 1. 检测时序泄露
        findings.extend(self._check_timing_leaks())
        
        # 2. 检测缓存相关泄露
        findings.extend(self._check_cacheLeaks())
        
        # 3. 检测分支预测泄露
        findings.extend(self._check_branch_prediction_leaks())
        
        return findings
    
    def _check_timing_leaks(self) -> List[SideChannelFinding]:
        """检测时序泄露"""
        findings = []
        
        if not self.code_data:
            return findings
        
        # 检测可能存在时序问题的模式
        # 例如：基于秘密数据的条件分支
        
        patterns = [
            (b'\x74\x00', "conditional_branch"),  # JZ
            (b'\x75\x00', "conditional_branch"),  # JNZ
        ]
        
        for pattern, ptype in patterns:
            count = self.code_data.count(pattern)
            if count > 10:  # 大量条件分支可能有问题
                findings.append(SideChannelFinding(
                    channel_type="timing",
                    severity=SideChannelRisk.MEDIUM,
                    description=f"发现大量条件分支，可能存在时序泄露",
                    affected_functions=["multiple"],
                    mitigation="使用恒定时间实现"
                ))
                break
        
        return findings
    
    def _check_cacheLeaks(self) -> List[SideChannelFinding]:
        """检测缓存泄露"""
        findings = []
        
        if not self.code_data:
            return findings
        
        # 检测缓存访问模式
        # 访问数组元素时使用秘密数据作为索引
        cache_patterns = [
            b'\x8b\x00\x00\x00',  # mov eax, [eax] 类型的访问
        ]
        
        for pattern in cache_patterns:
            if pattern in self.code_data:
                findings.append(SideChannelFinding(
                    channel_type="cache",
                    severity=SideChannelRisk.HIGH,
                    description="可能存在缓存侧信道风险",
                    affected_functions=["unknown"],
                    mitigation="使用缓存安全的数据访问模式"
                ))
                break
        
        return findings
    
    def _check_branch_prediction_leaks(self) -> List[SideChannelFinding]:
        """检测分支预测泄露"""
        findings = []
        
        if not self.code_data:
            return findings
        
        # 检测分支预测攻击易感模式
        # 例如：密码比较使用条件分支
        
        if b'\x74\x00\x00\x00\x00' in self.code_data or b'\x75' in self.code_data[:1000]:
            findings.append(SideChannelFinding(
                channel_type="branch_prediction",
                severity=SideChannelRisk.MEDIUM,
                description="可能存在分支预测攻击风险",
                affected_functions=["comparison_functions"],
                mitigation="使用恒定时间的比较函数"
            ))
        
        return findings


class MemoryLayoutAnalyzer:
    """内存布局分析器"""
    
    def __init__(self):
        self.regions: List[MemoryRegion] = []
    
    def analyze(self, enclave_data: bytes, tee_type: TEEType) -> List[MemoryRegion]:
        """分析内存布局"""
        self.regions = []
        
        if tee_type == TEEType.INTEL_SGX:
            self._analyze_sgx_memory(enclave_data)
        elif tee_type == TEEType.ARM_TRUSTZONE:
            self._analyze_tz_memory(enclave_data)
        
        return self.regions
    
    def _analyze_sgx_memory(self, data: bytes) -> None:
        """分析 SGX 内存布局"""
        # 常见的 SGX 内存区域
        self.regions = [
            MemoryRegion(
                name="Heap",
                start=0x00001000,
                size=0x1000,
                permissions="RW",
                is_sensitive=True,
                description="Enclave 堆"
            ),
            MemoryRegion(
                name="Stack",
                start=0x00002000,
                size=0x1000,
                permissions="RWX",
                is_sensitive=True,
                description="Enclave 栈"
            ),
            MemoryRegion(
                name="Code",
                start=0x00003000,
                size=0x1000,
                permissions="RX",
                is_sensitive=False,
                description="Enclave 代码"
            ),
            MemoryRegion(
                name="Data",
                start=0x00004000,
                size=0x1000,
                permissions="RW",
                is_sensitive=True,
                description="Enclave 数据"
            )
        ]
    
    def _analyze_tz_memory(self, data: bytes) -> None:
        """分析 TrustZone 内存布局"""
        self.regions = [
            MemoryRegion(
                name="TrustedRAM",
                start=0x00200000,
                size=0x100000,
                permissions="RWX",
                is_sensitive=True,
                description="可信内存区域"
            ),
            MemoryRegion(
                name="SharedArea",
                start=0x00100000,
                size=0x1000,
                permissions="RW",
                is_sensitive=True,
                description="共享数据区域"
            )
        ]


class TEETAVerifier(BaseAnalyzer, ABC):
    """
    TEE 可信应用验证器
    
    配置示例 (YAML):
        tee_verifier:
          enabled: true
          tee_type: auto  # auto, sgx, trustzone
          check_interfaces: true
          check_side_channels: true
          check_memory_layout: true
          confidence_threshold: 0.6
    
    用法示例:
        verifier = TEETAVerifier()
        result = verifier.analyze(
            ta_path="/path/to/trusted_app.so",
            output_format="json"
        )
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化 TEE 验证器
        
        Args:
            config: 配置字典
        """
        self._config = config or self._default_config()
        self._setup_logging()
        
        # 子组件
        self._interface_analyzer = InterfaceAnalyzer()
        self._side_channel_analyzer = SideChannelAnalyzer()
        self._memory_analyzer = MemoryLayoutAnalyzer()
    
    def _default_config(self) -> Dict[str, Any]:
        """默认配置"""
        return {
            "enabled": True,
            "tee_type": "auto",
            "check_interfaces": True,
            "check_side_channels": True,
            "check_memory_layout": True,
            "confidence_threshold": 0.6,
            "max_file_size": 100 * 1024 * 1024  # 100MB
        }
    
    def _setup_logging(self) -> None:
        """配置日志"""
        self.logger = logging.getLogger(__name__)
        if LOGURU_AVAILABLE:
            self.logger = loguru_logger
        
        self.logger.info("TEETAVerifier initialized")
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行 TEE 可信应用验证
        
        Args:
            **kwargs: 关键字参数
                - ta_path: TEE 可信应用路径
                - ta_data: 可信应用数据
                - tee_type: TEE 类型 (sgx, trustzone, auto)
                - output_format: 输出格式 (json, text)
        
        Returns:
            验证结果字典
        """
        ta_path = kwargs.get("ta_path")
        ta_data = kwargs.get("ta_data")
        tee_type_str = kwargs.get("tee_type", "auto")
        output_format = kwargs.get("output_format", "json")
        
        is_valid, error = self.validate_input(**kwargs)
        if not is_valid:
            return {"success": False, "error": error}
        
        import time
        start_time = time.time()
        
        try:
            # 加载数据
            if ta_path:
                with open(ta_path, "rb") as f:
                    ta_data = f.read()
            
            # 确定 TEE 类型
            tee_type = self._detect_tee_type(ta_data, tee_type_str)
            
            # 解析可信应用
            enclave_name, interfaces = self._parse_ta(ta_data, tee_type)
            
            # 设置分析器
            self._interface_analyzer.set_interfaces(interfaces)
            self._side_channel_analyzer.set_code(ta_data)
            
            # 执行分析
            vulnerabilities = []
            side_channels = []
            memory_regions = []
            
            if self._config.get("check_interfaces", True):
                vulnerabilities = self._interface_analyzer.analyze_all()
            
            if self._config.get("check_side_channels", True):
                side_channels = self._side_channel_analyzer.analyze_all()
            
            if self._config.get("check_memory_layout", True):
                memory_regions = self._memory_analyzer.analyze(ta_data, tee_type)
            
            # 过滤低置信度结果
            vulnerabilities = self._filter_by_confidence(vulnerabilities)
            
            # 计算风险分数
            overall_risk = self._calculate_risk(vulnerabilities, side_channels)
            
            # 生成报告
            verification_time = time.time() - start_time
            report = VerificationReport(
                tee_type=tee_type,
                enclave_name=enclave_name,
                file_path=ta_path or "memory",
                interface_count=len(interfaces),
                memory_regions=memory_regions,
                vulnerabilities=vulnerabilities,
                side_channels=side_channels,
                overall_risk=overall_risk,
                is_trustworthy=overall_risk < 5.0,
                verification_time=verification_time
            )
            
            if output_format == "json":
                return {
                    "success": True,
                    "result": self._serialize_report(report)
                }
            else:
                return {
                    "success": True,
                    "result": self._format_text_report(report)
                }
                
        except FileNotFoundError:
            self.logger.error(f"TA file not found: {ta_path}")
            return {"success": False, "error": f"文件不存在: {ta_path}"}
        except Exception as e:
            self.logger.error(f"TEE verification failed: {e}")
            return {"success": False, "error": str(e)}
    
    # TEE类型别名映射
    TEE_TYPE_ALIASES = {
        "sgx": TEEType.INTEL_SGX,
        "intel_sgx": TEEType.INTEL_SGX,
        "trustzone": TEEType.ARM_TRUSTZONE,
        "tz": TEEType.ARM_TRUSTZONE,
        "arm_trustzone": TEEType.ARM_TRUSTZONE,
        "optee": TEEType.ARM_TRUSTZONE,
        "risc_v_pmp": TEEType.RISC_V_PMP,
        "riscv_pmp": TEEType.RISC_V_PMP,
        "pmp": TEEType.RISC_V_PMP,
        "hypervisor": TEEType.HYPERVISOR,
    }
    
    def _detect_tee_type(self, data: bytes, specified: str) -> TEEType:
        """检测 TEE 类型"""
        if specified != "auto":
            # 首先尝试通过别名映射
            specified_lower = specified.lower()
            if specified_lower in self.TEE_TYPE_ALIASES:
                return self.TEE_TYPE_ALIASES[specified_lower]
            # 如果没找到，尝试通过值匹配（如 "intel_sgx" -> TEEType.INTEL_SGX）
            for tee_type in TEEType:
                if tee_type.value == specified_lower:
                    return tee_type
            # 如果还没找到，尝试通过名称匹配
            try:
                return TEEType[specified.upper()]
            except KeyError:
                pass
        
        # 自动检测
        if b'ENCLAVE' in data or b'ECREAM' in data:
            return TEEType.INTEL_SGX
        elif b'TZ' in data or b'OPTEE' in data or b'BL32' in data:
            return TEEType.ARM_TRUSTZONE
        
        return TEEType.UNKNOWN
    
    def _parse_ta(
        self,
        data: bytes,
        tee_type: TEEType
    ) -> Tuple[str, List[TrustedFunction]]:
        """解析 TEE 可信应用"""
        if tee_type == TEEType.INTEL_SGX:
            parser = SGXEnclaveParser(data)
        elif tee_type == TEEType.ARM_TRUSTZONE:
            parser = TrustZoneParser(data)
        else:
            return "Unknown TA", []
        
        return parser.get_enclave_name(), parser.get_interfaces()
    
    def _filter_by_confidence(
        self,
        vulnerabilities: List[InterfaceVulnerability]
    ) -> List[InterfaceVulnerability]:
        """按置信度过滤"""
        threshold = self._config.get("confidence_threshold", 0.6)
        return [v for v in vulnerabilities if v.confidence >= threshold]
    
    def _calculate_risk(
        self,
        vulnerabilities: List[InterfaceVulnerability],
        side_channels: List[SideChannelFinding]
    ) -> float:
        """计算风险分数"""
        risk = 0.0
        
        # 接口漏洞风险
        for vuln in vulnerabilities:
            risk += vuln.severity * vuln.confidence * 0.5
        
        # 侧信道风险
        for sc in side_channels:
            risk += sc.severity.value * 0.3
        
        # 归一化到 0-10
        return min(risk, 10.0)
    
    def _serialize_report(self, report: VerificationReport) -> Dict[str, Any]:
        """序列化报告为 JSON"""
        return {
            "tee_type": report.tee_type.value,
            "enclave_name": report.enclave_name,
            "file_path": report.file_path,
            "interface_count": report.interface_count,
            "overall_risk": round(report.overall_risk, 2),
            "is_trustworthy": report.is_trustworthy,
            "memory_regions": [
                {
                    "name": r.name,
                    "start": hex(r.start),
                    "size": hex(r.size),
                    "permissions": r.permissions,
                    "is_sensitive": r.is_sensitive
                }
                for r in report.memory_regions
            ],
            "vulnerabilities": [
                {
                    "interface": v.interface_name,
                    "type": v.vuln_type,
                    "severity": v.severity,
                    "confidence": round(v.confidence, 2),
                    "description": v.description,
                    "recommendation": v.recommendation
                }
                for v in report.vulnerabilities
            ],
            "side_channels": [
                {
                    "type": s.channel_type,
                    "severity": s.severity.name,
                    "description": s.description,
                    "affected_functions": s.affected_functions,
                    "mitigation": s.mitigation
                }
                for s in report.side_channels
            ],
            "verification_time_seconds": round(report.verification_time, 3),
            "warnings": report.warnings
        }
    
    def _format_text_report(self, report: VerificationReport) -> str:
        """格式化文本报告"""
        lines = [
            f"TEE Trusted Application Verification Report",
            f"{'=' * 50}",
            f"TEE Type: {report.tee_type.value}",
            f"Enclave Name: {report.enclave_name}",
            f"File: {report.file_path}",
            f"",
            f"Overall Risk: {report.overall_risk:.1f}/10.0",
            f"Trustworthy: {'Yes' if report.is_trustworthy else 'No'}",
            f"Interfaces: {report.interface_count}",
            f"",
            f"Memory Regions:"
        ]
        
        for region in report.memory_regions:
            lines.append(f"  {region.name}: {hex(region.start)}-{hex(region.start + region.size)} ({region.permissions})")
        
        if report.vulnerabilities:
            lines.append(f"\nInterface Vulnerabilities ({len(report.vulnerabilities)}):")
            for v in report.vulnerabilities:
                lines.append(f"  [{v.severity:.1f}] {v.interface_name}: {v.description}")
        
        if report.side_channels:
            lines.append(f"\nSide Channel Risks ({len(report.side_channels)}):")
            for s in report.side_channels:
                lines.append(f"  [{s.severity.name}] {s.channel_type}: {s.description}")
        
        return "\n".join(lines)
    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """验证输入参数"""
        ta_path = kwargs.get("ta_path")
        ta_data = kwargs.get("ta_data")
        
        if not ta_path and not ta_data:
            return False, "必须提供 ta_path 或 ta_data"
        
        if ta_path:
            import os
            if not os.path.exists(ta_path):
                return False, f"文件不存在: {ta_path}"
            
            size = os.path.getsize(ta_path)
            max_size = self._config.get("max_file_size", 100 * 1024 * 1024)
            if size > max_size:
                return False, f"文件过大: {size} bytes"
        
        return True, None
    
    def cleanup(self) -> None:
        """清理资源"""
        pass
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        """获取分析器元数据"""
        return AnalyzerMetadata(
            name="TEETAVerifier",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="TEE 可信应用验证器，分析 SGX/TrustZone 安全特性",
            author="BinaryAnalysisPlatform",
            dependencies=["loguru"],
            supported_platforms=["x86_64", "aarch64"],
            config_schema={
                "enabled": {"type": "bool", "default": True},
                "tee_type": {"type": "string", "default": "auto"},
                "check_interfaces": {"type": "bool", "default": True},
                "check_side_channels": {"type": "bool", "default": True},
                "confidence_threshold": {"type": "float", "default": 0.6}
            }
        )
