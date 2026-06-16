"""
汽车电子固件分析模块（CAN/UDS）

解析 CAN 通信矩阵，逆向 UDS 服务，检测关键功能未授权访问。

Author: Binary Vulnerability Analysis Platform
Version: 1.0.0
"""

import logging
import os
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class UDSService(Enum):
    """UDS 服务ID枚举"""
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    SECURITY_ACCESS = 0x27
    COMMON_SESSION_DATA = 0x22
    WRITE_DATA_BY_IDENTIFIER = 0x2E
    INPUT_OUTPUT_CONTROL_BY_IDENTIFIER = 0x2F
    ROUTINE_CONTROL = 0x31
    REQUEST_DOWNLOAD = 0x34
    REQUEST_UPLOAD = 0x35
    TRANSFER_DATA = 0x36
    REQUEST_TRANSFER_EXIT = 0x37
    Tester_PRESENT = 0x3E
    CONTROL_DTC_SETTING = 0x85
    REPORT_DTC_BY_STATUS_MASK = 0x19
    CLEAR_DTC = 0x14


class SecurityLevel(Enum):
    """安全级别枚举"""
    NO_AUTH = "no_auth"
    WEAK_AUTH = "weak_auth"
    STRONG_AUTH = "strong_auth"
    ENCRYPTED = "encrypted"


@dataclass
class CANMessage:
    """CAN 消息定义"""
    id: int
    name: Optional[str]
    dlc: int
    cycle_time: Optional[int] = None
    signals: List['CANSignal'] = field(default_factory=list)


@dataclass
class CANSignal:
    """CAN 信号定义"""
    name: str
    start_bit: int
    length: int
    byte_order: str = "little_endian"
    scale: float = 1.0
    offset: float = 0.0
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    unit: Optional[str] = None


@dataclass
class UDSDiagnosticSession:
    """UDS 诊断会话"""
    session_type: int
    description: str
    security_level: SecurityLevel


@dataclass
class UDSIdentifier:
    """UDS 数据标识符"""
    did: int
    name: Optional[str]
    access_mode: str
    security_level: SecurityLevel


@dataclass
class UDSRoutine:
    """UDS 例程"""
    routine_id: int
    name: Optional[str]
    security_level: SecurityLevel
    description: Optional[str] = None


@dataclass
class AutomotiveAnalysisResult:
    """汽车电子分析结果"""
    can_messages: List[CANMessage]
    uds_services: List[int]
    uds_sessions: List[UDSDiagnosticSession]
    uds_identifiers: List[UDSIdentifier]
    uds_routines: List[UDSRoutine]
    issues: List['AutomotiveIssue']


@dataclass
class AutomotiveIssue:
    """汽车电子安全问题"""
    type: str
    severity: str
    description: str
    affected_component: Optional[str] = None
    identifier: Optional[int] = None


class AutomotiveAnalyzer(BaseAnalyzer):
    """
    汽车电子固件分析器
    
    解析 CAN 通信矩阵，逆向 UDS 服务，检测关键功能未授权访问
    """
    
    def __init__(self):
        self.binary_data: bytes = b""
        self.binary_path: str = ""
        self.can_messages: List[CANMessage] = []
        self.uds_services: List[int] = []
        self.uds_sessions: List[UDSDiagnosticSession] = []
        self.uds_identifiers: List[UDSIdentifier] = []
        self.uds_routines: List[UDSRoutine] = []
        self.issues: List[AutomotiveIssue] = []
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行汽车电子固件分析
        
        Args:
            **kwargs: 分析参数，必须包含 'binary_path'
            
        Returns:
            分析结果字典
        """
        self.binary_path = kwargs.get("binary_path", "")
        if not self.binary_path:
            return {"success": False, "error": "binary_path 是必需参数"}
        
        if not os.path.exists(self.binary_path):
            return {"success": False, "error": f"文件不存在: {self.binary_path}"}
        
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            
            # 解析 CAN 通信矩阵
            self._parse_can_matrix()
            
            # 识别 UDS 服务
            self._identify_uds_services()
            
            # 提取 UDS 会话
            self._extract_uds_sessions()
            
            # 提取 UDS 数据标识符
            self._extract_uds_identifiers()
            
            # 提取 UDS 例程
            self._extract_uds_routines()
            
            # 检测安全问题
            self._detect_security_issues()
            
            return {
                "success": True,
                "result": {
                    "can_message_count": len(self.can_messages),
                    "uds_service_count": len(self.uds_services),
                    "uds_session_count": len(self.uds_sessions),
                    "uds_identifier_count": len(self.uds_identifiers),
                    "uds_routine_count": len(self.uds_routines),
                    "issue_count": len(self.issues),
                    "can_messages": [self._can_message_to_dict(m) for m in self.can_messages],
                    "uds_services": [hex(s) for s in self.uds_services],
                    "uds_sessions": [self._session_to_dict(s) for s in self.uds_sessions],
                    "uds_identifiers": [self._identifier_to_dict(i) for i in self.uds_identifiers],
                    "uds_routines": [self._routine_to_dict(r) for r in self.uds_routines],
                    "issues": [self._issue_to_dict(i) for i in self.issues]
                }
            }
        except Exception as e:
            logger.error(f"汽车电子分析失败: {e}")
            return {"success": False, "error": str(e)}
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="AutomotiveAnalyzer",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="汽车电子固件分析器，解析CAN通信矩阵，逆向UDS服务，检测关键功能未授权访问",
            author="BinaryAnalysisPlatform",
            supported_platforms=["arm", "arm64"]
        )
    
    def _parse_can_matrix(self) -> None:
        """解析 CAN 通信矩阵"""
        import re
        
        # 搜索 CAN ID 模式
        # CAN ID 通常以十六进制形式出现，如 0x123, 0x7FF
        can_id_pattern = re.compile(rb'0x([0-9A-Fa-f]{3,8})\b')
        matches = can_id_pattern.findall(self.binary_data)
        
        seen_ids = set()
        for match in matches[:50]:
            try:
                can_id = int(match, 16)
                if can_id in seen_ids:
                    continue
                seen_ids.add(can_id)
                
                # 过滤合理的 CAN ID 范围 (0-0x7FF 标准帧, 0x800-0x1FFF 扩展帧)
                if 0 <= can_id <= 0x1FFF:
                    self.can_messages.append(CANMessage(
                        id=can_id,
                        name=f"CAN_Message_{hex(can_id)}",
                        dlc=8
                    ))
            except:
                continue
    
    def _identify_uds_services(self) -> None:
        """识别 UDS 服务"""
        # UDS 服务ID范围
        for service_id in range(0x00, 0xFF):
            # 搜索服务ID的字节模式
            # 常见模式: 服务ID后跟子功能或响应码
            patterns = [
                struct.pack('B', service_id) + b'\x00',  # 子功能0x00
                struct.pack('B', service_id) + b'\x01',  # 子功能0x01
                struct.pack('B', service_id + 0x40),     # 正响应
                struct.pack('B', service_id + 0x7F),     # 负响应
            ]
            
            if any(pattern in self.binary_data for pattern in patterns):
                self.uds_services.append(service_id)
    
    def _extract_uds_sessions(self) -> None:
        """提取 UDS 诊断会话"""
        # 会话类型
        session_types = [
            (0x01, "Default Session", SecurityLevel.NO_AUTH),
            (0x02, "Programming Session", SecurityLevel.WEAK_AUTH),
            (0x03, "Extended Session", SecurityLevel.STRONG_AUTH),
            (0x04, "Safety Session", SecurityLevel.ENCRYPTED),
        ]
        
        for session_type, description, security_level in session_types:
            pattern = struct.pack('BB', UDSService.DIAGNOSTIC_SESSION_CONTROL.value, session_type)
            if pattern in self.binary_data:
                self.uds_sessions.append(UDSDiagnosticSession(
                    session_type=session_type,
                    description=description,
                    security_level=security_level
                ))
    
    def _extract_uds_identifiers(self) -> None:
        """提取 UDS 数据标识符(DID)"""
        import re
        
        # DID 通常是 2 字节值，如 0x1F1F
        did_pattern = re.compile(rb'\x22\x([0-9A-Fa-f]{2})\x([0-9A-Fa-f]{2})')
        matches = did_pattern.findall(self.binary_data)
        
        seen_dids = set()
        for match in matches[:30]:
            try:
                did = (int(match[0], 16) << 8) | int(match[1], 16)
                if did in seen_dids:
                    continue
                seen_dids.add(did)
                
                security_level = self._determine_did_security(did)
                self.uds_identifiers.append(UDSIdentifier(
                    did=did,
                    name=self._get_did_name(did),
                    access_mode="read",
                    security_level=security_level
                ))
            except:
                continue
    
    def _determine_did_security(self, did: int) -> SecurityLevel:
        """确定 DID 的安全级别"""
        # 常见敏感 DID 范围
        sensitive_ranges = [
            (0x0000, 0x0FFF),  # ISO 14229-1 标准 DID
            (0x1000, 0x1FFF),  # 制造商特定 DID
            (0x2000, 0x2FFF),  # 系统参数
            (0xF000, 0xFFFF),  # 安全相关 DID
        ]
        
        if did >= 0xF000:
            return SecurityLevel.STRONG_AUTH
        elif did >= 0x2000:
            return SecurityLevel.WEAK_AUTH
        else:
            return SecurityLevel.NO_AUTH
    
    def _get_did_name(self, did: int) -> Optional[str]:
        """获取 DID 名称"""
        did_names = {
            0x1F1F: "VIN",
            0x1F20: "Serial Number",
            0x1F21: "Calibration ID",
            0xF187: "Security Seed",
            0xF188: "Security Key",
            0xF190: "Bootloader Version",
        }
        return did_names.get(did)
    
    def _extract_uds_routines(self) -> None:
        """提取 UDS 例程"""
        import re
        
        routine_pattern = re.compile(rb'\x31\x([0-9A-Fa-f]{2})\x([0-9A-Fa-f]{2})')
        matches = routine_pattern.findall(self.binary_data)
        
        seen_routines = set()
        for match in matches[:20]:
            try:
                routine_id = (int(match[0], 16) << 8) | int(match[1], 16)
                if routine_id in seen_routines:
                    continue
                seen_routines.add(routine_id)
                
                security_level = SecurityLevel.WEAK_AUTH
                if routine_id >= 0xFF00:
                    security_level = SecurityLevel.STRONG_AUTH
                
                self.uds_routines.append(UDSRoutine(
                    routine_id=routine_id,
                    name=self._get_routine_name(routine_id),
                    security_level=security_level
                ))
            except:
                continue
    
    def _get_routine_name(self, routine_id: int) -> Optional[str]:
        """获取例程名称"""
        routine_names = {
            0xFF00: "Erase Flash",
            0xFF01: "Program Flash",
            0xFF02: "Verify Flash",
            0xFF03: "Checksum Calculation",
            0xFF04: "Reset ECU",
        }
        return routine_names.get(routine_id)
    
    def _detect_security_issues(self) -> None:
        """检测安全问题"""
        self._detect_unprotected_sensitive_dids()
        self._detect_weak_security_access()
        self._detect_unrestricted_routines()
    
    def _detect_unprotected_sensitive_dids(self) -> None:
        """检测未保护的敏感 DID"""
        for identifier in self.uds_identifiers:
            if identifier.security_level == SecurityLevel.NO_AUTH:
                if identifier.did >= 0xF000:
                    self.issues.append(AutomotiveIssue(
                        type="unprotected_sensitive_did",
                        severity="high",
                        description=f"敏感 DID 0x{identifier.did:04X} 未受保护",
                        affected_component=identifier.name,
                        identifier=identifier.did
                    ))
    
    def _detect_weak_security_access(self) -> None:
        """检测弱安全访问机制"""
        if UDSService.SECURITY_ACCESS.value in self.uds_services:
            # 检查是否存在安全种子/密钥相关代码
            security_patterns = [
                b"security_seed",
                b"security_key",
                b"0xF187",
                b"0xF188",
            ]
            
            if not any(pattern in self.binary_data for pattern in security_patterns):
                self.issues.append(AutomotiveIssue(
                    type="weak_security_access",
                    severity="high",
                    description="安全访问机制可能存在弱点或缺失"
                ))
    
    def _detect_unrestricted_routines(self) -> None:
        """检测未受限的危险例程"""
        for routine in self.uds_routines:
            if routine.security_level != SecurityLevel.STRONG_AUTH:
                if routine.routine_id >= 0xFF00:
                    self.issues.append(AutomotiveIssue(
                        type="unrestricted_routine",
                        severity="high",
                        description=f"危险例程 0x{routine.routine_id:04X} ({routine.name}) 访问未受限",
                        identifier=routine.routine_id
                    ))
    
    def _can_message_to_dict(self, msg: CANMessage) -> Dict[str, Any]:
        """CAN消息转字典"""
        return {
            "id": hex(msg.id),
            "name": msg.name,
            "dlc": msg.dlc,
            "cycle_time": msg.cycle_time,
            "signal_count": len(msg.signals)
        }
    
    def _session_to_dict(self, session: UDSDiagnosticSession) -> Dict[str, Any]:
        """会话转字典"""
        return {
            "session_type": hex(session.session_type),
            "description": session.description,
            "security_level": session.security_level.value
        }
    
    def _identifier_to_dict(self, identifier: UDSIdentifier) -> Dict[str, Any]:
        """标识符转字典"""
        return {
            "did": hex(identifier.did),
            "name": identifier.name,
            "access_mode": identifier.access_mode,
            "security_level": identifier.security_level.value
        }
    
    def _routine_to_dict(self, routine: UDSRoutine) -> Dict[str, Any]:
        """例程转字典"""
        return {
            "routine_id": hex(routine.routine_id),
            "name": routine.name,
            "security_level": routine.security_level.value,
            "description": routine.description
        }
    
    def _issue_to_dict(self, issue: AutomotiveIssue) -> Dict[str, Any]:
        """问题转字典"""
        return {
            "type": issue.type,
            "severity": issue.severity,
            "description": issue.description,
            "affected_component": issue.affected_component,
            "identifier": hex(issue.identifier) if issue.identifier else None
        }


# 便捷函数
def analyze_automotive_firmware(binary_path: str) -> Dict[str, Any]:
    """
    分析汽车电子固件
    
    Args:
        binary_path: 固件文件路径
    
    Returns:
        分析结果
    """
    analyzer = AutomotiveAnalyzer()
    return analyzer.analyze(binary_path=binary_path)
