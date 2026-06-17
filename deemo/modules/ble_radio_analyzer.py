"""
蓝牙/低功耗射频协议二进制分析模块

逆向 BLE 链路层固件，检测配对弱点、加密误用、GATT 权限问题。

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


class BLELayer(Enum):
    """BLE 协议层枚举"""
    PHY = "phy"
    LINK_LAYER = "link_layer"
    L2CAP = "l2cap"
    ATT = "att"
    GATT = "gatt"
    SM = "security_manager"
    GAP = "gap"


class EncryptionAlgorithm(Enum):
    """加密算法枚举"""
    NONE = "none"
    AES_CCM = "aes_ccm"
    AES_CMAC = "aes_cmac"
    ECC = "ecc"
    RC4 = "rc4"


class SecurityProperty(Enum):
    """安全属性枚举"""
    NO_BONDING = "no_bonding"
    BONDING = "bonding"
    MITM_PROTECTION = "mitm_protection"
    SC_ENABLED = "sc_enabled"
    LE_SECURE_CONNECTIONS = "le_secure_connections"


@dataclass
class BLECharacteristic:
    """BLE 特征定义"""
    uuid: str
    name: Optional[str]
    properties: int
    permissions: int
    handle: int
    value_handle: int


@dataclass
class BLEService:
    """BLE 服务定义"""
    uuid: str
    name: Optional[str]
    start_handle: int
    end_handle: int
    characteristics: List[BLECharacteristic] = field(default_factory=list)


@dataclass
class BLESecurityConfig:
    """BLE 安全配置"""
    encryption_enabled: bool
    encryption_algorithm: EncryptionAlgorithm
    mitm_protection: bool
    secure_connections: bool
    bonding_enabled: bool
    maximum_encryption_key_size: int


@dataclass
class BLEAnalysisResult:
    """BLE 分析结果"""
    ble_version: Optional[str]
    services: List[BLEService]
    security_config: BLESecurityConfig
    vulnerabilities: List['BLEVulnerability']
    warnings: List[str]


@dataclass
class BLEVulnerability:
    """BLE 安全漏洞"""
    type: str
    severity: str
    description: str
    affected_layer: BLELayer
    cvss_score: Optional[float] = None
    related_characteristics: List[str] = field(default_factory=list)


class BLERadioAnalyzer(BaseAnalyzer):
    """
    BLE 协议分析器
    
    逆向 BLE 链路层固件，检测配对弱点、加密误用、GATT 权限问题
    """
    
    def __init__(self):
        self.binary_data: bytes = b""
        self.binary_path: str = ""
        self.ble_version: Optional[str] = None
        self.services: List[BLEService] = []
        self.security_config: BLESecurityConfig = BLESecurityConfig()
            encryption_enabled=False,
            encryption_algorithm=EncryptionAlgorithm.NONE,
            mitm_protection=False,
            secure_connections=False,
            bonding_enabled=False,
            maximum_encryption_key_size=0
        
        self.vulnerabilities: List[BLEVulnerability] = []
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行 BLE 协议分析
        
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
            
            # 识别 BLE 版本
            self._identify_ble_version()
            
            # 提取 GATT 服务和特征
            self._extract_gatt_database()
            
            # 分析安全配置
            self._analyze_security_config()
            
            # 检测漏洞
            self._detect_vulnerabilities()
            
            return {
                "success": True,
                "result": {
                    "ble_version": self.ble_version,
                    "service_count": len(self.services),
                    "security_config": self._security_config_to_dict(),
                    "vulnerability_count": len(self.vulnerabilities),
                    "services": [self._service_to_dict(s) for s in self.services],
                    "vulnerabilities": [self._vulnerability_to_dict(v) for v in self.vulnerabilities]
                }
            }
        except Exception as e:
            logger.error(f"BLE 分析失败: {e}")
            return {"success": False, "error": str(e)}
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="BLERadioAnalyzer",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="BLE协议分析器，逆向链路层固件，检测配对弱点、加密误用、GATT权限问题",
            author="BinaryAnalysisPlatform",
            supported_platforms=["arm", "arm64", "riscv"])
        

    
    def _identify_ble_version(self) -> None:
        """识别 BLE 版本"""
        ble_patterns = [
            (b"BLE 5.4", "5.4"),
            (b"BLE 5.3", "5.3"),
            (b"BLE 5.2", "5.2"),
            (b"BLE 5.1", "5.1"),
            (b"BLE 5.0", "5.0"),
            (b"BLE 4.2", "4.2"),
            (b"BLE 4.1", "4.1"),
            (b"BLE 4.0", "4.0"),
            (b"Bluetooth Low Energy", "unknown"),
            (b"BLE Stack", "unknown"),
            (b"BLE Controller", "unknown"),
        ]
        
        for pattern, version in ble_patterns:
            if pattern in self.binary_data:
                self.ble_version = version
                break
    
    def _extract_gatt_database(self) -> None:
        """提取 GATT 数据库"""
        import re
        
        # 搜索 UUID 模式 (16-bit, 32-bit, 128-bit)
        # 16-bit UUID: 0xFFFF 格式
        uuid_pattern_16 = re.compile(rb'0x([0-9A-Fa-f]{4})')
        matches = uuid_pattern_16.findall(self.binary_data)
        
        seen_uuids = set()
        for match in matches[:40]:
            try:
                uuid_int = int(match, 16)
                if uuid_int in seen_uuids:
                    continue
                seen_uuids.add(uuid_int)
                
                # 检查是否是已知的 BLE UUID
                service_name = self._get_service_name(uuid_int)
                if service_name:
                    self.services.append(BLEService(
                        uuid=f"0x{match.decode('ascii')}",
                        name=service_name,
                        start_handle=0,
                        end_handle=0,
                        characteristics=[]
                    

            except:
                continue
        
        # 提取特征
        char_pattern = re.compile(rb'char_uuid|characteristic|gatt_char')
        if char_pattern.search(self.binary_data):
            for service in self.services:
                service.characteristics.append(BLECharacteristic(
                    uuid=f"0x0000{service.uuid[2:]}",
                    name=f"{service.name} Characteristic",
                    properties=0x02,  # read
                    permissions=0x01,
                    handle=0,
                    value_handle=0
                

    
    def _get_service_name(self, uuid: int) -> Optional[str]:
        """获取服务名称"""
        ble_uuids = {
            0x1800: "Generic Access",
            0x1801: "Generic Attribute",
            0x1802: "Immediate Alert",
            0x1803: "Link Loss",
            0x1804: "Tx Power",
            0x1805: "Current Time Service",
            0x1806: "Reference Time Update Service",
            0x1807: "Next DST Change Service",
            0x1808: "Glucose",
            0x1809: "Health Thermometer",
            0x180A: "Device Information",
            0x180F: "Battery Service",
            0x1810: "Blood Pressure",
            0x1811: "Alert Notification Service",
            0x1812: "Human Interface Device",
            0x1813: "Scan Parameters",
            0x1814: "Running Speed and Cadence",
            0x1815: "Automation IO",
            0x1816: "Cycling Speed and Cadence",
            0x1818: "Cycling Power",
            0x1819: "Location and Navigation",
            0x181A: "Environmental Sensing",
            0x181B: "Body Composition",
            0x181C: "User Data",
            0x181D: "Weight Scale",
            0x181E: "Bond Management",
            0x181F: "Continuous Glucose Monitoring",
            0xFEAA: "Eddystone",
        }
        return ble_uuids.get(uuid)
    
    def _analyze_security_config(self) -> None:
        """分析安全配置"""
        # 检查加密相关代码
        encryption_patterns = [
            (b"AES-CCM", EncryptionAlgorithm.AES_CCM),
            (b"AES_CCM", EncryptionAlgorithm.AES_CCM),
            (b"AES-CMAC", EncryptionAlgorithm.AES_CMAC),
            (b"AES_CMAC", EncryptionAlgorithm.AES_CMAC),
            (b"ECC", EncryptionAlgorithm.ECC),
            (b"ECDH", EncryptionAlgorithm.ECC),
            (b"RC4", EncryptionAlgorithm.RC4),
        ]
        
        for pattern, algorithm in encryption_patterns:
            if pattern in self.binary_data:
                self.security_config.encryption_enabled = True
                self.security_config.encryption_algorithm = algorithm
                break
        
        # 检查 MITM 保护
        if b"MITM" in self.binary_data or b"mitm" in self.binary_data.lower():
            self.security_config.mitm_protection = True
        
        # 检查安全连接
        if b"Secure Connection" in self.binary_data or b"SC_ENABLE" in self.binary_data:
            self.security_config.secure_connections = True
        
        # 检查绑定
        if b"bonding" in self.binary_data.lower() or b"BOND" in self.binary_data:
            self.security_config.bonding_enabled = True
        
        # 检查密钥长度
        key_size_pattern = re.compile(rb'(128|256)\s*bit\s*encryption')
        match = key_size_pattern.search(self.binary_data)
        if match:
            self.security_config.maximum_encryption_key_size = int(match.group(1

    
    def _detect_vulnerabilities(self) -> None:
        """检测 BLE 安全漏洞"""
        self._detect_encryption_disabled()
        self._detect_mitm_vulnerability()
        self._detect_weak_key_size()
        self._detect_rc4_usage()
        self._detect_insecure_gatt_permissions()
    
    def _detect_encryption_disabled(self) -> None:
        """检测加密未启用"""
        if not self.security_config.encryption_enabled:
            self.vulnerabilities.append(BLEVulnerability(
                type="encryption_disabled",
                severity="critical",
                description="BLE 加密未启用，通信数据可能被窃听",
                affected_layer=BLELayer.SM,
                cvss_score=9.8
            

    
    def _detect_mitm_vulnerability(self) -> None:
        """检测 MITM 漏洞"""
        if not self.security_config.mitm_protection:
            self.vulnerabilities.append(BLEVulnerability(
                type="mitm_vulnerability",
                severity="high",
                description="未启用 MITM 保护，配对过程可能被中间人攻击",
                affected_layer=BLELayer.SM,
                cvss_score=7.5
            

    
    def _detect_weak_key_size(self) -> None:
        """检测弱密钥长度"""
        if self.security_config.maximum_encryption_key_size > 0:
            if self.security_config.maximum_encryption_key_size < 128:
                self.vulnerabilities.append(BLEVulnerability(
                    type="weak_key_size",
                    severity="high",
                    description=f"加密密钥长度过短 ({self.security_config.maximum_encryption_key_size} bit)",
                    affected_layer=BLELayer.SM,
                    cvss_score=7.2
                

    
    def _detect_rc4_usage(self) -> None:
        """检测 RC4 使用"""
        if self.security_config.encryption_algorithm == EncryptionAlgorithm.RC4:
            self.vulnerabilities.append(BLEVulnerability(
                type="rc4_encryption",
                severity="critical",
                description="使用不安全的 RC4 加密算法，存在严重安全风险",
                affected_layer=BLELayer.SM,
                cvss_score=9.8
            

    
    def _detect_insecure_gatt_permissions(self) -> None:
        """检测不安全的 GATT 权限"""
        for service in self.services:
            for characteristic in service.characteristics:
                # 检查是否有敏感特征可被未认证访问
                sensitive_uuids = [
                    "0x00002a00",  # Device Name
                    "0x00002a01",  # Appearance
                    "0x00002a04",  # Peripheral Preferred Connection Parameters
                    "0x00002a29",  # Manufacturer Name String
                    "0x00002a24",  # Model Number String
                    "0x00002a25",  # Serial Number String
                    "0x00002a26",  # Firmware Revision String
                    "0x00002a27",  # Hardware Revision String
                ]
                
                if characteristic.uuid in sensitive_uuids:
                    self.vulnerabilities.append(BLEVulnerability(
                        type="insecure_gatt_permission",
                        severity="medium",
                        description=f"敏感特征 {characteristic.uuid} 可能存在不安全的访问权限",
                        affected_layer=BLELayer.GATT,
                        cvss_score=4.0,
                        related_characteristics=[characteristic.uuid]
                    

    
    def _security_config_to_dict(self) -> Dict[str, Any]:
        """安全配置转字典"""
        return {
            "encryption_enabled": self.security_config.encryption_enabled,
            "encryption_algorithm": self.security_config.encryption_algorithm.value,
            "mitm_protection": self.security_config.mitm_protection,
            "secure_connections": self.security_config.secure_connections,
            "bonding_enabled": self.security_config.bonding_enabled,
            "maximum_encryption_key_size": self.security_config.maximum_encryption_key_size
        }
    
    def _service_to_dict(self, service: BLEService) -> Dict[str, Any]:
        """服务转字典"""
        return {
            "uuid": service.uuid,
            "name": service.name,
            "start_handle": hex(service.start_handle),
            "end_handle": hex(service.end_handle),
            "characteristic_count": len(service.characteristics),
            "characteristics": [self._characteristic_to_dict(c) for c in service.characteristics]
        }
    
    def _characteristic_to_dict(self, char: BLECharacteristic) -> Dict[str, Any]:
        """特征转字典"""
        return {
            "uuid": char.uuid,
            "name": char.name,
            "properties": hex(char.properties),
            "permissions": hex(char.permissions),
            "handle": hex(char.handle),
            "value_handle": hex(char.value_handle)
        }
    
    def _vulnerability_to_dict(self, vuln: BLEVulnerability) -> Dict[str, Any]:
        """漏洞转字典"""
        return {
            "type": vuln.type,
            "severity": vuln.severity,
            "description": vuln.description,
            "affected_layer": vuln.affected_layer.value,
            "cvss_score": vuln.cvss_score,
            "related_characteristics": vuln.related_characteristics
        }


# 便捷函数
def analyze_ble_firmware(binary_path: str) -> Dict[str, Any]:
    """
    分析 BLE 固件
    
    Args:
        binary_path: 固件文件路径
    
    Returns:
        分析结果
    """
    analyzer = BLERadioAnalyzer()
    return analyzer.analyze(binary_path=binary_path)))))))))))))))))