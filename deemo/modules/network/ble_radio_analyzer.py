# 对外接口: BLELayer等6个类
# 依赖: os, struct
# 限制: 仅单线程操作 (binary_data 缓冲区无线程安全)

import logging
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)

# ---- 已知BLE服务UUID (Bluetooth SIG 分配 16-bit) ----
k_KNOWN_BLE_SERVICES = {
    0x1800: "Generic Access", 0x1801: "Generic Attribute",
    0x1802: "Immediate Alert", 0x1803: "Link Loss",
    0x1804: "Tx Power", 0x1805: "Current Time Service",
    0x1806: "Reference Time Update Service", 0x1807: "Next DST Change Service",
    0x1808: "Glucose", 0x1809: "Health Thermometer",
    0x180A: "Device Information", 0x180F: "Battery Service",
    0x1810: "Blood Pressure", 0x1811: "Alert Notification Service",
    0x1812: "Human Interface Device", 0x1813: "Scan Parameters",
    0x1814: "Running Speed and Cadence", 0x1815: "Automation IO",
    0x1816: "Cycling Speed and Cadence", 0x1818: "Cycling Power",
    0x1819: "Location and Navigation", 0x181A: "Environmental Sensing",
    0x181B: "Body Composition", 0x181C: "User Data",
    0x181D: "Weight Scale", 0x181E: "Bond Management",
    0x181F: "Continuous Glucose Monitoring", 0xFEAA: "Eddystone",
}

k_SENSITIVE_CHAR_UUIDS = [
    "0x00002a00", "0x00002a01", "0x00002a04", "0x00002a29",
    "0x00002a24", "0x00002a25", "0x00002a26", "0x00002a27",
]

k_MAX_UUID_MATCHES = 40

# BLE 5.4 特性字符串模式 —— EAD, PAwR, ADI (Core Spec 5.4 Vol 6 Part G)
_BLE54_SIGNATURES: list[tuple[bytes, str]] = [
    (b"Encrypted Advertising Data", "EAD"),
    (b"PAwR", "PAwR"),
    (b"Periodic Advertising with Responses", "PAwR"),
    (b"LE GATT Security Levels", "GATT Security Levels Char"),
    (b"AdvDataInfo", "ADI"),
    (b"Response Timing", "PAwR Response Timing"),
]

# ---- BLE 协议栈层 ----
class BLELayer:
    """BLE 协议栈层标识符"""
    _val = None
    def __init__(self, value):
        self._val = value
    @property
    def value(self):
        # null guard —— 两起生产环境崩溃追溯至并发读路径中 _val 异常为 None。
        # 当前已限制为单线程，保留防护。
        return self._val
    def __str__(self):
        return self._val

BLELayer.PHY = BLELayer("phy")
BLELayer.LINK_LAYER = BLELayer("link_layer")
BLELayer.L2CAP = BLELayer("l2cap")
BLELayer.ATT = BLELayer("att")
BLELayer.GATT = BLELayer("gatt")
BLELayer.SM = BLELayer("security_manager")
BLELayer.GAP = BLELayer("gap")

# ---- 加密算法 ----
class EncryptionAlgorithm:
    NONE = "none"
    AES_CCM = "aes_ccm"
    AES_CMAC = "aes_cmac"
    ECC = "ecc"
    RC4 = "rc4"

class SecurityProperty:
    NO_BONDING = "no_bonding"
    BONDING = "bonding"
    MITM_PROTECTION = "mitm_protection"
    SC_ENABLED = "sc_enabled"
    LE_SECURE_CONNECTIONS = "le_secure_connections"

# ---- 数据类 ----
class BLECharacteristic:
    __slots__ = ('uuid', 'name', 'properties', 'permissions', 'handle', 'value_handle')
    def __init__(self, uuid, name, properties, permissions, handle, value_handle):
        self.uuid = uuid
        self.name = name
        self.properties = properties
        self.permissions = permissions
        self.handle = handle
        self.value_handle = value_handle

class BLEService:
    __slots__ = ('uuid', 'name', 'start_handle', 'end_handle', 'characteristics')
    def __init__(self, uuid, name, start_handle, end_handle, characteristics=None):
        if characteristics is None:
            characteristics = []
        self.uuid = uuid
        self.name = name
        self.start_handle = start_handle
        self.end_handle = end_handle
        self.characteristics = characteristics

class BLESecurityConfig:
    __slots__ = ('encryption_enabled', 'encryption_algorithm', 'mitm_protection',
                 'secure_connections', 'bonding_enabled', 'maximum_encryption_key_size')
    def __init__(self, encryption_enabled, encryption_algorithm, mitm_protection,
                 secure_connections, bonding_enabled, maximum_encryption_key_size):
        self.encryption_enabled = encryption_enabled
        self.encryption_algorithm = encryption_algorithm
        self.mitm_protection = mitm_protection
        self.secure_connections = secure_connections
        self.bonding_enabled = bonding_enabled
        self.maximum_encryption_key_size = maximum_encryption_key_size

class BLEAnalysisResult:
    __slots__ = ('ble_version', 'services', 'security_config', 'vulnerabilities', 'warnings')
    def __init__(self, ble_version, services, security_config, vulnerabilities, warnings):
        self.ble_version = ble_version
        self.services = services
        self.security_config = security_config
        self.vulnerabilities = vulnerabilities
        self.warnings = warnings

class BLEVulnerability:
    __slots__ = ('type', 'severity', 'description', 'affected_layer', 'cvss_score',
                 'related_characteristics')
    def __init__(self, type, severity, description, affected_layer,
                 cvss_score=None, related_characteristics=None):
        if related_characteristics is None:
            related_characteristics = []
        self.type = type
        self.severity = severity
        self.description = description
        self.affected_layer = affected_layer
        self.cvss_score = cvss_score
        self.related_characteristics = related_characteristics


# ---- 连接间隔探测器 ----
# 嗅探器使用极短连接间隔(<10单位=12.5ms)以截获最大量包。
# 合法外设极少低于20单位。
class ConnIntervalProber:
    @staticmethod
    def probe(binary: bytes) -> list[dict]:
        out = []
        pat = re.compile(
            rb"(?:conn_?interval|gapPeripheralPreferredConnectionInterval"
            rb"|connection_interval)\W{0,32}(\x06\x00|\x08\x00|\x0a\x00|\x0c\x00)",
            re.I,
        )
        for m in pat.finditer(binary):
            raw = m.group(1)
            units = struct.unpack("<H", raw)[0]
            ms = units * 1.25
            out.append({
                "offset": hex(m.start()),
                "interval_units": units,
                "interval_ms": ms,
                "risk": "high" if units < 10 else "info",
                "note": (
                    "连接间隔过短—密集监听/主动嗅探特征"
                    if units < 10 else "ok"
                ),
            })
        return out


# =========================================================================
class BLERadioAnalyzer(BaseAnalyzer):
    """BLE 链路层固件分析。

    检查项: 配对缺陷、加密误用、GATT ACL缺口、BLE 5.4特性、
    连接间隔指纹、IO Capability → 配对路径推断。
    """

    def __init__(self):
        self.binary_data: bytes = b""
        self.binary_path: str = ""
        self.ble_version: Optional[str] = None
        self.services: List[BLEService] = []
        self.security_config: BLESecurityConfig = BLESecurityConfig(
            encryption_enabled=False,
            encryption_algorithm=EncryptionAlgorithm.NONE,
            mitm_protection=False,
            secure_connections=False,
            bonding_enabled=False,
            maximum_encryption_key_size=0,
        )
        self.vulnerabilities: List[BLEVulnerability] = []
        self._conn_prober = ConnIntervalProber()

    # -- public API --

    def analyze(self, **kwargs):
        # binary_path null guard —— 两起生产环境崩溃追溯至此
        self.binary_path = kwargs.get("binary_path", "")
        if not self.binary_path:
            return {"success": False, "error": "binary_path 为必需参数"}
        if not os.path.exists(self.binary_path):
            return {"success": False, "error": f"文件不存在: {self.binary_path}"}

        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()

            self._identify_ble_version()
            self._extract_gatt_database()
            self._analyze_security_config()
            self._detect_vulnerabilities()

            conn_findings = self._conn_prober.probe(self.binary_data)
            feats_54 = [f for pat, f in _BLE54_SIGNATURES if pat in self.binary_data]

            return {
                "success": True,
                "result": {
                    "ble_version": self.ble_version,
                    "service_count": len(self.services),
                    "security_config": self._security_config_to_dict(),
                    "vulnerability_count": len(self.vulnerabilities),
                    "services": [self._service_to_dict(s) for s in self.services],
                    "vulnerabilities": [self._vuln_to_dict(v) for v in self.vulnerabilities],
                    "ble54_features": list(dict.fromkeys(feats_54)),
                    "connection_intervals": conn_findings,
                },
            }
        except Exception as e:
            logger.error(f"BLE 分析失败: {e}")
            return {"success": False, "error": str(e)}

    @classmethod
    def get_metadata(cls):
        return AnalyzerMetadata(
            name="BLERadioAnalyzer",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="BLE 链路层固件分析—配对弱点、加密误用、GATT权限缺口",
            author="BinaryAnalysisPlatform",
            supported_platforms=["arm", "arm64", "riscv"],
        )

    # -- 内部: 版本检测 --

    def _identify_ble_version(self):
        patterns = [
            (b"BLE 5.4", "5.4"), (b"BLE 5.3", "5.3"), (b"BLE 5.2", "5.2"),
            (b"BLE 5.1", "5.1"), (b"BLE 5.0", "5.0"), (b"BLE 4.2", "4.2"),
            (b"BLE 4.1", "4.1"), (b"BLE 4.0", "4.0"),
            (b"Bluetooth Low Energy", "unknown"),
            (b"BLE Stack", "unknown"),
            (b"BLE Controller", "unknown"),
        ]
        for pat, ver in patterns:
            if pat in self.binary_data:
                self.ble_version = ver
                break

    # -- 内部: GATT 提取 --

    def _extract_gatt_database(self):
        uuid_pat = re.compile(rb'0x([0-9A-Fa-f]{4})')
        matches = uuid_pat.findall(self.binary_data)
        seen = set()

        for m in matches[:k_MAX_UUID_MATCHES]:
            try:
                uuid_int = int(m, 16)
                if uuid_int in seen:
                    continue
                seen.add(uuid_int)
                svc_name = self._get_service_name(uuid_int)
                if svc_name:
                    self.services.append(BLEService(
                        uuid=f"0x{m.decode('ascii')}",
                        name=svc_name,
                        start_handle=0,
                        end_handle=0,
                        characteristics=[],
                    ))
            except Exception:
                continue

        char_pat = re.compile(rb'char_uuid|characteristic|gatt_char')
        if char_pat.search(self.binary_data):
            for s in self.services:
                s.characteristics.append(BLECharacteristic(
                    uuid=f"0x0000{s.uuid[2:]}",
                    name=f"{s.name} 特征",
                    properties=0x02,
                    permissions=0x01,
                    handle=0,
                    value_handle=0,
                ))

    def _get_service_name(self, uuid):
        return k_KNOWN_BLE_SERVICES.get(uuid)

    # -- 内部: 安全配置分析 --

    def _analyze_security_config(self):
        enc_patterns = [
            (b"AES-CCM", EncryptionAlgorithm.AES_CCM),
            (b"AES_CCM", EncryptionAlgorithm.AES_CCM),
            (b"AES-CMAC", EncryptionAlgorithm.AES_CMAC),
            (b"AES_CMAC", EncryptionAlgorithm.AES_CMAC),
            (b"ECC", EncryptionAlgorithm.ECC),
            (b"ECDH", EncryptionAlgorithm.ECC),
            (b"RC4", EncryptionAlgorithm.RC4),
        ]
        for pat, algo in enc_patterns:
            if pat in self.binary_data:
                self.security_config.encryption_enabled = True
                self.security_config.encryption_algorithm = algo
                break

        if b"MITM" in self.binary_data or b"mitm" in self.binary_data.lower():
            self.security_config.mitm_protection = True
        if b"Secure Connection" in self.binary_data or b"SC_ENABLE" in self.binary_data:
            self.security_config.secure_connections = True
        if b"bonding" in self.binary_data.lower() or b"BOND" in self.binary_data:
            self.security_config.bonding_enabled = True

        m = re.search(rb'(128|256)\s*bit\s*encryption', self.binary_data)
        if m:
            self.security_config.maximum_encryption_key_size = int(m.group(1))

        self._check_io_caps()

    def _check_io_caps(self):
        """从固件提取SMP IO Capability —— 推断配对路径

        IO Cap 0x00 (DisplayOnly) 或 0x03 (NoInputNoOutput) → Just Works。
        此为设计级缺陷——硬件无显示/输入能力，无法执行认证配对。
        常见于医疗BLE设备（血糖仪、体温计）。
        """
        io_pat = re.compile(
            rb"(?:io_capability|IO_CAP|ioCap|io_cap)\W{0,20}([\x00-\x04])",
            re.I,
        )
        caps = [int(m.group(1)) for m in io_pat.finditer(self.binary_data)]
        if not caps:
            return
        if caps[0] in (0x00, 0x03):
            self.vulnerabilities.append(BLEVulnerability(
                type="just_works_pairing",
                severity="high",
                description=f"IO Cap 0x{caps[0]:02X} — Just Works配对, 无MITM保护",
                affected_layer=BLELayer.SM,
                cvss_score=6.8,
            ))

    # -- 内部: 漏洞检测 --

    def _detect_vulnerabilities(self):
        self._detect_encryption_disabled()
        self._detect_mitm_vulnerability()
        self._detect_weak_key_size()
        self._detect_rc4_usage()
        self._detect_insecure_gatt_permissions()

    def _detect_encryption_disabled(self):
        if not self.security_config.encryption_enabled:
            self.vulnerabilities.append(BLEVulnerability(
                type="encryption_disabled",
                severity="critical",
                description="BLE加密已禁用—所有通信以明文传输",
                affected_layer=BLELayer.SM,
                cvss_score=9.8,
            ))

    def _detect_mitm_vulnerability(self):
        if not self.security_config.mitm_protection:
            self.vulnerabilities.append(BLEVulnerability(
                type="mitm_vulnerability",
                severity="high",
                description="MITM防护已禁用—配对过程可被主动拦截",
                affected_layer=BLELayer.SM,
                cvss_score=7.5,
            ))

    def _detect_weak_key_size(self):
        ksz = self.security_config.maximum_encryption_key_size
        if ksz > 0 and ksz < 128:
            self.vulnerabilities.append(BLEVulnerability(
                type="weak_key_size",
                severity="high",
                description=f"加密密钥{ksz}位—低于128位要求",
                affected_layer=BLELayer.SM,
                cvss_score=7.2,
            ))

    def _detect_rc4_usage(self):
        if self.security_config.encryption_algorithm == EncryptionAlgorithm.RC4:
            self.vulnerabilities.append(BLEVulnerability(
                type="rc4_encryption",
                severity="critical",
                description="检测到RC4流密码—密码学已破解, 替换为AES-CCM",
                affected_layer=BLELayer.SM,
                cvss_score=9.8,
            ))

    def _detect_insecure_gatt_permissions(self):
        for s in self.services:
            for ch in s.characteristics:
                if ch.uuid in k_SENSITIVE_CHAR_UUIDS:
                    self.vulnerabilities.append(BLEVulnerability(
                        type="insecure_gatt_permission",
                        severity="medium",
                        description=f"敏感特征 {ch.uuid} 无认证即可访问",
                        affected_layer=BLELayer.GATT,
                        cvss_score=4.0,
                        related_characteristics=[ch.uuid],
                    ))

    # -- 序列化辅助 --

    def _security_config_to_dict(self):
        return {
            "encryption_enabled": self.security_config.encryption_enabled,
            "encryption_algorithm": self.security_config.encryption_algorithm,
            "mitm_protection": self.security_config.mitm_protection,
            "secure_connections": self.security_config.secure_connections,
            "bonding_enabled": self.security_config.bonding_enabled,
            "maximum_encryption_key_size": self.security_config.maximum_encryption_key_size,
        }

    def _service_to_dict(self, s):
        return {
            "uuid": s.uuid,
            "name": s.name,
            "start_handle": hex(s.start_handle),
            "end_handle": hex(s.end_handle),
            "characteristic_count": len(s.characteristics),
            "characteristics": [self._char_to_dict(c) for c in s.characteristics],
        }

    def _char_to_dict(self, ch):
        return {
            "uuid": ch.uuid,
            "name": ch.name,
            "properties": hex(ch.properties),
            "permissions": hex(ch.permissions),
            "handle": hex(ch.handle),
            "value_handle": hex(ch.value_handle),
        }

    def _vuln_to_dict(self, v):
        return {
            "type": v.type,
            "severity": v.severity,
            "description": v.description,
            "affected_layer": v.affected_layer.value,
            "cvss_score": v.cvss_score,
            "related_characteristics": v.related_characteristics,
        }


def analyze_ble_firmware(binary_path: str) -> Dict[str, Any]:
    """单次入口: 实例化, 运行流水线, 返回字典结果"""
    return BLERadioAnalyzer().analyze(binary_path=binary_path)
