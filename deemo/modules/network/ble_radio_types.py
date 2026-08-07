# 类型定义: 协议层标识、加密/安全枚举、数据类、服务UUID常量
# 分离动机: 消除主分析器对底层协议常量的耦合

import re
import struct
from typing import List, Optional

# 已知BLE服务UUID (Bluetooth SIG 分配 16-bit)
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

# BLE 协议栈层
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

# 加密算法
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

# 数据类
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


# 连接间隔探测器
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
