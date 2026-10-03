import logging
import os
import re

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from .ble_radio_types import (
    BLELayer,
    EncryptionAlgorithm,
    SecurityProperty,
    BLECharacteristic,
    BLEService,
    BLESecurityConfig,
    BLEAnalysisResult,
    BLEVulnerability,
    ConnIntervalProber,
    k_KNOWN_BLE_SERVICES,
    k_SENSITIVE_CHAR_UUIDS,
    k_MAX_UUID_MATCHES,
    _BLE54_SIGNATURES,
)
from .ble_radio_detection import BLEDetectionMixin
from .ble_radio_serializers import BLESerializerMixin

logger = logging.getLogger(__name__)

__all__ = [
    "BLERadioAnalyzer",
    "analyze_ble_firmware",
    "BLELayer",
    "EncryptionAlgorithm",
    "SecurityProperty",
    "BLECharacteristic",
    "BLEService",
    "BLESecurityConfig",
    "BLEAnalysisResult",
    "BLEVulnerability",
    "ConnIntervalProber",
    "k_KNOWN_BLE_SERVICES",
    "k_SENSITIVE_CHAR_UUIDS",
    "k_MAX_UUID_MATCHES",
]


class BLERadioAnalyzer(BLEDetectionMixin, BLESerializerMixin, BaseAnalyzer):
    """BLE 链路层固件分析。

    检查项: 配对缺陷、加密误用、GATT ACL缺口、BLE 5.4特性、
    连接间隔指纹、IO Capability → 配对路径推断。
    """

    def __init__(self):
        self.binary_data: bytes = b""
        self.binary_path: str = ""
        self.ble_version = None
        self.services = []
        self.security_config = BLESecurityConfig(
            encryption_enabled=False,
            encryption_algorithm=EncryptionAlgorithm.NONE,
            mitm_protection=False,
            secure_connections=False,
            bonding_enabled=False,
            maximum_encryption_key_size=0,
        )
        self.vulnerabilities = []
        self._conn_prober = ConnIntervalProber()

# public API

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

# 内部: 版本检测

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


def analyze_ble_firmware(binary_path: str):
    """单次入口: 实例化, 运行流水线, 返回字典结果"""
    return BLERadioAnalyzer().analyze(binary_path=binary_path)
