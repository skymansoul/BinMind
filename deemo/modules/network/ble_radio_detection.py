# 安全配置分析与漏洞检测逻辑 (mixin)
# 分离动机: 检测规则与主分析器编排解耦, 便于规则独立迭代

import re
from .ble_radio_types import (
    BLELayer,
    BLEVulnerability,
    BLEService,
    BLECharacteristic,
    EncryptionAlgorithm,
    k_KNOWN_BLE_SERVICES,
    k_SENSITIVE_CHAR_UUIDS,
    k_MAX_UUID_MATCHES,
)


class BLEDetectionMixin:
    """安全配置分析与漏洞检测混入。

    以 mixin 方式分离, 避免主分析器膨胀。方法直接操作分析器实例状态。
    """

# 内部: GATT 提取

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

# 内部: 安全配置分析

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

# 内部: 漏洞检测

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
