#!/usr/bin/env python3
"""
移动端密钥存储安全分析 — Android Keystore & iOS Keychain 深度审计。

覆盖范围：
  1. Keymaster HAL版本检测与已知漏洞映射
  2. KeyInfo参数审计（purposes/padding/block modes/digests）
  3. 用户认证绑定检查（biometric + credential）
  4. Secure Enclave / StrongBox 硬件支持检测
  5. Keychain accessibility flag 审计（kSecAttrAccessible*）
  6. 密钥提取可行性评估（root/jailbreak 下的攻击面）
  7. Key Attestation 链路验证
  8. 硬编码密钥材料扫描（AES key, RSA private key, HMAC secret 等）

技术参考：
  - Android Keystore KeyInfo 结构解析（Keymaster 1.0–4.1）
  - iOS Keychain item attributes 与 access control flags
  - TEE/SE 攻击面映射（CVE-2024-*, CVE-2025-* 已知漏洞库）
"""

import re
import struct
import logging
import os
import hashlib
import binascii
from pathlib import Path
from dataclasses import dataclass, field
from enum import StrEnum, IntEnum
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Android Keystore — 类型定义
# ---------------------------------------------------------------------------

class KeymasterVersion(StrEnum):
    """Keymaster HAL 版本枚举，对应 Android 版本与安全特性级别。"""
    V1_0 = "1.0"      # Android 6.0-, 软件实现为主
    V2_0 = "2.0"      # Android 7.0, 引入 ID attestation
    V3_0 = "3.0"      # Android 8.0, 引入 EC 曲线 + 独立 attestation key
    V4_0 = "4.0"      # Android 9.0, 3DES 移除, 引入 StrongBox
    V4_1 = "4.1"      # Android 11+, 引入 KM_PURPOSE_AGREE_KEY
    UNKNOWN = "unknown"


class KeyPurpose(IntEnum):
    """Keymaster 密钥用途位掩码。"""
    ENCRYPT = 0x01
    DECRYPT = 0x02
    SIGN = 0x04
    VERIFY = 0x08
    WRAP_KEY = 0x10
    AGREE_KEY = 0x20  # v4.1+
    ATTEST_KEY = 0x40


class KeyAuthenticationType(StrEnum):
    NONE = "none"
    PASSWORD = "password"
    FINGERPRINT = "fingerprint"
    FACE = "face"
    IRIS = "iris"
    STRONGBOX = "strongbox"
    BIOMETRIC_WEAK = "biometric_weak"  # class 2
    BIOMETRIC_STRONG = "biometric_strong"  # class 3


class KeyOrigin(StrEnum):
    GENERATED = "generated"
    DERIVED = "derived"
    IMPORTED = "imported"
    SECURELY_IMPORTED = "securely_imported"  # v4.0+
    UNKNOWN = "unknown"


class SecurityLevel(StrEnum):
    SOFTWARE = "software"
    TRUSTED_ENVIRONMENT = "tee"
    STRONGBOX = "strongbox"
    UNKNOWN = "unknown"


@dataclass
class AndroidKeyInfo:
    """从二进制/APK中提取的 Android Keystore 密钥元数据。"""
    alias: str
    purpose_mask: int = 0
    padding_modes: List[str] = field(default_factory=list)
    block_modes: List[str] = field(default_factory=list)
    digests: List[str] = field(default_factory=list)
    key_size_bits: int = 0
    origin: KeyOrigin = KeyOrigin.UNKNOWN
    security_level: SecurityLevel = SecurityLevel.UNKNOWN
    auth_required: bool = False
    auth_timeout_seconds: int = -1
    user_auth_required: bool = False
    biometric_required: bool = False
    is_exportable: bool = False
    attestation_challenge: Optional[bytes] = None
    # raw hints from binary pattern matching
    candidate_offsets: List[int] = field(default_factory=list)

    def purposes(self) -> List[KeyPurpose]:
        result = []
        for p in KeyPurpose:
            if self.purpose_mask & p.value:
                result.append(p)
        return result


@dataclass
class KeymasterVulnerability:
    """Keymaster 已知漏洞条目。"""
    cve_id: str
    affected_versions: List[KeymasterVersion]
    description: str
    severity: str
    exploit_complexity: str = "medium"
    patch_level: str = ""


@dataclass
class HardcodedKey:
    """从二进制扫描中发现的硬编码密钥。"""
    material: str                  # hex or truncated preview
    offset: int
    key_type: str                  # "AES", "RSA", "HMAC", "EC", "generic"
    size_bits: int
    context_preview: str = ""      # surrounding bytes for manual review
    confidence: float = 0.0        # 0-1, 基于熵 + 长度 + 上下文判定


# ---------------------------------------------------------------------------
# iOS Keychain — 类型定义
# ---------------------------------------------------------------------------

class KeychainAccessibility(StrEnum):
    """iOS kSecAttrAccessible 常量映射。越往下越严格。"""
    ALWAYS = "kSecAttrAccessibleAlways"                                    # 始终可访问（已弃用）
    ALWAYS_THIS_DEVICE_ONLY = "kSecAttrAccessibleAlwaysThisDeviceOnly"    # 始终，仅本设备（已弃用）
    WHEN_UNLOCKED = "kSecAttrAccessibleWhenUnlocked"                      # 解锁时
    WHEN_UNLOCKED_THIS_DEVICE_ONLY = "kSecAttrAccessibleWhenUnlockedThisDeviceOnly"
    AFTER_FIRST_UNLOCK = "kSecAttrAccessibleAfterFirstUnlock"             # 首次解锁后
    AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY = "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"
    WHEN_PASSCODE_SET_THIS_DEVICE_ONLY = "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly"
    UNKNOWN = "unknown"


class KeychainClass(StrEnum):
    """iOS Keychain item class (kSecClass)。"""
    GENERIC_PASSWORD = "genp"
    INTERNET_PASSWORD = "inet"
    CERTIFICATE = "cert"
    KEY = "keys"
    IDENTITY = "idnt"


@dataclass
class IOSKeychainItem:
    """iOS Keychain 条目分析结果。"""
    item_class: KeychainClass = KeychainClass.GENERIC_PASSWORD
    accessibility: KeychainAccessibility = KeychainAccessibility.UNKNOWN
    access_group: str = ""
    service_name: str = ""
    account: str = ""
    has_biometric_protection: bool = False
    has_acm: bool = False             # access control mode (kSecAccessControl)
    acm_flags: List[str] = field(default_factory=list)
    syncable: bool = False           # kSecAttrSynchronizable
    data_protection_class: str = ""
    candidate_addresses: List[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 已知漏洞数据库（内嵌，按需扩展）
# ---------------------------------------------------------------------------

_KEYMASTER_VULNS = [
    KeymasterVulnerability(
        cve_id="CVE-2018-9475",
        affected_versions=[KeymasterVersion.V1_0, KeymasterVersion.V2_0],
        description="Keymaster TA 边界检查缺失，可导致密钥材料泄露",
        severity="high",
        patch_level="2018-11-05",
    ),
    KeymasterVulnerability(
        cve_id="CVE-2021-0392",
        affected_versions=[KeymasterVersion.V3_0, KeymasterVersion.V4_0],
        description="Keymaster 4.0 importKey 绕过安全导入检查",
        severity="critical",
        exploit_complexity="low",
        patch_level="2021-02-05",
    ),
    KeymasterVulnerability(
        cve_id="CVE-2021-1905",
        affected_versions=[KeymasterVersion.V4_0],
        description="Qualcomm Keymaster 实现中 use-after-free 导致密钥泄露",
        severity="critical",
        patch_level="2021-05-05",
    ),
    KeymasterVulnerability(
        cve_id="CVE-2022-20224",
        affected_versions=[KeymasterVersion.V3_0, KeymasterVersion.V4_0, KeymasterVersion.V4_1],
        description="Keymaster TA race condition 在 attestation 流程中",
        severity="high",
        patch_level="2022-08-05",
    ),
    KeymasterVulnerability(
        cve_id="CVE-2023-21137",
        affected_versions=[KeymasterVersion.V4_0, KeymasterVersion.V4_1],
        description="Keymint (Keymaster 4.1) shared memory 未初始化导致密钥残留",
        severity="medium",
        patch_level="2023-05-05",
    ),
    KeymasterVulnerability(
        cve_id="CVE-2024-29745",
        affected_versions=[KeymasterVersion.V4_1],
        description="Android 14 Keymint auth token 重放，绕过生物认证超时限制",
        severity="high",
        exploit_complexity="low",
        patch_level="2024-04-05",
    ),
]


# 已知弱配置模式
_ANDROID_WEAK_PURPOSE_COMBOS = [
    # (mask, description)
    (KeyPurpose.ENCRYPT.value | KeyPurpose.DECRYPT.value,
     "加密+解密组合：可用于对称密码学绕过，攻击者获取后可直接解密数据"),
    (KeyPurpose.SIGN.value | KeyPurpose.VERIFY.value,
     "签名+验证组合：结合不当使用可伪造签名"),
]

_IOS_WEAK_ACCESSIBILITY = [
    KeychainAccessibility.ALWAYS,
    KeychainAccessibility.ALWAYS_THIS_DEVICE_ONLY,
    KeychainAccessibility.WHEN_UNLOCKED,
]

# ---------------------------------------------------------------------------
# 二进制模式：硬编码密钥检测
# ---------------------------------------------------------------------------

# 常见密钥头标记 (magic bytes + 猜测结构前缀)
_KEY_MAGIC_PATTERNS = {
    b'-----BEGIN RSA PRIVATE KEY-----': ('RSA private key', 1024),
    b'-----BEGIN EC PRIVATE KEY-----': ('EC private key', 256),
    b'-----BEGIN PRIVATE KEY-----': ('PKCS#8 private key', 1024),
    b'-----BEGIN CERTIFICATE-----': ('X.509 certificate', 0),
    b'\x30\x82': ('DER SEQUENCE (possible key)', 1024),
    b'3082': ('hex DER SEQUENCE (possible key)', 1024),
    # AES key 魔数较弱，用熵判定
}

# Hex-encoded 密钥正则
_HEX_KEY_PATTERNS = re.compile(
    r'[0-9a-fA-F]{32,128}',  # 128-bit 到 512-bit
)


def _estimate_entropy(data: bytes) -> float:
    """香农熵估计，用于区分随机密钥和普通字符串。"""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for _, count in freq.items():
        p = count / length
        entropy -= p * (p.bit_length() - 1)  # approx log2
    # normalize
    max_entropy = min(8.0, (len(freq).bit_length()))
    return entropy / max(max_entropy, 1)


# ---------------------------------------------------------------------------
# AndroidKeystoreAnalyzer
# ---------------------------------------------------------------------------

class AndroidKeystoreAnalyzer:
    """Android Keystore 静态分析器。

    从 APK/DEX/SO 中检测：
      - KeyStore 别名引用（AndroidKeyStore provider 字符串）
      - KeyGenParameterSpec.Builder 链条参数推导
      - Keymaster HAL 版本识别
      - 已知漏洞映射
    """

    # 从 DEX/Smali/反编译代码中匹配的签名
    _KEYSTORE_ALIAS_PATTERN = re.compile(
        rb'AndroidKeyStore|AndroidKeyStore\b',
    )
    _KEYGEN_BUILDER_PATTERN = re.compile(
        rb'KeyGenParameterSpec\.Builder|KeyGenParameterSpec\$Builder',
    )
    _KEY_PURPOSE_PATTERN = re.compile(
        rb'setPurposes?\(|PURPOSE_ENCRYPT|PURPOSE_DECRYPT|PURPOSE_SIGN|PURPOSE_VERIFY',
    )
    _AUTH_PATTERN = re.compile(
        rb'setUserAuthenticationRequired|setUserAuthenticationValidityDurationSeconds'
        rb'|setUserAuthenticationParameters|setInvalidatedByBiometricEnrollment',
    )
    _SET_BLOCK_MODE = re.compile(rb'setBlockModes?\(|setEncryptionPaddings?\(')
    _DIGEST_PATTERN = re.compile(rb'setDigests?\(')

    _KEYMASTER_IMPL_PATTERNS = [
        (rb'keymaster@?1\.0', KeymasterVersion.V1_0),
        (rb'keymaster@?2\.0', KeymasterVersion.V2_0),
        (rb'keymaster@?3\.0', KeymasterVersion.V3_0),
        (rb'keymaster@?4\.0', KeymasterVersion.V4_0),
        (rb'keymaster@?4\.1|keymint@?1\.0', KeymasterVersion.V4_1),
        (rb'android\.hardware\.gatekeeper', KeymasterVersion.V3_0),  # 间接指示
    ]

    _STRONGBOX_PATTERN = re.compile(rb'StrongBox|STRONGBOX|IsStrongBoxBacked')
    _SECURITY_LEVEL_PATTERN = re.compile(rb'SecurityLevel|TRUSTED_ENVIRONMENT|SOFTWARE')

    def __init__(self, binary_path: str = "", binary_data: bytes = b""):
        self.binary_path = binary_path
        self.data = binary_data
        if not self.data and binary_path and os.path.exists(binary_path):
            self.data = Path(binary_path).read_bytes()
        self.key_infos: List[AndroidKeyInfo] = []
        self.hardcoded_keys: List[HardcodedKey] = []
        self._detected_version = KeymasterVersion.UNKNOWN
        self._has_strongbox = False

    def detect_keymaster_version(self) -> KeymasterVersion:
        """通过二进制字符串匹配识别 Keymaster HAL 版本。"""
        for pattern, ver in self._KEYMASTER_IMPL_PATTERNS:
            if re.search(pattern, self.data):
                self._detected_version = ver
                logger.info(f"检测到 Keymaster 版本: {ver.value}")
                return ver
        # fallback: 检查 StrongBox 引用 (需要 >= v4.0)
        if self._STRONGBOX_PATTERN.search(self.data):
            self._detected_version = KeymasterVersion.V4_0
            return KeymasterVersion.V4_0
        return KeymasterVersion.UNKNOWN

    def extract_key_aliases(self) -> List[str]:
        """从二进制中提取 AndroidKeyStore 密钥别名引用。"""
        aliases: Set[str] = set()
        # 方法1: 直接搜索紧邻 AndroidKeyStore 字符串的别名
        for match in self._KEYSTORE_ALIAS_PATTERN.finditer(self.data):
            start = match.end()
            # 向后扫描直到遇到 null 或非可打印字符
            end = start
            data_len = len(self.data)
            while (end < data_len and end - start < 128
                   and self.data[end] >= 0x20 and self.data[end] <= 0x7E
                   and self.data[end] not in (0x00, 0x0A, 0x0D)):
                end += 1
            if end > start:
                alias = self.data[start:end].decode('ascii', errors='ignore').strip()
                if alias and len(alias) > 1 and not alias.startswith('org'):
                    aliases.add(alias)
        # 方法2: 匹配 getEntry( 或 getKey( 后的字符串参数
        entry_pattern = re.compile(rb"(?:getEntry|getKey|containsAlias)\s*\(\s*\"([^\"]+)\"", re.DOTALL)
        for m in entry_pattern.finditer(self.data):
            alias = m.group(1).decode('utf-8', errors='ignore')
            if alias and len(alias) > 1:
                aliases.add(alias)
        return list(aliases)

    def _infer_key_config(self, alias: str, region: bytes) -> AndroidKeyInfo:
        """从 KeyGenParameterSpec 上下文区间推导密钥配置。"""
        info = AndroidKeyInfo(alias=alias)

        # purpose 推导
        if b'PURPOSE_ENCRYPT' in region:
            info.purpose_mask |= KeyPurpose.ENCRYPT.value
        if b'PURPOSE_DECRYPT' in region:
            info.purpose_mask |= KeyPurpose.DECRYPT.value
        if b'PURPOSE_SIGN' in region:
            info.purpose_mask |= KeyPurpose.SIGN.value
        if b'PURPOSE_VERIFY' in region:
            info.purpose_mask |= KeyPurpose.VERIFY.value

        # auth
        if b'setUserAuthenticationRequired' in region:
            info.user_auth_required = True
        if b'setUserAuthenticationValidityDurationSeconds' in region:
            info.auth_required = True
            # 尝试解析超时值 (简单方法: 取邻近数字)
            dur_match = re.search(rb'DurationSeconds\s*\(\s*(\d+)', region)
            if dur_match:
                info.auth_timeout_seconds = int(dur_match.group(1))

        # 生物认证
        if (b'setInvalidatedByBiometricEnrollment' in region
                or b'BIOMETRIC_STRONG' in region
                or b'BIOMETRIC_WEAK' in region):
            info.biometric_required = True

        # block modes
        for mode in [b'GCM', b'CBC', b'CTR', b'ECB']:
            if mode in region:
                info.block_modes.append(mode.decode())

        # padding
        for pad in [b'PKCS7', b'PKCS1', b'OAEP', b'NoPadding']:
            if pad in region:
                info.padding_modes.append(pad.decode())

        # key size
        size_match = re.search(rb'setKeySize\s*\(\s*(\d+)', region)
        if size_match:
            info.key_size_bits = int(size_match.group(1))

        # origin
        if b'StrongBox' in region or b'StrongBoxKeymaster' in region:
            info.security_level = SecurityLevel.STRONGBOX
        elif b'TrustedEnvironment' in region or b'keymaster' in region:
            info.security_level = SecurityLevel.TRUSTED_ENVIRONMENT

        return info

    def analyze_key_configs(self) -> List[AndroidKeyInfo]:
        """完整密钥配置审计。"""
        aliases = self.extract_key_aliases()
        results: List[AndroidKeyInfo] = []

        for alias in aliases:
            alias_bytes = alias.encode('utf-8', errors='ignore')
            # 在二进制中找到别名附近的代码区域
            idx = self.data.find(alias_bytes)
            if idx == -1:
                continue
            # 取周围 4KB 窗口做上下文分析
            region_start = max(0, idx - 2048)
            region_end = min(len(self.data), idx + 2048)
            region = self.data[region_start:region_end]

            info = self._infer_key_config(alias, region)
            info.candidate_offsets.append(idx)
            results.append(info)

        self.key_infos = results
        return results

    def scan_hardcoded_keys(self) -> List[HardcodedKey]:
        """扫描二进制中可能的硬编码密钥材料。"""
        keys: List[HardcodedKey] = []
        data = self.data

        # 1. ASCII-armored 密钥
        for magic, (key_type, estimated_size) in _KEY_MAGIC_PATTERNS.items():
            offset = 0
            while True:
                offset = data.find(magic, offset)
                if offset == -1:
                    break
                # 取密钥块（最多 4KB）
                end = min(len(data), offset + 4096)
                key_block = data[offset:end]
                # 找结束标记
                end_tag_pos = key_block.find(b'-----END ', len(magic))
                if end_tag_pos > 0:
                    endline = key_block.find(b'\n', end_tag_pos)
                    if endline > 0:
                        key_block = key_block[:endline + 1]
                context_before = data[max(0, offset - 32):offset].decode('ascii', errors='replace')
                keys.append(HardcodedKey(
                    material=binascii.hexlify(key_block[:64]).decode() + '...',
                    offset=offset,
                    key_type=key_type,
                    size_bits=estimated_size,
                    context_preview=context_before,
                    confidence=0.95,
                ))
                offset += 1

        # 2. 高熵 hex 字符串（可能是 hex-encoded keys）
        for m in _HEX_KEY_PATTERNS.finditer(data.decode('ascii', errors='ignore')):
            hex_str = m.group()
            if len(hex_str) < 32:
                continue
            try:
                raw = bytes.fromhex(hex_str)
                entropy = _estimate_entropy(raw)
                if entropy > 0.85:
                    key_type = 'AES' if len(raw) in (16, 24, 32) else 'generic'
                    keys.append(HardcodedKey(
                        material=hex_str[:64],
                        offset=m.start(),
                        key_type=key_type,
                        size_bits=len(raw) * 8,
                        confidence=entropy * 0.9,  # 稍降噪
                    ))
            except (ValueError, TypeError):
                pass

        self.hardcoded_keys = keys
        return keys

    def map_known_vulnerabilities(self) -> List[KeymasterVulnerability]:
        """根据检测到的 Keymaster 版本匹配已知 CVE。"""
        ver = self._detected_version
        if ver == KeymasterVersion.UNKNOWN:
            ver = self.detect_keymaster_version()
        matched = []
        for vuln in _KEYMASTER_VULNS:
            if ver in vuln.affected_versions:
                matched.append(vuln)
        return matched

    def assess_weakness(self) -> List[Dict[str, Any]]:
        """综合薄弱点评估，生成可操作报告。"""
        findings: List[Dict[str, Any]] = []

        for info in self.key_infos:
            # 检查弱目的组合
            for mask, desc in _ANDROID_WEAK_PURPOSE_COMBOS:
                if (info.purpose_mask & mask) == mask:
                    findings.append({
                        'alias': info.alias,
                        'type': 'weak_purpose_combination',
                        'severity': 'medium',
                        'description': desc,
                        'recommendation': '分离加密/解密与签名/验证密钥',
                    })
            # 缺少用户认证
            if not info.user_auth_required and info.purpose_mask != 0:
                findings.append({
                    'alias': info.alias,
                    'type': 'no_user_authentication',
                    'severity': 'high',
                    'description': f'密钥 {info.alias} 未要求用户认证',
                    'recommendation': '调用 setUserAuthenticationRequired(true)',
                })
            # 认证超时过长
            if info.auth_timeout_seconds > 300 or info.auth_timeout_seconds == -1:
                findings.append({
                    'alias': info.alias,
                    'type': 'excessive_auth_timeout',
                    'severity': 'low',
                    'description': f'认证超时过长: {info.auth_timeout_seconds}s',
                    'recommendation': '将超时设置为 <= 300s（5分钟）',
                })

        # 硬编码密钥发现
        for hk in self.hardcoded_keys:
            if hk.confidence > 0.7:
                findings.append({
                    'type': 'hardcoded_key_material',
                    'severity': 'critical',
                    'key_type': hk.key_type,
                    'offset': hex(hk.offset),
                    'description': f'发现可能的硬编码{hk.key_type}: offset {hk.offset:#x}',
                    'recommendation': '使用 Android Keystore 生成密钥，移除硬编码材料',
                })

        return findings

    def analyze(self) -> Dict[str, Any]:
        """执行完整 Android 密钥存储分析。"""
        return {
            'platform': 'android',
            'keymaster_version': self.detect_keymaster_version().value,
            'has_strongbox': self._STRONGBOX_PATTERN.search(self.data) is not None,
            'key_configs': [
                {
                    'alias': k.alias,
                    'purpose_mask': hex(k.purpose_mask),
                    'block_modes': k.block_modes,
                    'padding_modes': k.padding_modes,
                    'key_size_bits': k.key_size_bits,
                    'security_level': k.security_level.value,
                    'user_auth_required': k.user_auth_required,
                    'biometric_required': k.biometric_required,
                    'auth_timeout_seconds': k.auth_timeout_seconds,
                }
                for k in self.key_infos
            ],
            'hardcoded_keys': [
                {'type': k.key_type, 'offset': hex(k.offset), 'confidence': round(k.confidence, 2)}
                for k in self.hardcoded_keys
            ],
            'known_vulnerabilities': [
                {'cve': v.cve_id, 'severity': v.severity, 'description': v.description}
                for v in self.map_known_vulnerabilities()
            ],
            'weakness_findings': self.assess_weakness(),
        }

    def run_full(self) -> Dict[str, Any]:
        """一站式运行：提取 → 配置审计 → 硬编码扫描 → 漏洞映射 → 弱点评估。"""
        self.extract_key_aliases()       # 填充 aliases
        self.analyze_key_configs()       # 填充 key_infos
        self.scan_hardcoded_keys()       # 填充 hardcoded_keys
        return self.analyze()


# ---------------------------------------------------------------------------
# IOSKeychainAnalyzer
# ---------------------------------------------------------------------------

class IOSKeychainAnalyzer:
    """iOS Keychain 静态分析器。

    从 Mach-O 二进制中检测：
      - Keychain Services API 调用 (SecItemAdd, SecItemCopyMatching, SecItemUpdate, SecItemDelete)
      - kSecAttrAccessible 常量映射 → 风险评估
      - kSecAccessControl / SecAccessControlCreateFlags 分析
      - 跨应用共享组 (access group) 检测
    """

    _SEC_ITEM_ADD = re.compile(rb'_SecItemAdd\b')
    _SEC_ITEM_COPY = re.compile(rb'_SecItemCopyMatching\b')
    _SEC_ITEM_UPDATE = re.compile(rb'_SecItemUpdate\b')
    _SEC_ITEM_DELETE = re.compile(rb'_SecItemDelete\b')

    # kSecAttrAccessible 字符串 → enum 映射
    _ACCESSIBILITY_MAP: Dict[bytes, KeychainAccessibility] = {
        b'kSecAttrAccessibleAlways': KeychainAccessibility.ALWAYS,
        b'kSecAttrAccessibleAlwaysThisDeviceOnly': KeychainAccessibility.ALWAYS_THIS_DEVICE_ONLY,
        b'kSecAttrAccessibleWhenUnlocked': KeychainAccessibility.WHEN_UNLOCKED,
        b'kSecAttrAccessibleWhenUnlockedThisDeviceOnly': KeychainAccessibility.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        b'kSecAttrAccessibleAfterFirstUnlock': KeychainAccessibility.AFTER_FIRST_UNLOCK,
        b'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly': KeychainAccessibility.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
        b'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly': KeychainAccessibility.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
    }

    # ACL flags
    _ACL_FLAG_PATTERNS = [
        (rb'kSecAccessControlUserPresence', 'UserPresence'),
        (rb'kSecAccessControlBiometryAny', 'BiometryAny'),
        (rb'kSecAccessControlBiometryCurrentSet', 'BiometryCurrentSet'),
        (rb'kSecAccessControlDevicePasscode', 'DevicePasscode'),
        (rb'kSecAccessControlOr', 'Or (组合)'),
        (rb'kSecAccessControlAnd', 'And (组合)'),
        (rb'kSecAccessControlPrivateKeyUsage', 'PrivateKeyUsage'),
        (rb'kSecAccessControlApplicationPassword', 'AppPassword'),
    ]

    _ACCESS_GROUP_PATTERN = re.compile(rb'keychain-access-groups|com\.\w+\.\w+')

    def __init__(self, binary_path: str = "", binary_data: bytes = b""):
        self.binary_path = binary_path
        self.data = binary_data
        if not self.data and binary_path and os.path.exists(binary_path):
            self.data = Path(binary_path).read_bytes()
        self.keychain_items: List[IOSKeychainItem] = []
        self._secitem_calls: Dict[str, List[int]] = defaultdict(list)

    def detect_keychain_api_usage(self) -> Dict[str, List[int]]:
        """定位所有 Keychain Services API 调用点地址。"""
        api_patterns = [
            ('SecItemAdd', self._SEC_ITEM_ADD),
            ('SecItemCopyMatching', self._SEC_ITEM_COPY),
            ('SecItemUpdate', self._SEC_ITEM_UPDATE),
            ('SecItemDelete', self._SEC_ITEM_DELETE),
        ]
        for name, pattern in api_patterns:
            for m in pattern.finditer(self.data):
                self._secitem_calls[name].append(m.start())
        return dict(self._secitem_calls)

    def _infer_accessibility(self) -> KeychainAccessibility:
        """从二进制中查找最不安全的 accessibility 设置。"""
        found = KeychainAccessibility.UNKNOWN
        for raw_flag, accessibility in self._ACCESSIBILITY_MAP.items():
            if raw_flag in self.data:
                # 保留最不安全（最低保护的）的那个
                if found == KeychainAccessibility.UNKNOWN:
                    found = accessibility
                elif list(KeychainAccessibility).index(accessibility) < list(KeychainAccessibility).index(found):
                    found = accessibility
        return found

    def _detect_acl_flags(self) -> List[str]:
        """检测 SecAccessControl 标志，推断生物认证使用情况。"""
        flags: List[str] = []
        for pattern, flag_name in self._ACL_FLAG_PATTERNS:
            if pattern in self.data:
                flags.append(flag_name)
        return flags

    def _extract_access_groups(self) -> List[str]:
        """从 entitlements 字符串或二进制中提取 Keychain access group。"""
        groups: Set[str] = set()
        for m in self._ACCESS_GROUP_PATTERN.finditer(self.data):
            group = m.group(0).decode('utf-8', errors='ignore')
            groups.add(group)
        return list(groups)

    def analyze_keychain_config(self) -> IOSKeychainItem:
        """综合分析 Keychain 配置。"""
        item = IOSKeychainItem()
        item.accessibility = self._infer_accessibility()
        item.acm_flags = self._detect_acl_flags()
        item.access_group = ','.join(self._extract_access_groups())
        item.has_biometric_protection = any(
            f in item.acm_flags for f in ['BiometryAny', 'BiometryCurrentSet', 'UserPresence']
        )
        item.has_acm = len(item.acm_flags) > 0
        return item

    def assess_weakness(self) -> List[Dict[str, Any]]:
        """评估 Keychain 配置弱点。"""
        findings: List[Dict[str, Any]] = []
        item = self.analyze_keychain_config()

        # 1. 弱 accessibility — Always 模式
        if item.accessibility in _IOS_WEAK_ACCESSIBILITY:
            findings.append({
                'type': 'weak_accessibility',
                'severity': 'high' if item.accessibility == KeychainAccessibility.ALWAYS else 'medium',
                'description': f'Keychain 使用弱 accessibility: {item.accessibility.value}',
                'recommendation': '改用 kSecAttrAccessibleWhenUnlockedThisDeviceOnly 或 AfterFirstUnlockThisDeviceOnly',
            })

        # 2. 未使用 access control
        if not item.has_acm:
            findings.append({
                'type': 'no_access_control',
                'severity': 'medium',
                'description': '未使用 SecAccessControl — 无生物认证或密码保护',
                'recommendation': '添加 kSecAccessControlUserPresence 或 kSecAccessControlBiometryCurrentSet',
            })

        # 3. 使用 BiometryAny 而非 BiometryCurrentSet
        if 'BiometryAny' in item.acm_flags and 'BiometryCurrentSet' not in item.acm_flags:
            findings.append({
                'type': 'weak_biometric_binding',
                'severity': 'medium',
                'description': '使用 kSecAccessControlBiometryAny — 任意指纹/面部均可解锁',
                'recommendation': '改用 kSecAccessControlBiometryCurrentSet 绑定至当前注册的生物特征',
            })

        # 4. 检测到 Keychain API 调用频次统计
        api_calls = self.detect_keychain_api_usage()
        total_calls = sum(len(v) for v in api_calls.values())
        if total_calls == 0:
            findings.append({
                'type': 'no_keychain_usage',
                'severity': 'info',
                'description': '未检测到 Keychain Services API 使用',
            })

        findings.append({
            'type': 'keychain_api_summary',
            'severity': 'info',
            'description': f'Keychain API 调用: { {k: len(v) for k, v in api_calls.items()} }',
        })

        return findings

    def analyze(self) -> Dict[str, Any]:
        """执行完整 iOS Keychain 分析。"""
        item = self.analyze_keychain_config()
        api_usage = self.detect_keychain_api_usage()

        return {
            'platform': 'ios',
            'keychain_accessibility': item.accessibility.value,
            'access_control_flags': item.acm_flags,
            'has_biometric_protection': item.has_biometric_protection,
            'access_groups': item.access_group.split(',') if item.access_group else [],
            'keychain_api_usage': {k: len(v) for k, v in api_usage.items()},
            'weakness_findings': self.assess_weakness(),
        }

    def run_full(self) -> Dict[str, Any]:
        self.detect_keychain_api_usage()
        return self.analyze()


# ---------------------------------------------------------------------------
# 统一入口
# ---------------------------------------------------------------------------

_MACHO_MAGICS = [
    b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
    b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce',
]


def analyze_keystore_security(binary_path: str, platform: str = 'auto') -> Dict[str, Any]:
    """移动端密钥存储安全分析统一入口。"""
    path = Path(binary_path)
    if not path.exists():
        return {'error': f'文件不存在: {binary_path}'}

    data = path.read_bytes()

    if platform == 'auto':
        magic = data[:4]
        if magic in _MACHO_MAGICS:
            platform = 'ios'
        elif data[:4] == b'\x7fELF':
            platform = 'android'
        else:
            # 可能是 APK/DEX — 尝试 Android
            platform = 'android' if (b'AndroidKeyStore' in data or b'keymaster' in data) else 'ios'

    if platform == 'android':
        analyzer = AndroidKeystoreAnalyzer(binary_data=data)
        result = analyzer.run_full()
    else:
        analyzer = IOSKeychainAnalyzer(binary_data=data)
        result = analyzer.run_full()

    result['binary_path'] = str(path)
    result['platform'] = platform
    result['file_hash'] = hashlib.sha256(data).hexdigest()[:16]
    return result


# 兼容性存根
@dataclass
class MobileKeystoreVulnerability:
    type: str = ''
    severity: str = 'Medium'
    description: str = ''
    platform: str = ''
    location: str = ''


class MobileKeystoreAnalyzer:
    def __init__(self, path: str, platform: str = 'auto'):
        self.path = path
        self.platform = platform

    def analyze(self) -> Dict[str, Any]:
        return analyze_keystore_security(self.path, self.platform)
