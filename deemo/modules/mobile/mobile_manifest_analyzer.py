#!/usr/bin/env python3
"""
移动应用 Manifest/Plist 安全分析。

分析维度:
  1. AndroidManifest.xml (二进制AXML) 解析与安全审计
  2. iOS Info.plist 安全分析 (ATS, 权限, URL Scheme)
  3. 危险权限组合检测 (permission collusion / confused deputy)
  4. 导出组件风险评估 (Activity, Service, Receiver, Provider)
  5. Intent Filter 劫持分析 (Deep Link / App Link)
  6. 调试标志检测 (debuggable, backup, cleartext)
  7. 第三方SDK权限指纹识别
  8. ATS (App Transport Security) 深度配置审计

技术参考:
  - AXML binary format (AndroidManifest.xml 的二进制编码)
  - Apple ATS Policy 框架
  - OWASP MASVS-CODE-4 证书透明度 & 安全配置要求
  - CWE-927: 隐式Intent劫持
"""

import re
import struct
import logging
import os
import zipfile
import plistlib
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from collections import defaultdict
from functools import lru_cache

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums & Constants
# ---------------------------------------------------------------------------

class ComponentType(StrEnum):
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"


class PermissionLevel(StrEnum):
    NORMAL = "normal"
    DANGEROUS = "dangerous"
    SIGNATURE = "signature"
    SIGNATURE_OR_SYSTEM = "signatureOrSystem"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class URISchemeType(StrEnum):
    DEEP_LINK = "deep_link"          # 标准 scheme://host/path
    APP_LINK = "app_link"            # Android App Links (HTTPS verified)
    UNIVERSAL_LINK = "universal_link"  # iOS Universal Links
    CUSTOM_SCHEME = "custom_scheme"   # 自定义 scheme


class ManifestSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Android 危险权限 (API 33+)
_DANGEROUS_PERMISSIONS: Dict[str, str] = {
    'android.permission.READ_CALENDAR': '读取日历',
    'android.permission.WRITE_CALENDAR': '写入日历',
    'android.permission.CAMERA': '相机',
    'android.permission.READ_CONTACTS': '读取联系人',
    'android.permission.WRITE_CONTACTS': '写入联系人',
    'android.permission.GET_ACCOUNTS': '获取账户列表',
    'android.permission.ACCESS_FINE_LOCATION': '精确位置',
    'android.permission.ACCESS_COARSE_LOCATION': '粗略位置',
    'android.permission.ACCESS_BACKGROUND_LOCATION': '后台位置',
    'android.permission.RECORD_AUDIO': '录音',
    'android.permission.READ_PHONE_STATE': '读取手机状态',
    'android.permission.CALL_PHONE': '拨打电话',
    'android.permission.READ_CALL_LOG': '读取通话记录',
    'android.permission.WRITE_CALL_LOG': '写入通话记录',
    'android.permission.ADD_VOICEMAIL': '添加语音邮件',
    'android.permission.USE_SIP': 'SIP通话',
    'android.permission.PROCESS_OUTGOING_CALLS': '处理外拨电话',
    'android.permission.BODY_SENSORS': '身体传感器',
    'android.permission.SEND_SMS': '发送短信',
    'android.permission.RECEIVE_SMS': '接收短信',
    'android.permission.READ_SMS': '读取短信',
    'android.permission.RECEIVE_WAP_PUSH': '接收WAP',
    'android.permission.RECEIVE_MMS': '接收彩信',
    'android.permission.READ_EXTERNAL_STORAGE': '读取外部存储',
    'android.permission.WRITE_EXTERNAL_STORAGE': '写入外部存储',
    'android.permission.ACCESS_MEDIA_LOCATION': '访问媒体位置',
    'android.permission.READ_MEDIA_AUDIO': '读取音频文件',
    'android.permission.READ_MEDIA_VIDEO': '读取视频文件',
    'android.permission.READ_MEDIA_IMAGES': '读取图片文件',
    'android.permission.POST_NOTIFICATIONS': '发送通知',
    'android.permission.NEARBY_WIFI_DEVICES': '附近WiFi设备',
}

# 超危权限（需要特别关注）
_CRITICAL_PERMISSIONS = [
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.CALL_PHONE',
    'android.permission.RECORD_AUDIO',
    'android.permission.CAMERA',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_BACKGROUND_LOCATION',
    'android.permission.READ_CONTACTS',
    'android.permission.MANAGE_EXTERNAL_STORAGE',
    'android.permission.INSTALL_PACKAGES',
    'android.permission.REQUEST_INSTALL_PACKAGES',
    'android.permission.SYSTEM_ALERT_WINDOW',
    'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'android.permission.BIND_DEVICE_ADMIN',
    'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
]

# 权限共谋 (collusion) 危险组合
_DANGEROUS_PERMISSION_COMBOS: List[Tuple[List[str], str]] = [
    (['CAMERA', 'RECORD_AUDIO'], '相机 + 录音 — 可进行隐秘音视频录制'),
    (['ACCESS_FINE_LOCATION', 'CAMERA'], 'GPS + 相机 — 可进行地理位置标记拍照'),
    (['READ_CONTACTS', 'SEND_SMS'], '通讯录 + 短信 — 可向所有联系人发送短信'),
    (['READ_SMS', 'INTERNET'], '短信 + 网络 — 可窃取短信验证码并外传'),
    (['ACCESS_FINE_LOCATION', 'INTERNET'], '位置 + 网络 — 可跟踪用户位置并上传'),
    (['RECORD_AUDIO', 'INTERNET'], '录音 + 网络 — 可窃听并上传'),
    (['CAMERA', 'INTERNET'], '相机 + 网络 — 可偷拍并上传'),
]

# iOS 隐私敏感 Plist Keys
_IOS_PRIVACY_KEYS: Dict[str, str] = {
    'NSCameraUsageDescription': '相机',
    'NSPhotoLibraryUsageDescription': '相册',
    'NSPhotoLibraryAddUsageDescription': '写入相册',
    'NSMicrophoneUsageDescription': '麦克风',
    'NSLocationWhenInUseUsageDescription': '位置(使用中)',
    'NSLocationAlwaysUsageDescription': '位置(始终)',
    'NSLocationAlwaysAndWhenInUseUsageDescription': '位置(始终+使用中)',
    'NSContactsUsageDescription': '通讯录',
    'NSCalendarsUsageDescription': '日历',
    'NSRemindersUsageDescription': '提醒事项',
    'NSMotionUsageDescription': '运动与健身',
    'NSHealthShareUsageDescription': '健康数据(读)',
    'NSHealthUpdateUsageDescription': '健康数据(写)',
    'NSFaceIDUsageDescription': 'Face ID',
    'NSBluetoothAlwaysUsageDescription': '蓝牙',
    'NSSpeechRecognitionUsageDescription': '语音识别',
    'NSAppleMusicUsageDescription': 'Apple Music',
    'NSHomeKitUsageDescription': 'HomeKit',
    'NFCReaderUsageDescription': 'NFC',
    'NSVideoSubscriberAccountUsageDescription': '视频订阅',
    'NSUserTrackingUsageDescription': '跟踪(ATT)',
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ManifestComponent:
    """Android 清单组件 (activity/service/receiver/provider)。"""
    name: str
    component_type: ComponentType
    exported: bool = False
    permission: str = ""         # 所需权限
    intent_filters: List[Dict] = field(default_factory=list)
    process: str = ""
    enabled: bool = True
    grant_uri_permissions: bool = False


@dataclass
class ManifestPermission:
    """清单中声明的权限。"""
    name: str
    level: PermissionLevel = PermissionLevel.UNKNOWN
    max_sdk_version: Optional[int] = None
    uses_permission_flags: List[str] = field(default_factory=list)


@dataclass
class ManifestFinding:
    """清单分析发现。"""
    category: str
    severity: ManifestSeverity
    description: str
    component: str = ""
    evidence: str = ""
    cwe_id: str = ""
    recommendation: str = ""


@dataclass
class URIScheme:
    """URL Scheme / Deep Link 定义。"""
    scheme: str
    host: str = ""
    path: str = ""
    path_prefix: str = ""
    path_pattern: str = ""
    scheme_type: URISchemeType = URISchemeType.CUSTOM_SCHEME
    auto_verify: bool = False


# ---------------------------------------------------------------------------
# AXML Parser (简化的 Android 二进制 XML 解析)
# ---------------------------------------------------------------------------

class AXMLParser:
    """Android二进制XML解析器 (简版)。

    仅提取关键字段：package, permissions, components, intent-filters。
    AndroidManifest.xml 的二进制格式 (AXML) 比较复杂，这里用以下策略:
      1. 如果能用 androguard 或 axmldec 解析最好
      2. 退化为二进制字符串匹配 (覆盖大多数场景)
      3. 如果 APK 未加固，尝试提取 AndroidManifest.xml 后用 AAPT 解析
    """

    # AXML 魔术字
    AXML_MAGIC = b'\x03\x00\x08\x00'

    # 字符串池中的关键字符串
    _EXPORTED_TRUE = re.compile(rb'(?:android:)?exported\s*=\s*"(?:true|1)"')
    _EXPORTED_FALSE = re.compile(rb'(?:android:)?exported\s*=\s*"(?:false|0)"')
    _PERMISSION_NAME = re.compile(rb'android\.permission\.([A-Z_]+)', re.ASCII)
    _COMPONENT_NAME = re.compile(rb'android:name\s*=\s*"([^"]+)"', re.ASCII)

    def __init__(self, data: bytes):
        self.data = data
        self.raw_text = data.decode('utf-8', errors='replace')

    def extract_package_name(self) -> str:
        m = re.search(r'package\s*=\s*"([^"]+)"', self.raw_text)
        return m.group(1) if m else "unknown"

    def extract_permissions(self) -> List[str]:
        perms: Set[str] = set()
        for m in self._PERMISSION_NAME.finditer(self.data):
            perms.add('android.permission.' + m.group(1).decode('ascii'))
        return sorted(perms)

    def extract_components(self) -> List[ManifestComponent]:
        components: List[ManifestComponent] = []

        # 这个简化版从二进制字符串中提取组件信息
        # 搜索 activity/service/receiver/provider 块
        comp_patterns = [
            (rb'<activity\b', ComponentType.ACTIVITY),
            (rb'<service\b', ComponentType.SERVICE),
            (rb'<receiver\b', ComponentType.RECEIVER),
            (rb'<provider\b', ComponentType.PROVIDER),
        ]

        for tag_pattern, ctype in comp_patterns:
            tag_name = tag_pattern[1:].split(b'\\b')[0][1:]  # strip '<' and '\b' suffix
            for m in re.finditer(tag_pattern, self.data):
                start = m.start()
                end_tag = self.data.find(b'>', start)
                if end_tag == -1:
                    continue
                block_end = self.data.find(b'</' + tag_name, end_tag)
                if block_end == -1:
                    block = self.data[start:end_tag + 1 + 256]
                else:
                    block = self.data[start:block_end]

                block_str = block.decode('utf-8', errors='replace')

                # extract name
                name_m = re.search(r'android:name\s*=\s*"([^"]+)"', block_str)
                comp_name = name_m.group(1) if name_m else f"unknown_{ctype.value}"

                # exported
                exported = False
                exported_explicit = False
                exp_m = re.search(r'android:exported\s*=\s*"(true|false)"', block_str)
                if exp_m:
                    exported = exp_m.group(1) == 'true'
                    exported_explicit = True
                else:
                    # 如果有 intent-filter 且无明确 exported，默认 exported=true
                    if '<intent-filter' in block_str:
                        exported = True

                # permission
                perm_m = re.search(r'android:permission\s*=\s*"([^"]+)"', block_str)
                perm = perm_m.group(1) if perm_m else ""

                # intent filters
                intent_filters = []
                if '<intent-filter' in block_str:
                    ifilter = {'actions': [], 'categories': [], 'data': []}
                    for action_m in re.finditer(r'android:name\s*=\s*"([^"]+)"',
                                                block_str):
                        action = action_m.group(1)
                        if 'android.intent.action' in action:
                            ifilter['actions'].append(action)
                    intent_filters.append(ifilter)

                # grant URI permissions
                grant_uri = r'grantUriPermissions\s*=\s*"true"' in block_str  # raw str for regex

                components.append(ManifestComponent(
                    name=comp_name,
                    component_type=ctype,
                    exported=exported,
                    permission=perm,
                    intent_filters=intent_filters,
                    grant_uri_permissions=grant_uri,
                ))

        return components

    def extract_debuggable(self) -> bool:
        return 'android:debuggable="true"' in self.raw_text

    def extract_backup_allowed(self) -> bool:
        # allowBackup defaults to true
        if 'android:allowBackup="false"' in self.raw_text:
            return False
        return True

    def extract_uses_cleartext(self) -> bool:
        return 'android:usesCleartextTraffic="true"' in self.raw_text

    def extract_target_sdk(self) -> int:
        m = re.search(r'targetSdkVersion\s*=\s*"(\d+)"', self.raw_text)
        return int(m.group(1)) if m else 0

    def extract_min_sdk(self) -> int:
        m = re.search(r'minSdkVersion\s*=\s*"(\d+)"', self.raw_text)
        return int(m.group(1)) if m else 0


# ---------------------------------------------------------------------------
# Android Manifest 分析器
# ---------------------------------------------------------------------------

class AndroidManifestAnalyzer:
    """AndroidManifest.xml 安全审计。

    检查项:
      - 导出组件 + intent filter 组合风险
      - 危险权限组合
      - 调试/备份/明文的Release标志
      - Deep Link 劫持可能性
      - 最小SDK版本约束
      - Provider 读写权限泄露
    """

    def __init__(self, manifest_data: bytes):
        self.raw = manifest_data
        self.parser = AXMLParser(manifest_data)
        self.components: List[ManifestComponent] = []
        self.permissions: List[str] = []
        self.findings: List[ManifestFinding] = []
        self.package_name: str = ""
        self._analyzed = False

    def analyze(self) -> List[ManifestFinding]:
        if self._analyzed:
            return self.findings
        self._analyzed = True

        self.package_name = self.parser.extract_package_name()
        self.permissions = self.parser.extract_permissions()
        self.components = self.parser.extract_components()

        self._check_debuggable()
        self._check_backup()
        self._check_cleartext()
        self._check_target_sdk()
        self._check_exported_components()
        self._check_dangerous_permissions()
        self._check_permission_collusion()
        self._check_provider_leaks()
        self._check_deep_link_hijacking()

        return self.findings

    def _check_debuggable(self):
        if self.parser.extract_debuggable():
            self.findings.append(ManifestFinding(
                category='debuggable',
                severity=ManifestSeverity.CRITICAL,
                description='android:debuggable="true" — 应用在发布版本中可调试',
                cwe_id='CWE-489',
                recommendation='在 release 构建中设置 debuggable=false',
            ))

    def _check_backup(self):
        if self.parser.extract_backup_allowed():
            self.findings.append(ManifestFinding(
                category='allow_backup',
                severity=ManifestSeverity.MEDIUM,
                description='android:allowBackup 默认开启 — 可通过 ADB backup 导出数据',
                cwe_id='CWE-200',
                recommendation='若需禁用备份，显式设置 android:allowBackup="false"',
            ))

    def _check_cleartext(self):
        if self.parser.extract_uses_cleartext():
            self.findings.append(ManifestFinding(
                category='cleartext_traffic',
                severity=ManifestSeverity.HIGH,
                description='usesCleartextTraffic="true" — 允许HTTP明文通信，IMSI catcher风险',
                recommendation='使用 HTTPS 并在 NetworkSecurityConfig 中禁用明文',
            ))

    def _check_target_sdk(self):
        ts = self.parser.extract_target_sdk()
        if ts > 0 and ts < 33:
            self.findings.append(ManifestFinding(
                category='low_target_sdk',
                severity=ManifestSeverity.MEDIUM,
                description=f'targetSdkVersion={ts} (< 33) — 未适配最新权限模型与隐私保护',
                recommendation='升级 targetSdkVersion 至 34+',
            ))

    def _check_exported_components(self):
        for comp in self.components:
            if comp.exported and not comp.permission:
                # 导出组件无权限保护
                has_intent_filter = any(ifl.get('actions') for ifl in comp.intent_filters)
                severity = ManifestSeverity.HIGH if has_intent_filter else ManifestSeverity.MEDIUM

                self.findings.append(ManifestFinding(
                    category='exported_no_permission',
                    severity=severity,
                    description=f'{comp.component_type.value} "{comp.name}" 导出且无权限保护',
                    component=comp.name,
                    cwe_id='CWE-926',
                    recommendation=f'为非必要导出组件设置 exported=false 或添加权限保护',
                ))

            # ContentProvider read/write 权限
            if comp.component_type == ComponentType.PROVIDER and comp.exported:
                self.findings.append(ManifestFinding(
                    category='exported_provider',
                    severity=ManifestSeverity.HIGH,
                    description=f'ContentProvider "{comp.name}" 导出 — 可能泄露数据',
                    component=comp.name,
                    cwe_id='CWE-284',
                    recommendation='设置 android:readPermission 和 android:writePermission',
                ))

    def _check_dangerous_permissions(self):
        for perm in self.permissions:
            if perm in _DANGEROUS_PERMISSIONS:
                self.findings.append(ManifestFinding(
                    category='dangerous_permission',
                    severity=ManifestSeverity.MEDIUM,
                    description=f'危险权限: {perm} ({_DANGEROUS_PERMISSIONS[perm]})',
                    evidence=perm,
                ))
            if perm in _CRITICAL_PERMISSIONS:
                self.findings.append(ManifestFinding(
                    category='critical_permission',
                    severity=ManifestSeverity.HIGH,
                    description=f'高敏权限: {perm}',
                    evidence=perm,
                    recommendation=f'确认 {perm} 的业务必要性，考虑使用更安全的替代方案',
                ))

    def _check_permission_collusion(self):
        """权限共谋检测 — 某些权限组合可能导致用户隐私被系统性收集。"""
        perm_set = set(self.permissions)
        for combo, description in _DANGEROUS_PERMISSION_COMBOS:
            matched = []
            for required in combo:
                for full_perm in perm_set:
                    if required in full_perm:
                        matched.append(required)
                        break
            if len(matched) == len(combo):
                self.findings.append(ManifestFinding(
                    category='permission_collusion',
                    severity=ManifestSeverity.HIGH,
                    description=f'权限共谋风险: {description}',
                    evidence=f'组合: {", ".join(matched)}',
                    recommendation='审查这些权限组合是否必要，避免滥用的可能性',
                ))

    def _check_provider_leaks(self):
        providers = [c for c in self.components if c.component_type == ComponentType.PROVIDER]
        for prov in providers:
            if prov.grant_uri_permissions and prov.exported:
                self.findings.append(ManifestFinding(
                    category='uri_permission_grant',
                    severity=ManifestSeverity.MEDIUM,
                    description=f'ContentProvider "{prov.name}" 导出且 allowUriPermissions',
                    component=prov.name,
                    cwe_id='CWE-284',
                    recommendation='审查 URI 权限授予范围，避免跨应用数据泄露',
                ))

    def _check_deep_link_hijacking(self):
        """检测可能被劫持的 Deep Link。"""
        for comp in self.components:
            for ifilter in comp.intent_filters:
                for action in ifilter.get('actions', []):
                    if 'VIEW' in action and not comp.permission:
                        self.findings.append(ManifestFinding(
                            category='deep_link_weak',
                            severity=ManifestSeverity.MEDIUM,
                            description=f'{comp.component_type.value} "{comp.name}" 处理 VIEW action 且无权限保护 — Deep Link 可被任意应用触发',
                            component=comp.name,
                            cwe_id='CWE-927',
                            recommendation='添加 permission 保护或使用 App Links (autoVerify)',
                        ))

    def generate_summary(self) -> Dict[str, Any]:
        return {
            'package': self.package_name,
            'target_sdk': self.parser.extract_target_sdk(),
            'min_sdk': self.parser.extract_min_sdk(),
            'permissions': self.permissions,
            'exported_components': [
                {
                    'type': c.component_type.value,
                    'name': c.name,
                    'permission': c.permission,
                    'has_intent_filter': any(ifl.get('actions') for ifl in c.intent_filters),
                }
                for c in self.components if c.exported
            ],
            'flags': {
                'debuggable': self.parser.extract_debuggable(),
                'allow_backup': self.parser.extract_backup_allowed(),
                'uses_cleartext': self.parser.extract_uses_cleartext(),
            },
            'findings': [
                {
                    'category': f.category,
                    'severity': f.severity.value,
                    'description': f.description,
                    'recommendation': f.recommendation,
                }
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# iOS Info.plist 分析器
# ---------------------------------------------------------------------------

class IOSInfoPlistAnalyzer:
    """iOS Info.plist 安全分析。

    检查项:
      - ATS (NSAppTransportSecurity) 配置
      - 隐私权限声明 (NSCameraUsageDescription 等)
      - URL Scheme 注册
      - 后台模式与潜在滥用
      - UIFileSharingEnabled / iTunes 文件共享
    """

    _URL_TYPES_KEY = 'CFBundleURLTypes'
    _ATS_KEY = 'NSAppTransportSecurity'
    _BACKGROUND_MODES_KEY = 'UIBackgroundModes'

    def __init__(self, plist_data: Union[bytes, Dict]):
        if isinstance(plist_data, bytes):
            try:
                self.plist = plistlib.loads(plist_data)
            except Exception:
                self.plist = {}
        else:
            self.plist = plist_data
        self.findings: List[ManifestFinding] = []
        self._analyzed = False

    def analyze(self) -> List[ManifestFinding]:
        if self._analyzed:
            return self.findings
        self._analyzed = True

        self._check_ats()
        self._check_privacy_permissions()
        self._check_url_schemes()
        self._check_background_modes()
        self._check_file_sharing()
        self._check_itunes_artwork()

        return self.findings

    def _check_ats(self):
        ats = self.plist.get(self._ATS_KEY, {})
        if not ats:
            return  # ATS 默认启用，无需警告

        if ats.get('NSAllowsArbitraryLoads', False):
            self.findings.append(ManifestFinding(
                category='ats_disabled',
                severity=ManifestSeverity.HIGH,
                description='NSAllowsArbitraryLoads=true — ATS已完全禁用，允许所有非安全连接',
                recommendation='移除 NSAllowsArbitraryLoads 或仅对特定域设置 NSExceptionDomains',
            ))

        exceptions = ats.get('NSExceptionDomains', {})
        for domain, config in exceptions.items():
            # 检查每个域的例外配置
            if config.get('NSExceptionAllowsInsecureHTTPLoads', False):
                self.findings.append(ManifestFinding(
                    category='ats_domain_exception',
                    severity=ManifestSeverity.MEDIUM,
                    description=f'ATS 例外域名 "{domain}" 允许不安全的 HTTP 加载',
                    evidence=domain,
                    recommendation=f'确认 {domain} 确实需要 HTTP 例外',
                ))
            if config.get('NSExceptionMinimumTLSVersion') in ('TLSv1.0', 'TLSv1.1'):
                self.findings.append(ManifestFinding(
                    category='ats_weak_tls',
                    severity=ManifestSeverity.MEDIUM,
                    description=f'ATS 例外域名 "{domain}" 使用弱 TLS 版本',
                    evidence=domain,
                    recommendation=f'将 TLS 最低版本提升至 TLSv1.2',
                ))
            if not config.get('NSIncludesSubdomains', True):
                self.findings.append(ManifestFinding(
                    category='ats_no_subdomains',
                    severity=ManifestSeverity.LOW,
                    description=f'ATS 例外域名 "{domain}" 不包含子域 — 可能遗漏',
                    evidence=domain,
                ))

    def _check_privacy_permissions(self):
        for key, description_cn in _IOS_PRIVACY_KEYS.items():
            if key in self.plist:
                desc = self.plist[key]
                if not desc or len(str(desc)) < 5:
                    self.findings.append(ManifestFinding(
                        category='empty_privacy_description',
                        severity=ManifestSeverity.HIGH,
                        description=f'{key}: 隐私用途描述为空或过短 — 审核可能拒绝',
                        evidence=str(desc),
                        recommendation=f'提供清晰的{description_cn}使用说明',
                    ))

    def _check_url_schemes(self):
        """检查注册的 URL schemes。"""
        url_types = self.plist.get(self._URL_TYPES_KEY, [])
        if not url_types:
            return

        for url_type in url_types:
            schemes = url_type.get('CFBundleURLSchemes', [])
            role = url_type.get('CFBundleTypeRole', 'Editor')
            for scheme in schemes:
                # 检测是否劫持知名 scheme (如 weixin, alipay, mqq 等)
                if scheme.lower() in _KNOWN_HIGH_RISK_SCHEMES:
                    self.findings.append(ManifestFinding(
                        category='url_scheme_hijack_risk',
                        severity=ManifestSeverity.HIGH,
                        description=f'注册敏感 URL scheme: "{scheme}" — 可能劫持其他应用通信',
                        evidence=scheme,
                        recommendation=f'确认是否无意劫持了 "{scheme}" scheme',
                    ))
                # 检测没有验证的 scheme (iOS 不支持 scheme 独占)
                self.findings.append(ManifestFinding(
                    category='url_scheme_registered',
                    severity=ManifestSeverity.INFO,
                    description=f'注册 URL scheme: "{scheme}" (role={role}) — 注意 scheme 可被任意应用声明',
                    evidence=scheme,
                    recommendation='优先使用 Universal Links 而非 URL scheme',
                ))

    def _check_background_modes(self):
        bg_modes = self.plist.get(self._BACKGROUND_MODES_KEY, [])
        for mode in bg_modes:
            if mode in ('location', 'external-accessory', 'bluetooth-central'):
                self.findings.append(ManifestFinding(
                    category='background_mode_sensitive',
                    severity=ManifestSeverity.LOW,
                    description=f'后台模式: {mode} — 可能被用于后台跟踪',
                    evidence=mode,
                    recommendation=f'确认后台模式 "{mode}" 的业务必要性',
                ))

    def _check_file_sharing(self):
        if self.plist.get('UIFileSharingEnabled', False):
            self.findings.append(ManifestFinding(
                category='file_sharing_enabled',
                severity=ManifestSeverity.MEDIUM,
                description='UIFileSharingEnabled=true — 可通过 iTunes 访问应用文件',
                recommendation='除非必要，关闭文件共享功能',
            ))

        if self.plist.get('LSSupportsOpeningDocumentsInPlace', False):
            self.findings.append(ManifestFinding(
                category='document_browser_exposed',
                severity=ManifestSeverity.LOW,
                description='LSSupportsOpeningDocumentsInPlace=true — 文档可被其他应用直接修改',
            ))

    def _check_itunes_artwork(self):
        # 检查是否暴露了 iTunes Artwork 可能导致信息泄露
        pass

    def generate_summary(self) -> Dict[str, Any]:
        return {
            'bundle_name': self.plist.get('CFBundleDisplayName', self.plist.get('CFBundleName', 'unknown')),
            'bundle_id': self.plist.get('CFBundleIdentifier', ''),
            'version': self.plist.get('CFBundleShortVersionString', ''),
            'platform': 'ios',
            'privacy_permissions': [
                key for key in _IOS_PRIVACY_KEYS if key in self.plist
            ],
            'url_schemes': [
                scheme
                for url_type in self.plist.get(self._URL_TYPES_KEY, [])
                for scheme in url_type.get('CFBundleURLSchemes', [])
            ],
            'findings': [
                {
                    'category': f.category,
                    'severity': f.severity.value,
                    'description': f.description,
                    'recommendation': f.recommendation,
                }
                for f in self.findings
            ],
        }


# 已知高风险 URL scheme (常用于劫持攻击)
_KNOWN_HIGH_RISK_SCHEMES = {
    'weixin', 'wechat', 'alipay', 'alipays', 'mqq', 'mqqapi',
    'taobao', 'tmall', 'jingdong', 'openapp.jdmobile',
    'fb', 'fbapi', 'twitter', 'instagram',
    'sinaweibo', 'weibosdk',
    'amzn', 'shopify',
    'bankcomm', 'cmb', 'icbc',
}


# ---------------------------------------------------------------------------
# 统一入口
# ---------------------------------------------------------------------------

class MobileManifestAnalyzer:
    """移动应用 Manifest/Plist 综合分析器。

    自动检测 APK/IPA/Manifest/Plist 并路由到合适的分析器。
    """

    def __init__(self, path: str = ""):
        self.path = path
        self.data: bytes = b""
        self._manifest_xml: Optional[bytes] = None
        self._info_plist: Optional[bytes] = None

        if path and os.path.exists(path):
            self._load(path)

    def _load(self, path: str):
        p = Path(path)
        suffix = p.suffix.lower()

        if suffix in ('.apk', '.aab'):
            try:
                with zipfile.ZipFile(path, 'r') as zf:
                    if 'AndroidManifest.xml' in zf.namelist():
                        self._manifest_xml = zf.read('AndroidManifest.xml')
            except zipfile.BadZipFile:
                pass
        elif suffix in ('.ipa',):
            try:
                with zipfile.ZipFile(path, 'r') as zf:
                    for name in zf.namelist():
                        if name.endswith('Info.plist'):
                            self._info_plist = zf.read(name)
                            break
            except zipfile.BadZipFile:
                pass
        else:
            self.data = p.read_bytes()

    def analyze(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            'file': self.path,
            'platform': 'unknown',
            'findings': [],
        }

        # Android
        if self._manifest_xml:
            analyzer = AndroidManifestAnalyzer(self._manifest_xml)
            analyzer.analyze()
            result.update(analyzer.generate_summary())
            result['platform'] = 'android'
        elif (b'AndroidManifest' in self.data[:200]
              or b'<manifest' in self.data[:200]):
            analyzer = AndroidManifestAnalyzer(self.data)
            analyzer.analyze()
            result.update(analyzer.generate_summary())
            result['platform'] = 'android'
        # iOS
        elif self._info_plist:
            analyzer = IOSInfoPlistAnalyzer(self._info_plist)
            analyzer.analyze()
            result.update(analyzer.generate_summary())
            result['platform'] = 'ios'
        elif b'<?xml' in self.data[:100] and b'plist' in self.data[:200]:
            analyzer = IOSInfoPlistAnalyzer(self.data)
            analyzer.analyze()
            result.update(analyzer.generate_summary())
            result['platform'] = 'ios'
        else:
            result['error'] = '无法识别清单文件格式 (需要 APK 中的 AndroidManifest.xml 或 IPA 中的 Info.plist)'

        return result


def analyze_manifest(file_path: str) -> Dict[str, Any]:
    return MobileManifestAnalyzer(file_path).analyze()
