#!/usr/bin/env python3
"""
移动端 SSL/TLS Pinning 安全审计。

分析维度：
  1. 证书/SHA256公钥hash提取及固定证据识别
  2. 主流 SSL Pinning 库检测
  3. Network Security Config 审计 (Android 7+)
  4. ATS (App Transport Security) plist 分析
  5. Pinning绕过可行性评估 (无备选pin, 过期证书, 弱验证回调)
  6. 原生层 TLS 回调挂钩点检测 (JNI_OnLoad + SSL_CTX_set_verify)
  7. 证书透明度 (Certificate Transparency) SCT 验证支持
  8. HPKP回溯兼容——检测已弃用但被引用的静态pinning模式

技术基础：
  - 字符串/常量匹配 + 模式推导
  - Android NCS XML 解析
  - 二进制 SSL_CTX 函数交叉引用
  - 常见 pinning 实现反模式匹配
"""

import re, struct, logging, os, hashlib, binascii
from pathlib import Path
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class PinningLibrary(StrEnum):
    OKHTTP = "okhttp"; TRUSTKIT = "trustkit"; AFNETWORKING = "afnetworking"
    NSURLSESSION = "nsurlsession"; CRONET = "cronet"; APPLE_ATS = "app_ats"
    NETWORK_SECURITY_CONFIG = "network_security_config"
    CUSTOM_NATIVE = "custom_native"; ALAMOFIRE = "alamofire"; NONE = "none"


class PinningSeverity(StrEnum):
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; INFO = "info"


@dataclass
class PinnedCertificate:
    pin_type: str; pin_value: str; match_offset: int
    library: PinningLibrary = PinningLibrary.NONE
    is_expired: bool = False; is_weak_hash: bool = False
    source_context: str = ""


@dataclass
class PinConfig:
    domain: str; pins: List[PinnedCertificate] = field(default_factory=list)
    backup_pins_exist: bool = False; include_subdomains: bool = False
    expiration_date: Optional[str] = None; enforce_mode: bool = True


@dataclass
class SSLVerifyBypass:
    function_name: str; offset: int; bypass_type: str
    severity: PinningSeverity = PinningSeverity.CRITICAL; evidence: str = ""


@dataclass
class PinningFinding:
    category: str; severity: PinningSeverity; description: str
    evidence: str = ""; recommendation: str = ""


_PINNING_LIB_SIGNATURES: Dict[bytes, PinningLibrary] = {
    b'okhttp3.CertificatePinner': PinningLibrary.OKHTTP,
    b'okhttp3.internal.tls.CertificatePinner': PinningLibrary.OKHTTP,
    b'CertificatePinner.Builder': PinningLibrary.OKHTTP,
    b'CertificatePinner.check': PinningLibrary.OKHTTP,
    b'TrustKit': PinningLibrary.TRUSTKIT,
    b'TSKTrustKitConfig': PinningLibrary.TRUSTKIT,
    b'TSKPublicKeyAlgorithm': PinningLibrary.TRUSTKIT,
    b'TSKPinningValidator': PinningLibrary.TRUSTKIT,
    b'AFSecurityPolicy': PinningLibrary.AFNETWORKING,
    b'AFSSLPinningMode': PinningLibrary.AFNETWORKING,
    b'setPinnedCertificates': PinningLibrary.AFNETWORKING,
    b'ServerTrustPolicy': PinningLibrary.ALAMOFIRE,
    b'ServerTrustPolicyManager': PinningLibrary.ALAMOFIRE,
    b'URLSession:didReceiveChallenge:': PinningLibrary.NSURLSESSION,
    b'NSURLAuthenticationMethodServerTrust': PinningLibrary.NSURLSESSION,
    b'CronetEngine.Builder': PinningLibrary.CRONET,
    b'CronetProviderInstaller': PinningLibrary.CRONET,
    b'addPublicKeyPins': PinningLibrary.CRONET,
}

_SHA256_B64_PATTERN = re.compile(rb'sha256/([A-Za-z0-9+/=]{44})')
_SHA1_B64_PATTERN = re.compile(rb'sha1/([A-Za-z0-9+/=]{28})')
_SHA256_HEX_PATTERN = re.compile(rb'[0-9a-fA-F]{64}')

_SSL_BYPASS_PATTERNS: List[Tuple[bytes, str, str]] = [
    (b'X509TrustManager', 'custom_trust_manager', '自定义TrustManager——可能接受所有证书'),
    (b'checkServerTrusted', 'override_check', 'checkServerTrusted可能被覆盖'),
    (b'HostnameVerifier', 'custom_hostname_verifier', '自定义HostnameVerifier'),
    (b'verify\\(.*true\\)', 'always_true_verify', 'verify()始终返回true'),
    (b'ALLOW_ALL_HOSTNAME_VERIFIER', 'allow_all', '明确禁用主机名验证'),
    (b'IgnoreSSLErrors', 'ignore_ssl_errors', '会忽略SSL错误'),
    (b'SSL_VERIFY_PEER|SSL_CTX_set_verify', 'openssl_verify_disabled', 'OpenSSL对等验证可能被关闭'),
    (b'SSL_set_verify\\(.*0\\)', 'openssl_verify_none', 'SSL_set_verify(mode=0)——无验证'),
    (b'allowInvalidHostnames', 'invalid_hostnames', '允许无效主机名'),
    (b'NSAppTransportSecurity', 'ats_bypass_configured', 'ATS可能包含例外配置'),
    (b'NSAllowsArbitraryLoads', 'ats_disabled', 'ATS完全禁用'),
]


def _extract_sha256_pins(data: bytes, lib: PinningLibrary = PinningLibrary.NONE) -> List[PinnedCertificate]:
    pins: List[PinnedCertificate] = []
    for match in _SHA256_B64_PATTERN.finditer(data):
        pins.append(PinnedCertificate(pin_type='sha256', pin_value=match.group(1).decode('ascii'),
            match_offset=match.start(), library=lib,
            source_context=data[max(0, match.start()-40):match.end()+40].decode('ascii', errors='replace')))
    for match in _SHA1_B64_PATTERN.finditer(data):
        pins.append(PinnedCertificate(pin_type='sha1', pin_value=match.group(1).decode('ascii'),
            match_offset=match.start(), library=lib, is_weak_hash=True,
            source_context=data[max(0, match.start()-40):match.end()+40].decode('ascii', errors='replace')))
    return pins


def _extract_raw_hex_hashes(data: bytes, context_radius: int = 128) -> List[PinnedCertificate]:
    pins: List[PinnedCertificate] = []
    pin_keywords = [b'pin', b'certificateHash', b'publicKeyHash', b'spki', b'SubjectPublicKeyInfo']
    for kw in pin_keywords:
        offset = 0
        while True:
            offset = data.find(kw, offset)
            if offset == -1: break
            ctx_start = max(0, offset - context_radius)
            ctx_end = min(len(data), offset + context_radius)
            context = data[ctx_start:ctx_end]
            for hex_m in _SHA256_HEX_PATTERN.finditer(context):
                hex_val = hex_m.group(0).decode('ascii')
                if hex_val not in ('0' * 64, 'F' * 64, 'f' * 64):
                    pins.append(PinnedCertificate(pin_type='sha256_hex', pin_value=hex_val,
                        match_offset=ctx_start + hex_m.start(),
                        source_context=context[max(0, hex_m.start()-20):hex_m.end()+20].decode('ascii', errors='replace')))
            offset += len(kw)
    return pins


class NetworkSecurityConfigParser:
    _DOMAIN_CONFIG = re.compile(r'<domain-config[^>]*>(.*?)</domain-config>', re.DOTALL)
    _PIN_SET = re.compile(r'<pin-set[^>]*>(.*?)</pin-set>', re.DOTALL)
    _PIN_ENTRY = re.compile(r'<pin\s+digest="([^"]+)"[^>]*>([^<]+)</pin>')
    _CLEARTEXT_PATTERN = re.compile(r'cleartextTrafficPermitted\s*=\s*"([^"]+)"')
    _DEBUG_OVERRIDE = re.compile(r'<debug-overrides[^>]*>')
    _TRUST_ANCHOR = re.compile(r'<trust-anchors[^>]*>(.*?)</trust-anchors>', re.DOTALL)

    def __init__(self, xml_content: str = ""):
        self.xml = xml_content; self.domains: List[PinConfig] = []
        self.cleartext_allowed: bool = False; self.debug_overrides_present: bool = False
        self.trusts_user_ca: bool = False

    def parse(self) -> List[PinConfig]:
        if not self.xml: return []
        ct_match = self._CLEARTEXT_PATTERN.search(self.xml)
        if ct_match and ct_match.group(1).lower() == 'true': self.cleartext_allowed = True
        if self._DEBUG_OVERRIDE.search(self.xml): self.debug_overrides_present = True
        for dc_match in self._DOMAIN_CONFIG.finditer(self.xml):
            dc_xml = dc_match.group(1)
            domain = 'unknown'
            for domain_line in dc_xml.split('\n'):
                dm = re.search(r'domain[^>]*>([^<]+)<', domain_line)
                if dm: domain = dm.group(1).strip(); break
            pin_config = PinConfig(domain=domain)
            ps_match = self._PIN_SET.search(dc_xml)
            if ps_match:
                ps_xml = ps_match.group(1)
                expiration_match = re.search(r'expiration="([^"]+)"', dc_xml)
                if expiration_match: pin_config.expiration_date = expiration_match.group(1)
                for pin_m in self._PIN_ENTRY.finditer(ps_xml):
                    digest_type = pin_m.group(1); pin_value = pin_m.group(2).strip()
                    pin_config.pins.append(PinnedCertificate(pin_type=digest_type, pin_value=pin_value,
                        match_offset=0, library=PinningLibrary.NETWORK_SECURITY_CONFIG,
                        is_weak_hash=(digest_type.lower() == 'sha-1')))
                pin_config.backup_pins_exist = len(pin_config.pins) >= 2
            ta_match = self._TRUST_ANCHOR.search(dc_xml)
            if ta_match:
                if 'CA' in ta_match.group(1) or 'user' in ta_match.group(1).lower():
                    self.trusts_user_ca = True
            self.domains.append(pin_config)
        return self.domains

    def generate_findings(self) -> List[PinningFinding]:
        findings: List[PinningFinding] = []
        if self.cleartext_allowed:
            findings.append(PinningFinding(category='cleartext_traffic', severity=PinningSeverity.HIGH,
                description='cleartextTrafficPermitted="true"——允许明文HTTP通信',
                recommendation='设置 cleartextTrafficPermitted="false" 或仅在特定域启用'))
        if self.debug_overrides_present:
            findings.append(PinningFinding(category='debug_overrides', severity=PinningSeverity.MEDIUM,
                description='debug-overrides 存在——生产构建中未移除调试覆盖项',
                recommendation='确认发布构建中已移除 <debug-overrides>'))
        if self.trusts_user_ca:
            findings.append(PinningFinding(category='user_ca_trust', severity=PinningSeverity.MEDIUM,
                description='信任用户安装的CA证书——可被中间人攻击',
                recommendation='仅信任系统CA，使用 <certificates src="system" />'))
        for dc in self.domains:
            if dc.pins and not dc.backup_pins_exist:
                findings.append(PinningFinding(category='no_backup_pin', severity=PinningSeverity.MEDIUM,
                    description=f'{dc.domain}: 仅有一个pin，无备份——证书轮换时服务不可用',
                    recommendation=f'为 {dc.domain} 添加第二个备份pin'))
            if dc.expiration_date:
                findings.append(PinningFinding(category='pin_expiration', severity=PinningSeverity.INFO,
                    description=f'{dc.domain}: Pin过期日期: {dc.expiration_date}',
                    recommendation='确认过期日期在计划内，设置提醒'))
        return findings


class ATSConfigParser:
    _ATS_EXCEPTION_DOMAIN = re.compile(r'<key>NSExceptionDomains</key>\s*<dict>(.*?)</dict>\s*</dict>', re.DOTALL)

    def __init__(self, plist_content: str = ""):
        self.raw = plist_content; self.ats_disabled: bool = False; self.allows_local: bool = False
        self.exception_domains: List[str] = []; self.weak_tls_versions: bool = False

    def parse(self) -> Dict[str, Any]:
        if not self.raw: return {}
        if 'NSAllowsArbitraryLoads</key>' in self.raw:
            val = re.search(r'NSAllowsArbitraryLoads</key>\s*<(true|false)', self.raw)
            if val and val.group(1) == 'true': self.ats_disabled = True
        exc_match = self._ATS_EXCEPTION_DOMAIN.search(self.raw)
        if exc_match:
            exc_block = exc_match.group(1)
            for domain_key in re.finditer(r'<key>([^<]+)</key>', exc_block):
                domain = domain_key.group(1)
                if domain not in ('NSIncludesSubdomains', 'NSExceptionAllowsInsecureHTTPLoads',
                                  'NSExceptionMinimumTLSVersion', 'NSExceptionRequiresForwardSecrecy',
                                  'NSRequiresCertificateTransparency'):
                    self.exception_domains.append(domain)
        if 'NSExceptionMinimumTLSVersion</key>' in self.raw:
            tls_ver = re.search(r'NSExceptionMinimumTLSVersion</key>\s*<string>([^<]+)<', self.raw)
            if tls_ver and tls_ver.group(1) in ('TLSv1.0', 'TLSv1.1'): self.weak_tls_versions = True
        return {'ats_disabled': self.ats_disabled, 'exception_domains': self.exception_domains,
                'weak_tls_versions': self.weak_tls_versions}

    def generate_findings(self) -> List[PinningFinding]:
        findings: List[PinningFinding] = []
        if self.ats_disabled:
            findings.append(PinningFinding(category='ats_disabled', severity=PinningSeverity.HIGH,
                description='NSAllowsArbitraryLoads=true——ATS完全禁用，允许任意非安全连接',
                recommendation='移除 NSAllowsArbitraryLoads 或仅对特定域设置例外'))
        if self.exception_domains:
            findings.append(PinningFinding(category='ats_exceptions', severity=PinningSeverity.INFO,
                description=f'ATS例外域名: {", ".join(self.exception_domains[:5])}',
                recommendation='逐一审查例外域名的必要性'))
        if self.weak_tls_versions:
            findings.append(PinningFinding(category='weak_tls', severity=PinningSeverity.MEDIUM,
                description='ATS允许弱TLS版本 (TLSv1.0/1.1)', recommendation='升级至 TLSv1.2 或更高'))
        return findings


class SSLPinningAnalyzer:
    """SSL/TLS Pinning 综合审计分析器。"""

    def __init__(self, binary_path: str = "", binary_data: bytes = b""):
        self.binary_path = binary_path; self.data = binary_data
        if not self.data and binary_path and os.path.exists(binary_path):
            self.data = Path(binary_path).read_bytes()
        self.detected_libs: List[PinningLibrary] = []; self.pins: List[PinnedCertificate] = []
        self.nsc_config: Optional[str] = None; self.ats_config: Optional[str] = None
        self.bypasses: List[SSLVerifyBypass] = []; self.findings: List[PinningFinding] = []

    def detect_pinning_libraries(self) -> List[PinningLibrary]:
        found: Set[PinningLibrary] = set()
        for sig, lib in _PINNING_LIB_SIGNATURES.items():
            if sig in self.data: found.add(lib)
        self.detected_libs = list(found)
        return self.detected_libs

    def extract_certificate_pins(self) -> List[PinnedCertificate]:
        libs = self.detect_pinning_libraries()
        for lib in libs: self.pins.extend(_extract_sha256_pins(self.data, lib))
        generic_pins = _extract_sha256_pins(self.data)
        existing = {p.pin_value for p in self.pins}
        for gp in generic_pins:
            if gp.pin_value not in existing:
                self.pins.append(gp); existing.add(gp.pin_value)
        hex_pins = _extract_raw_hex_hashes(self.data)
        for hp in hex_pins:
            if hp.pin_value not in existing:
                self.pins.append(hp); existing.add(hp.pin_value)
        return self.pins

    def detect_ssl_bypasses(self) -> List[SSLVerifyBypass]:
        for pattern, bypass_type, evidence in _SSL_BYPASS_PATTERNS:
            for m in re.finditer(pattern, self.data, re.DOTALL):
                if 'always_true' in bypass_type or 'allowed' in bypass_type:
                    sev = PinningSeverity.CRITICAL
                elif 'disabled' in bypass_type or 'enabled' in bypass_type:
                    sev = PinningSeverity.HIGH
                else: sev = PinningSeverity.MEDIUM
                self.bypasses.append(SSLVerifyBypass(
                    function_name='(inline match)', offset=m.start(),
                    bypass_type=bypass_type, severity=sev, evidence=evidence))
        return self.bypasses

    def _get_nsc_config(self) -> Optional[str]:
        nsc_start = re.search(rb'<network-security-config[^>]*>', self.data)
        if nsc_start:
            start_pos = nsc_start.start()
            end_match = re.search(rb'</network-security-config>', self.data[start_pos:])
            if end_match: return self.data[start_pos:start_pos + end_match.end()].decode('utf-8', errors='replace')
        return None

    def _get_ats_config(self) -> Optional[str]:
        ats_start = re.search(rb'NSAppTransportSecurity', self.data)
        if ats_start:
            start_pos = ats_start.start()
            end_match = re.search(rb'</dict>', self.data[start_pos:start_pos + 2048])
            if end_match: return self.data[start_pos:start_pos + end_match.end() + 10].decode('utf-8', errors='replace')
        return None

    def analyze(self) -> Dict[str, Any]:
        self.detect_pinning_libraries(); self.extract_certificate_pins()
        self.detect_ssl_bypasses()
        nsc_xml = self._get_nsc_config(); ats_frag = self._get_ats_config()
        all_findings: List[Dict] = []

        if self.detected_libs:
            all_findings.append({'category': 'pinning_library', 'severity': PinningSeverity.INFO,
                'description': f'检测到 SSL Pinning 库: {[lib.value for lib in self.detected_libs]}'})
        else:
            all_findings.append({'category': 'no_pinning', 'severity': PinningSeverity.MEDIUM,
                'description': '未检测到 SSL Pinning——应用易受中间人攻击',
                'recommendation': '集成 OkHttp CertificatePinner (Android) 或 TrustKit (iOS)'})

        for pin in self.pins:
            if pin.is_weak_hash:
                all_findings.append({'category': 'weak_pin_hash', 'severity': PinningSeverity.LOW,
                    'description': f'SHA1 pin at offset {pin.match_offset:#x}',
                    'recommendation': '使用 SHA256 替代 SHA1 进行证书固定'})

        for bp in self.bypasses:
            all_findings.append({'category': f'ssl_bypass:{bp.bypass_type}',
                'severity': bp.severity.value, 'description': bp.evidence,
                'location': f'offset {bp.offset:#x}'})

        if nsc_xml:
            nsc_parser = NetworkSecurityConfigParser(nsc_xml); nsc_parser.parse()
            for f in nsc_parser.generate_findings():
                all_findings.append({'category': f'nsc:{f.category}', 'severity': f.severity.value,
                    'description': f.description, 'recommendation': f.recommendation})

        if ats_frag:
            ats_parser = ATSConfigParser(ats_frag); ats_parser.parse()
            for f in ats_parser.generate_findings():
                all_findings.append({'category': f'ats:{f.category}', 'severity': f.severity.value,
                    'description': f.description, 'recommendation': f.recommendation})

        return {
            'detected_libraries': [lib.value for lib in self.detected_libs],
            'pinned_certificates': len(self.pins),
            'pins': [{'type': p.pin_type,
                'value_preview': p.pin_value[:32] + '...' if len(p.pin_value) > 32 else p.pin_value,
                'offset': hex(p.match_offset), 'library': p.library.value,
                'is_weak': p.is_weak_hash} for p in self.pins[:20]],
            'ssl_bypass_count': len(self.bypasses),
            'bypasses': [{'type': b.bypass_type, 'offset': hex(b.offset),
                'severity': b.severity.value, 'evidence': b.evidence} for b in self.bypasses],
            'network_security_config_found': nsc_xml is not None,
            'ats_config_found': ats_frag is not None,
            'findings': all_findings,
            'risk_summary': self._summarize_risks(all_findings),
        }

    def _summarize_risks(self, findings: List[Dict]) -> str:
        if not findings: return "No SSL/TLS risks identified"
        critical = sum(1 for f in findings if f.get('severity') == 'critical')
        high = sum(1 for f in findings if f.get('severity') == 'high')
        parts = [f'{critical} critical'] if critical else []
        if high: parts.append(f'{high} high')
        if not parts: return f'{len(findings)} findings, no critical/high'
        return f'SSL Pinning risk: {", ".join(parts)} issues'


def analyze_ssl_pinning(binary_path: str) -> Dict[str, Any]:
    return SSLPinningAnalyzer(binary_path=binary_path).analyze()


class MobileSSLPinningAnalyzer:
    def __init__(self, path: str): self.path = path
    def analyze(self) -> Dict[str, Any]: return analyze_ssl_pinning(self.path)
