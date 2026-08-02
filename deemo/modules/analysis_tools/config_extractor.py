#!/usr/bin/env python3
import os, re, json, logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

__log = logging.getLogger(__name__)


class ConfigType(str, Enum):
    DATABASE = "database"; API_KEY = "api_key"; CREDENTIALS = "credentials"
    URL = "url"; EMAIL = "email"; CERTIFICATE = "certificate"
    CONFIG_FILE = "config_file"; CONNECTION_STRING = "connection_string"
    MISC = "misc"; AWS_KEY = "aws_key"; JWT_TOKEN = "jwt_token"


@dataclass
class ExtractedConfig:
    type: ConfigType; key: str; value: str; confidence: float = 0.0
    description: str = ""; location: Optional[str] = None; line_number: Optional[int] = None


@dataclass
class ExtractionResult:
    configs: List[ExtractedConfig] = field(default_factory=list)
    database_connections: List[ExtractedConfig] = field(default_factory=list)
    api_keys: List[ExtractedConfig] = field(default_factory=list)
    credentials: List[ExtractedConfig] = field(default_factory=list)
    urls: List[ExtractedConfig] = field(default_factory=list)
    emails: List[ExtractedConfig] = field(default_factory=list)
    certificates: List[ExtractedConfig] = field(default_factory=list)


class ConfigExtractor:
    DB_PATTERNS = {
        'mysql': re.compile(r'mysql://[\w.:]+@[\w.-]+(?::\d+)?/[\w]+'),
        'postgresql': re.compile(r'postgresql://[\w.:]+@[\w.-]+(?::\d+)?/[\w]+'),
        'mongodb': re.compile(r'mongodb://[\w.:]+@?[\w.-]+(?::\d+)?/?'),
        'redis': re.compile(r'redis://[\w.:]*@?[\w.-]+(?::\d+)?/?'),
        'sqlite': re.compile(r'sqlite:///[\w./-]+'),
    }
    API_KEY_PATTERNS = [
        re.compile(r"(?i)(api[_.-]?key|api[_.-]?token|secret[_.-]?key|access[_.-]?token)\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{16,})['\"]?"),
        re.compile(r"(?i)(sk|pk|api|secret|token)_[a-zA-Z0-9_-]{16,}"),
        re.compile(r"[a-zA-Z0-9+/]{40,}={0,2}"),
    ]
    CREDENTIAL_PATTERNS = [
        re.compile(r'(?i)(username|user|login)\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?'),
        re.compile(r'(?i)(password|pass|pwd)\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?'),
    ]
    URL_PATTERNS = [re.compile(r'https?://[\w.-]+(?:/[\w./_-]*)+(?:\?[\w=&-]*)?')]
    EMAIL_PATTERNS = [re.compile(r'[\w.-]+@[\w.-]+\.\w+')]
    CERT_PATTERNS = [re.compile(r'-----BEGIN (CERTIFICATE|RSA PRIVATE KEY|PRIVATE KEY)-----')]
    _EMBEDDED_IP_PORT = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\b')
    # AWS 密钥特征: AKIA + 16位 base62 大写
    _AWS_KEY_PAT = re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}')
    # JWT token: eyJ 开头的 base64url
    _JWT_PAT = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')

    def __init__(self):
        self.results = ExtractionResult()
        __log.info("Extractor instantiated.")

    def extract_from_strings(self, strings: List[str]) -> ExtractionResult:
        __log.info("String extraction pipeline started.")
        for s in strings:
            if not isinstance(s, str): continue
            self._extract_database(s); self._extract_api_keys(s)
            self._extract_credentials(s); self._extract_urls(s)
            self._extract_emails(s); self._extract_certificates(s)
            self._extract_config_files(s); self._extract_embedded_endpoints(s)
            self._extract_aws_keys(s); self._extract_jwt_tokens(s)
        __log.info(f"Extraction finished. Items found: {len(self.results.configs)}")
        return self.results

    def _extract_database(self, s: str):
        for db_type, pattern in self.DB_PATTERNS.items():
            for match in pattern.findall(s):
                config = ExtractedConfig(
                    type=ConfigType.DATABASE, key=db_type, value=match,
                    confidence=0.95, description=f"{db_type} connection string",
                    location=s[:50] if len(s) > 50 else s)
                self.results.configs.append(config)
                self.results.database_connections.append(config)

    def _extract_api_keys(self, s: str):
        for pattern in self.API_KEY_PATTERNS:
            for match in pattern.findall(s):
                if isinstance(match, tuple):
                    key_name = match[0]; key_value = match[1]
                else: key_name = "api_key"; key_value = match
                if len(key_value) >= 16:
                    config = ExtractedConfig(
                        type=ConfigType.API_KEY, key=key_name,
                        value=self._mask_sensitive(key_value), confidence=0.85,
                        description="API key or token",
                        location=s[:50] if len(s) > 50 else s)
                    self.results.configs.append(config)
                    self.results.api_keys.append(config)

    def _extract_credentials(self, s: str):
        for pattern in self.CREDENTIAL_PATTERNS:
            for match in pattern.findall(s):
                if isinstance(match, tuple) and len(match) >= 2:
                    key_name = match[0]; value = match[1]
                    config = ExtractedConfig(
                        type=ConfigType.CREDENTIALS, key=key_name,
                        value=self._mask_sensitive(value), confidence=0.9,
                        description=f"{key_name} credential",
                        location=s[:50] if len(s) > 50 else s)
                    self.results.configs.append(config)
                    self.results.credentials.append(config)

    def _extract_urls(self, s: str):
        for pattern in self.URL_PATTERNS:
            for match in pattern.findall(s):
                cfg = ExtractedConfig(
                    type=ConfigType.URL, key="url", value=match, confidence=0.95,
                    description="Network URL",
                    location=s[:50] if len(s) > 50 else s)
                self.results.configs.append(cfg)
                self.results.urls.append(cfg)

    def _extract_emails(self, s: str):
        for pattern in self.EMAIL_PATTERNS:
            for match in pattern.findall(s):
                cfg = ExtractedConfig(
                    type=ConfigType.EMAIL, key="email",
                    value=self._mask_sensitive(match), confidence=0.95,
                    description="Email address",
                    location=s[:50] if len(s) > 50 else s)
                self.results.configs.append(cfg); self.results.emails.append(cfg)

    def _extract_certificates(self, s: str):
        for pattern in self.CERT_PATTERNS:
            for match in pattern.findall(s):
                cert_type = match if isinstance(match, str) else match[0]
                cfg = ExtractedConfig(
                    type=ConfigType.CERTIFICATE, key="certificate",
                    value=f"{cert_type}...", confidence=0.9,
                    description=f"{cert_type} certificate",
                    location=s[:50] if len(s) > 50 else s)
                self.results.configs.append(cfg); self.results.certificates.append(cfg)

    def _extract_config_files(self, s: str):
        pat = re.compile(r'(?i)(config|settings|cfg|ini|xml|json)\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?')
        for match in pat.findall(s):
            config_type = match[0]; config_path = match[1] if isinstance(match, tuple) else match
            self.results.configs.append(ExtractedConfig(
                type=ConfigType.CONFIG_FILE, key=str(config_type),
                value=str(config_path) if isinstance(match, tuple) else str(match),
                confidence=0.8, description=f"{config_type} config file path",
                location=s[:50] if len(s) > 50 else s))

    def _extract_embedded_endpoints(self, s: str):
        for m in self._EMBEDDED_IP_PORT.finditer(s):
            octets = [int(x) for x in m.group(1).split('.')]
            port = int(m.group(2))
            if octets[0] == 0 or octets[0] == 255 or port > 65535: continue
            endpoint = f"{m.group(1)}:{m.group(2)}"
            cfg = ExtractedConfig(
                type=ConfigType.URL, key="embedded_endpoint", value=endpoint,
                confidence=0.7, description=f"Embedded IP endpoint: {endpoint}",
                location=s[:50] if len(s) > 50 else s)
            self.results.configs.append(cfg); self.results.urls.append(cfg)

    def _extract_aws_keys(self, s: str):
        """检测 AWS IAM 访问密钥——AKIA/ASIA 前缀 + 16位 base62。"""
        for m in self._AWS_KEY_PAT.finditer(s):
            cfg = ExtractedConfig(
                type=ConfigType.AWS_KEY, key="aws_access_key", value=self._mask_sensitive(m.group()),
                confidence=0.9, description="AWS IAM access key",
                location=s[:50] if len(s) > 50 else s)
            self.results.configs.append(cfg); self.results.api_keys.append(cfg)

    def _extract_jwt_tokens(self, s: str):
        """检测 JWT token——标准三段式 base64url 编码。"""
        for m in self._JWT_PAT.finditer(s):
            cfg = ExtractedConfig(
                type=ConfigType.JWT_TOKEN, key="jwt", value=self._mask_sensitive(m.group()),
                confidence=0.85, description="JWT token",
                location=s[:50] if len(s) > 50 else s)
            self.results.configs.append(cfg); self.results.api_keys.append(cfg)

    def _mask_sensitive(self, value: str) -> str:
        if not value: return value
        if len(value) <= 8: return '***'
        return value[:4] + '*' * (len(value) - 8) + value[-4:]

    def extract_from_binary(self, binary_path: str) -> ExtractionResult:
        __log.info(f"Binary extraction initiated: {binary_path}")
        try:
            with open(binary_path, 'rb') as f: data = f.read()
            return self.extract_from_strings(self._extract_strings_from_binary(data))
        except Exception as e:
            __log.error(f"Binary extraction error: {e}"); return self.results

    def _extract_strings_from_binary(self, data: bytes) -> List[str]:
        strings = []; current_string = []
        for byte in data:
            if 0x20 <= byte <= 0x7E: current_string.append(chr(byte))
            else:
                if len(current_string) >= 4: strings.append(''.join(current_string))
                current_string = []
        if len(current_string) >= 4: strings.append(''.join(current_string))
        return strings

    def save_results(self, output_path: str) -> bool:
        try:
            result_dict = {
                'total_configs': len(self.results.configs),
                'database_connections': [self._cfg_dict(c) for c in self.results.database_connections],
                'api_keys': [self._cfg_dict(c) for c in self.results.api_keys],
                'credentials': [self._cfg_dict(c) for c in self.results.credentials],
                'urls': [self._cfg_dict(c) for c in self.results.urls],
                'emails': [self._cfg_dict(c) for c in self.results.emails],
                'certificates': [self._cfg_dict(c) for c in self.results.certificates],
            }
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result_dict, f, indent=2, ensure_ascii=False)
            __log.info(f"Results written: {output_path}"); return True
        except Exception as e: __log.error(f"Save error: {e}"); return False

    def _cfg_dict(self, c: ExtractedConfig) -> dict:
        return {'type': c.type.value, 'key': c.key, 'value': c.value,
                'confidence': c.confidence, 'description': c.description}

    def get_summary(self) -> Dict[str, Any]:
        return {'total_configs': len(self.results.configs),
                'database_connections': len(self.results.database_connections),
                'api_keys': len(self.results.api_keys),
                'credentials': len(self.results.credentials),
                'urls': len(self.results.urls), 'emails': len(self.results.emails),
                'certificates': len(self.results.certificates)}


def get_config_extractor() -> ConfigExtractor: return ConfigExtractor()
