#!/usr/bin/env python3
import os
import re
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ConfigType(str, Enum):
    DATABASE = "database"
    API_KEY = "api_key"
    CREDENTIALS = "credentials"
    URL = "url"
    EMAIL = "email"
    CERTIFICATE = "certificate"
    CONFIG_FILE = "config_file"
    CONNECTION_STRING = "connection_string"
    MISC = "misc"


@dataclass
class ExtractedConfig:
    type: ConfigType
    key: str
    value: str
    confidence: float = 0.0
    description: str = ""
    location: Optional[str] = None
    line_number: Optional[int] = None


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
    """
    Scans binary segments and embedded resources for configuration data and credentials.

    Operates via regex pattern matching across extracted strings.
    """

    DB_PATTERNS = {
        'mysql': re.compile(r'mysql://[\w.:]+@[\w.-]+(?::\d+)?/[\w]+'),
        'postgresql': re.compile(r'postgresql://[\w.:]+@[\w.-]+(?::\d+)?/[\w]+'),
        'mongodb': re.compile(r'mongodb://[\w.:]+@?[\w.-]+(?::\d+)?/?'),
        'redis': re.compile(r'redis://[\w.:]*@?[\w.-]+(?::\d+)?/?'),
        'sqlite': re.compile(r'sqlite:///[\w./-]+'),
        'oracle': re.compile(r'oracle://[\w.:]+@[\w.-]+(?::\d+)?/[\w]+'),
        'mssql': re.compile(r'mssql://[\w.:]+@[\w.-]+(?::\d+)?/[\w]+'),
    }

    API_KEY_PATTERNS = [
        re.compile(r"(?i)(api[_.-]?key|api[_.-]?token|secret[_.-]?key|access[_.-]?token|secret)\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{16,})['\"]?"),
        re.compile(r"(?i)(sk|pk|api|secret|token)_[a-zA-Z0-9_-]{16,}"),
        re.compile(r"(?i)(sk|pk)_[a-zA-Z0-9_]+"),
        re.compile(r"[a-zA-Z0-9+/]{40,}={0,2}"),
    ]

    CREDENTIAL_PATTERNS = [
        re.compile(r'(?i)(username|user|login)\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?'),
        re.compile(r'(?i)(password|pass|pwd)\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?'),
        re.compile(r'(?i)(username|user)\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?.*?(password|pass|pwd)\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?'),
    ]

    URL_PATTERNS = [
        re.compile(r'https?://[\w.-]+(?:/[\w./_-]*)+(?:\?[\w=&-]*)?'),
        re.compile(r'ftp://[\w.-]+(?:/[\w./_-]*)+(?:\?[\w=&-]*)?'),
    ]

    EMAIL_PATTERNS = [
        re.compile(r'[\w.-]+@[\w.-]+\.\w+'),
    ]

    CERT_PATTERNS = [
        re.compile(r'-----BEGIN (CERTIFICATE|RSA PRIVATE KEY|PRIVATE KEY)-----'),
        re.compile(r'MII[BKG]jCCAZKgAwIBAg'),
    ]

    CONFIG_FILE_PATTERNS = [
        re.compile(r'(?i)(config|settings|cfg|ini|xml|json)\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?'),
    ]

    def __init__(self):
        """Instantiate extractor with an empty result set."""
        self.results = ExtractionResult()
        logger.info("Extractor instantiated.")

    def extract_from_strings(self, strings: List[str]) -> ExtractionResult:
        """Run extraction pipeline over a sequence of strings."""
        logger.info("String extraction pipeline started.")

        for s in strings:
            if not isinstance(s, str):
                continue

            self._extract_database(s)
            self._extract_api_keys(s)
            self._extract_credentials(s)
            self._extract_urls(s)
            self._extract_emails(s)
            self._extract_certificates(s)
            self._extract_config_files(s)

        logger.info(f"Extraction finished. Items found: {len(self.results.configs)}")
        return self.results

    def _extract_database(self, s: str):
        """Match database connection strings against known URI patterns."""
        for db_type, pattern in self.DB_PATTERNS.items():
            matches = pattern.findall(s)
            for match in matches:
                config = ExtractedConfig(
                    type=ConfigType.DATABASE,
                    key=db_type,
                    value=match,
                    confidence=0.95,
                    description=f"{db_type} database connection string",
                    location=s[:50] if len(s) > 50 else s
                )
                self.results.configs.append(config)
                self.results.database_connections.append(config)

    def _extract_api_keys(self, s: str):
        """Identify API tokens and secret keys via keyword and format heuristics."""
        for pattern in self.API_KEY_PATTERNS:
            matches = pattern.findall(s)
            for match in matches:
                if isinstance(match, tuple):
                    key_name = match[0]
                    key_value = match[1]
                else:
                    key_name = "api_key"
                    key_value = match

                if len(key_value) >= 16:
                    config = ExtractedConfig(
                        type=ConfigType.API_KEY,
                        key=key_name,
                        value=self._mask_sensitive(key_value),
                        confidence=0.85,
                        description="API key or token",
                        location=s[:50] if len(s) > 50 else s
                    )
                    self.results.configs.append(config)
                    self.results.api_keys.append(config)

    def _extract_credentials(self, s: str):
        """Detect username, password, and login string pairs."""
        for pattern in self.CREDENTIAL_PATTERNS:
            matches = pattern.findall(s)
            for match in matches:
                if isinstance(match, tuple) and len(match) >= 2:
                    if len(match) == 2:
                        key_name = match[0]
                        value = match[1]
                        config = ExtractedConfig(
                            type=ConfigType.CREDENTIALS,
                            key=key_name,
                            value=self._mask_sensitive(value),
                            confidence=0.9,
                            description=f"{key_name} credential",
                            location=s[:50] if len(s) > 50 else s
                        )
                        self.results.configs.append(config)
                        self.results.credentials.append(config)
                    elif len(match) == 4:
                        username_key, username_val, password_key, password_val = match
                        user_config = ExtractedConfig(
                            type=ConfigType.CREDENTIALS,
                            key=username_key,
                            value=username_val,
                            confidence=0.9,
                            description=f"{username_key} username",
                            location=s[:50] if len(s) > 50 else s
                        )
                        pass_config = ExtractedConfig(
                            type=ConfigType.CREDENTIALS,
                            key=password_key,
                            value=self._mask_sensitive(password_val),
                            confidence=0.9,
                            description=f"{password_key} password",
                            location=s[:50] if len(s) > 50 else s
                        )
                        self.results.configs.append(user_config)
                        self.results.configs.append(pass_config)
                        self.results.credentials.extend([user_config, pass_config])

    def _extract_urls(self, s: str):
        """Capture HTTP(S) and FTP URLs from string content."""
        for pattern in self.URL_PATTERNS:
            matches = pattern.findall(s)
            for match in matches:
                config = ExtractedConfig(
                    type=ConfigType.URL,
                    key="url",
                    value=match,
                    confidence=0.95,
                    description="Network URL",
                    location=s[:50] if len(s) > 50 else s
                )
                self.results.configs.append(config)
                self.results.urls.append(config)

    def _extract_emails(self, s: str):
        """Isolate email addresses from text."""
        for pattern in self.EMAIL_PATTERNS:
            matches = pattern.findall(s)
            for match in matches:
                config = ExtractedConfig(
                    type=ConfigType.EMAIL,
                    key="email",
                    value=self._mask_sensitive(match),
                    confidence=0.95,
                    description="Email address",
                    location=s[:50] if len(s) > 50 else s
                )
                self.results.configs.append(config)
                self.results.emails.append(config)

    def _extract_certificates(self, s: str):
        """Flag certificate and private key PEM/ASN.1 headers."""
        for pattern in self.CERT_PATTERNS:
            matches = pattern.findall(s)
            for match in matches:
                cert_type = match if isinstance(match, str) else match[0]
                config = ExtractedConfig(
                    type=ConfigType.CERTIFICATE,
                    key="certificate",
                    value=f"{cert_type}...",
                    confidence=0.9,
                    description=f"{cert_type} certificate",
                    location=s[:50] if len(s) > 50 else s
                )
                self.results.configs.append(config)
                self.results.certificates.append(config)

    def _extract_config_files(self, s: str):
        """Recognize configuration file path assignments."""
        for pattern in self.CONFIG_FILE_PATTERNS:
            matches = pattern.findall(s)
            for match in matches:
                if isinstance(match, tuple):
                    config_type = match[0]
                    config_path = match[1]
                else:
                    config_type = "config"
                    config_path = match

                config = ExtractedConfig(
                    type=ConfigType.CONFIG_FILE,
                    key=config_type,
                    value=config_path,
                    confidence=0.8,
                    description=f"{config_type} config file path",
                    location=s[:50] if len(s) > 50 else s
                )
                self.results.configs.append(config)

    def _mask_sensitive(self, value: str) -> str:
        """Truncate middle portion of sensitive strings for display safety."""
        if not value:
            return value

        if len(value) <= 8:
            return '***'

        return value[:4] + '*' * (len(value) - 8) + value[-4:]

    def extract_from_binary(self, binary_path: str) -> ExtractionResult:
        """Read binary file, extract printable strings, then run the extraction pipeline."""
        logger.info(f"Binary extraction initiated: {binary_path}")

        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            strings = self._extract_strings_from_binary(data)
            return self.extract_from_strings(strings)

        except Exception as e:
            logger.error(f"Binary extraction error: {e}")
            return self.results

    def _extract_strings_from_binary(self, data: bytes) -> List[str]:
        """Pull ASCII-printable byte sequences (>=4 chars) from raw binary data."""
        strings = []
        current_string = []

        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current_string.append(chr(byte))
            else:
                if len(current_string) >= 4:
                    strings.append(''.join(current_string))
                current_string = []

        if len(current_string) >= 4:
            strings.append(''.join(current_string))

        return strings

    def save_results(self, output_path: str) -> bool:
        """Serialize extraction results to a JSON file."""
        try:
            result_dict = {
                'total_configs': len(self.results.configs),
                'database_connections': [
                    {
                        'type': c.type.value,
                        'key': c.key,
                        'value': c.value,
                        'confidence': c.confidence,
                        'description': c.description
                    } for c in self.results.database_connections
                ],
                'api_keys': [
                    {
                        'type': c.type.value,
                        'key': c.key,
                        'value': c.value,
                        'confidence': c.confidence,
                        'description': c.description
                    } for c in self.results.api_keys
                ],
                'credentials': [
                    {
                        'type': c.type.value,
                        'key': c.key,
                        'value': c.value,
                        'confidence': c.confidence,
                        'description': c.description
                    } for c in self.results.credentials
                ],
                'urls': [
                    {
                        'type': c.type.value,
                        'key': c.key,
                        'value': c.value,
                        'confidence': c.confidence,
                        'description': c.description
                    } for c in self.results.urls
                ],
                'emails': [
                    {
                        'type': c.type.value,
                        'key': c.key,
                        'value': c.value,
                        'confidence': c.confidence,
                        'description': c.description
                    } for c in self.results.emails
                ],
                'certificates': [
                    {
                        'type': c.type.value,
                        'key': c.key,
                        'value': c.value,
                        'confidence': c.confidence,
                        'description': c.description
                    } for c in self.results.certificates
                ],
                'all_configs': [
                    {
                        'type': c.type.value,
                        'key': c.key,
                        'value': c.value,
                        'confidence': c.confidence,
                        'description': c.description,
                        'location': c.location
                    } for c in self.results.configs
                ]
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result_dict, f, indent=2, ensure_ascii=False)

            logger.info(f"Results written: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Save error: {e}")
            return False

    def get_summary(self) -> Dict[str, Any]:
        """Return counts per configuration category."""
        return {
            'total_configs': len(self.results.configs),
            'database_connections': len(self.results.database_connections),
            'api_keys': len(self.results.api_keys),
            'credentials': len(self.results.credentials),
            'urls': len(self.results.urls),
            'emails': len(self.results.emails),
            'certificates': len(self.results.certificates)
        }


def get_config_extractor() -> ConfigExtractor:
    """Return a new ConfigExtractor instance."""
    return ConfigExtractor()
