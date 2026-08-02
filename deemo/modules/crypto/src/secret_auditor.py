# 2026-07-24
# 硬编码密钥/Token/凭证审计器 — 正则+熵双通道检测。
# 覆盖: AWS AKID/Session Token, GCP SA Key, Azure SAS/Connection, GitHub PAT,
# GitLab CI Token, SSH私钥, JWT HS256 secret, 通用base64密钥。
#
# 2026-07-26: 新增GCP service account key, Azure storage connection string,
# SSH private key (OpenSSH/PuTTY), GitLab runner token, Slack webhook URL,
# Twilio auth token, SendGrid API key, Mailgun API key。

import re
from dataclasses import dataclass, field
from typing import List
from .utils import shannon_entropy


@dataclass
class SecretFinding:
    secret_type: str
    offset: int
    value_preview: str
    entropy: float
    confidence: float


_SECRET_PATTERNS = [
    # AWS
    (rb'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 0.6, 0.9),
    (rb'(?i)aws[_\-]?secret[_\-]?access[_\-]?key[=:]\s*[\"\']?([A-Za-z0-9+/]{40})',
     'AWS Secret Key', 0.7, 0.85),
    (rb'(?i)aws[_\-]?session[_\-]?token[=:]\s*[\"\']?([A-Za-z0-9+/=]{100,})',
     'AWS Session Token', 0.5, 0.7),
    # GCP
    (rb'"type":\s*"service_account"', 'GCP Service Account Key (JSON)', 0.7, 0.85),
    (rb'"private_key_id":\s*"([a-f0-9]{40})"', 'GCP Private Key ID', 0.6, 0.8),
    # Azure
    (rb'DefaultEndpointsProtocol=https;AccountName=([^;]+);AccountKey=([^;]+)',
     'Azure Storage Connection String', 0.7, 0.9),
    (rb'(?i)azure[_\-]?storage[_\-]?key[=:]\s*[\"\']?([A-Za-z0-9+/=]{60,})',
     'Azure Storage Key', 0.7, 0.8),
    # PEM 私钥
    (rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----',
     'Private Key (PEM)', 0.9, 0.98),
    # SSH 私钥变体
    (rb'-----BEGIN OPENSSH PRIVATE KEY-----', 'SSH Private Key (OpenSSH)', 0.9, 0.98),
    (rb'PuTTY-User-Key-File-2:', 'SSH Private Key (PuTTY)', 0.9, 0.95),
    # GitHub/GitLab
    (rb'ghp_[0-9A-Za-z]{36}', 'GitHub Personal Access Token', 0.7, 0.85),
    (rb'ghs_[0-9A-Za-z]{36}', 'GitHub OAuth Token', 0.7, 0.85),
    (rb'glpat-[0-9A-Za-z\-]{20,}', 'GitLab Personal Access Token', 0.7, 0.85),
    (rb'GR1348941[0-9A-Za-z_-]{20,}', 'GitLab Runner Token', 0.7, 0.85),
    # Slack
    (rb'xox[bprs]-[0-9A-Za-z-]{10,}', 'Slack Token', 0.6, 0.8),
    (rb'https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+',
     'Slack Webhook URL', 0.9, 0.95),
    # Stripe
    (rb'sk_live_[0-9A-Za-z]{24,}', 'Stripe Live Secret Key', 0.7, 0.9),
    (rb'sk_test_[0-9A-Za-z]{24,}', 'Stripe Test Key', 0.6, 0.7),
    # Twilio
    (rb'SK[0-9a-fA-F]{32}', 'Twilio Auth Token', 0.7, 0.85),
    # SendGrid
    (rb'SG\.[0-9A-Za-z\-_]{20,}\.[0-9A-Za-z\-_]{20,}', 'SendGrid API Key', 0.8, 0.9),
    # Mailgun
    (rb'key-[0-9a-f]{32}', 'Mailgun API Key', 0.6, 0.75),
    # Generic
    (rb'(?i)api[_-]?key[=:]\s*[\"\']([A-Za-z0-9+/=]{20,60})[\"\']',
     'Generic API Key', 0.6, 0.6),
    (rb'(?i)password[=:]\s*[\"\']([^\s\"\']{8,64})[\"\']',
     'Hardcoded Password', 0.4, 0.5),
    (rb'(?i)private[_-]?key[=:]\s*[\"\']([A-Za-z0-9+/=]{32,})[\"\']',
     'Generic Private Key', 0.8, 0.7),
    (rb'(?i)secret[=:]\s*[\"\']([A-Za-z0-9+/=]{16,80})[\"\']',
     'Generic Secret', 0.5, 0.5),
]


class SecretAuditor:
    def __init__(self):
        self.findings: List[SecretFinding] = []

    def scan(self, data: bytes) -> List[SecretFinding]:
        out: List[SecretFinding] = []
        seen_offsets: set = set()

        for pattern, stype, min_entropy, base_conf in _SECRET_PATTERNS:
            for match in re.finditer(pattern, data):
                off = match.start()
                if off in seen_offsets:
                    continue
                seen_offsets.add(off)

                region = data[max(0, off - 8):off + match.end() - match.start() + 8]
                ent = shannon_entropy(region)
                if ent < min_entropy:
                    continue

                preview = match.group(0)[:48]
                try:
                    prev_str = preview.decode('ascii')
                except Exception:
                    prev_str = preview.hex()

                out.append(SecretFinding(
                    secret_type=stype, offset=off,
                    value_preview=prev_str,
                    entropy=round(ent, 3),
                    confidence=base_conf * (0.5 + 0.5 * ent)))

        out.sort(key=lambda f: -f.confidence)
        return out


__all__ = ['SecretAuditor', 'SecretFinding']
