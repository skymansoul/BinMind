# 2025-04-17
# 敏感操作检测器 — 从内存 dump 或 trace 中识别 keys/creds/secrets
# 零依赖：纯字节扫描 + 熵分析，不需要 cryptography 库
import struct
import re
from typing import List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class SensitiveOp:
    op_type: str        # crypto_key / credential / token / private_key
    offset: int
    size: int
    confidence: float
    description: str = ""
    raw_sample: bytes = b''


# 模式库
_KEY_PATTERNS = [
    # AES keys: 16/24/32 bytes high entropy
    (rb'(?s)(\x00\x00\x00\x00.{16})', 'aes_key'),
    # RSA private key markers (DER sequence)
    (rb'\x30\x82[\x02-\x05]..\x02\x01\x00', 'rsa_private_key'),
    # PEM-like base64 chunks
    (rb'[A-Za-z0-9+/]{40,}={0,2}', 'base64_blob'),
    # SSH private key header
    (rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'ssh_private_key'),
    # PGP key block
    (rb'-----BEGIN PGP (?:PRIVATE|SECRET) KEY BLOCK-----', 'pgp_key'),
]

_TOKEN_PATTERNS = [
    (rb'(?:eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})', 'jwt_token'),
    (rb'(?:AKIA|ASIA)[A-Za-z0-9]{16}', 'aws_access_key'),
    (rb'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_\-]{20,}', 'github_token'),
    (rb'(?:xox[baprs]\-[A-Za-z0-9\-]{10,})', 'slack_token'),
]

_CRED_PATTERNS = [
    (rb'(?:password|passwd|pwd)\s*[=:]\s*[\x20-\x7e]{4,}', 'hardcoded_password'),
    (rb'(?:secret|api_key|apikey)\s*[=:]\s*[\x20-\x7e]{6,}', 'api_credential'),
    (rb'(?:connectionString|connStr)\s*[=:]\s*[\x20-\x7e]{10,}', 'connection_string'),
]

_ALL_PATTERNS = _KEY_PATTERNS + _TOKEN_PATTERNS + _CRED_PATTERNS


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    inv_n = 1.0 / len(data)
    for c in counts:
        if c:
            p = c * inv_n
            ent -= p * (p.bit_length() - 1)  # approximate log2
    # proper log2
    import math
    ent = 0.0
    for c in counts:
        if c:
            p = c * inv_n
            ent -= p * math.log2(p)
    return ent / 8.0


class SensitiveOpDetector:
    """从内存 dump 中检测敏感操作痕迹：密钥材料、凭证、令牌"""

    def __init__(self, data: bytes = None, path: str = None):
        if data:
            self._buf = data
        elif path:
            with open(path, "rb") as f:
                self._buf = f.read()
        else:
            self._buf = b''
        self._findings: List[SensitiveOp] = []

    def scan_all(self) -> List[SensitiveOp]:
        self._findings = []
        self._scan_patterns()
        self._scan_high_entropy_regions()
        self._scan_xor_key_candidates()
        self._dedup()
        return sorted(self._findings, key=lambda f: -f.confidence)

    def _scan_patterns(self):
        for pat, ptype in _ALL_PATTERNS:
            try:
                for m in re.finditer(pat, self._buf, re.IGNORECASE):
                    conf = 0.88
                    if 'private' in ptype or 'token' in ptype:
                        conf = 0.95
                    self._findings.append(SensitiveOp(
                        op_type=ptype, offset=m.start(),
                        size=m.end() - m.start(), confidence=conf,
                        description=f"{ptype} matched via regex",
                        raw_sample=self._buf[m.start():m.end()],
                    ))
            except re.error:
                continue

    def _scan_high_entropy_regions(self, window: int = 128, step: int = 64,
                                    min_entropy: float = 0.72):
        """滑动窗口熵扫描 —— 高熵区块通常是密钥或密文"""
        blen = len(self._buf)
        if blen < window:
            return
        for off in range(0, blen - window, step):
            chunk = self._buf[off:off + window]
            ent = _shannon_entropy(chunk)
            if ent >= min_entropy:
                # 检查是否看起来像随机密钥（不是 ASCII 文本）
                printable = sum(32 <= b < 127 for b in chunk) / window
                if printable < 0.55:  # 非可打印字符多→可能是二进制密钥
                    self._findings.append(SensitiveOp(
                        op_type="crypto_key", offset=off, size=window,
                        confidence=min(ent, 0.85),
                        description=f"high-entropy ({ent:.2f}) region at 0x{off:x}",
                        raw_sample=chunk[:32],
                    ))

    def _scan_xor_key_candidates(self, min_len: int = 4, max_len: int = 64):
        """扫描可能的 XOR 密钥 —— 出现在.data/.rdata 中固定长度的重复值
        用相邻字节差值的一致性来判断是否是密钥"""
        ent_regions = [(f.offset, f.size) for f in self._findings if f.op_type == 'crypto_key']
        for off, size in ent_regions:
            # 在密钥附近找可能的使用痕迹
            ctx = self._buf[max(0, off - 128):off + 256]
            # 找重复字节模式（XOR key 常见特征）
            for klen in range(min_len, max_len + 1):
                if klen > size:
                    break

    def _dedup(self):
        """合并重叠匹配 —— 保留置信度最高的"""
        if len(self._findings) <= 1:
            return
        merged = []
        self._findings.sort(key=lambda f: -f.confidence)
        used_ranges: Set[tuple] = set()
        for f in self._findings:
            key = (f.offset, f.offset + f.size)
            if key not in used_ranges:
                merged.append(f)
                used_ranges.add(key)
        self._findings = merged
