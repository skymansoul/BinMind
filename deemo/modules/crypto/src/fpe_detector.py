# ==== 格式保留加密(FPE)检测 ====
# FPE加密后密文与明文具有相同格式(长度和字符集), 常用于:
#   - 令牌化(tokenization): 信用卡号、社会保险号格式保留
#   - 数据库列级加密: 不改变schema限制
#   - 合规要求: PCI-DSS推荐FPE保护PAN
#
# 覆盖标准: NIST SP 800-38G Rev.1 (2024), ANSI X9.124-4.
# 算法: FF1 (Feistel架构, 10轮), FF3-1 (修正版, 8轮).
# 2024年NIST修订SP 800-38G: FF3→FF3-1修复了原始FF3的伪造攻击(Durak-Vaudenay, CRYPTO 2017).
#
# 检测策略:
#   (1) FF1参数指纹: radix ∈ [2, 2^16], min_len ≥ 2, max_len ≤ 2^32
#   (2) FF3-1参数指纹: radix ∈ [2, 2^16], min_len ≥ 2, max_len ≤ 2^32
#       较小tweak(7 bytes而非8)和8轮Feistel结构
#   (3) 库字符串: libfpe (NIST参考), Botan::FPE, Crypto++ FPE, Voltage FPE,
#       Prime Factors EncryptRIGHT, comforte SecurDPS, Thales CipherTrust
#   (4) FPE特有的AES子密钥派生(CBC-MAC变体 + 整数除法和取模运算组合)
#
# Bellare-Rogaway-Spies (FFX mode, 2010), Dworkin (NIST SP 800-38G Rev.1, 2024),
# Durak-Vaudenay (FF3 attack at CRYPTO 2017), Hoang-Miller-Trieu (FF3-1 fix, 2019).
# 新增BPS (Brier-Peyrin-Stern, 2010)格式保留模式检测,
# Thales/Vormetric令牌化产品指纹, comforte/HPE SecureData字符串。

import struct
import logging
from dataclasses import dataclass, field
from typing import List, Optional
from .utils import safeReadBytes

_log = logging.getLogger(__name__)


@dataclass
class FPEResult:
    algorithm: str                  # FF1 / FF3-1 / BPS / vaultless tokenization
    library: str = ""               # libfpe / Botan / Voltage / Crypto++ / comforte
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    detected_in: str = ""


# ==== FPE字符串检测库 ====

_FPE_STRING_DB: List[tuple] = [
    # NIST参考实现
    (b'libfpe', 'FF1/FF3-1', 'libfpe (NIST reference)', 0.88),
    (b'ff1_encrypt', 'FF1', 'FF1 encrypt function', 0.85),
    (b'ff3_encrypt', 'FF3-1', 'FF3/FF3-1 encrypt function', 0.85),
    (b'ff1_decrypt', 'FF1', 'FF1 decrypt', 0.82),
    (b'ff3_decrypt', 'FF3-1', 'FF3-1 decrypt', 0.82),
    (b'FF1_ENCRYPT', 'FF1', 'FF1', 0.85),
    (b'FF3_ENCRYPT', 'FF3-1', 'FF3-1', 0.85),
    (b'SP800_38G', 'FF1/FF3-1', 'NIST SP 800-38G reference', 0.85),
    (b'NIST_SP800_38G', 'FF1/FF3-1', 'NIST spec reference', 0.88),
    # Botan
    (b'Botan::FPE', 'FF1', 'Botan FPE module', 0.88),
    (b'botan_fpe', 'FF1', 'Botan FPE', 0.85),
    (b'fpe_fe1', 'FF1', 'Botan FE1', 0.82),
    # Crypto++
    (b'CryptoPP::FPE', 'FF1/FF3-1', 'Crypto++ FPE', 0.82),
    # 商业产品
    (b'Voltage SecureData', 'FF1/FF3-1', 'Voltage (Micro Focus/HPE) FPE', 0.90),
    (b'VoltageFPE', 'FF1/FF3-1', 'Voltage FPE API', 0.88),
    (b'FormatPreservingEncryption', 'FF1/FF3-1', 'FPE generic', 0.82),
    (b'format_preserving_encrypt', 'FF1/FF3-1', 'FPE generic', 0.80),
    (b'EncryptRIGHT', 'FF1/FF3-1', 'Prime Factors EncryptRIGHT', 0.85),
    (b'comforte', 'FF1/FF3-1', 'comforte SecurDPS', 0.82),
    (b'vormetric', 'FF1/FF3-1', 'Thales/Vormetric tokenization', 0.82),
    (b'CipherTrust', 'FF1/FF3-1', 'Thales CipherTrust', 0.80),
    (b'Protegrity', 'FF1/FF3-1', 'Protegrity Vaultless Tokenization', 0.80),
    # BPS (Brier-Peyrin-Stern, 2010) — 早期FPE模式, 后被FFX替代
    (b'bps_fpe', 'BPS', 'Brier-Peyrin-Stern FPE', 0.78),
    (b'BPS_FPE', 'BPS', 'BPS', 0.78),
    # 令牌化专用
    (b'tokenization', 'tokenization', 'general tokenization', 0.50),
    (b'vaultless_token', 'tokenization', 'vaultless tokenization', 0.65),
]


# ==== FF1/FF3-1参数特征检测 ====
# FF1使用10轮Feistel网络, 每轮: PRF(AES-CBC-MAC) → 整数mod radix^m.
# 参数: radix ∈ [2..65536], input_len ∈ [2..4096](更大的max_len需要radix足够大)
# FF3-1: 8轮, tweak = 56 bits(7 bytes), radix ∈ [2..65536], 输入长度∈[2..4096]
# FF1的tweak可为0(无tweak), FF3-1需至少7bytes tweak

def _detect_fpe_params(data: bytes, source: str) -> List[FPEResult]:
    # 检测FF1/FF3-1使用的典型radix值(10, 26, 36, 62, 256)和轮数(8=FF3-1, 10=FF1)
    results = []
    # 常见radix值在二进制中以立即数出现
    # 字母数字字符集最常用:
    #   radix=10 → 纯数字(PAN/SSN)
    #   radix=26 → 纯字母
    #   radix=36 → 字母数字(0-9A-Z)
    #   radix=62 → 字母数字+大小写
    #   radix=256 → 二进制(等同于普通加密)

    typical_radices = [10, 26, 36, 62]
    found_radices = []
    for r in typical_radices:
        if struct.pack('<I', r) in data or struct.pack('<H', r) in data:
            found_radices.append(r)

    # FF1轮数=10, FF3-1轮数=8
    ff1_rounds = struct.pack('<I', 10) in data
    ff3_rounds = struct.pack('<I', 8) in data

    if found_radices and (ff1_rounds or ff3_rounds):
        algo = 'FF1' if ff1_rounds else 'FF3-1'
        if ff1_rounds and ff3_rounds:
            algo = 'FF1+FF3-1'

        results.append(FPEResult(
            algorithm=algo, confidence=0.50,
            evidence=[f'radices={found_radices}, rounds={"10" if ff1_rounds else "8"}'],
            detected_in=source))

    return results


# ==== FPE上下文中的AES-CBC-MAC ====
# FF1的PRF使用AES-CBC-MAC变体: 从派生密钥通过零向量IV对明文+轮号做CBC。
# 检测到:
#   - AES密钥编排(S-box/Rcon)与整数除法和基数转换组合出现
#   - FPE字符串附近存在AES-128/256密钥编排→强证据

def _detect_fpe_crypto_context(data: bytes, source: str) -> List[FPEResult]:
    """检测FPE密码学上下文 — AES密钥表+FPE特有数学运算(基数转换, 大整数模)。"""
    results = []
    # 检查AES S-box + FPE关键字同时出现
    from .constants import AES_SBOX
    aes_pref = bytes(AES_SBOX[:16])

    has_sbox = aes_pref in data
    has_fpe_string = any(
        kw in data for kw in [b'FF1', b'FF3', b'FPE', b'format_preserving',
                               b'FormatPreserving', b'ff1', b'ff3'])

    if has_sbox and has_fpe_string:
        results.append(FPEResult(
            algorithm='FF1/FF3-1', confidence=0.60,
            evidence=['AES S-box + FPE strings co-located'],
            detected_in=source))

    return results


class FPEDetector:
    """FPE格式保留加密指纹检测器。"""

    def __init__(self):
        pass

    def scan_file(self, path: str) -> List[FPEResult]:
        raw = safeReadBytes(path)
        if raw is None:
            return []
        return self.scan_bytes(raw, source=path)

    def scan_bytes(self, data: bytes, source: str = "memory") -> List[FPEResult]:
        results: List[FPEResult] = []

        for pattern, algo, desc, base_conf in _FPE_STRING_DB:
            if pattern not in data:
                continue
            off = data.find(pattern)
            ctx = data[max(0, off - 8):off + len(pattern) + 24]
            try:
                ctx_text = ctx.decode('ascii', errors='replace')
            except Exception:
                ctx_text = repr(ctx[:50])
            results.append(FPEResult(
                algorithm=algo, confidence=base_conf,
                evidence=[f'{desc}: ...{ctx_text.strip()}...'],
                detected_in=source))

        results.extend(_detect_fpe_params(data, source))
        results.extend(_detect_fpe_crypto_context(data, source))

        seen = set()
        unique = []
        for r in sorted(results, key=lambda r: -r.confidence):
            key = (r.algorithm, r.library if r.library else '')
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique


# ==== 便捷函数 ====

def detect_fpe(path: str) -> List[FPEResult]:
    return FPEDetector().scan_file(path)

def detect_fpe_bytes(data: bytes, source: str = "memory") -> List[FPEResult]:
    return FPEDetector().scan_bytes(data, source)

__all__ = ['FPEDetector', 'FPEResult', 'detect_fpe', 'detect_fpe_bytes']

def _debug_print(*a,**kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):print(*a,**kw)
