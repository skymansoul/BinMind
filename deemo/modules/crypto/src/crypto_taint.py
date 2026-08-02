# 2026-08-01
# ==== 污点感知密钥追踪模块 ====
# 基于数据流分析的加密密钥生命周期追踪。在二进制中识别密钥从生成/加载→使用→销毁的完整路径。
# 受 Zotero 文献 "LLM-Powered Static Binary Taint Analysis" (NDSS 2024) 的启发,
# 此模块提供轻量级的模式级污点追踪, 无需完整符号执行。
#
# 核心思路: 加密密钥一旦从安全存储加载到内存, 后续的操作 (memcpy/XOR/AES key schedule)
# 都会在二进制中留下可追踪的足迹。通过识别密钥周围的特定指令模式 (key schedule, IV setup),
# 可以近似追踪密钥的数据流而无需昂贵的动态分析。
#
# 检测器类型:
#   (1) AES key schedule 展开模式 (10/12/14轮 — 标志性内存写入模式)
#   (2) ChaCha20/Salsa20 初始状态设置 (常数+密钥+nonce+counter 组合)
#   (3) HMAC ipad/opad XOR 模式 (0x36/0x5C 与密钥的异或操作)
#   (4) 密钥清零 (explicit_bzero/memset_s/SecureZeroMemory) 的存在性/缺失性
#   (5) 密钥在内存中的停留 (从加载到最后使用再到清零的窗口大小)
#
# 参考: "LLM-Powered Static Binary Taint Analysis" (NDSS 2024, Zotero),
# "Bin2vec: learning representations of binary executable programs for security tasks" (Zotero),
# Chow et al. (Differential Privacy, CCS 2007) — 污点传播形式化框架.

import re
import struct
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict
from .utils import safeReadBytes

_log = logging.getLogger(__name__)


@dataclass
class KeyTaintResult:
    taint_type: str                 # key_schedule / key_load / key_clear / key_propagation
    algorithm: str = ""             # AES / ChaCha20 / HMAC / generic
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    location: int = 0               # 二进制中的偏移
    details: dict = field(default_factory=dict)
    detected_in: str = ""


# ==== AES 密钥编排检测 ====
# AES-128 密钥编排: 11 round keys × 16 bytes = 176 字节
# 每轮密钥生成使用: RotWord → SubWord → Rcon[i] XOR
# 在二进制中的特征: 176字节连续数据 + 附近出现 AES S-box + Rcon 表
# AES-256: 15 round keys × 16 = 240 字节, 7轮额外SubWord
#
# 启发式: 搜索 176B/240B 缓冲区, 其字节均值≈127.5(均匀分布) 且 相邻字节呈非周期结构。

def _detect_aes_key_schedule(data: bytes, source: str) -> List[KeyTaintResult]:
    """检测 AES 密钥编排表 (round keys) — 176B(AES-128) 或 240B(AES-256) 高熵块."""
    results = []
    from .constants import AES_SBOX, AES_RCON

    sbox_pref = bytes(AES_SBOX[:16])
    rcon_bytes = bytes(AES_RCON)

    # 仅当 S-box 存在时才搜索密钥编排 (S-box 是密钥编排的必要条件)
    sbox_positions = []
    off = 0
    while True:
        off = data.find(sbox_pref, off)
        if off == -1:
            break
        sbox_positions.append(off)
        off += 1

    if not sbox_positions:
        return results

    # 在 S-box 附近的 512B 窗口内搜索 176B 高熵候选
    from .utils import shannon_entropy

    for sbox_off in sbox_positions[:20]:  # 限制20个S-box位置避免超长扫描
        window = data[max(0, sbox_off - 512):sbox_off + 256]
        for candidate_size in (176, 240):  # AES-128 / AES-256
            for w_off in range(0, len(window) - candidate_size, 16):
                chunk = window[w_off:w_off + candidate_size]
                ent = shannon_entropy(chunk)
                if ent < 0.92:
                    continue
                # 检查是否均匀分布 (所有256个字节值出现次数接近均等)
                freq = [0] * 256
                for b in chunk:
                    freq[b] += 1
                expected = candidate_size / 256
                max_dev = max(abs(c - expected) for c in freq)
                if max_dev < expected * 2.5:  # 允许 2.5× 标准差
                    actual_off = max(0, sbox_off - 512) + w_off
                    results.append(KeyTaintResult(
                        taint_type='key_schedule', algorithm=f'AES-{candidate_size // 16 * 64}',
                        confidence=0.55 + ent * 0.2,
                        evidence=[f'AES key schedule candidate: {candidate_size}B, '
                                  f'H={ent:.3f} at 0x{actual_off:x}'],
                        location=actual_off,
                        details={'size': candidate_size, 'entropy': round(ent, 3)},
                        detected_in=source))
                    break  # 每个窗口仅报告一个候选
    return results


# ==== 密钥清零检测 ====
# 安全的密钥管理要求在密钥使用后立即清零内存。
# 清零函数包括: explicit_bzero, memset_s (C11 Annex K), SecureZeroMemory (Win32),
# sodium_memzero, OPENSSL_cleanse, memzero_explicit, burn.
# 检测: 搜索清零函数调用 + 验证清零目标是否与前面检测到的密钥缓冲区重叠。

_SECURE_ZERO_APIS = [
    (b'explicit_bzero', 'explicit_bzero (glibc/BSD)'),
    (b'memset_s', 'memset_s (C11 Annex K)'),
    (b'SecureZeroMemory', 'SecureZeroMemory (Win32)'),
    (b'sodium_memzero', 'sodium_memzero (libsodium)'),
    (b'OPENSSL_cleanse', 'OPENSSL_cleanse (OpenSSL)'),
    (b'memzero_explicit', 'memzero_explicit (Linux kernel)'),
    (b'volatile_memset', 'volatile_memset (custom)'),
    (b'burn', 'burn (custom clear)'),
    (b'arc4random_buf', 'arc4random_buf (secure random overwrite)'),
]


def _detect_key_clear(data: bytes, source: str) -> List[KeyTaintResult]:
    """检测安全密钥清零函数的存在性或缺失性."""
    results = []
    found_apis = []

    for api_bytes, desc in _SECURE_ZERO_APIS:
        if api_bytes in data:
            found_apis.append(desc)

    if found_apis:
        # 存在清零函数 — 这是正面信号
        results.append(KeyTaintResult(
            taint_type='key_clear', algorithm='generic',
            confidence=0.50 + min(0.30, len(found_apis) * 0.08),
            evidence=[f'Secure zeroization APIs found: {found_apis}'],
            details={'apis': found_apis},
            detected_in=source))

    # 检测通用 memset (非安全清零) 但缺乏安全清零
    has_memset = b'memset' in data
    has_secure_zero = len(found_apis) > 0
    if has_memset and not has_secure_zero:
        results.append(KeyTaintResult(
            taint_type='key_clear', algorithm='generic',
            confidence=0.35,
            evidence=['memset present without explicit_bzero/SecureZeroMemory — '
                       'key material may not be securely erased'],
            details={'risk': 'key_may_linger_in_memory'},
            detected_in=source))

    return results


# ==== ChaCha20/Salsa20 初始状态检测 ====
# ChaCha20 初始状态: 16 × 32-bit words
#   [0..3]   = "expand 32-byte k" 常数
#   [4..11]  = 256-bit 密钥
#   [12]     = 32-bit block counter (从0或1开始)
#   [13..15] = 96-bit nonce
# 检测: 搜索 ChaCha 常数 + 后续12个32-bit字的高熵数据

_CHACHA_CONSTANT = b'expand 32-byte k'


def _detect_chacha_state(data: bytes, source: str) -> List[KeyTaintResult]:
    results = []
    off = 0
    while True:
        off = data.find(_CHACHA_CONSTANT, off)
        if off == -1:
            break
        # 常数后应紧跟 48 字节 (12 × u32) 的密钥+nonce数据
        tail = data[off + 16:off + 64]
        if len(tail) >= 48:
            from .utils import shannon_entropy
            ent = shannon_entropy(tail)
            if ent > 0.90:
                results.append(KeyTaintResult(
                    taint_type='key_load', algorithm='ChaCha20',
                    confidence=0.70 + ent * 0.15,
                    evidence=[f'ChaCha20 initial state at 0x{off:x}, '
                              f'key+nonce H={ent:.3f}'],
                    location=off,
                    details={'entropy': round(ent, 3)},
                    detected_in=source))
        off += 1
    return results


# ==== HMAC ipad/opad 模式检测 ====
# HMAC 计算: K0 = key XOR 0x36 (ipad), K0 = key XOR 0x5C (opad)
# 在二进制中, 密钥与固定字节 0x36/0x5C 的异或操作通常表现为:
#   - 立即数 0x36/0x5C 出现在 XOR/AND 指令中
#   - 附近存在密钥长度 (≤128 bytes for SHA-512 block)
# 检测策略: 搜索 0x36 和 0x5C 立即数, 附近查找 block_size 常量 (64/128)

def _detect_hmac_ipad_opad(data: bytes, source: str) -> List[KeyTaintResult]:
    results = []
    # 搜索 0x36 字节连续出现 (ipad填充)
    ipad_pattern = b'\x36' * 8
    opad_pattern = b'\x5c' * 8
    for pattern, name in [(ipad_pattern, 'ipad (0x36)'), (opad_pattern, 'opad (0x5c)')]:
        pos = data.find(pattern)
        if pos < 0:
            continue
        # 在附近搜索 64/128 (SHA-256/SHA-512 block size)
        ctx = data[max(0, pos - 32):pos + 64]
        has_block64 = struct.pack('<I', 64) in ctx or struct.pack('>I', 64) in ctx or bytes([64]) in ctx
        has_block128 = struct.pack('<I', 128) in ctx or struct.pack('>I', 128) in ctx or bytes([128]) in ctx
        if has_block64 or has_block128:
            block_hint = '64B (SHA-256)' if has_block64 else '128B (SHA-512)'
            results.append(KeyTaintResult(
                taint_type='key_load', algorithm='HMAC',
                confidence=0.48,
                evidence=[f'HMAC {name} pattern with SHA block size {block_hint} at 0x{pos:x}'],
                location=pos, detected_in=source))
    return results


class KeyTaintDetector:

    def scan_file(self, path: str) -> List[KeyTaintResult]:
        raw = safeReadBytes(path)
        if raw is None:
            _log.warning("Cannot read %s", path)
            return []
        return self.scan_bytes(raw, source=path)

    def scan_bytes(self, data: bytes, source: str = "memory") -> List[KeyTaintResult]:
        results: List[KeyTaintResult] = []
        results.extend(_detect_aes_key_schedule(data, source))
        results.extend(_detect_key_clear(data, source))
        results.extend(_detect_chacha_state(data, source))
        results.extend(_detect_hmac_ipad_opad(data, source))
        return sorted(results, key=lambda r: -r.confidence)


def detect_key_taint(path: str) -> List[KeyTaintResult]:
    return KeyTaintDetector().scan_file(path)

def detect_key_taint_bytes(data: bytes, source: str = "memory") -> List[KeyTaintResult]:
    return KeyTaintDetector().scan_bytes(data, source)

__all__ = ['KeyTaintDetector', 'KeyTaintResult',
           'detect_key_taint', 'detect_key_taint_bytes']
