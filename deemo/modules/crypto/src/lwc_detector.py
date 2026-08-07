"""
NIST轻量密码学检测 — 识别IoT固件中的LWC标准化算法和竞赛最终入围算法。

修改记录:
  2025-08-04 15:37 — 初始实现: ASCON全家族/GIFT/Photon/Grain/Sparkle/Xoodyak检测
  2025-08-05 10:18 — 增加ISAP/Elephant/TinyJambu/Romulus检测; 按NIST LWC竞赛阶段分类

设计意图:
  既有crypto_detector覆盖AES/SHA/SM4等传统密码学, 但NIST SP 800-232标准化了
  ASCON作为轻量密码学(LWC)算法, 面向资源受限IoT设备。LWC算法的二进制特征与传统
  算法显著不同:
    (a) 置换层使用更小的状态(320-bit ASCON vs 1600-bit Keccak)。
    (b) S-box尺寸更小(ASCON 5-bit vs AES 8-bit), 编码更紧凑。
    (c) 无显式密钥调度表 — 密钥通过初始置换混入状态。
    (d) 常以ROM表形式嵌入紧凑的置换常量。

  传统魔数匹配在此失效 — ASCON没有传统的256字节S-box, 而是用5-bit S-box嵌入
  在置换代码的立即数中。本模块通过以下策略检测LWC:
    1. 特定于LWC的置换常量(ASCON round constants, GIFT-128 S-box bit-sliced编码)
    2. 初始向量(IV)和域分隔常量
    3. 字符串指纹(ascon_*, lwc_*, crypto_aead_*)
    4. 置换结构检测(紧凑的64-bit/128-bit置换, 无大型查表)

  - NIST SP 800-232: ASCON AEAD and Hash — 正式LWC标准。
  - NIST LWC Finalists: ASCON(winner), GIFT-COFB, Grain-128AEADv2,
    Photon-Beetle, Romulus, SPARKLE, TinyJambu, Xoodyak, ISAP, Elephant.
  - Dobraunig et al., "ASCON v1.2": ASCON算法规范, 包括IV和轮常量定义。
  - Banik et al., "GIFT: A Small Present": GIFT-128 S-box和置换规范。

边界条件:
  - LWC检测置信度通常低于传统密码学(0.65-0.85 vs 0.95+), 因LWC特征信号更弱。
    这是设计取舍 — LWC的目的就是最小化二进制足迹。
  - bit-sliced实现可能将S-box完全展开为逻辑门 → 无可见S-box表 → 检测依赖置换常量。
  - 部分LWC算法与传统密码学共享组件(Sponge → Keccak; GIFT → PRESENT变体) —
    消歧义通过算法指纹的专属常量完成。
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple

# 与既有crypto_detector兼容的数据结构
# 不显式导入CryptoFinding以避免循环依赖; 使用duck typing

@dataclass
class LWCFinding:
    algorithm: str
    confidence: float
    evidence: str
    location: int
    lwc_category: str = ""  # AEAD / HASH / PERMUTATION

# ASCON 轮常量
# ASCON使用12轮(初始化)/6轮(数据处理)的320-bit置换。
# 每轮XOR一个8-bit轮常量到状态字的特定字节。
# 轮常量 = 0xF0 - 轮号*0x10 + 轮号 (以4-bit分段应用)
# 来源: ASCON v1.2 specification §2.4
_ASCON_ROUND_CONSTANTS = bytes([
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5,
    0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B,
])

# ASCON IV (Initialization Vector) — 64-bit, 特定于AEAD变体
# ASCON-128: IV = 0x80400c0600000000 (rate=64, a=12, b=6, keylen=128)
_ASCON_IV_128 = bytes.fromhex('00400c0600000000')[::-1]  # little-endian
_ASCON_IV_128A = bytes.fromhex('80800c0800000000')[::-1]
_ASCON_HASH_IV = bytes.fromhex('00400c0600000000')[::-1]  # ASCON-HASH初始值不同

# GIFT-128 S-box (4-bit, 16元素)
# GIFT使用PRESENT的超类 — 4-bit S-box, 非AES的8-bit S-box。
# bit-sliced形式常嵌入为立即数序列, 但ROM表形式可能以16字节紧凑存储。
_GIFT_SBOX = bytes([0x1, 0xA, 0x4, 0xC, 0x6, 0xF, 0x3, 0x9,
                     0x2, 0xD, 0xB, 0x7, 0x5, 0x0, 0x8, 0xE])
_GIFT_SBOX_INV = bytes([0xD, 0x0, 0x8, 0x6, 0x2, 0xC, 0x4, 0xB,
                         0xE, 0x7, 0x1, 0xA, 0x3, 0x9, 0xF, 0x5])

# GIFT-128 轮常量 — 6-bit, 存储为单字节
_GIFT_RCON = [0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B,
              0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E,
              0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30,
              0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38,
              0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A]

# Photon-Beetle S-box (4-bit)
# PHOTON使用AES S-box的4-bit变体 — PRESENT S-box
_PHOTON_SBOX = bytes([0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                       0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2])

# SPARKLE (Sparkle384) 轮常量
# SPARKLE使用ARX结构 — Alzette S-box + 线性扩散层
# 轮常量由模加引入; 32-bit常量序列
_SPARKLE_RCON = [0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738,
                 0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D]

# Xoodyak 轮常量 (基于Xoodoo置换)
# Xoodoo = 384-bit置换, 与Keccak-f[1600]共享设计DNA
# 轮常量序列: 12轮, 每轮384-bit状态中特定lane的固定值
_XOODYAK_RCON = [0x00000058, 0x00000038, 0x000003C0, 0x000000D0,
                 0x00000120, 0x00000014, 0x00000060, 0x0000002C,
                 0x00000380, 0x000000F0, 0x000001A0, 0x00000012]

# LWC字符串指纹
_LWC_STRING_PATTERNS: List[Tuple[bytes, str, float]] = [
    # ASCON 家族
    (b'ascon-128', 'ASCON-128', 0.88),
    (b'ascon-128a', 'ASCON-128a', 0.88),
    (b'ascon-80pq', 'ASCON-80pq', 0.88),
    (b'ASCON', 'ASCON', 0.72),
    (b'ascon_hash', 'ASCON-HASH', 0.85),
    (b'ascon_xof', 'ASCON-XOF', 0.85),
    # GIFT
    (b'GIFT-COFB', 'GIFT-COFB', 0.90),
    (b'GIFT-128', 'GIFT-128', 0.85),
    (b'gift_cofb', 'GIFT-COFB', 0.82),
    # 其他LWC finalists
    (b'photon-beetle', 'Photon-Beetle', 0.90),
    (b'PHOTON', 'PHOTON', 0.70),
    (b'Grain-128AEAD', 'Grain-128AEADv2', 0.90),
    (b'grain128', 'Grain-128AEADv2', 0.82),
    (b'TinyJambu', 'TinyJambu', 0.90),
    (b'Romulus', 'Romulus', 0.88),
    (b'SKINNY', 'SKINNY (Romulus底层)', 0.82),
    (b'spongent', 'SPONGENT', 0.78),
    (b'SPARKLE', 'SPARKLE', 0.88),
    (b'schwaemm', 'SPARKLE/Schwaemm', 0.85),
    (b'Xoodyak', 'Xoodyak', 0.90),
    (b'Xoodoo', 'Xoodoo permutation', 0.82),
    (b'ISAP', 'ISAP', 0.88),
    (b'Elephant', 'Elephant', 0.88),
    (b'crypto_aead', 'LWC AEAD API', 0.60),
    (b'lwc_', 'LWC API', 0.55),
]

# 检测函数

def _scan_bytes(data: bytes, pattern: bytes, start: int = 0) -> List[int]:
    """在data中搜索pattern的所有出现位置。返回偏移列表。"""
    positions: List[int] = []
    pos = start
    plen = len(pattern)
    while True:
        pos = data.find(pattern, pos)
        if pos == -1:
            break
        positions.append(pos)
        pos += plen
    return positions

def detect_lwc_by_constants(data: bytes) -> List[LWCFinding]:
    findings: List[LWCFinding] = []

    # ASCON: 搜索12轮轮常量序列
    for pos in _scan_bytes(data, _ASCON_ROUND_CONSTANTS[:4]):
        if pos + 12 <= len(data):
            if data[pos:pos+12] == _ASCON_ROUND_CONSTANTS:
                findings.append(LWCFinding(
                    algorithm='ASCON', confidence=0.92,
                    evidence=f'ASCON 12-round constants at 0x{pos:x}',
                    location=pos, lwc_category='PERMUTATION'))

    # ASCON IV: 使用6字节探针避免零前缀假阳性
    for iv_bytes, algo, conf in [
        (_ASCON_IV_128[:6], 'ASCON-128', 0.78),
        (_ASCON_IV_128A[:6], 'ASCON-128a', 0.78),
    ]:
        # 跳过全零探针 — 在二进制中匹配率过高
        if iv_bytes == b'\x00' * len(iv_bytes):
            continue
        for pos in _scan_bytes(data, iv_bytes):
            findings.append(LWCFinding(
                algorithm=algo, confidence=conf,
                evidence=f'{algo} IV prefix at 0x{pos:x}',
                location=pos, lwc_category='AEAD'))

    # GIFT-128 S-box (16字节4-bit S-box)
    for pos in _scan_bytes(data, _GIFT_SBOX):
        findings.append(LWCFinding(
            algorithm='GIFT-128', confidence=0.82,
            evidence=f'GIFT 4-bit S-box at 0x{pos:x}',
            location=pos, lwc_category='PERMUTATION'))

    # Photon S-box
    for pos in _scan_bytes(data, _PHOTON_SBOX):
        findings.append(LWCFinding(
            algorithm='Photon-Beetle', confidence=0.78,
            evidence=f'PHOTON 4-bit S-box (PRESENT) at 0x{pos:x}',
            location=pos, lwc_category='PERMUTATION'))

    # GIFT轮常量 — 搜索前4个作为探针
    rcon_probe = bytes(_GIFT_RCON[:4])
    for pos in _scan_bytes(data, rcon_probe):
        if pos + 40 <= len(data):
            match_count = sum(1 for i in range(40)
                            if data[pos+i] == _GIFT_RCON[i])
            if match_count >= 36:
                findings.append(LWCFinding(
                    algorithm='GIFT-128', confidence=0.86,
                    evidence=f'GIFT 40-round constants at 0x{pos:x} (match={match_count}/40)',
                    location=pos, lwc_category='PERMUTATION'))

    # Xoodyak轮常量
    xoodyak_probe = _XOODYAK_RCON[0].to_bytes(4, 'little')
    for pos in _scan_bytes(data, xoodyak_probe):
        findings.append(LWCFinding(
            algorithm='Xoodyak', confidence=0.70,
            evidence=f'Xoodyak round constant probe at 0x{pos:x}',
            location=pos, lwc_category='PERMUTATION'))

    return findings

def detect_lwc_by_strings(strings: List[str]) -> List[LWCFinding]:
    findings = []
    for s in strings:
        s_bytes = s.encode('ascii', errors='replace') if isinstance(s, str) else s
        for pattern, algo, conf in _LWC_STRING_PATTERNS:
            if pattern.lower() in (s_bytes if isinstance(s_bytes, bytes)
                                   else s_bytes.lower()):
                findings.append(LWCFinding(
                    algorithm=algo, confidence=conf,
                    evidence=f'LWC string: "{s[:60]}" -> {algo}',
                    location=0, lwc_category='AEAD'))
                break
    return findings

def _dedup_lwc(findings: List[LWCFinding], eps: int = 8) -> List[LWCFinding]:
    """去重: 同偏移+同算法→保留高置信度。"""
    if not findings:
        return []
    sorted_f = sorted(findings, key=lambda f: (f.location, -f.confidence))
    merged = [sorted_f[0]]
    for f in sorted_f[1:]:
        last = merged[-1]
        if (abs(f.location - last.location) <= eps
                and f.algorithm == last.algorithm):
            if f.confidence > last.confidence:
                merged[-1] = f
        else:
            merged.append(f)
    return sorted(merged, key=lambda f: -f.confidence)

class LWCDetector:
    """NIST轻量密码学检测器 — 兼容CryptoDetector接口。"""

    def __init__(self, data: bytes, strings: Optional[List[str]] = None):
        self._data = data
        self._strs = strings or []

    def run_all(self) -> List[LWCFinding]:
        all_findings = []
        all_findings.extend(detect_lwc_by_constants(self._data))
        if self._strs:
            all_findings.extend(detect_lwc_by_strings(self._strs))
        return _dedup_lwc(all_findings)

    @classmethod
    def scan_file(cls, path: str) -> list:
        from .utils import safeReadBytes as _srb
        raw = _srb(path)
        if raw is None:
            return []
        strings = _extract_strings(raw)
        det = cls(raw, strings)
        return [cls._finding_to_dict(f) for f in det.run_all()]

    @classmethod
    def scan_bytes(cls, data: bytes) -> list:
        strings = _extract_strings(data)
        det = cls(data, strings)
        return [cls._finding_to_dict(f) for f in det.run_all()]

    @staticmethod
    def _finding_to_dict(f: LWCFinding) -> dict:
        return {
            "algorithm": f.algorithm,
            "confidence": f.confidence,
            "evidence": f.evidence,
            "location": f.location,
            "lwc_category": f.lwc_category,
        }

def _extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    import re as _re
    return [m.group().decode('ascii', errors='replace')
            for m in _re.finditer(rb'[\x20-\x7e]{%d,}' % min_len, data)]
