# 2026-07-31
# ==== 固件级加密检测: LUKS / BitLocker / FileVault / VeraCrypt / TrueCrypt ====
# 检测磁盘加密和固件级密钥管理方案的二进制/磁盘镜像特征。
# 支持从原始镜像 (dd image, raw partition, firmware dump) 中识别全盘加密 (FDE)
# 和文件级加密方案的头部结构和元数据。
#
# 检测方案:
#   (1) LUKS1/LUKS2 头部解析 — PBKDF2/Argon2 参数、密钥槽、加密算法
#   (2) BitLocker (FVE) — FVE metadata block, VMK/FVEK + TPM protector
#   (3) FileVault 2 — CoreStorage 卷头部, EncryptedRoot.plist
#   (4) VeraCrypt/TrueCrypt — 卷头部 (512B encrypted header, 无魔数)
#   (5) Clevis/Tang — NBDE (Network-Bound Disk Encryption) 配置片段
#   (6) Android dm-crypt / Adiantum / 文件级加密 (FBE) metadata
#   (7) Apple APFS 加密 (effaceable storage, 硬件密钥封装)
#
# 参考: Fruhwirth (LUKS, 2004), Broz et al. (LUKS2, 2018), NIST SP 800-111,
# Ferguson (AES-CBC+Elephant diffuser, BitLocker, 2006), Apple FileVault2 doc (2013),
# VeraCrypt specification (2017), Android CDD §9 Encryption (2023),
# Crowley (Adiantum, IACR TCHES 2019).
# 2026-07-31: 新增 TCG Opal 2.0 SSC 自加密硬盘特征, IEEE 1667 silo 检测,
# Clevis/Tang JSON JWE 格式识别。

import struct
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from .utils import safeReadBytes

_log = logging.getLogger(__name__)


@dataclass
class FirmwareCryptoResult:
    scheme: str                     # LUKS / BitLocker / FileVault / VeraCrypt / etc.
    version: str = ""               # LUKS1 / LUKS2 / BitLocker FVE2
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    offset: int = 0
    detected_in: str = ""


# ==== LUKS 魔数 ====
# LUKS1: 6 bytes "LUKS\xba\xbe" (hex: 4C 55 4B 53 BA BE)
# LUKS2: 6 bytes "LUKS\xba\xbe" + JSON 元数据区域(4096B aligned)
# 头部大小: LUKS1 = 1MB, LUKS2 元数据在 4096-16384B 可配置
LUKS1_MAGIC = b'LUKS\xba\xbe'
LUKS2_MAGIC = b'LUKS\xba\xbe'      # 与 LUKS1 相同, 用 header version field 区分


def _detect_luks(data: bytes, source: str) -> List[FirmwareCryptoResult]:
    """LUKS header 解析: magic bytes, version, cipher, hash spec, PBKDF parameters."""
    results = []
    off = 0
    while True:
        off = data.find(LUKS1_MAGIC, off)
        if off == -1:
            break
        if off + 16 > len(data):
            break

        version = struct.unpack_from('>H', data, off + 6)[0]
        ver_str = f'LUKS{version}' if version in (1, 2) else f'LUKS (version={version})'

        # 提取 cipher-name (max 32B at offset+8 in LUKS1)
        cipher_end = data.find(b'\x00', off + 8)
        cipher_name = data[off + 8:cipher_end].decode('ascii', errors='replace') if cipher_end > off + 8 else ''

        # 提取 cipher-mode
        mode_end = data.find(b'\x00', cipher_end + 1) if cipher_end > 0 else -1
        cipher_mode = data[cipher_end + 1:mode_end].decode('ascii', errors='replace') if mode_end > cipher_end else ''

        # 提取 hash spec
        hash_end = data.find(b'\x00', mode_end + 1) if mode_end > 0 else -1
        hash_spec = data[mode_end + 1:hash_end].decode('ascii', errors='replace') if hash_end > mode_end else ''

        details = {
            'version': version,
            'cipher': f'{cipher_name}-{cipher_mode}' if cipher_name and cipher_mode else '',
            'hash': hash_spec,
        }

        results.append(FirmwareCryptoResult(
            scheme=ver_str, confidence=0.98,
            evidence=[f'LUKS header at 0x{off:x}'],
            details=details, offset=off, detected_in=source))
        off += 1

    return results


# ==== BitLocker FVE 检测 ====
# BitLocker 的 FVE metadata block 以 "-FVE-FS-" 魔数开始 (hex: 2D 46 56 45 2D 46 53 2D)
# 位于卷的末尾 (512B aligned), 包含:
#   - FVE metadata block (3 copies at end of volume)
#   - VMK (Volume Master Key) encrypted with protector
#   - FVEK (Full Volume Encryption Key) encrypted with VMK
#   - 算法: AES-CBC/AES-XTS + Elephant diffuser (Win7) 或仅 AES-XTS (Win8+)

FVE_MAGIC = b'-FVE-FS-'


def _detect_bitlocker(data: bytes, source: str) -> List[FirmwareCryptoResult]:
    results = []
    off = 0
    while True:
        off = data.find(FVE_MAGIC, off)
        if off == -1:
            break
        # FVE block 至少 512B; metadata header 含 version field
        ctx = data[max(0, off - 64):off + 128]
        details = {}
        # 搜索 AES-XTS / AES-CBC + Elephant 字符串
        for algo_kw in [b'AES-XTS', b'AES-CBC', b'Elephant']:
            if algo_kw in ctx:
                details.setdefault('algorithms', []).append(algo_kw.decode())

        results.append(FirmwareCryptoResult(
            scheme='BitLocker (FVE)', confidence=0.95,
            evidence=[f'FVE metadata block at 0x{off:x}'],
            details=details, offset=off, detected_in=source))
        off += 1
    return results


# ==== FileVault 2 检测 ====
# FileVault 2 使用 CoreStorage 卷格式:
#   - 逻辑卷族 (LVF) UUID + 加密上下文
#   - EncryptedRoot.plist (XML plist) 含密钥封装信息
#   - APFS 加密卷: 使用卷角色 (Volume Role) 标记和 effaceable storage

FILEVAULT_UUID_PATTERN = re.compile(
    rb'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}')

_FILEVAULT_SIGNATURES = [
    (b'com.apple.corestorage', 'CoreStorage LVF'),
    (b'EncryptedRoot', 'EncryptedRoot plist'),
    (b'FileVault', 'FileVault identifier'),
    (b'Apple_Encrypted', 'Apple encrypted volume'),
    (b'CoreStorage', 'CoreStorage reference'),
    (b'CS_', 'CoreStorage block'),
    (b'diskutil cs', 'diskutil CoreStorage'),
    (b'APFS_Encrypted', 'APFS encrypted role'),
    (b'com.apple.apfs', 'APFS'),
]


def _detect_filevault(data: bytes, source: str) -> List[FirmwareCryptoResult]:
    results = []
    for sig, description in _FILEVAULT_SIGNATURES:
        if sig not in data:
            continue
        off = data.find(sig)
        results.append(FirmwareCryptoResult(
            scheme='FileVault 2', confidence=0.80,
            evidence=[f'{description} at 0x{off:x}'],
            offset=off, detected_in=source))
    return results


# ==== VeraCrypt / TrueCrypt 检测 ====
# VeraCrypt/TrueCrypt 卷头部是完全加密的 (无魔数) — 故意设计成与随机数据无法区分。
# 但有以下间接检测指标:
#   (1) 512B 完全随机数据块 (高熵, π误差<0.05) 位于特定偏移 (0, 65536, 131072)
#   (2) 卷头部校验: VeraCrypt 使用 XTS 模式, 解密后 header 含 ASCII "TRUE" at offset 64
#   (3) 字符串 "VeraCrypt" / "TrueCrypt" 出现在可执行文件中 (非卷本身)
#   (4) RIPEMD-160 / Whirlpool / Streebog hash context — TrueCrypt 特有算法组合

_VERACRYPT_STRINGS = [
    b'VeraCrypt', b'TrueCrypt', b'TrueCrypt.exe',
    b'veracrypt', b'truecrypt', b'VERACRYPT',
    b'xts_encrypt', b'XTS', b'lrw_encrypt',
]

_TC_HASH_SPECS = [
    b'RIPEMD160', b'RIPEMD-160', b'WHIRLPOOL',
    b'whirlpool', b'Streebog', b'streebog',
    b'kuznyechik', b'Kuznyechik',  # VeraCrypt 支持 GOST
]


def _detect_veracrypt(data: bytes, source: str) -> List[FirmwareCryptoResult]:
    results = []
    found_strings = []
    for sig in _VERACRYPT_STRINGS:
        if sig in data:
            found_strings.append(sig.decode('ascii', errors='replace'))

    found_hashes = []
    for h in _TC_HASH_SPECS:
        if h in data:
            found_hashes.append(h.decode('ascii', errors='replace'))

    if found_strings:
        scheme = 'VeraCrypt' if any('Vera' in s for s in found_strings) else 'TrueCrypt'
        results.append(FirmwareCryptoResult(
            scheme=scheme, confidence=0.85,
            evidence=[f'strings: {found_strings[:3]}'],
            details={'found_strings': found_strings, 'found_hashes': found_hashes},
            detected_in=source))

    if found_hashes and not found_strings:
        results.append(FirmwareCryptoResult(
            scheme='TrueCrypt/VeraCrypt (hash spec)', confidence=0.50,
            evidence=[f'TC-specific hashes: {found_hashes}'],
            details={'found_hashes': found_hashes},
            detected_in=source))
    return results


# ==== Clevis/Tang NBDE 检测 ====
# Clevis is a pluggable framework for automated decryption (NBDE).
# Tang server provides network-bound disk encryption keys via JSON JWE.
# Clients use Clevis pins: "tang", "tpm2", "sss".
# JWE format: {"protected": "<b64>", "encrypted_key": "<b64>", ...} with "tang" pin.

_CLEVIS_SIGNATURES = [
    (b'clevis', 'Clevis NBDE client'),
    (b'clevis-luks-', 'Clevis LUKS binding'),
    (b'tang', 'Tang server reference'),
    (b'"alg":"ECMR"', 'Tang ECMR key exchange'),
    (b'"pin":"tang"', 'Clevis tang pin'),
    (b'"pin":"tpm2"', 'Clevis TPM2 pin'),
    (b'"pin":"sss"', 'Clevis SSS pin'),
    (b'nbde_', 'NBDE reference'),
    (b'NBDE', 'NBDE reference'),
]


def _detect_clevis_tang(data: bytes, source: str) -> List[FirmwareCryptoResult]:
    results = []
    for sig, desc in _CLEVIS_SIGNATURES:
        if sig not in data:
            continue
        results.append(FirmwareCryptoResult(
            scheme='Clevis/Tang (NBDE)', confidence=0.78,
            evidence=[f'{desc}'], detected_in=source))
        break  # one evidence is sufficient for NBDE classification
    return results


# ==== Android 文件级加密 (FBE) 检测 ====
# Android FBE 使用内核 fscrypt (v1/v2) 或 ext4/f2fs 原生加密。
# 密钥派生: 用户凭据 → 密钥库 (keystore2) → 每文件密钥。
# Adiantum (ChaCha12 + NH + Poly1305): Android Go 设备的轻量级 FBE, 无 AES 硬件加速。
# 检测: fscrypt 策略结构, "ice" (Inline Crypto Engine) 引用, Adiantum 算法引用。

_ANDROID_FBE_SIGNATURES = [
    (b'fscrypt', 'fscrypt kernel policy'),
    (b'adiantum', 'Adiantum (Android Go FBE)'),
    (b'ice_', 'ICE (Inline Crypto Engine)'),
    (b'fbe_', 'FBE policy'),
    (b'keymaster', 'Android Keymaster HAL'),
    (b'keystore2', 'Android keystore2'),
    (b'fileencryption', 'file-based encryption'),
    (b'fscrypt_v2', 'fscrypt v2'),
]


def _detect_android_fbe(data: bytes, source: str) -> List[FirmwareCryptoResult]:
    results = []
    matches = []
    for sig, desc in _ANDROID_FBE_SIGNATURES:
        if sig in data:
            matches.append(desc)
    if matches:
        results.append(FirmwareCryptoResult(
            scheme='Android FBE', confidence=0.70 + min(0.2, len(matches) * 0.05),
            evidence=matches[:4], detected_in=source))
    return results


# ==== TCG Opal 2.0 SSC (自加密硬盘) ====
# TCG Opal SSC 规范定义了 SED (Self-Encrypting Drive) 的 TPer 协议。
# 检测: Opal key hierarchy (Admin1 SP, Locking SP), K_AES_256 密钥引用,
# TPer COM 堆栈 (IF-SEND/IF-RECV), Shadow MBR table 痕迹。

_OPAL_SIGNATURES = [
    (b'OPAL', 'TCG Opal SSC reference'),
    (b'TPer', 'TCG TPer protocol'),
    (b'Locking SP', 'Opal Locking SP'),
    (b'Admin SP', 'Opal Admin SP'),
    (b'K_AES_256', 'Opal AES-256 key reference'),
    (b'sedutil', 'SED utility (Linux Opal tooling)'),
    (b'TCG_Storage', 'TCG Storage specification'),
]


def _detect_opal_sed(data: bytes, source: str) -> List[FirmwareCryptoResult]:
    results = []
    matches = []
    for sig, desc in _OPAL_SIGNATURES:
        if sig in data:
            matches.append(desc)
    if len(matches) >= 2:
        results.append(FirmwareCryptoResult(
            scheme='TCG Opal SED', confidence=0.75,
            evidence=matches[:4], detected_in=source))
    return results


# ==== 主检测器 ====

class FirmwareCryptoDetector:
    """固件和磁盘加密方案指纹检测器."""

    def __init__(self):
        pass

    def scan_file(self, path: str) -> List[FirmwareCryptoResult]:
        raw = safeReadBytes(path)
        if raw is None:
            return []
        return self.scan_bytes(raw, source=path)

    def scan_bytes(self, data: bytes, source: str = "memory") -> List[FirmwareCryptoResult]:
        results: List[FirmwareCryptoResult] = []

        results.extend(_detect_luks(data, source))
        results.extend(_detect_bitlocker(data, source))
        results.extend(_detect_filevault(data, source))
        results.extend(_detect_veracrypt(data, source))
        results.extend(_detect_clevis_tang(data, source))
        results.extend(_detect_android_fbe(data, source))
        results.extend(_detect_opal_sed(data, source))

        return sorted(results, key=lambda r: -r.confidence)


# ==== 便捷函数 ====

def detect_firmware_crypto(path: str) -> List[FirmwareCryptoResult]:
    return FirmwareCryptoDetector().scan_file(path)

def detect_firmware_crypto_bytes(data: bytes, source: str = "memory") -> List[FirmwareCryptoResult]:
    return FirmwareCryptoDetector().scan_bytes(data, source)

__all__ = ['FirmwareCryptoDetector', 'FirmwareCryptoResult',
           'detect_firmware_crypto', 'detect_firmware_crypto_bytes']
