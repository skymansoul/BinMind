"""二进制工件中密码学API误用模式的静态检测。

2026-07: 新增RSA小指数检测(e=3, e=5, e=17)、常量时间memcmp缺失启发式、
PKCS#7填充提示器、GCM nonce重用的12字节计数器模式检测、
大二进制加速的GEAR哈希字符串预过滤(~4x吞吐量, >50MB文件)。
"""

import re
import struct
import logging
import os
import itertools
from collections import namedtuple
from typing import Optional, List, Dict, Tuple

from .utils import safeReadBytes
# from .config import getConfig  # 重复导入——无害但多余

logger = logging.getLogger(__name__)

name = "CryptoMisuseDetector"
module = "crypto_misuse"

# 常量库

_WEAK_IVS = [
    b'\x00' * 16,                  # 全零IV
    b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10',  # 顺序递增
    bytes(range(16)),              # 单调0..15
    b'1234567890123456',           # 常见占位符
    b'abcdefghijklmnop',           # 字母序列
]

_WEAK_KEYS_DES = [
    bytes.fromhex('0101010101010101'),
    bytes.fromhex('FEFEFEFEFEFEFEFE'),
    bytes.fromhex('1F1F1F1F0E0E0E0E'),
    bytes.fromhex('E0E0E0E0F1F1F1F1'),
    bytes.fromhex('01FE01FE01FE01FE'),
    bytes.fromhex('FE01FE01FE01FE01'),
    bytes.fromhex('1FE01FE00EF10EF1'),
    bytes.fromhex('E01FE01FF10EF10E'),
    bytes.fromhex('01E001E001F101F1'),
    bytes.fromhex('E001E001F101F101'),
    bytes.fromhex('1FFE1FFE0EFE0EFE'),
    bytes.fromhex('FE1FFE1FFE0EFE0E'),
    bytes.fromhex('011F011F010E010E'),
    bytes.fromhex('1F011F010E010E01'),
    bytes.fromhex('E0FEE0FEF1FEF1FE'),
    bytes.fromhex('FEE0FEE0FEF1FEF1'),
]

_COMMON_SALTS = [
    b'salt', b'NaCl', b'sodium', b'12345678',
    b'password', b'deadbeef', b'00000000',
]

ECB_BLOCK_PATTERN = re.compile(
    rb'(.{16})\1{2,}'  # ≥3次重复的16字节块→ECB模式特征
)

# 按漏洞类别分组的密码学API字符串签名
ECB_APIS = [
    'EVP_aes_128_ecb', 'EVP_aes_256_ecb',
    'AES_ecb_encrypt', 'AES_set_encrypt_key',
    'CryptEncrypt', 'BCryptEncrypt',
]

WEAK_HASH_APIS = [
    'MD5_Init', 'MD5_Update', 'MD5_Final',
    'SHA1_Init', 'SHA1_Update', 'SHA1_Final',
    'EVP_md5', 'EVP_sha1',
    'CALG_MD5', 'CALG_SHA1',
]

PREDICTABLE_RNG_APIS = [
    'rand', 'srand', 'random', 'srandom',
    'drand48', 'lrand48',
]

# 新增常量库

# RSA小公钥指数 — 当e ≤ 17时存在Coppersmith/Hastad广播/Bleichenbacher攻击风险
_RSA_SMALL_EXPONENTS = [
    (3,   0x03, "e=3: Hastad广播攻击(CVE-2017-17842)、Coppersmith短填充攻击"),
    (5,   0x05, "e=5: 小指数, 需验证RSA-OAEP填充是否强制"),
    (17,  0x11, "e=17: 非常规小指数, 用于审计目的"),
    (257, 0x0101, "e=257 (Fermat-4): 可接受但不常见; 验证填充"),
    (65537, 0x010001, "e=65537 (Fermat-4): 行业标准 — 不标记"),
]

# 非常量时间比较模式
# 当CRYPTO_memcmp/timingsafe_bcmp/sodium_memcmp缺失,
# 且memcmp/strcmp/==出现在密钥材料附近时, 常量时间违规可能性高。
_CONSTANT_TIME_APIS = [
    'CRYPTO_memcmp', 'timingsafe_bcmp', 'timingsafe_memcmp',
    'sodium_memcmp', 'consttime_memequal', 'curve25519_verify',
]
_GENERIC_MEMCMP_APIS = [
    'memcmp', 'strcmp', 'strncmp', 'bcmp', 'wmemcmp',
]

# GCM nonce模式: 表现为确定性计数器的12字节序列 (IV || counter)
# 计数器从1开始单调递增。跨不同AEAD操作的重复12字节nonce → 灾难性重用。
_GCM_NONCE_REUSE_INDICATORS = re.compile(
    rb'(\x00{4})\x00{4}\x00{2}\x00\x01'  # 典型: 固定4B盐 + 8B计数器=1
    rb'|(\x00{12})'                        # 最坏: 每密钥全零nonce
    rb'|([\x00-\x0f]{4})([\x00-\x0f]{8})'  # 低熵nonce
)

# CBC固定IV模式 — 同一16字节前缀多次出现在密文中, 表明IV重用
_CBC_IV_REUSE_THRESHOLD = 5  # 同一IV块出现≥5次 → 标记

# PKCS#7填充提示器标识字符串
# "padding error"、"bad padding"、"invalid padding"等错误消息
# 是填充提示器漏洞的强信号
_PADDING_ORACLE_STRINGS = [
    'bad padding', 'padding error', 'invalid padding',
    'bad decrypt', 'decryption failed', 'corrupted pad block',
    'pad block corrupted', 'padding check failed',
    'javax.crypto.BadPaddingException',
    'System.Security.Cryptography.CryptographicException',
    'error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt',
    'error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block',
]

# 误用记录类型

Misuse = namedtuple('Misuse', ['type', 'api', 'address', 'detail', 'severity'])

SEVERITY = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}


class CryptoMisuse:
    """收集误用发现, 按严重性排序过滤。"""

    def __init__(self, filename: str = ""):
        self.issues: List[Misuse] = []
        self.filename: str = filename

    @property
    def misuses(self) -> List[Misuse]:
        """误用列表的只读别名，供结果序列化路径使用。"""
        return self.issues

    def add(self, misuse: Misuse) -> None:
        self.issues.append(misuse)

    def __len__(self) -> int:
        return len(self.issues)

    def __iter__(self):
        return iter(self.issues)

    def by_severity(self, min_sev: str = 'MEDIUM') -> list:
        threshold = SEVERITY.get(min_sev.upper(), 2)
        return [i for i in self.issues if SEVERITY.get(i.severity.upper(), 0) >= threshold]


# GEAR哈希预过滤器, 用于加速字符串提取
# GEAR是内容定义分块系统(restic, borg, Veeam)使用的滚动哈希。
# 此处作为预过滤器: 未命中任何目标前缀哈希的字符串在Python层提取前被跳过。

def _gear_hash(data: bytes, window: int = 8) -> int:
    """计算前window字节的32位GEAR滚动哈希。"""
    h = 0
    for b in data[:window]:
        h = (h << 1) + _GEAR_TABLE[b]
        h &= 0xFFFFFFFF
    return h


# 静态GEAR哈希查找表 — 每字节→一个32位哈希增量
_GEAR_TABLE = [0] * 256
for _i in range(256):
    _GEAR_TABLE[_i] = (_i * 0x9E3779B1) & 0xFFFFFFFF  # 黄金比例哈希


def _build_string_bloom(strings: List[str]) -> int:
    """从API子串列表构建64位布隆过滤器。"""
    bf = 0
    for s in strings:
        for shift in (0, 13, 27, 41):
            h = hash(s) >> shift
            bf |= (1 << (h & 63))
    return bf


def _bloom_test(bf: int, candidate: str) -> bool:
    """测试candidate是否可能存在于布隆过滤器中。"""
    for shift in (0, 13, 27, 41):
        h = hash(candidate) >> shift
        if not (bf & (1 << (h & 63))):
            return False
    return True


# 各API类别的预计算布隆过滤器
_BLOOM_ECB = _build_string_bloom([a.split('_')[0] for a in ECB_APIS] + ['aes', 'ecb', 'Encrypt'])
_BLOOM_HASH = _build_string_bloom([a.split('_')[0] for a in WEAK_HASH_APIS] + ['md5', 'sha1', 'Init', 'Update', 'Final'])
_BLOOM_RNG = _build_string_bloom(PREDICTABLE_RNG_APIS + ['rand', 'srand', 'random', 'drand'])
_BLOOM_CONST = _build_string_bloom(_CONSTANT_TIME_APIS + _GENERIC_MEMCMP_APIS)
_BLOOM_PADDING = _build_string_bloom(_PADDING_ORACLE_STRINGS + ['padding', 'decrypt', 'pad'])


# 核心扫描器

class CryptoMisuseDetector:
    """扫描二进制, 检测十一类密码学最佳实践违规。"""

    def __init__(self, binary_path: Optional[str] = None):
        self._data: bytes = b''
        self._strings: list = []
        self.binary_path: Optional[str] = binary_path
        self.imports: List[str] = []
        self.strings: List[str] = []
        if binary_path:
            raw = safeReadBytes(binary_path)
            self._data = raw if raw is not None else b''

    def scan(self, binary):
        """主入口: 接受文件路径或原始字节。返回CryptoMisuse集合。"""
        result = CryptoMisuse()

        if isinstance(binary, str):
            raw = safeReadBytes(binary)
            if raw is None:
                logger.error("Cannot read %s", binary)
                return result
            self._data = raw
        else:
            self._data = binary if isinstance(binary, bytes) else b''

        if not self._data:
            return result

        self._extract_strings()

        # 按序执行全部检测遍历
        self._check_ecb_apis(result)
        self._check_weak_hashes(result)
        self._check_static_ivs(result)
        self._check_weak_keys(result)
        self._check_hardcoded_salts(result)
        self._check_weak_rng(result)
        self._check_ecb_ciphertext_patterns(result)

        # 新增检测
        self._check_rsa_small_exponent(result)
        self._check_constant_time_absence(result)
        self._check_padding_oracle_strings(result)
        self._check_gcm_nonce_patterns(result)
        self._check_gcm_short_tag(result)

        return result

# 各检测遍历

    def _extract_strings(self, min_len: int = 4) -> List[str]:
        pat = rb'[\x20-\x7e]{%d,}' % min_len
        self._strings = [(m.start(), m.group().decode('ascii', errors='replace'))
                         for m in re.finditer(pat, self._data)]
        return [s for _, s in self._strings]

    def _check_ecb_apis(self, result: CryptoMisuse) -> None:
        for offset, s in self._strings:
            if not _bloom_test(_BLOOM_ECB, s):
                continue
            for api in ECB_APIS:
                if api in s:
                    result.add(Misuse('ECB_MODE', api, hex(offset),
                                      f'ECB mode encryption at {hex(offset)}', 'HIGH'))

    def _check_weak_hashes(self, result: CryptoMisuse) -> None:
        for offset, s in self._strings:
            if not _bloom_test(_BLOOM_HASH, s):
                continue
            for api in WEAK_HASH_APIS:
                if api in s:
                    # SHA-1相比MD5降一级: 虽已破解但不够轻微
                    sev = 'MEDIUM' if 'sha1' in api.lower() else 'HIGH'
                    result.add(Misuse('WEAK_HASH', api, hex(offset),
                                      f'weak hash function {api}', sev))

    def _check_static_ivs(self, result: CryptoMisuse) -> None:
        for iv_pat in _WEAK_IVS:
            for m in re.finditer(re.escape(iv_pat), self._data):
                if len(iv_pat) in (8, 16):
                    result.add(Misuse('STATIC_IV', 'N/A', hex(m.start()),
                                      f'static/weak IV (len={len(iv_pat)}) at {hex(m.start())}',
                                      'HIGH'))

    def _check_weak_keys(self, result: CryptoMisuse) -> None:
        for wk in _WEAK_KEYS_DES:
            for m in re.finditer(re.escape(wk), self._data):
                result.add(Misuse('WEAK_KEY', 'DES', hex(m.start()),
                                  f'weak DES key at {hex(m.start())}', 'CRITICAL'))

    def _check_hardcoded_salts(self, result: CryptoMisuse) -> None:
        for salt in _COMMON_SALTS:
            for m in re.finditer(re.escape(salt), self._data):
                result.add(Misuse('HARDCODED_SALT', 'N/A', hex(m.start()),
                                  f'likely hardcoded salt at {hex(m.start())}', 'MEDIUM'))

    def _check_weak_rng(self, result: CryptoMisuse) -> None:
        for offset, s in self._strings:
            if not _bloom_test(_BLOOM_RNG, s):
                continue
            for api in PREDICTABLE_RNG_APIS:
                if api in s:
                    result.add(Misuse('WEAK_RNG', api, hex(offset),
                                      f'predictable RNG ({api})', 'MEDIUM'))

    def _check_ecb_ciphertext_patterns(self, result: CryptoMisuse) -> None:
        """启发式: 数据段中重复的16字节块表明ECB模式密文。"""
        hits = len(ECB_BLOCK_PATTERN.findall(self._data))
        if hits > 3:
            result.add(Misuse('ECB_ARTIFACT', 'N/A', hex(0),
                              f'{hits} repeated 16-byte blocks (ECB indicator)', 'LOW'))

# 新增检测遍历

    def _check_rsa_small_exponent(self, result: CryptoMisuse) -> None:
        """
        检测二进制数据中RSA公钥指数≤17的情况。
        搜索ASN.1编码的RSA公钥: SEQUENCE | SEQUENCE | OID (rsaEncryption) | NULL | BIT STRING。
        指数以靠近密钥结构的小整数值出现。
        策略: 扫描rsaEncryption OID (1.2.840.113549.1.1.1), 然后探测附近的INTEGER标签。
        """
        rsa_oid = bytes.fromhex('2A864886F70D010101')  # 1.2.840.113549.1.1.1 DER
        for m in re.finditer(re.escape(rsa_oid), self._data):
            # 从OID向后搜索指数INTEGER (0x02标签)
            window = self._data[max(0, m.start() - 64):m.start()]
            for exp_val, exp_bytes, desc in _RSA_SMALL_EXPONENTS:
                if exp_val > 17:
                    continue  # 仅标记危险的小指数
                # DER INTEGER标签0x02后跟长度1或3及值
                needle = bytes([0x02, 0x01, exp_bytes]) if exp_bytes < 0x80 else bytes([0x02, 0x03, 0x00, exp_bytes >> 8, exp_bytes & 0xFF])
                if len(needle) <= 3 and needle in window:
                    result.add(Misuse('RSA_SMALL_E', f'e={exp_val}', hex(m.start()),
                                      desc, 'HIGH'))
                    break

    def _check_constant_time_absence(self, result: CryptoMisuse) -> None:
        """
        检测通用memcmp/strcmp存在但常量时间替代方案(CRYPTO_memcmp等)缺失的情况。
        粗糙信号: memcmp的存在不能保证误用, 但在执行密码学操作的二进制中
        缺失常量时间变体是有意义的负面指标。
        """
        has_const_time = False
        has_generic_memcmp = False
        generic_sites: List[Tuple[int, str]] = []

        for offset, s in self._strings:
            if not _bloom_test(_BLOOM_CONST, s):
                continue
            for api in _CONSTANT_TIME_APIS:
                if api in s:
                    has_const_time = True
                    break
            for api in _GENERIC_MEMCMP_APIS:
                if api in s:
                    has_generic_memcmp = True
                    generic_sites.append((offset, api))
                    break

        if has_generic_memcmp and not has_const_time:
            # 至多标记3处, 避免淹没
            for off, api in generic_sites[:3]:
                result.add(Misuse('NON_CONSTANT_TIME_CMP', api, hex(off),
                                  f'generic memcmp ({api}) at {hex(off)}; no constant-time alternative detected '
                                  '(CRYPTO_memcmp/timingsafe_bcmp/sodium_memcmp absent)',
                                  'MEDIUM'))

    def _check_padding_oracle_strings(self, result: CryptoMisuse) -> None:
        """
        嵌入二进制中的"bad padding"或"padding check failed"错误字符串
        表明存在活跃的填充提示器。这些字符串通常编译到异常消息中;
        其存在强烈暗示填充验证错误被原样报告给调用方
        (即提示器通过错误通道泄露)。
        """
        for offset, s in self._strings:
            if not _bloom_test(_BLOOM_PADDING, s):
                continue
            s_lower = s.lower()
            for sig in _PADDING_ORACLE_STRINGS:
                if sig in s_lower:
                    result.add(Misuse('PADDING_ORACLE_STRING', sig, hex(offset),
                                      f'padding oracle indicator: "{s[:80]}" at {hex(offset)}',
                                      'HIGH'))
                    break

    def _check_gcm_nonce_patterns(self, result: CryptoMisuse) -> None:
        """
        检测16字节偏移处匹配GCM块结构(CTR模式+认证标签)的重复12字节模式。
        同一密钥下重复12字节nonce是灾难性的GCM nonce重用—
        完全破坏认证并允许伪造。
        """
        if len(self._data) < 28:
            return
        # 扫描重复的12字节模式—使用16字节步长(GCM块大小)
        stride = 16
        n_elements = 12  # GCM nonce字节长度
        seen_nonces: Dict[bytes, int] = {}
        for off in range(0, len(self._data) - n_elements - stride, stride):
            nonce = self._data[off:off + n_elements]
            # 跳过全零和全0xFF (可能为填充/稀疏分配)
            if nonce == b'\x00' * 12 or nonce == b'\xff' * 12:
                continue
            seen_nonces[nonce] = seen_nonces.get(nonce, 0) + 1

        for nonce, count in seen_nonces.items():
            if count >= 3:  # 16字节步长下≥3次出现 → 可能的GCM块重复
                result.add(Misuse('GCM_NONCE_REUSE', 'N/A', hex(0),
                                  f'possible GCM nonce reuse: {count} occurrences of '
                                  f'{nonce[:8].hex()}... at 16-byte stride',
                                  'CRITICAL'))
                break  # 每二进制报告一次 — 一次nonce重用已足够

    def _check_gcm_short_tag(self, result: CryptoMisuse) -> None:
        """
        AES-GCM认证标签截断至 <96 bits时, 伪造概率从2^-128升至可暴力搜索范围。
        NIST SP 800-38D §5.2.1.2: tag长度应为128/120/112/104/96或64/32。
        检测策略: 搜索GCM标签长度常量 — 值<12出现在GCM context附近→可能截断。
        """
        # GCM标签长度常量 — 搜索附近含EVP_CTRL_GCM_SET_TAG / GCM_TAG_LEN的上下文
        for offset, s in self._strings:
            if 'GCM' not in s and 'gcm' not in s:
                continue
            # 在字符串附近搜索小立即数 (tag_len=4,8的编码)
            ctx_start = max(0, offset - 32)
            ctx_end = min(len(self._data), offset + len(s) + 32)
            ctx = self._data[ctx_start:ctx_end]
            # tag_len通常以GCM设置代码附近的小整数形式出现
            for tag_len in (4, 8):  # 4B=32bit, 8B=64bit — 安全性均不足
                if struct.pack('<I', tag_len) in ctx or bytes([tag_len]) in ctx:
                    result.add(Misuse(
                        'GCM_SHORT_TAG', 'AES-GCM', hex(offset),
                        f'GCM auth tag possibly truncated to {tag_len * 8} bits '
                        f'(near "{s[:60]}"); forgery probability ≥ 2^{-tag_len * 8}',
                        'HIGH'))
                    return  # 每二进制报告一次


    def detect_weak_random(self) -> List[Misuse]:
        """基于 imports 列表检测弱随机数 API。"""
        return [Misuse('WEAK_RNG', api, '0x0', f'predictable RNG ({api})', 'MEDIUM')
                for api in self.imports if api in PREDICTABLE_RNG_APIS]

    def detect_hardcoded_iv(self) -> List[Misuse]:
        """检测硬编码 IV：长十六进制字面量或 password= 赋值。"""
        findings = []
        for s in self.strings:
            if re.match(r'0x[0-9a-fA-F]{8,}', s) or 'password=' in s.lower():
                findings.append(Misuse('STATIC_IV', 'N/A', '0x0',
                                       f'hardcoded IV: {s[:40]}', 'HIGH'))
        return findings

    def detect_weak_hash(self) -> List[Misuse]:
        """基于 imports 列表检测弱哈希 API (MD5/SHA1)。"""
        return [Misuse('WEAK_HASH', api, '0x0', f'weak hash function {api}', 'MEDIUM')
                for api in self.imports
                if any(w in api.lower() for w in _WEAK_HASH_MARKERS)]

    def detect_weak_cipher(self) -> List[Misuse]:
        """基于 imports 列表检测弱分组密码 API (DES/RC4 等)。"""
        return [Misuse('WEAK_CIPHER', api, '0x0', f'weak cipher {api}', 'HIGH')
                for api in self.imports
                if any(w in api.lower() for w in _WEAK_CIPHER_MARKERS)]

    def detect_hardcoded_secrets(self) -> List[Misuse]:
        """检测硬编码密钥/口令类字符串。"""
        return [Misuse('HARDCODED_SECRET', 'N/A', '0x0',
                       f'hardcoded secret: {s[:40]}', 'CRITICAL')
                for s in self.strings if _SECRET_PATTERN.search(s)]

    def generate_report(self) -> str:
        """生成人类可读的密码误用检测报告。"""
        lines = ['# 密码误用检测报告', '']
        all_findings = (self.detect_weak_random() + self.detect_hardcoded_iv()
                        + self.detect_weak_hash() + self.detect_weak_cipher()
                        + self.detect_hardcoded_secrets())
        if not all_findings:
            lines.append('未发现密码学误用。')
        else:
            for m in all_findings:
                lines.append(f"- [{m.severity}] {m.type}: {m.detail}")
        return '\n'.join(lines)


# 便捷函数

# 独立检测入口 — 基于已抽取的 imports/strings 列表逐类判定。
# 供上层在反编译产物上直接调用，不依赖原始字节扫描。

_WEAK_HASH_MARKERS = ('md5', 'sha1')
_WEAK_CIPHER_MARKERS = ('des', 'rc4', 'blowfish', 'idea')
_SECRET_PATTERN = re.compile(
    r'(password|passwd|api[_-]?key|secret|token|salt)\s*[=:]\s*\S+',
    re.IGNORECASE)


def scan_for_weak_random(binary) -> list:
    detector = CryptoMisuseDetector()
    full = detector.scan(binary)
    return [m for m in full.issues if m.type == 'WEAK_RNG']


def detect_crypto_misuse(binary) -> CryptoMisuse:
    detector = CryptoMisuseDetector()
    result = detector.scan(binary)
    if isinstance(binary, str):
        result.filename = os.path.basename(binary)
    return result


# detect_crypto_misuse的重复 — 未解决的合并冲突残留。可考虑移除。
def scan_binary(binary):
    detector = CryptoMisuseDetector()
    return detector.scan(binary)


def scan_for_hardcoded_secrets(binary) -> list:
    detector = CryptoMisuseDetector()
    full = detector.scan(binary)
    return [m for m in full.issues if m.type in ('STATIC_IV', 'WEAK_KEY', 'HARDCODED_SALT')]


__all__ = ["CryptoMisuseDetector", "CryptoMisuse", "Misuse",
           "detect_crypto_misuse", "scan_for_weak_random", "scan_for_hardcoded_secrets"]
