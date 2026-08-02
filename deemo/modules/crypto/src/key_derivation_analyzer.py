# 2026-07-22
# ---- KDF检测与审计 ----
# 覆盖OWASP 2025密码存储备忘单推荐: PBKDF2(>=600k SHA-256), bcrypt(>=12), scrypt(N=2^17), Argon2id(m=46MB,t=1,p=1)
# 弱KDF清单: PBKDF1, EVP_BytesToKey(OpenSSL legacy), NTLM, MD5/DES crypt — 一律标记为CRITICAL
# KDF参数检测: 静态分析立即数/常量附近的字符串, 推断iter/mem/parallelism配置

from dataclasses import dataclass
from typing import List, Optional, Dict
from .utils import find_pattern


@dataclass
class KDFFinding:
    """KDF使用检测结果"""
    kdf_type: str
    params: dict
    meets_owasp: bool
    severity: str
    recommendation: str


# OWASP 2025 推荐参数
OWASP_2025_RECOMMENDATIONS = {
    'PBKDF2': {'hash': 'SHA-256', 'iterations': 600000, 'note': '或SHA-512'},
    'bcrypt': {'cost': 12, 'note': '>=12'},
    'scrypt': {'N': 131072, 'r': 8, 'p': 1, 'note': 'N=2^17 minimum'},
    'Argon2id': {'memory_mb': 46, 'iterations': 1, 'parallelism': 1, 'note': 'm=46MB, t=1'},
}

# 弱KDF数据库
WEAK_KDF_DB = {
    'PBKDF1': {'reason': 'PBKDF1已废弃(RFC 2898), 输出长度固定且无salt保护', 'severity': 'CRITICAL'},
    'EVP_BytesToKey': {'reason': 'OpenSSL legacy, 仅1轮MD5, 无内存开销', 'severity': 'CRITICAL'},
    'NTLM': {'reason': 'NTLM哈希无salt, 彩虹表秒破', 'severity': 'CRITICAL'},
    'MD5_crypt': {'reason': '基于MD5的Unix crypt, 1k轮不够', 'severity': 'CRITICAL'},
    'DES_crypt': {'reason': 'DES crypt仅8字符有效, 现代硬件秒破', 'severity': 'CRITICAL'},
    'SHA1_crypt': {'reason': 'SHA1已碰撞攻破, 不应再用', 'severity': 'CRITICAL'},
    'CRC32': {'reason': 'CRC32不是哈希函数, 不能做KDF', 'severity': 'CRITICAL'},
    'XOR': {'reason': 'XOR混淆不是KDF, 无密钥拉伸', 'severity': 'CRITICAL'},
}

_KDF_SIGNATURES: Dict[str, List[bytes]] = {
    'PBKDF2': [b'PBKDF2', b'PKCS5_PBKDF2_HMAC', b'Rfc2898DeriveBytes',
               b'pbkdf2_hmac', b'PBKDF2_HMAC', b'CCKeyDerivationPBKDF'],
    'bcrypt': [b'bcrypt', b'$2a$', b'$2b$', b'$2y$',
               b'BCryptGenerateSymmetricKey', b'crypt_raw'],
    'scrypt': [b'scrypt', b'crypto_scrypt', b'EVP_PBE_scrypt',
               b'crypto_pwhash_scryptsalsa208sha256'],
    'Argon2': [b'argon2', b'Argon2', b'Argon2id', b'Argon2i',
               b'crypto_pwhash', b'ARGON2'],
    'HKDF': [b'HKDF', b'hkdf_extract', b'hkdf_expand',
             b'HKDFExpand', b'HKDFExtract'],
    'PBKDF1': [b'PBKDF1', b'PKCS5_PBKDF1'],
    'EVP_BytesToKey': [b'EVP_BytesToKey'],
    'NTLM': [b'NTLM', b'NtLmOwF', b'NTOWFv', b'MSV1_0'],
    'MD5_crypt': [b'$1$', b'crypt_md5'],
    'DES_crypt': [b'crypt_des', b'fcrypt'],
}


def detect_kdf(strings: List[str], data: bytes) -> List[KDFFinding]:
    """检测二进制文件中的KDF使用"""
    _findings: List[KDFFinding] = []

    for _kdf, _sigs in _KDF_SIGNATURES.items():
        for _sig in _sigs:
            _offsets = find_pattern(data, _sig)
            if not _offsets:
                continue

            _params = extract_params(data, _kdf)
            _owasp_ok = _check_owasp(_kdf, _params)
            _sev, _rec = _assess(_kdf, _params, _owasp_ok)

            _findings.append(KDFFinding(
                kdf_type=_kdf,
                params=_params,
                meets_owasp=_owasp_ok,
                severity=_sev,
                recommendation=_rec,
            ))
            break

    # 也扫字符串
    _text = ' '.join(strings)
    for _kdf, _sigs in _KDF_SIGNATURES.items():
        _found = False
        for _sig in _sigs:
            try:
                if _sig.decode() in _text:
                    _found = True
                    break
            except:
                pass
        if _found and not any(f.kdf_type == _kdf for f in _findings):
            _params = {}
            _owasp_ok = _check_owasp(_kdf, _params)
            _sev, _rec = _assess(_kdf, _params, _owasp_ok)
            _findings.append(KDFFinding(
                kdf_type=_kdf, params=_params,
                meets_owasp=_owasp_ok, severity=_sev, recommendation=_rec,
            ))

    return _findings


def extract_params(data: bytes, func_name: str) -> dict:
    """静态提取KDF参数 — 搜索函数附近的立即数/常量"""
    _params = {}
    _defaults = {
        'PBKDF2': {'iterations': 10000, 'hash': 'SHA-1'},
        'bcrypt': {'cost': 5},
        'scrypt': {'N': 16384, 'r': 8, 'p': 1},
        'Argon2': {'memory_mb': 32, 'iterations': 3, 'parallelism': 4},
        'HKDF': {'hash': 'SHA-256'},
    }

    _val_map = _defaults.get(func_name, {})
    _params.update(_val_map)

    # 搜索大立即数 (可能的iteration count)
    if func_name == 'PBKDF2':
        for _off in find_pattern(data, b'PBKDF2'):
            _ctx = data[max(0, _off - 32):_off + 64]
            _big_vals = _extract_immediates(_ctx, min_val=10000)
            if _big_vals:
                _params['iterations'] = _big_vals[0]

    return _params


def _extract_immediates(data: bytes, min_val: int = 100) -> List[int]:
    """从字节流中提取可能的立即数(32-bit LE/BE)"""
    import struct
    _vals = []
    for _i in range(len(data) - 3):
        _v = struct.unpack_from('<I', data, _i)[0]
        if min_val <= _v <= 100_000_000:
            _vals.append(_v)
    return sorted(set(_vals), reverse=True)[:10]


def _check_owasp(kdf_type: str, params: dict) -> bool:
    if kdf_type in WEAK_KDF_DB:
        return False
    if kdf_type == 'PBKDF2':
        return params.get('iterations', 0) >= 600000
    if kdf_type == 'bcrypt':
        return params.get('cost', 0) >= 12
    if kdf_type == 'scrypt':
        return params.get('N', 0) >= 131072
    if kdf_type == 'Argon2':
        return params.get('memory_mb', 0) >= 46
    return True


def _assess(kdf_type: str, params: dict, owasp_ok: bool):
    if kdf_type in WEAK_KDF_DB:
        _info = WEAK_KDF_DB[kdf_type]
        return _info['severity'], _info['reason']
    if owasp_ok:
        return 'OK', '符合OWASP 2025推荐'
    return 'WARNING', '{}: 参数不足OWASP最低标准({})'.format(kdf_type, params)
