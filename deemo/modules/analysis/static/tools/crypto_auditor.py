import re
import hashlib
import base64
from typing import List, Dict, Tuple, Optional
from collections import Counter

class CryptoAuditor:
    """硬编码密钥检测 + 弱加密识别 + PEM私钥提取 + 加密库指纹"""

# 初始化: 定义风险模式库

    def __init__(self):
        # 弱加密算法模式
        self._weak_algorithms = {
            # symmetric ciphers
            'DES': [r'\bDES\b', r'\bdes\b', r'3DES', r'DES_ede', r'des_cbc', r'des_ecb'],
            'RC4': [r'\bRC4\b', r'\brc4\b', r'ARC4', r'arcfour'],
            'RC2': [r'\bRC2\b', r'\brc2\b'],
            'Blowfish': [r'\bblowfish\b', r'\bBF_cbc\b'],
            'MD4': [r'\bMD4\b', r'\bmd4\b'],
            'MD5': [r'\bMD5\b', r'\bmd5\b'],
            'SHA1': [r'\bSHA1\b', r'\bsha1\b', r'\bSHA-1\b'],
            'ECB_mode': [r'_ecb\b', r'\bECB\b', r'CIPHER_ECB'],
            'CBC_no_iv': [r'CBC\b.*\x00', r'iv.*=.*\x00'],
        }

        # 弱随机数
        self._weak_rng = [
            r'\brand\b\s*\(', r'\bsrand\b', r'\brandom\b\s*\(',
            r'Math\.random', r'java\.util\.Random',
            r'mt_rand', r'lcg', r'linear.congruential',
        ]

        # 弱hash
        self._weak_hash = [
            r'\bCRC32\b', r'\bCRC16\b', r'\badler32\b',
            r'\bMD2\b', r'\bMD4\b', r'\bMD5\b',
            r'\bSHA-?0\b', r'\bSHA-?1\b',
            r'\bRIPEMD-?128\b',
        ]

        # 常见secret格式patterns
        self._secret_patterns = {
            'aws_access_key': re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'),
            'aws_secret_key': re.compile(r'(?:aws.{0,5}secret.{0,5})([A-Za-z0-9/+=]{40})', re.I),
            'google_api_key': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            'github_token': re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}'),
            'slack_token': re.compile(r'(?:xox[baprs]-[a-zA-Z0-9\-]+)'),
            'stripe_key': re.compile(r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24}'),
            'private_key_header': re.compile(r'-{3,}BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-{3,}'),
            'jwt_token': re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
            'generic_api_key': re.compile(r'(?:api[_-]?key|apikey|api[_-]?secret|auth[_-]?token)["\s:=]+([A-Za-z0-9+/=]{16,})', re.I),
            'password_assign': re.compile(r'(?:password|passwd|pwd|pass)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I),
            'database_url': re.compile(r'(?:jdbc|mongodb|mysql|postgresql|redis)://[^:]+:[^@]+@', re.I),
            'base64_secret': self._find_base64_secrets,
        }

        # crypto library fingerprints
        self._crypto_libs = {
            'OpenSSL': [r'OpenSSL\s+\d', r'openssl', r'libssl', r'libcrypto', r'SSLeay'],
            'BoringSSL': [r'BoringSSL', r'boringssl'],
            'LibreSSL': [r'LibreSSL\s+\d', r'libressl'],
            'mbedTLS': [r'mbed\s*TLS', r'mbedtls', r'polarssl'],
            'wolfSSL': [r'wolfSSL', r'wolfssl', r'cyassl', r'CyaSSL'],
            'GnuTLS': [r'GnuTLS\s+\d', r'gnutls'],
            'NSS': [r'Network\s+Security\s+Services', r'libnss'],
            'CryptoAPI': [r'CryptAcquireContext', r'CryptEncrypt', r'CryptDecrypt',
                          r'CryptHashData', r'CryptDeriveKey'],
            'CNG': [r'BCryptOpenAlgorithmProvider', r'NCryptOpenStorageProvider',
                    r'BCryptEncrypt', r'BCryptDecrypt'],
            'Java_JCE': [r'javax\.crypto', r'java\.security\.MessageDigest',
                          r'Cipher\.getInstance'],
            'Python_crypto': [r'Crypto\.Cipher', r'cryptography\.fernet',
                              r'pycrypto', r'pycryptodome'],
            'Go_crypto': [r'crypto/aes', r'crypto/tls', r'crypto/rand',
                          r'golang\.org/x/crypto'],
            'Rust_crypto': [r'rust-crypto', r'ring::', r'aes-ni', r'aes_gcm'],
        }

# 硬编码密钥检测

    def detect_hardcoded_secrets(self, strings: List[str]) -> List[Dict]:
        _findings = []

        for _s in strings:
            for _name, _pattern in self._secret_patterns.items():
                if _name == 'base64_secret':
                    continue  # handled below
                if isinstance(_pattern, re.Pattern):
                    _m = _pattern.search(_s)
                    if _m:
                        _val = _m.group(1) if _m.groups() else _m.group(0)
                        _findings.append({
                            'type': _name,
                            'value_masked': _val[:4] + '***' + _val[-4:] if len(_val) > 10 else '***',
                            'context': _s[:100],
                        })

        # base64-like high entropy strings
        _b64_findings = self._find_base64_secrets(strings)
        _findings.extend(_b64_findings)

        return _findings

    def _find_base64_secrets(self, strings: List[str]) -> List[Dict]:
        _r = []
        _b64_re = re.compile(r'^[A-Za-z0-9+/]{24,}={0,2}$')
        for _s in strings:
            if _b64_re.match(_s) and len(_s) >= 24:
                # 检查 entropy: base64 random keys entropy ~5-6 bits/char
                _ent = self._string_entropy(_s)
                if _ent > 4.5:
                    _r.append({
                        'type': 'base64_high_entropy',
                        'value_masked': _s[:4] + '***' + _s[-4:],
                        'length': len(_s),
                        'entropy': round(_ent, 2),
                        'context': _s[:80],
                    })
        return _r

    # 弱加密/哈希/RNG检测

    def detect_weak_crypto(self, strings: List[str]) -> List[Dict]:
        _findings = []
        _strs_all = ' '.join(strings)

        # Weak ciphers
        for _alg, _patterns in self._weak_algorithms.items():
            for _pat in _patterns:
                if re.search(_pat, _strs_all):
                    _findings.append({
                        'type': 'weak_algorithm',
                        'algorithm': _alg,
                        'pattern': _pat,
                        'severity': 'HIGH' if _alg in ('DES', 'RC4', 'MD4', 'MD5') else 'MEDIUM',
                    })
                    break

        # Weak RNG
        for _pat in self._weak_rng:
            if re.search(_pat, _strs_all):
                _findings.append({
                    'type': 'weak_rng',
                    'pattern': _pat,
                    'severity': 'HIGH',
                })
                break

        # Weak hash non-crypto context
        for _pat in self._weak_hash:
            if re.search(_pat, _strs_all, re.I):
                _findings.append({
                    'type': 'weak_hash',
                    'pattern': _pat,
                    'severity': 'MEDIUM',
                })
                break

        return _findings

# PEM私钥检测

    def detect_pem_keys(self, data: bytes, strings: List[str]) -> List[Dict]:
        _findings = []

        # Search binary data for PEM markers
        _pem_re = re.compile(
            rb'-{3,}BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE)\s+(?:PRIVATE\s+)?KEY-{3,}'
            rb'.*?'
            rb'-{3,}END\s+(?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE)\s+(?:PRIVATE\s+)?KEY-{3,}',
            re.DOTALL,
        )
        for _m in _pem_re.finditer(data):
            _pem_text = _m.group()[:200].decode('ascii', errors='replace')
            _key_type = 'unknown'
            if b'RSA' in _m.group()[:50]:
                _key_type = 'RSA'
            elif b'DSA' in _m.group()[:50]:
                _key_type = 'DSA'
            elif b'EC' in _m.group()[:50]:
                _key_type = 'EC'
            elif b'OPENSSH' in _m.group()[:50]:
                _key_type = 'OpenSSH'

            _findings.append({
                'type': 'pem_private_key',
                'key_type': _key_type,
                'offset': _m.start(),
                'size': len(_m.group()),
                'preview': _pem_text[:80],
                'severity': 'CRITICAL',
            })

        # 检查 strings for PEM markers
        for _s in strings:
            if 'BEGIN' in _s and 'PRIVATE KEY' in _s:
                already_found = any(
                    f.get('key_type') in _s for f in _findings
                )
                if not already_found:
                    _findings.append({
                        'type': 'pem_private_key_string',
                        'context': _s[:80],
                        'severity': 'CRITICAL',
                    })

        return _findings

# 自定义/自制加密检测

    def detect_custom_crypto(self, strings: List[str], imports: dict) -> List[Dict]:
        # 自制加密启发式: 检测XOR/移位/轮函数模式但无标准crypto库imports时
        # 可能是自定义加密
        _findings = []
        _strs_all = ' '.join(strings)
        _imp_flat = set()
        for _mod, _funcs in imports.items():
            for _f in _funcs:
                _imp_flat.add(_f.lower())

        # 检查是否有标准加密库
        _has_crypto_lib = False

        # 检查 import names
        for _lib, _pats in self._crypto_libs.items():
            for _pat in _pats:
                if any(_pat.lower() in _i for _i in _imp_flat):
                    _has_crypto_lib = True
                    break

        # 自定义加密信号
        _custom_signals = [
            (r'\bxor\b.*\bencrypt', 'XOR-based encryption'),
            (r'\brot13\b', 'ROT13 (trivial substitution)'),
            (r'\bbase64\b.{0,30}\bencrypt', 'base64 as encryption'),
            (r'\baes\b.{0,40}\bxor', 'AES+XOR homebrew'),
        ]

        if not _has_crypto_lib:
            for _pat, _desc in _custom_signals:
                if re.search(_pat, _strs_all, re.I):
                    _findings.append({
                        'type': 'custom_crypto',
                        'description': _desc,
                        'severity': 'HIGH',
                    })

        return _findings

    # 加密库指纹识别

    def fingerprint_crypto_lib(self, strings: List[str], imports: dict) -> List[Dict]:
        _found = []
        _strs_all = ' '.join(strings)
        _imp_flat = set()
        for _mod, _funcs in imports.items():
            _ml = _mod.lower()
            for _f in _funcs:
                _imp_flat.add(f"{_ml}.{_f.lower()}")

        for _lib, _patterns in self._crypto_libs.items():
            _match_count = 0
            _match_examples = []
            for _pat in _patterns:
                _pl = _pat.lower()
                if _pl in _strs_all.lower():
                    _match_count += 1
                    _match_examples.append(('string', _pat[:60]))
                for _imp in _imp_flat:
                    if _pl in _imp:
                        _match_count += 1
                        _match_examples.append(('import', _pat[:60]))
                        break

            if _match_count >= 1:
                _found.append({
                    'library': _lib,
                    'confidence': min(_match_count / max(len(_patterns) * 0.3, 1), 1.0),
                    'indicators': _match_examples[:5],
                })

        return _found

# 综合审计入口

    def audit(self, data: bytes, strings: List[str] = None,
              imports: Dict[str, List[str]] = None) -> Dict:
        if strings is None:
            strings = self._extract_strings(data)
        if imports is None:
            imports = {}

        _secrets = self.detect_hardcoded_secrets(strings)
        _weak = self.detect_weak_crypto(strings)
        _pem = self.detect_pem_keys(data, strings)
        _custom = self.detect_custom_crypto(strings, imports)
        _libs = self.fingerprint_crypto_lib(strings, imports)

        # 风险总计
        _critical = len([s for s in _secrets if s.get('type') == 'pem_private_key']) + len(_pem)
        _high = len(_secrets) + len([w for w in _weak if w['severity'] == 'HIGH']) + len(_custom)
        _medium = len([w for w in _weak if w['severity'] == 'MEDIUM'])
        _total = _critical * 25 + _high * 10 + _medium * 5
        _score = min(_total, 100)

        return {
            'risk_score': _score,
            'risk_level': 'CRITICAL' if _critical > 0 else ('HIGH' if _score >= 50 else ('MEDIUM' if _score >= 20 else 'LOW')),
            'secrets': _secrets,
            'weak_crypto': _weak,
            'pem_keys': _pem,
            'custom_crypto': _custom,
            'crypto_libraries': _libs,
            'summary': {
                'hardcoded_secrets': len(_secrets),
                'weak_algorithms': len(_weak),
                'pem_private_keys': len(_pem),
                'custom_implementations': len(_custom),
                'identified_libraries': len(_libs),
            },
        }

# 辅助函数

    def _extract_strings(self, data: bytes, min_len=4) -> List[str]:
        _strings = []
        _pat = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
        for _m in _pat.finditer(data):
            _strings.append(_m.group().decode('ascii', errors='ignore'))
        # UTF-16LE
        _i = 0
        while _i < len(data) - 1:
            if 0x20 <= data[_i] <= 0x7e and data[_i + 1] == 0:
                _buf = bytearray()
                _j = _i
                while _j < len(data) - 1 and 0x20 <= data[_j] <= 0x7e and data[_j + 1] == 0:
                    _buf.append(data[_j])
                    _j += 2
                if len(_buf) >= min_len:
                    _strings.append(_buf.decode('ascii', errors='ignore'))
                _i = _j
            else:
                _i += 1
        return _strings

    def _string_entropy(self, s: str) -> float:
        import math
        if not s:
            return 0.0
        _cnt = Counter(s)
        _ent = 0.0
        _n = len(s)
        for _c in _cnt.values():
            _p = _c / _n
            _ent -= _p * math.log2(_p)
        return _ent
