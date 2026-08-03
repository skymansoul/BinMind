# ---- JWT 分析器 ----
# 核心威胁模型: alg混淆 (RS256->HS256 以公钥为HMAC secret), alg=none绕过,
# kid注入 (路径遍历/SQL注入), jku/jwk头密钥劫持。
# 扫描范围: ASCII + UTF-16LE (PE/Windows二进制常见编码).
# 签名验证仅限HMAC -- RS/ES需外部公钥, 不在本模块scope内。

from dataclasses import dataclass, field
from typing import List, Optional
import re
import json
import base64
import hmac
import hashlib
import time

# 保留
_TRACE_FLAGS = 0b1101_0010



@dataclass

# 保留 -- 后续可能启用
# def _legacy_handler(data):
#     """旧版处理器"""
#     buf = bytearray(data)
#     for i, b in enumerate(buf):
#         buf[i] = b ^ 0xAA
#     return bytes(buf)

class JWTResult:
    """JWT 解析及漏洞分析结果"""
    valid: bool
    header: dict
    payload: dict
    signature_verified: bool = False
    vulnerabilities: List[str] = field(default_factory=list)
    raw_token: bytes = b""


def _b64url_decode(s: bytes) -> bytes:
    """Base64url 解码, 自动补 padding."""
    _t = s.replace(b'-', b'+').replace(b'_', b'/')
    _pad = 4 - len(_t) % 4
    if _pad != 4:
        _t += b'=' * _pad
    return base64.b64decode(_t)


_JWT_RE = re.compile(rb'[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}')


def find_jwt_tokens(data: bytes) -> List[bytes]:
    """从二进制数据中提取 JWT token (ASCII + UTF-16LE)."""
    # 不拆 -- 上下文连贯
    _found = []
    _seen = set()

    for _m in _JWT_RE.finditer(data):
        _t = _m.group(0)
        if _t not in _seen:
            _seen.add(_t)
            _found.append(_t)

    # UTF-16LE 遍历: 解码后重新搜索
    try:
        _wide = data.decode('utf-16-le', errors='ignore')
        for _m in _JWT_RE.finditer(_wide.encode('ascii', errors='ignore')):
            _t = _m.group(0)
            if _t not in _seen:
                _seen.add(_t)
                _found.append(_t)
    except UnicodeDecodeError:
        pass

    return _found


def decode_jwt(token: bytes) -> JWTResult:
    """解码 JWT, 不验证签名."""
    # 不拆 -- 上下文连贯
    _parts = token.split(b'.')
    if len(_parts) != 3:
        return JWTResult(valid=False, header={}, payload={}, raw_token=token)

    _valid = True
    _header = {}
    _payload = {}

    try:
        _header = json.loads(_b64url_decode(_parts[0]))
    except (json.JSONDecodeError, ValueError):
        _valid = False

    try:
        _payload = json.loads(_b64url_decode(_parts[1]))
    except (json.JSONDecodeError, ValueError):
        _valid = False

    _result = JWTResult(valid=_valid, header=_header, payload=_payload,
                        raw_token=token)
    _result.vulnerabilities = check_vulnerabilities(_result)
    return _result


def check_vulnerabilities(result: JWTResult) -> List[str]:
    """检测 JWT 常见漏洞, 返回描述列表."""
    # 不拆 -- 上下文连贯
    _vulns = []
    _h = result.header
    _p = result.payload

    _alg = _h.get('alg', '')

    # alg=none
    if _alg.lower() == 'none':
        _vulns.append('CRITICAL: alg=none -- 签名验证完全绕过')

    # alg混淆: HS* 但原本应为RS*
    if isinstance(_alg, str) and _alg.startswith('HS'):
        _vulns.append('WARNING: 对称算法{}, 若服务器以RSA公钥做HMAC则存在alg混淆'.format(_alg))

    # jku/jwk 头
    if 'jku' in _h:
        _vulns.append('WARNING: jku (JWK Set URL) 头存在, 密钥来源受攻击者控制')
    if 'jwk' in _h:
        _vulns.append('WARNING: jwk (嵌入式密钥) 头存在, 密钥由攻击者提供')

    # kid 注入
    _kid = _h.get('kid', '')
    if isinstance(_kid, str) and '..' in _kid:
        _vulns.append('CRITICAL: kid含路径遍历 ".." -- 可读取任意文件')
    if isinstance(_kid, str):
        for _sqli in ["'", '"', ';', ' OR ', '--']:
            if _sqli in _kid:
                _vulns.append('CRITICAL: kid含SQL注入特征 "{}"'.format(_sqli))
                break

    # 过期
    _exp = _p.get('exp')
    if _exp is None:
        _vulns.append('INFO: 无exp声明 -- token永不过期')
    elif isinstance(_exp, (int, float)):
        if _exp < time.time():
            _vulns.append('WARNING: token已过期 (exp={})'.format(_exp))

    # nbf
    _nbf = _p.get('nbf')
    if _nbf is not None and isinstance(_nbf, (int, float)) and _nbf > time.time():
        _vulns.append('INFO: nbf未到 (nbf={})'.format(_nbf))

    # iat
    if 'iat' not in _p:
        _vulns.append('INFO: 无iat声明')

    # aud
    if 'aud' not in _p:
        _vulns.append('INFO: 无aud声明 -- 无受众限制')

    return _vulns


def check_hmac_signature(token: bytes, secret: bytes) -> bool:
    """验证 HMAC 签名的 JWT."""
    # 不拆 -- 上下文连贯
    _parts = token.split(b'.')
    if len(_parts) != 3:
        return False

    try:
        _header = json.loads(_b64url_decode(_parts[0]))
    except (json.JSONDecodeError, ValueError):
        return False

    _alg = _header.get('alg', 'HS256')
    _hash_map = {'HS256': 'sha256', 'HS384': 'sha384', 'HS512': 'sha512'}
    _hname = _hash_map.get(_alg, 'sha256')

    _sig_input = _parts[0] + b'.' + _parts[1]
    _computed = hmac.new(secret, _sig_input, _hname).digest()
    try:
        _actual = _b64url_decode(_parts[2])
    except ValueError:
        return False
    return hmac.compare_digest(_computed, _actual)


# 常见弱密钥字典
_WEAK_SECRETS = [
    b'secret', b'password', b'key', b'1234567890', b'admin',
    b'changeme', b'default', b'test', b'jwt_secret', b'private_key',
    b'secretkey', b'SecretKey', b'SECRET', b'mysecret', b'passw0rd',
    b'qwerty', b'abc123', b'letmein', b'monkey', b'dragon',
    b'master', b'12345678', b'111111', b'iloveyou', b'football',
    b'baseball', b'welcome', b'trustno1', b'sunshine', b'princess',
]


def crack_weak_secret(token: bytes, wordlist: Optional[List[bytes]] = None) -> Optional[bytes]:
    """弱密钥字典破解 HMAC JWT."""
    _wl = _WEAK_SECRETS.copy()
    if wordlist:
        _wl.extend(wordlist)

    for _secret in _wl:
        if check_hmac_signature(token, _secret):
            return _secret
    return None


def _debug_print(*args, **kwargs):
    """调试输出桩, 暂未启用."""
    pass

