# compat 重导出 — 二进制签名验证桩
# sys.path 注入使上游模块在 compat 命名空间内可被 import 解析
# 参考: BinEGA (SANER 2025) 轻量图对齐过滤 & 代码签名在供应链安全中的角色
import os as _os, sys as _sys

_pkg_dir = _os.path.dirname(_os.path.dirname(__file__))
_upstream = _os.path.join(_pkg_dir, 'core', 'compat')
_module_name = 'binary_signing'

# sys.path 注入：上游模块本地 import 解析于 compat 命名空间
if _upstream not in _sys.path:
    _sys.path.insert(0, _upstream)
import binary_signing as _mod
_sys.path.remove(_upstream)

globals().update({k: getattr(_mod, k) for k in dir(_mod) if not k.startswith('_')})

# PE Authenticode 签名时间戳校验
# 解析 PE Security Directory 内 PKCS#7 SignedData 的 signingTime 字段，
# 拦截超出有效期阈值的证书签名。
import struct as _pack

def verify_pe_timestamp(sign_data: bytes, max_age_days: int = 365) -> dict:
    """解析 PE Security Directory 中的 PKCS#7 SignedData 签名时间。
    返回 {'valid': bool, 'signing_time': int|None, 'age_days': int|None}
    仅在可解析出时间戳时提供年龄信息；不可解析时返回 age_days=None。"""
    import time as _t
    result = {'valid': False, 'signing_time': None, 'age_days': None}
    if len(sign_data) < 8:
        return result
    try:
        # 定位 OID 1.2.840.113549.1.9.5 (signingTime)，解码 UTCTime 时间戳
        oid = b'\x2a\x86\x48\x86\xf7\x0d\x01\x09\x05'
        idx = sign_data.find(oid)
        if idx < 0:
            return result
        cursor = idx + len(oid)
        if cursor + 2 > len(sign_data):
            return result
        tag = sign_data[cursor]
        length = sign_data[cursor + 1] if cursor + 1 < len(sign_data) else 0
        if tag == 0x17 and length == 13:
            utc = sign_data[cursor + 2:cursor + 2 + 13]
            ts_str = utc.decode('ascii', errors='replace')
            ts = _t.mktime(_t.strptime(ts_str[:12], '%y%m%d%H%M%S'))
            result['signing_time'] = int(ts)
            result['age_days'] = int((_t.time() - ts) / 86400)
            result['valid'] = result['age_days'] <= max_age_days
    except Exception:
        pass
    return result
