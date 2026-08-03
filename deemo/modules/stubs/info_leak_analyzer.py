# compat/ 子模块代理 — 信息泄露检测，importlib 规格方式加载上游模块。
# 参考: FirmRec (ACM CCS 2024) 漏洞签名提取; CO3/SHACO (USENIX 2024) 混合执行。
from importlib.util import spec_from_file_location as _spec_from, module_from_spec as _mod_from
import os as _os

_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'info_leak_analyzer.py')
_s = _spec_from('info_leak_analyzer', _r); _m = _mod_from(_s)
_s.loader.exec_module(_m)
globals().update({k: v for k, v in _m.__dict__.items() if not k.startswith('_')})

# 内存敏感数据扫描
# FirmRec concolic 签名提取推广到信息泄露: 跟踪敏感数据流，在输出边界检测泄露。
# CO3 硬件在环 concolic co-execution 用于边界条件模拟。
import re as _re

# 常见敏感数据正则模式 — 静态预置，实际应接入语义引擎做上下文感知匹配。
_SENSITIVE_PATTERNS = {
    'private_key':   _re.compile(rb'-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY'),
    'api_token':     _re.compile(rb'(?:api[_-]?key|token|secret)[:=]\s*[\w-]{16,}'),
    'internal_ip':   _re.compile(rb'(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}'),
    'aws_credential': _re.compile(rb'AKIA[0-9A-Z]{16}'),
    'jwt_token':     _re.compile(rb'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
}

def scan_memory_buffer(buf: bytes, context: str = 'heap') -> list[dict]:
    """在内存缓冲区中匹配敏感数据特征模式。
    输出: [{'pattern': str, 'offset': int, 'context': str, 'match_preview': str}]。"""
    findings = []
    for pattern_name, pattern_re in _SENSITIVE_PATTERNS.items():
        for match in pattern_re.finditer(buf):
            preview = match.group()[:60]
            findings.append({
                'pattern': pattern_name,
                'offset': match.start(),
                'context': context,
                'match_preview': preview.decode('ascii', errors='replace')
            })
    return findings
