# utils — 字符串分类 / 熵计算 / 字符串提取 / YARA 规则骨架
# 分类器参照 Stringy 思路：多模式正则，按具体性降序返回最精确匹配
# 熵使用标量 Shannon 熵，窗口策略由调用方决定

import math
import re
from collections import Counter
from typing import List, Tuple, Optional

# 预编译正则：编译一次，避免重复解析
_URL_PAT = re.compile(
    r'^https?://[^\s/$.?#].[^\s]*$|^ftp://[^\s]+$|^[a-zA-Z][a-zA-Z0-9+\-.]*://[^\s]+$'
)
_DOMAIN_PAT = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
_IPV4_PAT = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
_REGISTRY_PAT = re.compile(
    r'^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|'
    r'HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)\\'
)
_GUID_PAT = re.compile(
    r'^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$'
)
_BASE64_PAT = re.compile(r'^[A-Za-z0-9+/]{4,}={0,2}$')
_PASSWORD_CONST_PAT = re.compile(
    r'^(password|passwd|pwd|pass|secret|token|key|credential|auth)_\w+$',
    re.IGNORECASE,
)
_IPV6_PAT = re.compile(
    r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
    r'^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$'
)

class StringClassifier:
    """多模式字符串分类器，按具体性降序返回最精确类别。
    策略：URL > IPv6 > IPv4 > DOMAIN > REGISTRY > GUID > BASE64 > PASSWORD。
    """

    CATEGORIES = [
        "URL", "IPV6", "IPV4", "DOMAIN", "REGISTRY_PATH",
        "GUID", "BASE64", "PASSWORD_CONSTANT", "UNKNOWN",
    ]

    @staticmethod
    def classify(s: str) -> str:
        _s = s.strip()
        if not _s:
            return "UNKNOWN"

        # URL 优先：含协议前缀，匹配最具体
        if _URL_PAT.match(_s):
            return "URL"

        # IPv6 优先级高于 IPv4，避免误匹配
        if _IPV6_PAT.match(_s):
            return "IPV6"

        if _IPV4_PAT.match(_s):
            return "IPV4"

        # 域名：至少一个点，TLD 为字母
        if _DOMAIN_PAT.match(_s):
            return "DOMAIN"

        if _REGISTRY_PAT.match(_s):
            return "REGISTRY_PATH"

        if _GUID_PAT.match(_s):
            return "GUID"

        # BASE64：限定字符集 + 可选等号填充
        if len(_s) >= 4 and _BASE64_PAT.match(_s):
            return "BASE64"

        if _PASSWORD_CONST_PAT.match(_s):
            return "PASSWORD_CONSTANT"

        return "UNKNOWN"


def shannon_entropy(data: bytes) -> float:
    """标准 Shannon 熵，输出范围 [0, 8]。不设滑动窗口。"""
    if not data:
        return 0.0
    _n = len(data)
    _cnt = Counter(data)
    _h = 0.0
    for _c in _cnt.values():
        _p = _c / _n
        _h -= _p * math.log2(_p)
    return _h


# 可打印字符集
_ASCII_PRINTABLE = set(range(0x20, 0x7F))  # space (0x20) 至 ~ (0x7E)
_ASCII_PRINTABLE_WITH_TAB_NL = set(range(0x09, 0x0B)) | set(range(0x20, 0x7F))
_ASCII_PRINTABLE_WITH_TAB_NL.discard(0x0A)  # 保留 \n
_ASCII_PRINTABLE_WITH_TAB_NL.add(0x0A)


class StringExtractor:
    """三路扫描字符串提取：ASCII、UTF-16LE、UTF-16BE。
    覆盖绝大多数 Win/Linux 二进制。每路 O(n)，总 O(3n)。
    """

    def __init__(self, min_length: int = 4):
        self._min = max(2, min_length)

    def _scan_ascii(self, data: bytes) -> List[Tuple[int, str, str]]:
        _r: List[Tuple[int, str, str]] = []
        _buf = bytearray()
        _start = 0
        _in_run = False
        for _i, _b in enumerate(data):
            if _b in _ASCII_PRINTABLE:
                if not _in_run:
                    _start = _i
                    _buf.clear()
                    _in_run = True
                _buf.append(_b)
            else:
                if _in_run and len(_buf) >= self._min:
                    _r.append((_start, _buf.decode('ascii', errors='replace'), 'ASCII'))
                _in_run = False
                _buf.clear()
        if _in_run and len(_buf) >= self._min:
            _r.append((_start, _buf.decode('ascii', errors='replace'), 'ASCII'))
        return _r

    def _scan_utf16(self, data: bytes, le: bool = True) -> List[Tuple[int, str, str]]:
        """UTF-16 扫描：检测交替 null 字节模式。
        le=True 为 UTF-16LE，le=False 为 UTF-16BE。
        """
        _r: List[Tuple[int, str, str]] = []
        _enc = 'UTF-16LE' if le else 'UTF-16BE'
        _null_pos = 1 if le else 0  # null 字节偏移：LE 为高字节(offset+1)，BE 为低字节(offset+0)
        _run_start = -1
        _run_bytes = bytearray()
        _n = len(data)

        for _i in range(0, _n - 1, 2):
            _lo = data[_i]
            _hi = data[_i + 1]
            _null_byte = _hi if le else _lo
            _char_byte = _lo if le else _hi

            if _null_byte == 0x00 and _char_byte in _ASCII_PRINTABLE:
                if _run_start < 0:
                    _run_start = _i
                _run_bytes.append(_char_byte)
            else:
                if _run_start >= 0 and len(_run_bytes) >= self._min:
                    try:
                        _decoded = _run_bytes.decode('ascii')
                        _r.append((_run_start, _decoded, _enc))
                    except UnicodeDecodeError:
                        pass
                _run_start = -1
                _run_bytes.clear()

        if _run_start >= 0 and len(_run_bytes) >= self._min:
            try:
                _decoded = _run_bytes.decode('ascii')
                _r.append((_run_start, _decoded, _enc))
            except UnicodeDecodeError:
                pass
        return _r

    def extract_strings(self, data: bytes) -> List[Tuple[int, str, str]]:
        """三路扫描入口：ASCII → UTF-16LE → UTF-16BE。
        返回 [(offset, string, encoding), ...]。
        """
        if not data:
            return []
        _all = []
        _all.extend(self._scan_ascii(data))
        _all.extend(self._scan_utf16(data, le=True))
        _all.extend(self._scan_utf16(data, le=False))
        # 按偏移升序排列
        _all.sort(key=lambda x: x[0])
        return _all


# //// YARA 规则骨架 ////
_DANGEROUS_STRINGS = {
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
    "CreateRemoteThread", "NtUnmapViewOfSection", "LoadLibrary",
    "GetProcAddress", "WinExec", "URLDownloadToFile",
    "RegSetValueEx", "RegCreateKeyEx", "CreateProcess",
    "socket", "connect", "send", "recv", "bind",
}

_YARA_TEMPLATE = """rule {rule_name} {{
    meta:
        description = "Auto-generated rule from extracted strings"
        author = "BinMind info_collection"
        date = "2026-07-16"
        score = 60
    strings:
{string_defs}
    condition:
        any of them
}}"""

def generate_yara_skeleton(strings: list, rule_name: str = "auto_generated") -> str:
    """从提取字符串构造 YARA 扫描规则骨架。
    仅保留安全相关字符串（危险 API、路径、URL、注册表键），避免普通库函数误报。
    """
    if not strings:
        return _YARA_TEMPLATE.format(rule_name=rule_name, string_defs="        $s0 = \"NONE\"")

    _filtered = []
    _seen = set()
    _idx = 0
    for _s in strings:
        _text = _s[1] if isinstance(_s, tuple) else _s
        _text_lower = _text.lower()
        _include = False
        for _kw in _DANGEROUS_STRINGS:
            if _kw.lower() in _text_lower:
                _include = True
                break
        if not _include:
            for _c in _text_lower:
                if _c in {'\\', '/', '.dll', '.exe', '.sys', 'hkey_'}:
                    _include = True
                    break
        if _include and _text not in _seen and len(_text) <= 256:
            _seen.add(_text)
            _escaped = _text.replace('\\', '\\\\').replace('"', '\\"')
            _filtered.append(f'        ${"s"}{_idx} = "{_escaped}" nocase wide ascii')
            _idx += 1

    if not _filtered:
        _filtered.append('        $s0 = "NONE"')

    return _YARA_TEMPLATE.format(
        rule_name=rule_name,
        string_defs="\n".join(_filtered),
    )
