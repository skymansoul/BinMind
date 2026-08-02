# 2026-07-16
# utils — 字符串分类/熵/提取/YARA生成
# Stringy-inspired 分类器：多模式正则，返回最具体匹配
# 熵用标量 Shannon，不做滑动窗口（交给调用方决定窗口策略）

import math
import re
from collections import Counter
from typing import List, Tuple, Optional

# ---- 预编译正则：一次性编译，避免每次调用重新解析 ----
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
    """对单条字符串做多模式分类，返回最精确的类别。

    对齐 Stringy 思路：URL > IP > DOMAIN > REGISTRY > GUID > BASE64 > PASSWORD 常量,
    按具体性降序检查，先匹配的优先返回。
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

        # 优先 URL —— 包含协议前缀，最具体
        if _URL_PAT.match(_s):
            return "URL"

        # IPv6 优先于 IPv4（IPv4 可能被错误匹配）
        if _IPV6_PAT.match(_s):
            return "IPV6"

        if _IPV4_PAT.match(_s):
            return "IPV4"

        # 域名：至少一个点，TLD 字母
        if _DOMAIN_PAT.match(_s):
            return "DOMAIN"

        if _REGISTRY_PAT.match(_s):
            return "REGISTRY_PATH"

        if _GUID_PAT.match(_s):
            return "GUID"

        # BASE64 特征：字符集 + 末尾等号填充
        if len(_s) >= 4 and _BASE64_PAT.match(_s):
            return "BASE64"

        if _PASSWORD_CONST_PAT.match(_s):
            return "PASSWORD_CONSTANT"

        return "UNKNOWN"


def shannon_entropy(data: bytes) -> float:
    """标准 Shannon 熵，输出 [0, 8] 范围。
    不设窗口 —— 调用方决定分片策略。
    """
    if not data:
        return 0.0
    _n = len(data)
    _cnt = Counter(data)
    _h = 0.0
    for _c in _cnt.values():
        _p = _c / _n
        _h -= _p * math.log2(_p)
    return _h


# ===== 可打印字符范围 =====
_ASCII_PRINTABLE = set(range(0x20, 0x7F))  # space (0x20) 到 ~ (0x7E)
_ASCII_PRINTABLE_WITH_TAB_NL = set(range(0x09, 0x0B)) | set(range(0x20, 0x7F))
_ASCII_PRINTABLE_WITH_TAB_NL.discard(0x0A)  # 保留 \n
_ASCII_PRINTABLE_WITH_TAB_NL.add(0x0A)


class StringExtractor:
    """三元扫描提取字符串：ASCII、UTF-16LE、UTF-16BE。

    设计权衡：不做全编码探测（如 UTF-32、EBCDIC）—— 三路扫描覆盖
    绝大多数 Windows 二进制（PE 资源以 UTF-16LE 为主）和 Linux 二进制
    （ASCII 为主）。每路扫描 O(n)，总 O(3n)。
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
        """UTF-16 扫描：检查交替 null 字节模式。
        le=True  -> UTF-16LE（低字节在前，偶数字节为 null）
        le=False -> UTF-16BE（高字节在前，奇数字节为 null）
        """
        _r: List[Tuple[int, str, str]] = []
        _enc = 'UTF-16LE' if le else 'UTF-16BE'
        _null_pos = 1 if le else 0  # null 字节在奇数还是偶数位置
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
        """三路扫描：ASCII -> UTF-16LE -> UTF-16BE。

        Returns: [(offset, string, encoding), ...]
        """
        if not data:
            return []
        _all = []
        _all.extend(self._scan_ascii(data))
        _all.extend(self._scan_utf16(data, le=True))
        _all.extend(self._scan_utf16(data, le=False))
        # 按偏移量排序
        _all.sort(key=lambda x: x[0])
        return _all


# //// YARA 规则骨架生成 ////
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
    """从提取的字符串自动生成 YARA 扫描规则骨架。

    过滤策略：仅保留疑似安全相关的字符串（危险 API、路径、URL、注册表键），
    避免把普通库函数拉入规则导致误报泛滥。
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
