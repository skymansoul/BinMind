# 2026-07-25
# leak_analyzer — 信息泄露分析：格式化字符串 / OOB 读 / 未初始化内存
# 检测方法：导入表扫描 + 字符串模式匹配 + section 特征交叉验证
# 权衡：不做数据流分析（需要控制流图），仅静态特征检测

import os
import re
from typing import List, Dict, Tuple, Set

# ---- 格式化字符串函数 ----
_FORMAT_FUNC_PATTERNS = [
    # (函数名, fmt_arg_position, 风险权重)
    ("printf", 0, 7),
    ("fprintf", 1, 7),
    ("sprintf", 1, 7),
    ("snprintf", 2, 5),
    ("syslog", 1, 6),
    ("vsyslog", 1, 6),
    ("FormatMessage", 3, 4),
    ("FormatMessageA", 3, 4),
    ("FormatMessageW", 3, 4),
    ("dprintf", 1, 7),
    ("vprintf", 0, 7),
    ("vfprintf", 1, 7),
    ("vsprintf", 1, 7),
    ("vsnprintf", 2, 5),
    ("scanf", 0, 6),
    ("fscanf", 1, 6),
    ("sscanf", 1, 6),
    ("setproctitle", 1, 4),
    ("err", 1, 4),
    ("verr", 1, 4),
    ("warn", 1, 4),
    ("vwarn", 1, 4),
    ("errx", 1, 4),
    ("warnx", 1, 4),
]

# 检测非字面量格式字符串的指标
_NON_LITERAL_FORMAT_INDICATORS = [
    r'%\d*\$\w',  # 位置参数 %1$d
    r'%[nN]',  # %n 写入攻击
    r'%\*',  # 宽度/精度来自参数而非字面量
]

# ---- OOB 读相关函数 ----
_OOB_READ_FUNCTIONS = [
    "memcpy", "memmove", "bcopy", "strcpy", "strcat", "strncpy",
    "strncat", "sprintf", "vsprintf", "snprintf", "gets",
    "read", "fread", "recv", "recvfrom", "recvmsg",
    "CopyMemory", "RtlCopyMemory", "memcpy_s", "strcpy_s",
    "wmemcpy", "wcscpy", "wcscat",
]

_OOB_READ_STRINGS_PATTERNS = [
    r"(memcpy|memmove|strcpy|strcat)\s*\([^,]*,\s*[^,]*,\s*(?!sizeof)",
    r"(gets|scanf)\(",  # 无条件危险
    r"(recv|recvfrom|recvmsg)\(",
    r"copy_from_user\s*\(",
    r"copy_to_user\s*\(",
    # sprintf 到局部缓冲区时无长度检查
    r"sprintf\s*\(\s*\w+,\s*\"[^\"]*%[^\"]*\"",
]


def _extract_api_set(imports: dict) -> Set[str]:
    _r = set()
    for _dll, _funcs in imports.items():
        for _f in _funcs:
            _r.add(_f.lower().strip())
    return _r


def _get_strings_text(strings: list) -> str:
    _s = []
    for _x in strings:
        _t = _x[1] if isinstance(_x, tuple) else _x
        _s.append(_t)
    return " ".join(_s)


# //// 格式化字符串泄露检测 ////
def detect_format_string_leaks(imports: dict = None, strings: list = None) -> List[dict]:
    """检测格式化字符串函数调用中潜在的非字面量格式字符串。

    原理：如果导入表中包含 printf 族函数 + 字符串中没有明显的格式字面量模式，
    则标记为潜在风险 —— 攻击者可能通过用户输入控制格式字符串。
    """
    _findings = []
    _api_set = set()
    if imports:
        _api_set = _extract_api_set(imports)

    _str_text = ""
    if strings:
        _str_text = _get_strings_text(strings)

    for _fn, _pos, _weight in _FORMAT_FUNC_PATTERNS:
        _fn_lower = _fn.lower()
        _found = _fn_lower in _api_set
        if not _found and strings:
            _found = re.search(r'\b' + re.escape(_fn_lower) + r'\b', _str_text, re.IGNORECASE)
        if not _found:
            continue

        _risk = "LOW"
        _detail = f"Format function '{_fn}' detected"

        # 检查是否有明显的格式字面量
        _has_format_literal = bool(re.search(r'\"[^\"]*%[^\"]*\"', _str_text))
        # 检查 %n 危险标记
        _has_percent_n = bool(re.search(r'%n', _str_text))

        if _has_percent_n:
            _risk = "HIGH"
            _detail = f"Format function '{_fn}' with %n (write primitive)"
        elif _fn in ("printf", "fprintf", "sprintf", "snprintf") and not _has_format_literal:
            _risk = "MEDIUM"
            _detail = f"Format function '{_fn}' without visible format literal - potential fmtstr vulnerability"

        # 位置参数泄露
        _has_positional = any(re.search(p, _str_text) for p in _NON_LITERAL_FORMAT_INDICATORS)
        if _has_positional:
            _risk = "MEDIUM"

        _findings.append({
            "type": "format_string", "function": _fn,
            "risk": _risk, "weight": _weight,
            "detail": _detail,
        })

    return _findings


# //// OOB 读检测 ////
def detect_oob_reads(imports: dict = None, strings: list = None, sections: list = None) -> List[dict]:
    """检测潜在的越界读/写模式。

    双层检测：
    1) 导入表中有危险内存操作函数
    2) 字符串中出现了无边界检查的调用模式 (memcpy 无 sizeof、strcpy 无长度限制)
    """
    _findings = []
    _api_set = set()
    if imports:
        _api_set = _extract_api_set(imports)

    _str_text = ""
    if strings:
        _str_text = _get_strings_text(strings)

    # 导入表检测
    _found_funcs = []
    for _f in _OOB_READ_FUNCTIONS:
        if _f.lower() in _api_set:
            _found_funcs.append(_f)

    if _found_funcs:
        _has_safe_variants = any(f"{x}_s" in _api_set or f"__{x}_chk" in _api_set for x in _found_funcs)
        _risk = "LOW" if _has_safe_variants else "MEDIUM"
        _findings.append({
            "type": "oob_read", "subtype": "imported_functions",
            "functions": _found_funcs, "risk": _risk,
            "has_safe_variants": _has_safe_variants,
            "detail": f"Memory copy functions without bounds checking: {', '.join(_found_funcs[:5])}",
        })

    # 字符串模式检测
    for _pat in _OOB_READ_STRINGS_PATTERNS:
        _matches = re.findall(_pat, _str_text, re.IGNORECASE)
        if _matches:
            for _m in _matches[:3]:
                _str_val = _m if isinstance(_m, str) else str(_m)
                _risk = "HIGH" if any(k in _str_val.lower() for k in ["gets", "scanf", "sprintf"]) else "MEDIUM"
                _findings.append({
                    "type": "oob_read", "subtype": "string_pattern",
                    "pattern": _str_val, "risk": _risk,
                    "detail": f"Unbounded memory operation: {_str_val[:80]}",
                })

    # 结合 section 特征：可写 + 可执行段 = 更危险
    if sections:
        _wx_sections = [s for s in sections if isinstance(s, dict) and
                        "MEM_WRITE" in str(s.get("characteristics", "")) and
                        "MEM_EXECUTE" in str(s.get("characteristics", ""))]
        if _wx_sections and _found_funcs:
            _findings.append({
                "type": "oob_read", "subtype": "wx_memory",
                "sections": [s.get("name", "") for s in _wx_sections],
                "risk": "HIGH",
                "detail": "W+X memory sections present with dangerous memory functions",
            })

    return _findings


# //// 综合分析入口 ////
def analyze(filepath: str, imports: dict = None, strings: list = None, sections: list = None) -> dict:
    """对二进制文件进行信息泄露综合分析。

    如果提供了 imports/strings/sections 则直接使用；否则尝试从文件路径提取基本信息。

    返回:
        { "format_string_leaks": [...], "oob_reads": [...],
          "total_issues": int, "risk_level": str }
    """
    _fmt_leaks = detect_format_string_leaks(imports, strings)
    _oob = detect_oob_reads(imports, strings, sections)

    _total = len(_fmt_leaks) + len(_oob)
    _high = sum(1 for f in _fmt_leaks if f["risk"] == "HIGH")
    _high += sum(1 for o in _oob if o["risk"] == "HIGH")
    _med = sum(1 for f in _fmt_leaks if f["risk"] == "MEDIUM")
    _med += sum(1 for o in _oob if o["risk"] == "MEDIUM")

    if _high >= 2:
        _level = "CRITICAL"
    elif _high >= 1 or _med >= 3:
        _level = "HIGH"
    elif _med >= 1:
        _level = "MEDIUM"
    elif _total > 0:
        _level = "LOW"
    else:
        _level = "CLEAN"

    _r = {
        "file": filepath,
        "format_string_leaks": _fmt_leaks,
        "oob_reads": _oob,
        "total_issues": _total,
        "high_issues": _high,
        "medium_issues": _med,
        "risk_level": _level,
    }

    # 如果可以，读取文件基本信息
    if os.path.isfile(filepath):
        _r["size"] = os.path.getsize(filepath)

    return _r
