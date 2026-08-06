# leak_analyzer — 格式化字符串泄露 + OOB 读检测
# 双层检测：导入表扫描 + 字符串模式匹配
# 不做数据流分析（需 CFG），仅静态特征

import os
import re
from typing import List, Dict, Tuple, Set

# 格式化函数列表：(函数名, fmt参数位置, 风险权重)
_FORMAT_FUNC_PATTERNS = [
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

# 非字面量格式字符串的识别模式
_NON_LITERAL_FORMAT_INDICATORS = [
    r'%\d*\$\w',
    r'%[nN]',
    r'%\*',
]

# OOB 读相关内存操作函数
_OOB_READ_FUNCTIONS = [
    "memcpy", "memmove", "bcopy", "strcpy", "strcat", "strncpy",
    "strncat", "sprintf", "vsprintf", "snprintf", "gets",
    "read", "fread", "recv", "recvfrom", "recvmsg",
    "CopyMemory", "RtlCopyMemory", "memcpy_s", "strcpy_s",
    "wmemcpy", "wcscpy", "wcscat",
]

# 无边界检查的调用模式
_OOB_READ_STRINGS_PATTERNS = [
    r"(memcpy|memmove|strcpy|strcat)\s*\([^,]*,\s*[^,]*,\s*(?!sizeof)",
    r"(gets|scanf)\(",
    r"(recv|recvfrom|recvmsg)\(",
    r"copy_from_user\s*\(",
    r"copy_to_user\s*\(",
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


def detect_format_string_leaks(imports: dict = None, strings: list = None,
                                use_arg_annotations: bool = True) -> List[dict]:
    """检测 printf 族调用中的非字面量格式串。
    启用 use_arg_annotations 时使用 dangerous_arg_annotations 模块的参数
    位置感知标注替代原有的固定权重表。格式串漏洞的三要素评估:
    (a) 导入表含格式函数 (b) 字符串中无显式格式字面量 (c) 参数位置0是格式控制串
    """
    _findings = []
    _api_set = set()
    if imports:
        _api_set = _extract_api_set(imports)
    _str_text = ""
    if strings:
        _str_text = _get_strings_text(strings)

    if use_arg_annotations:
        from .dangerous_arg_annotations import get_arg_annotations, ParamRole
        _fmt_funcs = ["printf","fprintf","sprintf","snprintf","dprintf",
                      "vprintf","vfprintf","vsprintf","vsnprintf","syslog"]
        _weights = {"printf":7,"fprintf":7,"sprintf":7,"snprintf":5,"dprintf":7,
                    "vprintf":7,"vfprintf":7,"vsprintf":7,"vsnprintf":5,"syslog":6}
    else:
        _fmt_funcs = [p[0].lower() for p in _FORMAT_FUNC_PATTERNS]
        _weights = {p[0].lower(): p[2] for p in _FORMAT_FUNC_PATTERNS}

    for _fn in _fmt_funcs:
        _found = _fn in _api_set
        if not _found and strings:
            _found = re.search(r'\b' + re.escape(_fn) + r'\b', _str_text, re.IGNORECASE)
        if not _found:
            continue

        _risk = "LOW"
        _detail = f"Format function '{_fn}' detected"

        # 参数位置感知增强: 检查 format 参数是否在位置0（用户最易控制的位置）
        if use_arg_annotations:
            _annotations = get_arg_annotations(_fn)
            _fmt_params = [a for a in _annotations if a[1] == ParamRole.PARAM_FORMAT]
            if _fmt_params and _fmt_params[0][0] == 0:
                _risk = "MEDIUM"
                _detail += " — format 参数在位置0（最易受用户输入控制）"

        _has_format_literal = bool(re.search(r'\"[^\"]*%[^\"]*\"', _str_text))
        _has_percent_n = bool(re.search(r'%n', _str_text))

        if _has_percent_n:
            _risk = "HIGH"
            _detail = f"Format function '{_fn}' with %n (write primitive)"
        elif _fn in ("printf", "fprintf", "sprintf", "snprintf") and not _has_format_literal:
            _risk = "MEDIUM"
            _detail = f"Format function '{_fn}' without visible format literal - potential fmtstr vulnerability"

        _has_positional = any(re.search(p, _str_text) for p in _NON_LITERAL_FORMAT_INDICATORS)
        if _has_positional:
            _risk = "MEDIUM"

        _weight = _weights.get(_fn, 4)
        _findings.append({
            "type": "format_string", "function": _fn,
            "risk": _risk, "weight": _weight,
            "detail": _detail,
        })

    return _findings


def detect_oob_reads(imports: dict = None, strings: list = None, sections: list = None) -> List[dict]:
    """检测越界读写模式。
    导入表危险函数 + 字符串中无 sizeof/长度限制的调用 + W+X 段叠加判定。
    """
    _findings = []
    _api_set = set()
    if imports:
        _api_set = _extract_api_set(imports)

    _str_text = ""
    if strings:
        _str_text = _get_strings_text(strings)

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


def analyze(filepath: str, imports: dict = None, strings: list = None, sections: list = None) -> dict:
    """信息泄露综合分析入口。
    汇总格式化串泄露 + OOB 读发现，按 HIGH/MEDIUM 数量定级。
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

    if os.path.isfile(filepath):
        _r["size"] = os.path.getsize(filepath)

    return _r
