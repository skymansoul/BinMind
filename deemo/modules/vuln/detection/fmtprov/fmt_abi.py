# coding: utf-8
# 创建: 2026-05-17  |  格式化字符串 ABI 与输入源定义
#
"""格式化函数签名与用户输入源集合."""

from typing import Dict, List

# fmt 参数索引 (0-based) → 各 ABI 候选寄存器
FORMAT_FUNCS: Dict[str, Dict] = {
    "printf": {"idx": 0, "win64": ["rcx", "ecx"], "sysv": ["rdi", "edi"]},
    "fprintf": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "sprintf": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "snprintf": {"idx": 2, "win64": ["r8", "r8d"], "sysv": ["rdx", "edx"]},
    "dprintf": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "syslog": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "vprintf": {"idx": 0, "win64": ["rcx", "ecx"], "sysv": ["rdi", "edi"]},
    "vfprintf": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "vsprintf": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "vsnprintf": {"idx": 2, "win64": ["r8", "r8d"], "sysv": ["rdx", "edx"]},
    "err": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "errx": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "warn": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
    "warnx": {"idx": 1, "win64": ["rdx", "edx"], "sysv": ["rsi", "esi"]},
}

# 用户输入源: 返回 rax / 写缓冲区
INPUT_FUNCS = frozenset({
    "scanf", "gets", "fgets", "read", "fread", "recv", "recvfrom",
    "getline", "getenv", "getc", "getchar", "fgetc", "fscanf",
    "__isoc99_scanf", "__isoc99_fscanf",
})


def find_format(callee: str):
    """匹配最长键 (__mingw_snprintf → snprintf, 而非 printf)."""
    best = None
    best_key = ""
    for key, sig in FORMAT_FUNCS.items():
        if key in callee and len(key) > len(best_key):
            best_key = key
            best = sig
    return (best_key, best) if best else (None, None)


__all__ = ["FORMAT_FUNCS", "INPUT_FUNCS", "find_format"]
