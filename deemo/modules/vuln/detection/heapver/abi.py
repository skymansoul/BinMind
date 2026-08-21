# coding: utf-8
#
"""
ABI 与危险函数签名表。

堆溢出检测的两个核心事实来源:
  1. 分配函数 (malloc/calloc/realloc) 的 size 参数寄存器位置
  2. 写入函数 (memcpy/memset/strncpy/read/recv...) 的 dst/size 参数位置

同时支持 System V (Linux ELF) 与 Microsoft x64 (MinGW/Windows PE) 两种调用约定。
解析时对每个参数位置尝试两个约定下的候选寄存器名, 取首个可解析者——
实际编译产物只会设置其中一套, 该策略天然适配目标 ABI。

每条签名标注:
  sig  函数名
  args 参数列表 [(作用, 参数索引), ...]
  unbounded 是否为无界写入 (strcpy/gets/sprintf 等, 无显式 size)
"""

from typing import Dict, List, Optional, Tuple

# 分配函数 → (abi, 大小参数寄存器名列表按参数序)
# SysV: malloc(size=rdi) calloc(n=rdi,size=rsi) realloc(ptr=rdi,size=rsi)
# Win64: malloc(size=rcx) calloc(n=rcx,size=rdx) realloc(ptr=rcx,size=rdx)
ALLOC_FUNCS = {
    "malloc": {"sysv": [("size", ["rdi", "edi"])],
               "win64": [("size", ["rcx", "ecx"])]},
    "calloc": {"sysv": [("n", ["rdi", "edi"]), ("size", ["rsi", "esi"])],
               "win64": [("n", ["rcx", "ecx"]), ("size", ["rdx", "edx"])]},
    "realloc": {"sysv": [("ptr", ["rdi", "edi"]), ("size", ["rsi", "esi"])],
                "win64": [("ptr", ["rcx", "ecx"]), ("size", ["rdx", "edx"])]},
    "_Znwm": {"sysv": [("size", ["rdi", "edi"])],
              "win64": [("size", ["rcx", "ecx"])]},
    "_Znam": {"sysv": [("size", ["rdi", "edi"])],
              "win64": [("size", ["rcx", "ecx"])]},
}

# 写入函数: dst 参数索引 + size 参数索引 (按函数内参数位置)
# size_idx == -1 表示无界 (strcpy/strcat/gets)
WRITE_FUNCS = {
    "memcpy": {"sysv": (0, 2, ["rdi", "edi"], ["rdx", "edx"]),
               "win64": (0, 2, ["rcx", "ecx"], ["r8", "r8d"])},
    "memmove": {"sysv": (0, 2, ["rdi", "edi"], ["rdx", "edx"]),
                "win64": (0, 2, ["rcx", "ecx"], ["r8", "r8d"])},
    "memset": {"sysv": (0, 2, ["rdi", "edi"], ["rdx", "edx"]),
               "win64": (0, 2, ["rcx", "ecx"], ["r8", "r8d"])},
    "strncpy": {"sysv": (0, 2, ["rdi", "edi"], ["rdx", "edx"]),
                "win64": (0, 2, ["rcx", "ecx"], ["r8", "r8d"])},
    "strncat": {"sysv": (0, 2, ["rdi", "edi"], ["rdx", "edx"]),
                "win64": (0, 2, ["rcx", "ecx"], ["r8", "r8d"])},
    "strcpy": {"sysv": (0, -1, ["rdi", "edi"], []),
               "win64": (0, -1, ["rcx", "ecx"], [])},
    "strcat": {"sysv": (0, -1, ["rdi", "edi"], []),
               "win64": (0, -1, ["rcx", "ecx"], [])},
    "sprintf": {"sysv": (0, -1, ["rdi", "edi"], []),
                "win64": (0, -1, ["rcx", "ecx"], [])},
    "gets": {"sysv": (0, -1, ["rdi", "edi"], []),
             "win64": (0, -1, ["rcx", "ecx"], [])},
    "read": {"sysv": (1, 2, ["rsi", "esi"], ["rdx", "edx"]),
             "win64": (1, 2, ["rdx", "edx"], ["r8", "r8d"])},
    "fread": {"sysv": (1, 2, ["rsi", "esi"], ["rdx", "edx"]),
              "win64": (0, 3, ["rcx", "ecx"], ["r9", "r9d"])},
    "recv": {"sysv": (1, 2, ["rsi", "esi"], ["rdx", "edx"]),
             "win64": (1, 2, ["rdx", "edx"], ["r8", "r8d"])},
    "recvfrom": {"sysv": (1, 2, ["rsi", "esi"], ["rdx", "edx"]),
                 "win64": (1, 2, ["rdx", "edx"], ["r8", "r8d"])},
    "fgets": {"sysv": (0, 1, ["rdi", "edi"], ["rsi", "esi"]),
              "win64": (0, 1, ["rcx", "ecx"], ["rdx", "edx"])},
}

# 无界 API 集合 (sprintf 仅当 format 含 %s 且无宽度才真正无界, 此处保守)
UNBOUNDED_API = frozenset({"strcpy", "strcat", "gets", "sprintf"})

# 释放函数
FREE_FUNCS = {
    "free": {"sysv": (0, ["rdi", "edi"]), "win64": (0, ["rcx", "ecx"])},
    "_ZdlPv": {"sysv": (0, ["rdi", "edi"]), "win64": (0, ["rcx", "ecx"])},
    "_ZdaPv": {"sysv": (0, ["rdi", "edi"]), "win64": (0, ["rcx", "ecx"])},
}


def find_alloc(fname: str) -> Optional[str]:
    for key in ALLOC_FUNCS:
        if key in fname:
            return key
    return None


def find_write(fname: str) -> Optional[str]:
    for key in WRITE_FUNCS:
        if key in fname:
            return key
    return None


def find_free(fname: str) -> Optional[str]:
    for key in FREE_FUNCS:
        if key in fname:
            return key
    return None


__all__ = [
    "ALLOC_FUNCS", "WRITE_FUNCS", "FREE_FUNCS", "UNBOUNDED_API",
    "find_alloc", "find_write", "find_free",
]
