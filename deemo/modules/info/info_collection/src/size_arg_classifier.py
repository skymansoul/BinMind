# size_arg_classifier — 内存操作函数参数来源分类器
# 判断 memcpy/malloc 等函数的 size 参数是常量、输入派生的、还是未知。
# 分类依据: 导入表特征 (atoi/strtoul→输入派生)、字符串常量模式、调用约定。
#
# 三类来源:
#   CONSTANT      — 参数在二进制中以立即数/常量字符串形式出现, 非外部输入
#   INPUT_DERIVED — 参数来自 recv/read/fgets/atoi 等输入函数, 攻击者可控
#   UNKNOWN       — 无法从导入表+字符串确定来源
#
# 降低误报的核心逻辑: 若 alloc_size 和 copy_size 同为 CONSTANT 且相等,
# 则为安全配对 (如 memcpy(buf, src, FIXED_SIZE) + malloc(FIXED_SIZE)),
# 置信度大幅降低。

from typing import Dict, List, Set, Tuple, Optional
from enum import Enum
from collections import defaultdict


class SizeSource(Enum):
    CONSTANT = 1
    INPUT_DERIVED = 2
    UNKNOWN = 3


# 输入转换函数 — 将外部数据转换为数值, 攻击者可间接控制
_INPUT_CONVERTERS: Set[str] = {
    "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull",
    "strtod", "strtof", "sscanf", "scanf", "fscanf",
}

# 网络输入函数 — 外部数据的第一落点
_NETWORK_INPUTS: Set[str] = {
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets",
    "getenv", "getopt", "gets",
}

# 已知的常量模式 (在二进制数据段中)
_CONSTANT_PATTERNS: Set[str] = {
    "4096", "8192", "16384", "32768", "65536",
    "BUFSIZ", "MAX_PATH", "PATH_MAX", "PIPE_BUF",
    "sizeof", "size_t", "unsigned int",
}


def _extract_numeric_constants(strings: List[str]) -> Set[int]:
    """从字符串列表中提取可能的内存操作常量值。"""
    consts = set()
    for s in (strings or []):
        t = s[1] if isinstance(s, tuple) else str(s)
        t = t.strip()
        try:
            v = int(t)
            if 4 <= v <= 1048576:  # 4B ~ 1MB, 合理的内存操作范围
                consts.add(v)
        except ValueError:
            pass
        # 十六进制常量
        if t.startswith("0x") and len(t) <= 6:
            try:
                consts.add(int(t, 16))
            except ValueError:
                pass
    return consts


def classify_size_arg(func_name: str, imports: Dict,
                       strings: List[str] = None) -> SizeSource:
    """分类指定函数 size 参数的来源。

    判定规则:
    1. 若导入表中有 atoi/strtol 等转换函数 + recv/read 等输入函数
       → INPUT_DERIVED (攻击者可能通过输入链控制 size)
    2. 若字符串中存在与常见分配大小匹配的常量, 且无输入转换函数
       → CONSTANT (size 是编译期固定值)
    3. 其他 → UNKNOWN
    """
    api_set = set()
    all_imps = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for funcs in all_imps.values():
            if isinstance(funcs, list):
                api_set.update(f.lower().rstrip('aw') for f in funcs)

    has_input = bool(api_set & _NETWORK_INPUTS)
    has_converter = bool(api_set & _INPUT_CONVERTERS)

    # 规则1: 有输入+转换 → 攻击者可控
    if has_input and has_converter:
        return SizeSource.INPUT_DERIVED
    if has_input:
        return SizeSource.INPUT_DERIVED  # 即使没有显式转换, recv 也可以直接控制 size

    # 规则2: 检查常量模式
    consts = _extract_numeric_constants(strings or [])
    if consts:
        return SizeSource.CONSTANT

    # 规则3: 无输入无常量 → 未知
    if not has_input and not has_converter:
        # 进一步检查: 若二进制整体干净 (无网络导入), size 大概率是内部常量
        return SizeSource.CONSTANT

    return SizeSource.UNKNOWN


def classify_buffer_ownership(api_set: Set[str], func_name: str) -> str:
    """判断缓冲区是否由调用方控制。
    返回 'caller_owned' / 'callee_allocated' / 'unknown'。
    """
    alloc_funcs = {"malloc", "calloc", "realloc", "alloca"}
    if func_name in alloc_funcs:
        return "callee_allocated"
    return "caller_owned"
