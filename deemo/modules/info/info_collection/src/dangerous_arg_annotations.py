# Created: 2025-07-28 09:15:00
#
# dangerous_arg_annotations — 危险函数参数位置标注与调用约定推断
# 为每个危险函数标注哪个参数是攻击者可控的攻击面（如 memcpy 的 size 参数、
# printf 的 format 参数），并结合二进制格式推断默认调用约定下的参数传递方式。
#
# 三层分类:
#   PARAM_SOURCE  — 该参数来自外部输入（网络/文件/环境变量），需重点审查
#   PARAM_SIZE    — 该参数控制内存操作的大小，溢出类漏洞的攻击面
#   PARAM_FORMAT  — 该参数是格式控制串，格式串漏洞的攻击面
#   PARAM_TARGET  — 该参数是写入目标地址，任意写原语的攻击面
#   PARAM_CODE    — 该参数会被当作代码执行，代码注入的攻击面

from enum import Enum
from typing import Dict, List, Tuple, Set, Optional


class ParamRole(Enum):
    PARAM_SOURCE = 1   # 外部数据来源
    PARAM_SIZE = 2     # 控制大小的参数
    PARAM_FORMAT = 3   # 格式控制串
    PARAM_TARGET = 4   # 写入目标
    PARAM_CODE = 5     # 代码执行目标
    PARAM_FLAGS = 6    # 控制保护位/权限


# 危险函数参数注解: (函数名归一化形式, [(参数位置0-based, 角色, 危险度0-1), ...])
# 参数位置基于常见调用约定中的参数顺序
_DANGEROUS_ARG_MAP: Dict[str, List[Tuple[int, ParamRole, float]]] = {
    # ---- 内存操作 (溢出/越界) ----
    "memcpy":  [(2, ParamRole.PARAM_SIZE, 0.80), (0, ParamRole.PARAM_TARGET, 0.60)],
    "memmove": [(2, ParamRole.PARAM_SIZE, 0.75), (0, ParamRole.PARAM_TARGET, 0.55)],
    "memset":  [(2, ParamRole.PARAM_SIZE, 0.70), (0, ParamRole.PARAM_TARGET, 0.50)],
    "bcopy":   [(2, ParamRole.PARAM_SIZE, 0.70), (0, ParamRole.PARAM_TARGET, 0.50)],
    "strcpy":  [(1, ParamRole.PARAM_SOURCE, 0.70), (0, ParamRole.PARAM_TARGET, 0.60)],
    "strcat":  [(1, ParamRole.PARAM_SOURCE, 0.65), (0, ParamRole.PARAM_TARGET, 0.55)],
    "sprintf": [(0, ParamRole.PARAM_TARGET, 0.60), (1, ParamRole.PARAM_FORMAT, 0.75)],
    "vsprintf":[(0, ParamRole.PARAM_TARGET, 0.55), (1, ParamRole.PARAM_FORMAT, 0.75)],
    "snprintf":[(1, ParamRole.PARAM_SIZE, 0.40), (2, ParamRole.PARAM_FORMAT, 0.45)],
    "gets":    [(0, ParamRole.PARAM_TARGET, 0.90)],
    "scanf":   [(0, ParamRole.PARAM_FORMAT, 0.80)],
    "sscanf":  [(1, ParamRole.PARAM_FORMAT, 0.75)],
    "read":    [(1, ParamRole.PARAM_TARGET, 0.55), (2, ParamRole.PARAM_SIZE, 0.45)],
    "fread":   [(3, ParamRole.PARAM_SIZE, 0.40), (0, ParamRole.PARAM_TARGET, 0.40)],
    "recv":    [(1, ParamRole.PARAM_SIZE, 0.50), (0, ParamRole.PARAM_TARGET, 0.45)],
    "recvfrom":[(1, ParamRole.PARAM_SIZE, 0.45), (0, ParamRole.PARAM_TARGET, 0.40)],

    # ---- 格式字符串 ----
    "printf":  [(0, ParamRole.PARAM_FORMAT, 0.85)],
    "fprintf": [(1, ParamRole.PARAM_FORMAT, 0.85)],
    "dprintf": [(1, ParamRole.PARAM_FORMAT, 0.80)],
    "vprintf": [(0, ParamRole.PARAM_FORMAT, 0.80)],
    "syslog":  [(1, ParamRole.PARAM_FORMAT, 0.70)],

    # ---- 代码执行 ----
    "system":  [(0, ParamRole.PARAM_CODE, 0.90)],
    "popen":   [(0, ParamRole.PARAM_CODE, 0.85)],
    "execve":  [(0, ParamRole.PARAM_CODE, 0.90), (1, ParamRole.PARAM_SOURCE, 0.60)],
    "execvp":  [(0, ParamRole.PARAM_CODE, 0.85), (1, ParamRole.PARAM_SOURCE, 0.55)],
    "dlopen":  [(0, ParamRole.PARAM_CODE, 0.70)],

    # ---- 内存保护修改 ----
    "mprotect":       [(2, ParamRole.PARAM_FLAGS, 0.80), (0, ParamRole.PARAM_TARGET, 0.50)],
    "virtualprotect": [(1, ParamRole.PARAM_SIZE, 0.50), (3, ParamRole.PARAM_FLAGS, 0.80)],
    "mmap":           [(3, ParamRole.PARAM_FLAGS, 0.55)],

    # ---- 堆操作 (UAF/double-free 相关) ----
    "malloc":  [(0, ParamRole.PARAM_SIZE, 0.30)],
    "free":    [(0, ParamRole.PARAM_TARGET, 0.70)],
    "realloc": [(0, ParamRole.PARAM_TARGET, 0.65), (1, ParamRole.PARAM_SIZE, 0.35)],
    "calloc":  [(1, ParamRole.PARAM_SIZE, 0.30)],
}


# 安全变体映射: 危险函数 → 其安全替代
_SAFE_ALTERNATIVES: Dict[str, str] = {
    "strcpy": "strncpy", "strcat": "strncat",
    "sprintf": "snprintf", "vsprintf": "vsnprintf",
    "gets": "fgets", "scanf": "scanf_s",
    "memcpy": "memcpy_s", "memmove": "memmove_s",
    "strtok": "strtok_s", "wcscpy": "wcsncpy",
    "read": "pread", "recv": "recvmsg",
}

# 输入验证函数模式 — 导入表中存在这些说明开发者有意识做输入净化
_INPUT_VALIDATION_PATTERNS: Set[str] = {
    "is_valid", "validate", "sanitize", "check_bounds", "verify",
    "assert", "bounds_check", "range_check", "length_check",
}


def get_arg_annotations(func_name: str) -> List[Tuple[int, ParamRole, float]]:
    """获取函数的参数注解列表。返回 [(position, role, severity), ...]。"""
    clean = func_name.lower().rstrip('aw')
    return _DANGEROUS_ARG_MAP.get(clean, [])


def has_safe_alternative(func_name: str, api_set: Set[str]) -> bool:
    """检查导入表中是否存在该函数的安全替代。"""
    alt = _SAFE_ALTERNATIVES.get(func_name.lower().rstrip('aw'))
    if not alt:
        return False
    return alt in api_set or any(
        alt in a for a in api_set
    )


def has_input_validation(api_set: Set[str]) -> bool:
    """检查导入表中是否存在输入验证函数。"""
    return any(
        any(pattern in api for pattern in _INPUT_VALIDATION_PATTERNS)
        for api in api_set
    )


def infer_calling_convention(binary_format: str, arch: str) -> Dict:
    """从二进制格式和架构推断默认调用约定下的参数传递方式。
    x86: cdecl (栈传参，右→左压栈)
    x86-64 System V: rdi, rsi, rdx, rcx, r8, r9, then stack
    ARM64: x0-x7, then stack
    """
    fmt = binary_format.upper() if binary_format else "UNKNOWN"
    arch_lower = (arch or "").lower()

    if "x86_64" in arch_lower or "amd64" in arch_lower or "x64" in arch_lower:
        return {"convention": "system_v_amd64",
                "reg_args": ["rdi","rsi","rdx","rcx","r8","r9"],
                "stack_alignment": 16, "max_reg_args": 6}
    elif "aarch64" in arch_lower or "arm64" in arch_lower:
        return {"convention": "aapcs64",
                "reg_args": ["x0","x1","x2","x3","x4","x5","x6","x7"],
                "stack_alignment": 16, "max_reg_args": 8}
    elif "arm" in arch_lower:
        return {"convention": "aapcs32",
                "reg_args": ["r0","r1","r2","r3"],
                "stack_alignment": 8, "max_reg_args": 4}
    elif "i386" in arch_lower or "x86" in arch_lower:
        return {"convention": "cdecl",
                "reg_args": [],
                "stack_alignment": 4, "max_reg_args": 0}
    elif fmt == "PE":
        return {"convention": "ms_x64" if "64" in arch_lower else "stdcall",
                "reg_args": ["rcx","rdx","r8","r9"] if "64" in arch_lower else [],
                "stack_alignment": 16 if "64" in arch_lower else 4,
                "max_reg_args": 4 if "64" in arch_lower else 0}
    return {"convention": "unknown", "reg_args": [], "stack_alignment": 4, "max_reg_args": 0}


def arg_passed_via_register(arg_index: int, calling_conv: Dict) -> bool:
    """判断索引为 arg_index 的参数是否通过寄存器传递。"""
    return arg_index < calling_conv.get("max_reg_args", 0)
