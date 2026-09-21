"""
守卫感知区间验证 类型定义 — 栈守卫感知验证器共用类型.
Guard-Bounded Write Proof 的数据载体.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Set, Tuple


class SoVerdict(Enum):
    VULN = "VULN"
    SAFE = "SAFE"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class BufferDesc:
    """栈缓冲区描述符."""
    name: str               # 变量名
    size: int               # 字节大小; -1=VLA, -2=alloca
    kind: str               # fixed|vla|alloca|struct_field
    line: int = 0
    base_buf: str = ""      # 别名解析后的根缓冲区名
    offset: int = 0         # 在根缓冲区内的偏移(struct field)
    elem_size: int = 1      # 元素大小(char=1, int=4)
    aliases: Set[str] = field(default_factory=set)  # 指向此缓冲区的别名集合


@dataclass
class WriteDesc:
    """对栈缓冲区的写入操作."""
    line: int
    target: str             # 写入目标变量名(可能为别名)
    resolved_buf: str = ""  # 别名解析后的根缓冲区名
    kind: str = ""          # gets|strcpy|strcat|sprintf|scanf|sscanf|read|memcpy|
                            # memset|strncpy|snprintf|fgets|strncat|memmove|oob|loop_copy
    write_size: int = -1    # -1=unbounded, >=0=常量, -2=variable, -3=sizeof(expr)
    src_var: str = ""       # 源变量
    guard_cond: str = ""    # 所在路径的守卫条件(如 "len<32")
    func_name: str = ""     # 所在函数名


@dataclass
class GuardConstraint:
    """路径守卫约束."""
    var: str                # 被约束的变量名
    op: str                 # <, <=, >, >=, ==, !=
    bound: int              # 约束边界值
    line: int = 0           # 守卫所在行号
    is_else: bool = False   # 是否else分支


@dataclass
class ValueRange:
    """值范围区间."""
    lo: int = 0             # 下界
    hi: int = 0x7FFFFFFF    # 上界(默认无界)
    is_const: bool = False  # 是否常量


@dataclass
class SoResult:
    """守卫感知区间验证 验证结果."""
    verdict: SoVerdict
    buffer_line: int = 0
    write_line: int = 0
    buf_name: str = ""
    buf_size: int = 0
    write_size: int = -1
    confidence: float = 0.0
    reason: str = ""
    guard_info: str = ""    # 守卫分析信息


__all__ = [
    'SoVerdict', 'BufferDesc', 'WriteDesc', 'GuardConstraint',
    'ValueRange', 'SoResult',
]
