"""
栈溢出源级检测类型定义 — SOSV (Stack Overflow Source Verifier) 共用类型.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class SoVerdict(Enum):
    VULN = "VULN"
    SAFE = "SAFE"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class StackBuffer:
    """栈缓冲区."""
    line: int
    name: str
    size: int            # -1=VLA, -2=alloca, >=0=fixed
    kind: str            # 'fixed'|'vla'|'alloca'


@dataclass
class StackWrite:
    """对栈缓冲区的写入操作."""
    line: int
    target: str          # 目标缓冲区名
    kind: str            # gets|strcpy|strcat|sprintf|scanf|read|memcpy|memset|oob
    write_size: int = -1 # -1=unbounded, >=0=常量, -2=variable
    src_var: str = ""    # 源变量 (strcpy/strcat/oob等)


@dataclass
class SoResult:
    """SOSV判定结果."""
    verdict: SoVerdict
    buffer_line: int = 0
    write_line: int = 0
    buf_name: str = ""
    buf_size: int = 0
    write_size: int = -1
    confidence: float = 0.0
    reason: str = ""


__all__ = ['SoVerdict', 'StackBuffer', 'StackWrite', 'SoResult']
