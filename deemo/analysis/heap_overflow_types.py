"""
堆溢出源级检测类型定义 — 堆写模式验证 (Heap Write Verification) 共用类型.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple, Dict


class HoVerdict(Enum):
    VULN = "VULN"
    SAFE = "SAFE"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class HeapAllocSite:
    """堆分配点."""
    line: int
    func: str             # malloc|calloc|realloc|alloca
    var: str              # 指针变量名
    size_expr: str        # 大小表达式原文
    size_const: int = -1  # -1=变量, -2=表达式, >=0=常量
    kind: str = "malloc"  # malloc|calloc|realloc


@dataclass
class HeapWriteSite:
    """对堆缓冲区的写入操作."""
    line: int
    target: str           # 目标指针/表达式
    kind: str             # memcpy|memset|strcpy|strcat|sprintf|read|fread|loop_write|ptr_write
    write_size: int = -1  # -1=无界, >=0=常量, -2=变量表达式
    offset: int = 0       # 相对分配基址的偏移
    src_var: str = ""     # 源变量名 (用于污点追踪)
    loop_bound: int = -1  # 跨函数loop_write的循环边界常量 (>0=已解析)


@dataclass
class HoResult:
    """堆写模式验证 (Heap Write Verification) 判定结果."""
    verdict: HoVerdict
    alloc_line: int = 0
    write_line: int = 0
    var_name: str = ""
    alloc_size: int = -1
    write_size: int = -1
    overflow_bytes: int = 0
    confidence: float = 0.0
    reason: str = ""
    # 过滤阶段标记
    stage_raw: bool = True          # 原始模式匹配
    stage_guard: bool = True        # guard/bounds检查后仍为溢出
    stage_constraint: bool = True   # 差异约束图后仍为溢出
    stage_alloc_model: bool = True  # 分配器模型后仍为溢出


__all__ = ['HoVerdict', 'HeapAllocSite', 'HeapWriteSite', 'HoResult']
