"""堆分析共享类型 — AllocRecord / WriteRecord / FuncAnalysis.

从reg_tracker和_insn_handlers的共同依赖中提取,
打破循环import。
"""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AllocRecord:
    """一次堆分配记录."""
    addr: int
    alloc_func: str       # malloc/calloc/realloc
    size_reg: str         # 承载size的寄存器
    size_val: Optional[int] = None  # 已知size值(None=运行时确定)
    func_name: str = ""


@dataclass
class WriteRecord:
    """一次对堆缓冲区的写入记录."""
    addr: int
    write_func: str       # memcpy/strcpy/memset等
    base_src: str         # 目标缓冲区的值来源 (malloc@addr)
    offset: int = 0
    size_reg: str = ""
    size_val: Optional[int] = None
    access_size: int = 4
    func_name: str = ""


@dataclass
class FuncAnalysis:
    """单函数分析结果."""
    name: str
    n_insns: int = 0
    allocs: List[AllocRecord] = field(default_factory=list)
    writes: List[WriteRecord] = field(default_factory=list)
