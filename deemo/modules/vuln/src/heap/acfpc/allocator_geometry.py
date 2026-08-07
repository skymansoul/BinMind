"""分配器几何 — 双模式可用大小模型.

  - strict 模式: 可用大小 = 请求大小. 与语言语义 (C 标准对象边界)
    及通用静态工具 (angr/Ghidra/CodeQL) 的基准一致, 用于指标对比.
  - glibc 模式: ptmalloc2 几何. chunk_size = align16(req+8),
    usable = chunk-8, 最小块 32. 与运行时实际可利用性一致.
  - 双模式共存: 报告主指标用 strict (与外部工具可比), glibc 用于
    讨论可利用性边界 (chunk 内越界不可破坏相邻块).
"""

from typing import Optional

SIZE_SZ = 8
MINSIZE = 32
ALIGN = 16


def align_up(value: int, alignment: int = ALIGN) -> int:
    return (value + alignment - 1) // alignment * alignment


def chunk_size(requested: int) -> int:
    return max(MINSIZE, align_up(requested + SIZE_SZ))


def usable_size(requested: int, mode: str = 'strict') -> int:
    if mode == 'glibc':
        return chunk_size(requested) - SIZE_SZ
    return max(0, requested)


def write_fits(requested: int, offset: int, length: int,
               mode: str = 'strict') -> bool:
    if length < 0 or offset < 0:
        return False
    return offset + length <= usable_size(requested, mode)


def overflow_bytes(requested: int, offset: int, length: int,
                   mode: str = 'strict') -> int:
    end = offset + length
    return max(0, end - usable_size(requested, mode))
