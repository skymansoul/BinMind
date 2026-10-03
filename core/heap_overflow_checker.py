"""
堆溢出检查器 - copy操作溢出判定 + 循环边界推断.
"""
import re
from typing import Optional

from core.heap_overflow_detector import HeapAllocSite, HeapStore, HeapOverflowCandidate
from core.heap_store_extractor import _UNBOUNDED_COPY


def _check_copy_overflow(alloc: HeapAllocSite, store: HeapStore) -> Optional[HeapOverflowCandidate]:
    """检查拷贝操作 (strcpy/memcpy/strncpy/memset) 是否溢出分配缓冲区.

    核心逻辑:
      - strcpy: 无界拷贝, 始终标记为潜在溢出 (除非有守卫证明安全)
      - memcpy/strncpy/memset: 若拷贝大小 > 分配大小, 确定溢出
      - 拷贝大小未知 (变量): 低置信度标记 (后续管线阶段可收紧)
    """
    copy_size = store.store_size
    alloc_size = alloc.size_arg
    alloc_is_dyn = alloc.size_is_dynamic
    op = store.mnemonic

    if op in ('strcpy', 'strcat'):
        alias_off = store.offset if store.offset > 0 else 0
        if alloc_is_dyn or alloc_size <= 0:
            return HeapOverflowCandidate(
                alloc_site=alloc, overflow_store=store,
                overflow_bytes=-1,
                confidence=0.40,
                description=(f'{alloc.alloc_func}(dynamic) + strcpy: '
                            f'无界拷贝到动态缓冲区, 静态不可判定'),
            )
        effective_size = alloc_size - alias_off
        if alias_off > 0:
            return HeapOverflowCandidate(
                alloc_site=alloc, overflow_store=store,
                overflow_bytes=-1,
                confidence=0.72,
                description=(f'{alloc.alloc_func}({alloc_size}) + strcpy @ offset {alias_off}: '
                            f'无界拷贝, 仅剩{effective_size}B可用 → 潜在溢出'),
            )
        return HeapOverflowCandidate(
            alloc_site=alloc, overflow_store=store,
            overflow_bytes=-1,
            confidence=0.65,
            description=(f'{alloc.alloc_func}({alloc_size}) + strcpy: '
                        f'无界拷贝到{alloc_size}B缓冲区 → 潜在溢出'),
        )

    if op == 'copy':
        if alloc_is_dyn or alloc_size <= 0:
            return HeapOverflowCandidate(
                alloc_site=alloc, overflow_store=store,
                overflow_bytes=-1,
                confidence=0.25,
                description=(f'{alloc.alloc_func}(dynamic) + copy: '
                            f'拷贝到动态缓冲区, 大小未知 → 需值流约束分析'),
            )
        return HeapOverflowCandidate(
            alloc_site=alloc, overflow_store=store,
            overflow_bytes=-1,
            confidence=0.35,
            description=(f'{alloc.alloc_func}({alloc_size}) + copy: '
                        f'拷贝到{alloc_size}B缓冲区, 大小未知'),
        )

    if copy_size == _UNBOUNDED_COPY:
        return HeapOverflowCandidate(
            alloc_site=alloc, overflow_store=store,
            overflow_bytes=-1,
            confidence=0.65,
            description=f'{alloc.alloc_func}({alloc_size}) + {op}: 无界写入',
        )

    if copy_size > 0:
        if alloc_is_dyn or alloc_size <= 0:
            return HeapOverflowCandidate(
                alloc_site=alloc, overflow_store=store,
                overflow_bytes=copy_size,
                confidence=0.40,
                description=(f'{alloc.alloc_func}(dynamic) + {op}({copy_size}): '
                            f'拷贝{op}大小与分配大小独立'),
            )
        alias_off = store.offset if store.offset > 0 else 0
        effective_boundary = alloc_size - alias_off
        if copy_size > effective_boundary:
            overflow = copy_size - effective_boundary
            desc = (f'{alloc.alloc_func}({alloc_size}) + {op}({copy_size})'
                    f' @ offset {alias_off}: '
                    f'拷贝{op}大小{op} > 剩余空间{effective_boundary}B')
            if alias_off > 0:
                desc += f' → 溢出{overflow}B'
            else:
                desc += f' > 分配大小{alloc_size} → 溢出{overflow}B'
            return HeapOverflowCandidate(
                alloc_site=alloc, overflow_store=store,
                overflow_bytes=overflow,
                confidence=0.82,
                description=desc,
            )
        return None

    if copy_size == -1:
        if alloc_is_dyn or alloc_size <= 0:
            return HeapOverflowCandidate(
                alloc_site=alloc, overflow_store=store,
                overflow_bytes=-1,
                confidence=0.30,
                description=(f'{alloc.alloc_func}(dynamic) + {op}(dynamic): '
                            f'分配与拷贝均为动态, 需值流约束分析'),
            )
        return HeapOverflowCandidate(
            alloc_site=alloc, overflow_store=store,
            overflow_bytes=-1,
            confidence=0.45,
            description=(f'{alloc.alloc_func}({alloc_size}) + {op}(var): '
                        f'拷贝大小可变, 可能超过{alloc_size}B缓冲区'),
        )

    return None


def _infer_loop_bound(ir_lines: list[str],
                      alloc: 'HeapAllocSite') -> int:
    """从IR行推断循环上界. 搜索for头和cmp模式提取循环终止条件中的常量.

    模式: for(i=0;i<N;i++) → N; cmp i,N; jl loop_start → N.
    返回: 循环上界(正整数), -1表示无法推断.
    """
    for i in range(alloc.pc, min(len(ir_lines), alloc.pc + 30)):
        line = ir_lines[i]
        fm = re.search(r'for\s*\([^;]*;\s*(\w+)\s*(<=|<|>)\s*(\w+|\d+)[^;]*;', line)
        if fm:
            bound_var = fm.group(3)
            try:
                bound = int(bound_var, 0)
                if 0 < bound < 100000:
                    return bound
            except ValueError:
                traced = _trace_var_constant(ir_lines, bound_var, i)
                if traced > 0:
                    return traced
    for i in range(alloc.pc, min(len(ir_lines), alloc.pc + 30)):
        line = ir_lines[i]
        m = re.search(r'cmp\s+\w+,\s*(0x[0-9a-fA-F]+|\d+)', line, re.IGNORECASE)
        if m:
            try:
                bound = int(m.group(1), 0)
                if 0 < bound < 100000:
                    return bound
            except ValueError:
                pass
    return -1


def _trace_var_constant(ir_lines: list[str], var_name: str, max_pc: int) -> int:
    """搜索变量 var_name 的常量赋值: var = <constant>.
    先在 max_pc 之前搜索, 若未找到则搜索整个 IR.
    返回常量值, -1 表示无法追踪.
    """
    pat = re.compile(rf'{re.escape(var_name)}\s*=\s*(\d+)')
    for i in range(max_pc, -1, -1):
        m = pat.search(ir_lines[i])
        if m:
            try:
                return int(m.group(1), 0)
            except ValueError:
                pass
    for i in range(max_pc + 1, len(ir_lines)):
        m = pat.search(ir_lines[i])
        if m:
            try:
                return int(m.group(1), 0)
            except ValueError:
                pass
    return -1
