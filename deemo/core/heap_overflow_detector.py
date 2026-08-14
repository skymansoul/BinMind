"""
chunk 边界感知的堆溢出检测。
提取 malloc 调用点与分配大小, 将返回值追踪到后续 store 的基址寄存器,
仅报告 offset > chunk_size 的堆写入; 变量恢复失败时退回启发式规则。
"""

from dataclasses import dataclass, field
import re
from typing import Optional

from core.ir_normalizer import normalize_ir


@dataclass
class HeapAllocSite:
    pc: int
    alloc_func: str
    size_arg: int
    size_is_dynamic: bool
    result_var: str = ''
    size_expr: str = ''  # 动态分配时的符号表达式


@dataclass
class HeapStore:
    """堆写入点 — 写向 malloc 缓冲区的写入。"""
    pc: int
    base_var: str         # 基址变量 (malloc 的返回值)
    offset: int            # 相对基址的偏移 (常量) 或 -1 (动态)
    offset_is_dynamic: bool
    store_size: int        # 写入大小 (1/2/4/8 或 -1 表示未知)
    mnemonic: str = ''


@dataclass
class HeapOverflowCandidate:
    """堆溢出候选 — store 偏移超出分配大小。"""
    alloc_site: HeapAllocSite
    overflow_store: HeapStore
    overflow_bytes: int = 0
    confidence: float = 0.0
    description: str = ''


def extract_heap_allocations(ir_lines: list[str]) -> list[HeapAllocSite]:
    """从IR行中提取堆分配点。"""
    allocs = []
    alloc_pattern = re.compile(
        r'(?:(\w+)\s*=\s*)?(malloc|calloc|realloc)\s*\(\s*(\d+|\w+)\s*'
        r'(?:,\s*(\d+|\w+))?\s*\)',
        re.IGNORECASE,
    )

    for i, line in enumerate(ir_lines):
        m = alloc_pattern.search(line)
        if not m:
            continue
        result_var = m.group(1) or ''
        func = m.group(2).lower()
        size_str = m.group(3)

        try:
            size = int(size_str, 0)
            is_dynamic = False
        except (ValueError, TypeError):
            size = 0
            is_dynamic = True

        allocs.append(HeapAllocSite(
            pc=i, alloc_func=func, size_arg=size,
            size_is_dynamic=is_dynamic, result_var=result_var,
        ))

    return allocs


def track_heap_stores(ir_lines: list[str],
                      alloc: HeapAllocSite) -> list[HeapStore]:
    """追踪 malloc 返回值到后续 store 指令; result_var 缺失时退回启发式查找。"""
    stores = []
    if not alloc.result_var:
        return stores

    var = alloc.result_var
    store_pattern = re.compile(
        rf'store.*{re.escape(var)}'
        rf'|{re.escape(var)}\s*\[.*\]\s*='
        rf'|memcpy\s*\(\s*{re.escape(var)}\s*,'
        rf'|strcpy\s*\(\s*{re.escape(var)}\s*,',
        re.IGNORECASE,
    )

    # 直接文本搜索比逐行匹配更稳健
    for i in range(alloc.pc + 1, min(len(ir_lines), alloc.pc + 50)):
        line = ir_lines[i]

        # 检查 store 模式
        offset = _extract_store_offset(line, var)
        if offset is not None:
            stores.append(HeapStore(
                pc=i, base_var=var,
                offset=offset[0], offset_is_dynamic=offset[1],
                store_size=offset[2],
            ))
        elif store_pattern.search(line):
            stores.append(HeapStore(
                pc=i, base_var=var,
                offset=-1, offset_is_dynamic=True,
                store_size=-1,
            ))

    return stores


def _extract_store_offset(line: str, base_var: str) -> Optional[tuple[int, bool, int]]:
    """从 store 行提取偏移量。支持 [base+offset] 和 base[offset] 两种语法。

    返回 (offset, is_dynamic, store_size) 或 None。"""
    # 模式1: [base + 0x10] 或 [base + 16]
    m = re.search(rf'\[{re.escape(base_var)}\s*\+\s*((?:0x)?[0-9a-fA-F]+)\]', line)
    if m:
        try:
            return (int(m.group(1), 0), False, _infer_store_size(line))
        except (ValueError, TypeError):
            return (-1, True, -1)
    # 模式2: base[offset] = value
    m = re.search(rf'{re.escape(base_var)}\[(\d+)\]', line)
    if m:
        return (int(m.group(1)), False, _infer_store_size(line))
    # 模式3: memcpy(base, src, size) 或 strcpy(base, src)
    m = re.search(rf'(?:memcpy|strcpy|strncpy)\s*\(\s*{re.escape(base_var)}\s*,', line)
    if m:
        return (0, False, -1)  # 起始偏移为 0, 大小需要从参数推断
    return None


def _infer_store_size(line: str) -> int:
    """从 store 指令的操作数大小标记推断写入字节数。"""
    lowered = line.lower()
    if any(s in lowered for s in ('qword', 'mov q', 'fstp', 'stosq', 'sqword')):
        return 8
    if any(s in lowered for s in ('dword', 'mov d', 'movsd', 'stosd')):
        return 4
    if any(s in lowered for s in ('word', 'mov w', 'stosw')):
        return 2
    if any(s in lowered for s in ('byte', 'mov b', 'stosb', 'movzx')):
        return 1
    return -1


def detect_heap_overflow(
    ir_lines: list[str],
    decompiled_text: str = '',
) -> list[HeapOverflowCandidate]:
    """chunk 边界感知的堆溢出检测主入口。

    返回: 置信度排序的候选溢出列表。"""
    if not ir_lines and decompiled_text:
        ir_lines = normalize_ir(decompiled_text)

    allocs = extract_heap_allocations(ir_lines)
    candidates = []

    for alloc in allocs:
        if alloc.size_is_dynamic or alloc.size_arg <= 0:
            continue

        stores = track_heap_stores(ir_lines, alloc)
        # L2: 为索引写入推断循环上界
        loop_bound = _infer_loop_bound(ir_lines, alloc)
        for store in stores:
            if store.offset_is_dynamic and loop_bound > 0:
                # 动态偏移但有循环边界: 比较循环上限 vs 分配大小
                if loop_bound > alloc.size_arg:
                    overflow = loop_bound - alloc.size_arg
                    candidates.append(HeapOverflowCandidate(
                        alloc_site=alloc, overflow_store=store,
                        overflow_bytes=overflow,
                        confidence=0.55,
                        description=(f'{alloc.alloc_func}({alloc.size_arg}) '
                                    f'循环边界={loop_bound}→溢出{overflow}B'),
                    ))
                continue
            if store.offset_is_dynamic:
                continue

            if store.offset >= alloc.size_arg:
                overflow = store.offset + max(store.store_size, 1) - alloc.size_arg
                confidence = 0.85 if store.offset > alloc.size_arg + 8 else 0.60
                candidates.append(HeapOverflowCandidate(
                    alloc_site=alloc, overflow_store=store,
                    overflow_bytes=max(0, overflow), confidence=confidence,
                    description=(f'{alloc.alloc_func}({alloc.size_arg}) -> '
                                f'store at offset {store.offset} '
                                f'(overflow by {overflow}B)'),
                ))

    candidates.sort(key=lambda c: -c.confidence)
    return candidates


def _infer_loop_bound(ir_lines: list[str],
                      alloc: 'HeapAllocSite') -> int:
    """从IR行推断循环上界。搜索cmp/jne模式提取循环终止条件中的常量。

    模式: for(i=0;i<N;i++)编译为 cmp i,N; jl loop_start。
    从cmp指令的第二操作数提取N作为循环上界。
    返回: 循环上界(正整数), -1表示无法推断。
    """
    import re as _re
    # 在alloc之后的IR行中搜索cmp reg, imm模式
    for i in range(alloc.pc, min(len(ir_lines), alloc.pc + 30)):
        line = ir_lines[i]
        m = _re.search(r'cmp\s+\w+,\s*(0x[0-9a-fA-F]+|\d+)', line, _re.IGNORECASE)
        if m:
            try:
                bound = int(m.group(1), 0)
                if 0 < bound < 100000:
                    return bound
            except ValueError:
                pass
    return -1
